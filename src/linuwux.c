/*
 * Copyright (C) 2026 brcly
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*
 * linuwux — LD_PRELOAD library for DenuvOwO under Wine/Proton.
 * Constructor only; modules/ holds hooks, cpuid, sigsys, registry, faketime,
 * overrides.
 * Debug: LINUWUX_DEBUG=1
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "modules/linuwux.h"
#include "modules/cpuid.h"
#include "modules/faketime.h"
#include "modules/overrides.h"

/* Kept for `strings` / `linuwux --version`. */
static const char linuwux_version_tag[] __attribute__((used)) =
    "linuwux " LINUWUX_VERSION;

/*
 * is_game markers beside the Windows target exe (existence only, never loaded):
 *   reflex.dll / reflex64.dll  — modern reflex-loader packs
 *   DenuvOwO.dll               — older hybrid DenuvOwO loader
 *   DenuvOwO.ini               — SimpleSvm-backed winmm-loader packs
 *
 * Prefer reflex* when both families are present.
 *
 * The same directory walk also records pack-native DLLs we may need to
 * prefer via WINEDLLOVERRIDES (winmm / version / reflex / reflex64).
 */
enum linuwux_game_marker {
    LINUWUX_GAME_NONE = 0,
    LINUWUX_GAME_REFLEX,
    LINUWUX_GAME_DENUVOWO,
    LINUWUX_GAME_SIMPLE_SVM,
};

struct linuwux_game_scan {
    int marker;
    unsigned native; /* LINUWUX_NATIVE_* from overrides.h */
};

static void linuwux_dir_scan(const char *dir, struct linuwux_game_scan *out)
{
    DIR *d;
    struct dirent *ent;

    out->marker = LINUWUX_GAME_NONE;
    out->native = 0;

    d = opendir(dir);
    if (!d)
        return;

    while ((ent = readdir(d))) {
        if (!strcasecmp(ent->d_name, "reflex.dll")) {
            out->marker = LINUWUX_GAME_REFLEX;
            out->native |= LINUWUX_NATIVE_REFLEX;
            linuwux_log("Found %s\n", ent->d_name);
            continue;
        }
        if (!strcasecmp(ent->d_name, "reflex64.dll")) {
            out->marker = LINUWUX_GAME_REFLEX;
            out->native |= LINUWUX_NATIVE_REFLEX64;
            linuwux_log("Found %s\n", ent->d_name);
            continue;
        }
        if (!strcasecmp(ent->d_name, "winmm.dll")) {
            out->native |= LINUWUX_NATIVE_WINMM;
            continue;
        }
        if (!strcasecmp(ent->d_name, "version.dll")) {
            out->native |= LINUWUX_NATIVE_VERSION;
            continue;
        }
        if (!strcasecmp(ent->d_name, "DenuvOwO.dll") &&
            (out->marker == LINUWUX_GAME_NONE ||
             out->marker == LINUWUX_GAME_SIMPLE_SVM)) {
            out->marker = LINUWUX_GAME_DENUVOWO;
            linuwux_log("Found %s\n", ent->d_name);
            continue;
        }
        if (!strcasecmp(ent->d_name, "DenuvOwO.ini") &&
            out->marker == LINUWUX_GAME_NONE) {
            out->marker = LINUWUX_GAME_SIMPLE_SVM;
            linuwux_log("Found %s\n", ent->d_name);
        }
    }
    closedir(d);
}

/*
 * Resolve argv[1] Windows path (X:\...) to the host directory that holds
 * the target exe, then scan it for markers and pack-native DLLs.
 */
static void linuwux_game_dir_scan(const char *argv1, struct linuwux_game_scan *out)
{
    const char *prefix;
    char path[PATH_MAX];
    char drive;
    char *slash;
    size_t i;

    out->marker = LINUWUX_GAME_NONE;
    out->native = 0;

    if (!argv1 || !argv1[0] || argv1[1] != ':')
        return;

    drive = (char)tolower((unsigned char)argv1[0]);

    /* Z: = host filesystem root; skip dosdevices. */
    if (drive == 'z') {
        if (snprintf(path, sizeof(path), "%s", argv1 + 2) >= (int)sizeof(path))
            return;
    } else {
        prefix = getenv("WINEPREFIX");
        if (!prefix)
            return;

        if (snprintf(path, sizeof(path), "%s/dosdevices/%c:%s",
                     prefix, drive, argv1 + 2) >= (int)sizeof(path))
            return;
    }

    for (i = 0; path[i]; i++)
        if (path[i] == '\\')
            path[i] = '/';

    slash = strrchr(path, '/');
    if (!slash)
        return;
    *slash = '\0';

    linuwux_dir_scan(path, out);
}

/* /proc/self/comm holds the kernel task name (<=15 chars + NUL); wineserver
 * fits comfortably. Cheaper and simpler than resolving /proc/self/exe and
 * comparing basenames. */
static int linuwux_proc_comm_is_wineserver(void)
{
    char comm[32];
    int fd;
    ssize_t n;

    fd = open("/proc/self/comm", O_RDONLY);
    if (fd < 0)
        return 0;
    n = read(fd, comm, sizeof(comm) - 1);
    close(fd);
    if (n <= 0)
        return 0;
    if (comm[n - 1] == '\n')
        n--;
    comm[n] = '\0';

    return strcmp(comm, "wineserver") == 0;
}

/* GNU constructor extension: glibc passes real argc/argv/envp. */
__attribute__((constructor))
static void linuwux_init(int argc, char **argv, char **envp)
{
    struct linuwux_game_scan scan;
    int is_game, is_wineserver;

    (void)envp;

    /* Wine: argv[0] is the loader; argv[1] is the Windows target path. */
    linuwux_game_dir_scan(argc > 1 ? argv[1] : NULL, &scan);
    is_game = scan.marker != LINUWUX_GAME_NONE;
    linuwux_set_game_process(is_game);
    if (is_game && argc > 1 && argv[1]) {
        const char *exe = argv[1];
        const char *slash = exe;
        for (const char *p = exe; *p; p++)
            if (*p == '\\' || *p == '/')
                slash = p + 1;
        linuwux_log("Found game: %s\n", *slash ? slash : exe);
    }

    /* wineserver is never also the game (argv[1] would have to be
     * both "-w" and a reflex.dll-adjacent X:\...exe path), so these
     * two flags are mutually exclusive in practice. */
    is_wineserver = linuwux_proc_comm_is_wineserver();
    linuwux_set_is_wineserver(is_wineserver);

    /* Only the game (to publish a faketime handshake) and wineserver
     * (to serve it back out through gettimeofday) ever touch the
     * prefix-shared faketime state -- see faketime.c. */
    if (is_game || is_wineserver)
        linuwux_faketime_prefix_init();

    /* Spoof leaves only needed in the game process (CPUID path gated). */
    if (is_game) {
        if (scan.marker == LINUWUX_GAME_DENUVOWO)
            linuwux_cpuid_hint_denuvowo();
        else if (scan.marker == LINUWUX_GAME_SIMPLE_SVM)
            linuwux_cpuid_hint_simple_svm();
        linuwux_detect_cpu_vendor();
    }

    /*
     * DLL load order only in the game process (Wine reads env at PE load).
     * Existence-gated merge: prefer native winmm/version/reflex only when
     * those files sit next to the exe. User/Proton keys are never clobbered.
     */
    if (is_game)
        linuwux_overrides_apply(scan.native);

    /* Global: Proton may read this before any Wine process starts. */
    setenv("PROTON_DISABLE_LSTEAMCLIENT", "1", 0);

    /* Version banner only for the game process. */
    if (is_game)
        fprintf(stderr, "[linuwux] v%s loaded (pid=%d)\n", LINUWUX_VERSION, getpid());
}
