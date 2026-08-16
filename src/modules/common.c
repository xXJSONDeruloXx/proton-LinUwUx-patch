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
 * linuwux -- shared logging.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "linuwux.h"

/* Default 1 so test harnesses without set_game_process still log. */
static int g_is_game_process = 1;
static int g_debug_fd = STDERR_FILENO;
static int g_debug_output_initialized;
static pid_t g_debug_identity_pid = (pid_t)-1;
static char g_debug_process_name[64] = "unknown";

static void linuwux_debug_refresh_identity(void)
{
    pid_t pid;
    int fd;
    ssize_t length;

    pid = getpid();
    if (g_debug_identity_pid == pid)
        return;

    g_debug_identity_pid = pid;
    memcpy(g_debug_process_name, "unknown", sizeof("unknown"));

    fd = open("/proc/self/comm", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return;

    length = read(fd, g_debug_process_name, sizeof(g_debug_process_name) - 1);
    close(fd);

    if (length <= 0)
        return;

    g_debug_process_name[length] = '\0';
    while (length > 0 &&
           (g_debug_process_name[length - 1] == '\n' ||
            g_debug_process_name[length - 1] == '\r'))
    {
        g_debug_process_name[length - 1] = '\0';
        length--;
    }

    if (length == 0)
        memcpy(g_debug_process_name, "unknown", sizeof("unknown"));
}

static int linuwux_debug_make_log_path(const char *directory,
                                       char *path,
                                       size_t path_size)
{
    struct timespec now;
    struct tm local;
    char timestamp[32];
    pid_t session_id;
    int written;
    int needs_slash;

    if (!directory || !*directory || !path || path_size == 0)
        return -1;

    if (clock_gettime(CLOCK_REALTIME, &now) != 0 ||
        !localtime_r(&now.tv_sec, &local) ||
        strftime(timestamp, sizeof(timestamp), "%Y%m%d-%H%M%S", &local) == 0)
        return -1;

    session_id = getsid(0);
    if (session_id < 0)
        session_id = getpid();

    needs_slash = directory[strlen(directory) - 1] != '/';
    written = snprintf(path, path_size,
                       "%s%slinuwux-runtime-%s-s%ld.log",
                       directory, needs_slash ? "/" : "", timestamp,
                       (long)session_id);
    if (written < 0 || (size_t)written >= path_size)
        return -1;

    return 0;
}

void linuwux_debug_init_output(void)
{
    const char *existing_log;
    const char *directory;
    const char *path;
    char generated_path[PATH_MAX];
    int fd;
    int saved_errno;

    if (g_debug_output_initialized)
        return;
    g_debug_output_initialized = 1;

    if (!getenv("LINUWUX_DEBUG"))
        return;

    existing_log = getenv("LINUWUX_DEBUG_LOG");
    if (existing_log && *existing_log)
    {
        path = existing_log;
    }
    else
    {
        directory = getenv("LINUWUX_DEBUG_DIR");
        if (!directory || !*directory)
            return;

        if (linuwux_debug_make_log_path(directory, generated_path,
                                        sizeof(generated_path)) != 0 ||
            setenv("LINUWUX_DEBUG_LOG", generated_path, 1) != 0)
        {
            fprintf(stderr,
                    "[linuwux] could not create a session debug path; "
                    "using stderr\n");
            return;
        }

        path = getenv("LINUWUX_DEBUG_LOG");
        if (!path || !*path)
            return;
    }

    fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd < 0)
    {
        saved_errno = errno;
        fprintf(stderr,
                "[linuwux] could not open debug log '%s': %s; using stderr\n",
                path, strerror(saved_errno));
        return;
    }

    g_debug_fd = fd;
}

static void linuwux_debug_write(const char *buffer, size_t length)
{
    size_t written = 0;

    while (written < length)
    {
        ssize_t result = write(g_debug_fd, buffer + written, length - written);
        if (result > 0)
        {
            written += (size_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR)
            continue;
        break;
    }

    if (written < length && g_debug_fd != STDERR_FILENO)
    {
        written = 0;
        while (written < length)
        {
            ssize_t result = write(STDERR_FILENO, buffer + written,
                                   length - written);
            if (result > 0)
            {
                written += (size_t)result;
                continue;
            }
            if (result < 0 && errno == EINTR)
                continue;
            break;
        }
    }
}

void linuwux_set_game_process(int is_game)
{
    g_is_game_process = is_game;
}

/* wineserver is the process Wine clients route their "current time"
 * through -- see faketime.c for why that matters. Set once alongside
 * is_game, never true at the same time as it. */
static int g_is_wineserver;

void linuwux_set_is_wineserver(int is_wineserver)
{
    g_is_wineserver = is_wineserver;
}

int linuwux_is_wineserver(void)
{
    return g_is_wineserver;
}

int linuwux_is_game_process(void)
{
    return g_is_game_process;
}

void linuwux_log(const char *fmt, ...)
{
    char line[4096];
    va_list ap;
    int prefix_length;
    int message_length;
    int saved_errno;
    size_t length;

    /* wineserver now does real, intentional work too (see faketime.c),
     * so its debug output is worth keeping, same as the game's. */
    if ((!g_is_game_process && !g_is_wineserver) || !getenv("LINUWUX_DEBUG"))
        return;

    linuwux_debug_init_output();
    saved_errno = errno;
    linuwux_debug_refresh_identity();

    prefix_length = snprintf(line, sizeof(line),
                             "[linuwux] pid=%ld proc=%s ",
                             (long)getpid(), g_debug_process_name);
    if (prefix_length < 0 || (size_t)prefix_length >= sizeof(line))
    {
        errno = saved_errno;
        return;
    }

    va_start(ap, fmt);
    message_length = vsnprintf(line + prefix_length,
                               sizeof(line) - (size_t)prefix_length,
                               fmt, ap);
    va_end(ap);

    if (message_length < 0)
    {
        errno = saved_errno;
        return;
    }

    length = (size_t)prefix_length + (size_t)message_length;
    if (length >= sizeof(line) - 1)
        length = sizeof(line) - 2;
    if (length == 0 || line[length - 1] != '\n')
        line[length++] = '\n';

    linuwux_debug_write(line, length);
    errno = saved_errno;
}
