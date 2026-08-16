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
 * linuwux -- SIGSYS/DenuvOwO redirect.
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <ucontext.h>

#include "linuwux.h"
#include "cpuid.h"
#include "sigsys.h"

/* Wine-system RIP helpers: linuwux.h */

/*
 * Wine amd64 keeps the SUD filter byte at TEB+0x340
 * (amd64_thread_data.syscall_dispatch). No prctl interpose needed.
 * ALLOW=0, BLOCK=1; only poke if it already looks like a filter byte
 * so seccomp-only trees (Proton 10) are left alone.
 */
#define LINUWUX_WINE_SUD_TEB_OFFSET 0x340

static void linuwux_rearm_sud(void)
{
    unsigned char *teb = (unsigned char *)linuwux_get_teb();
    unsigned char *sel;

    if (!teb)
        return;

    sel = teb + LINUWUX_WINE_SUD_TEB_OFFSET;
    if (*sel == 0 || *sel == 1)
        *sel = 1;  /* BLOCK before resuming TargetSysHandler */
}

static void linuwux_simple_svm_clear_query_buffer(ucontext_t *ctx,
                                                   size_t size)
{
    unsigned long long address;
    volatile unsigned char *buffer;
    size_t i;

    if (!ctx || size == 0)
        return;

    address = (unsigned long long)ctx->uc_mcontext.gregs[REG_RDX];
    if (!address || address > 0x00007fffffffffffULL ||
        address + size < address || address + size > 0x0000800000000000ULL)
        return;

    buffer = (volatile unsigned char *)(uintptr_t)address;
    for (i = 0; i < size; ++i)
        buffer[i] = 0;
}

int linuwux_sigsys_route(siginfo_t *info, ucontext_t *ctx)
{
    __uint128_t *xmm_regs;
    struct linuwux_syscall_route route;
    unsigned long long syscall_nr, rip, resume, saved_rcx;
    unsigned char *fault_ip, opcode0, opcode1;

    if (!ctx->uc_mcontext.fpregs)
        return 0;
    xmm_regs = (__uint128_t *)ctx->uc_mcontext.fpregs->_xmm;

    if (!linuwux_cpuid_syscall_route(ctx, &route) ||
        (xmm_regs[5] & 0xFFFFFFFFFFFFFFFFULL) == 0x1337133713371337ULL)
        goto not_ours;

    syscall_nr = (unsigned long long)ctx->uc_mcontext.gregs[REG_RAX];
    rip = (unsigned long long)ctx->uc_mcontext.gregs[REG_RIP];
    saved_rcx = (unsigned long long)ctx->uc_mcontext.gregs[REG_RCX];

    /* SimpleSvm's native LSTAR hook maps these private syscall markers back
     * to Windows syscall IDs before re-entering the original syscall path.
     * Its follow-up syscall is nested inside this SIGSYS delivery on Linux,
     * so SUD allows it as a host syscall instead of delivering a second
     * signal.  Let Wine's original SIGSYS handler perform the dispatch with
     * the mapped Windows ID instead. */
    if (0 && linuwux_cpuid_simple_svm_active()) {
        unsigned long mapped_nr = 0;

        /* winmm's native TargetSysHandler sets SyscallBypassMagic before
         * re-executing every target syscall.  The second SimpleSvm hook sees
         * that magic and clears XMM5 before the original LSTAR runs.  Since
         * the Wine SIGSYS chain performs that second pass for us, reproduce
         * the register side effect here as well. */
        xmm_regs[5] = 0;

        if (syscall_nr == 0x13371337u)
            mapped_nr = 0x36u;
        else if (syscall_nr == 0x13371338u)
            mapped_nr = 0xbeu;

        if (mapped_nr) {
            if (syscall_nr == 0x13371337u &&
                (unsigned long long)ctx->uc_mcontext.gregs[REG_R8] >= 0x39)
                linuwux_simple_svm_clear_query_buffer(ctx, 0x39);
            else if (syscall_nr == 0x13371338u)
                linuwux_simple_svm_clear_query_buffer(ctx, 0x34);
            linuwux_log("SimpleSvm syscall handoff rax=%#llx -> Windows syscall %#lx "
                        "rdi=%#llx rsi=%#llx rdx=%#llx r8=%#llx r9=%#llx "
                        "r10=%#llx rip=%#llx rcx=%#llx\n",
                        syscall_nr, mapped_nr,
                        (unsigned long long)ctx->uc_mcontext.gregs[REG_RDI],
                        (unsigned long long)ctx->uc_mcontext.gregs[REG_RSI],
                        (unsigned long long)ctx->uc_mcontext.gregs[REG_RDX],
                        (unsigned long long)ctx->uc_mcontext.gregs[REG_R8],
                        (unsigned long long)ctx->uc_mcontext.gregs[REG_R9],
                        (unsigned long long)ctx->uc_mcontext.gregs[REG_R10],
                        rip, saved_rcx);
            ctx->uc_mcontext.gregs[REG_RAX] = (long long)mapped_nr;
            return 0;
        }

        /* The Windows TargetSysHandler would pass ordinary syscalls back to
         * the original LSTAR.  Returning here lets Wine's SIGSYS dispatcher
         * perform that same operation without executing a Linux syscall with
         * a Windows syscall number. */
        return 0;
    }

    if (!linuwux_redirect_all_enabled() && linuwux_rip_is_wine_system(rip))
        return 0;

    fault_ip = (unsigned char *)(uintptr_t)rip;
    opcode0 = fault_ip[0];
    opcode1 = fault_ip[1];
    /* Advance past `syscall` (0f 05) when that is the fault site. */
    resume = (opcode0 == 0x0f && opcode1 == 0x05) ? rip + 2 : rip;

    linuwux_log("sigsys redirect pid=%d si_code=%d si_errno=%d rax=%llx rip=%llx rcx=%llx resume=%llx rdi=%llx rsi=%llx rdx=%llx r8=%llx r9=%llx r10=%llx r11=%llx mode=%d xmm5=%llx -> %#llx\n",
                (int)getpid(),
                info ? info->si_code : 0,
                info ? info->si_errno : 0,
                syscall_nr, rip, saved_rcx, resume,
                (unsigned long long)ctx->uc_mcontext.gregs[REG_RDI],
                (unsigned long long)ctx->uc_mcontext.gregs[REG_RSI],
                (unsigned long long)ctx->uc_mcontext.gregs[REG_RDX],
                (unsigned long long)ctx->uc_mcontext.gregs[REG_R8],
                (unsigned long long)ctx->uc_mcontext.gregs[REG_R9],
                (unsigned long long)ctx->uc_mcontext.gregs[REG_R10],
                (unsigned long long)ctx->uc_mcontext.gregs[REG_R11],
                route.rax_is_resume,
                (unsigned long long)(xmm_regs[5] & 0xFFFFFFFFFFFFFFFFULL),
                (unsigned long long)route.handler);

    /* SimpleSvm's LSTAR hook begins every handoff with `movd xmm4,eax`.
     * MOVD clears the upper 96 bits; preserving the caller's XMM4 state
     * changes the register-visible result after the native handler jumps
     * back to the protected caller. */
    xmm_regs[4] = syscall_nr & 0xFFFFFFFFULL;
    ctx->uc_mcontext.gregs[REG_RAX] = (long long)(route.rax_is_resume ? resume : saved_rcx);
    ctx->uc_mcontext.gregs[REG_RCX] = (long long)route.handler;
    ctx->uc_mcontext.gregs[REG_RIP] = (long long)route.handler;

    linuwux_rearm_sud();
    linuwux_log("sigsys context pid=%d rip=%#llx rax=%#llx rcx=%#llx xmm4=%#llx\n",
                (int)getpid(),
                (unsigned long long)ctx->uc_mcontext.gregs[REG_RIP],
                (unsigned long long)ctx->uc_mcontext.gregs[REG_RAX],
                (unsigned long long)ctx->uc_mcontext.gregs[REG_RCX],
                (unsigned long long)(xmm_regs[4] & 0xFFFFFFFFULL));
    return 1;

not_ours:
    if ((xmm_regs[5] & 0xFFFFFFFFFFFFFFFFULL) == 0x1337133713371337ULL) {
        unsigned char *teb = (unsigned char *)linuwux_get_teb();
        linuwux_log("sigsys magic passthrough pid=%d rax=%llx rip=%llx rcx=%llx xmm4=%llx sud=%u\n",
                    (int)getpid(),
                    (unsigned long long)ctx->uc_mcontext.gregs[REG_RAX],
                    (unsigned long long)ctx->uc_mcontext.gregs[REG_RIP],
                    (unsigned long long)ctx->uc_mcontext.gregs[REG_RCX],
                    (unsigned long long)(xmm_regs[4] & 0xFFFFFFFFULL),
                    teb ? teb[LINUWUX_WINE_SUD_TEB_OFFSET] : 0xff);
        xmm_regs[5] = 0;
    }
    return 0;
}
