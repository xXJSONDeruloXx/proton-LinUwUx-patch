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
 * linuwux -- CPUID spoofing, KUSER_SHARED_DATA patch, and the
 * DenuvOwO arm/faketime handshake leaves.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "linuwux.h"
#include "cpuid.h"
#include "faketime.h"
#include "registry.h"

/* Set on arm leaf; read from all threads. */
static _Atomic uint64_t g_target_sys_handler = 0;

#ifdef LINUWUX_LEGACY_REFLEX
static _Atomic int g_legacy_reflex_initialized = 0;
static _Atomic uint64_t g_legacy_reflex_single_handler = 0;
static _Atomic int g_legacy_reflex_dual = 0;
static _Atomic uint32_t g_legacy_reflex_query_system_id = 0xffffffff;
static _Atomic uint64_t g_legacy_reflex_query_full_handler = 0;
static _Atomic uint32_t g_legacy_reflex_query_full_id = 0xffffffff;
#endif

/* Filled once in the constructor before any other thread exists. */
static unsigned int g_spoof_leaf1_eax, g_spoof_leaf1_ebx, g_spoof_leaf1_ecx, g_spoof_leaf1_edx;
static unsigned int g_spoof_leaf40000000_eax, g_spoof_leaf40000000_ebx, g_spoof_leaf40000000_ecx, g_spoof_leaf40000000_edx;
static unsigned int g_spoof_leaf40000001_eax, g_spoof_leaf40000001_ebx, g_spoof_leaf40000001_ecx, g_spoof_leaf40000001_edx;

uint64_t linuwux_cpuid_target_sys_handler(void)
{
    return atomic_load(&g_target_sys_handler);
}

#ifdef LINUWUX_LEGACY_REFLEX
int linuwux_cpuid_legacy_reflex_initialized(void)
{
    return atomic_load(&g_legacy_reflex_initialized);
}

uint64_t linuwux_cpuid_legacy_reflex_single_handler(void)
{
    return atomic_load(&g_legacy_reflex_single_handler);
}

int linuwux_cpuid_legacy_reflex_dual(void)
{
    return atomic_load(&g_legacy_reflex_dual);
}

uint32_t linuwux_cpuid_legacy_reflex_query_system_id(void)
{
    return atomic_load(&g_legacy_reflex_query_system_id);
}

uint64_t linuwux_cpuid_legacy_reflex_query_full_handler(void)
{
    return atomic_load(&g_legacy_reflex_query_full_handler);
}

uint32_t linuwux_cpuid_legacy_reflex_query_full_id(void)
{
    return atomic_load(&g_legacy_reflex_query_full_id);
}
#endif

void linuwux_detect_cpu_vendor(void)
{
    unsigned int eax, ebx, ecx, edx;
    int avx = 0;
    if (getenv("PROTON_AVX") != NULL && strcmp(getenv("PROTON_AVX"), "1") == 0)
        avx = 1;

    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0) : "memory");

    if (ebx == 0x756E6547 && edx == 0x49656E69 && ecx == 0x6C65746E) {
        /* GenuineIntel */
        g_spoof_leaf1_eax = 0x000A0655;
        g_spoof_leaf1_ebx = 0x00200800;
        g_spoof_leaf1_ecx = avx ? 0x7BFAFBFF : 0x01FAEBFF;
        g_spoof_leaf1_edx = 0xBFEBFBFF;
        g_spoof_leaf40000000_eax = 0x40000001;
        g_spoof_leaf40000000_ebx = 0x65707948;
        g_spoof_leaf40000000_ecx = 0x67624472;
        g_spoof_leaf40000000_edx = 0;
        g_spoof_leaf40000001_eax = 0x30237648;
        g_spoof_leaf40000001_ebx = 0;
        g_spoof_leaf40000001_ecx = 0;
        g_spoof_leaf40000001_edx = 0;
        linuwux_log("detect_cpu_vendor: Intel (avx=%d)\n", avx);
    } else if (ebx == 0x68747541 && edx == 0x69746E65 && ecx == 0x444D4163) {
        /* AuthenticAMD */
        g_spoof_leaf1_eax = 0x00A20F12;
        g_spoof_leaf1_ebx = 0x00100800;
        g_spoof_leaf1_ecx = avx ? 0x7AD8320B : 0x00F8220B;
        g_spoof_leaf1_edx = 0x178BFBFF;
        g_spoof_leaf40000000_eax = 0x40000001;
        g_spoof_leaf40000000_ebx = 0x706D6953;
        g_spoof_leaf40000000_ecx = 0x7653656C;
        g_spoof_leaf40000000_edx = 0x2020206D;
        g_spoof_leaf40000001_eax = 0x30237648;
        g_spoof_leaf40000001_ebx = 0;
        g_spoof_leaf40000001_ecx = 0;
        g_spoof_leaf40000001_edx = 0;
        linuwux_log("detect_cpu_vendor: AMD (avx=%d)\n", avx);
    } else {
        linuwux_log("detect_cpu_vendor: unknown vendor ebx=%08x edx=%08x ecx=%08x\n", ebx, edx, ecx);
    }
}

#define LINUWUX_KUSER_SHARED_DATA_ADDR 0x000000007FFE0000UL

static void linuwux_patch_kuser_shared_data(void)
{
    uint8_t *kuser = (uint8_t *)LINUWUX_KUSER_SHARED_DATA_ADDR;
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    void *page_start = (void *)((uintptr_t)LINUWUX_KUSER_SHARED_DATA_ADDR & ~(page_size - 1));

    if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE) == -1) {
        linuwux_log("kuser_shared_data: mprotect failed: %s\n", strerror(errno));
        return;
    }

    {
        static const unsigned short nt_system_root[] = { 'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', 0 };
        memcpy(kuser + 0x30, nt_system_root, sizeof(nt_system_root));
    }

    *(uint64_t *)(kuser + 0x260) = 0x0100006658;
    *(uint32_t *)(kuser + 0x268) = 0x090001;
    *(uint32_t *)(kuser + 0x26C) = 0x0A;
    *(uint32_t *)(kuser + 0x270) = 0x00;
    *(uint32_t *)(kuser + 0x274) = 0x01010000;
    *(uint32_t *)(kuser + 0x278) = 0x010000;
    *(uint32_t *)(kuser + 0x27C) = 0x010101;
    *(uint32_t *)(kuser + 0x280) = 0x010101;
    *(uint32_t *)(kuser + 0x284) = 0x0100;
    *(uint32_t *)(kuser + 0x288) = 0x01010101;
    *(uint32_t *)(kuser + 0x28C) = 0x0;
    *(uint32_t *)(kuser + 0x290) = 0x01;
    *(uint32_t *)(kuser + 0x294) = 0x01000101;
    *(uint32_t *)(kuser + 0x298) = 0x01010101;
    *(uint32_t *)(kuser + 0x29C) = 0x010001;
    *(uint32_t *)(kuser + 0x2A0) = 0x0;
    *(uint32_t *)(kuser + 0x2A4) = 0x0;
    *(uint32_t *)(kuser + 0x2A8) = 0x0;
    *(uint32_t *)(kuser + 0x2AC) = 0x0;
    *(uint32_t *)(kuser + 0x2B0) = 0x1;
    *(uint8_t *)(kuser + 0x290) = 0x0;  /* MONITORX */
    *(uint8_t *)(kuser + 0x294) = 0x0;  /* RDTSCP */
    *(uint8_t *)(kuser + 0x295) = 0x0;  /* RDPID */
    *(uint8_t *)(kuser + 0x297) = 0x0;  /* RDRAND */

    if (getenv("PROTON_AVX") == NULL || strcmp(getenv("PROTON_AVX"), "1") != 0) {
        *(uint8_t *)(kuser + 0x285) = 0x0;  /* XSAVE */
        *(uint8_t *)(kuser + 0x29B) = 0x0;  /* AVX */
        *(uint8_t *)(kuser + 0x29C) = 0x0;  /* AVX2 */
    }

    *(uint64_t *)(kuser + 0x3D8) = 0x0;
    *(uint64_t *)(kuser + 0x3E0) = 0x0;
    *(uint32_t *)(kuser + 0x3EC) = 0x0;
    memset((void *)(kuser + 0x3F0), 0x00, 0x200);
    *(uint64_t *)(kuser + 0x5F0) = 0x0;
    *(uint64_t *)(kuser + 0x5F8) = 0x0;
    memset((void *)(kuser + 0x604), 0x00, 0x200);
    *(uint64_t *)(kuser + 0x808) = 0x0;
    *(uint64_t *)(kuser + 0x810) = 0x0;
    *(uint64_t *)(kuser + 0x2D0) = 0x320A0000000110;
    *(uint64_t *)(kuser + 0x2E8) = 0x0100007FB10B;
    *(uint32_t *)(kuser + 0x2F4) = 0x0;
    *(uint64_t *)(kuser + 0x36C) = 0x0;
    *(uint64_t *)(kuser + 0x374) = 0x0;
    *(uint32_t *)(kuser + 0x37C) = 0x1;
    *(uint64_t *)(kuser + 0x3C0) = 0x83000100000010;
    *(uint32_t *)(kuser + 0xFFC) = 0x13371337;

    linuwux_log("kuser_shared_data: patched\n");
}

#ifdef LINUWUX_LEGACY_REFLEX
static void linuwux_patch_legacy_single_kuser_shared_data(void)
{
    uint8_t *kuser = (uint8_t *)LINUWUX_KUSER_SHARED_DATA_ADDR;
    long page_size_long = sysconf(_SC_PAGESIZE);
    size_t page_size;
    void *page_start;

    if (page_size_long <= 0)
    {
        linuwux_log("legacy kuser_shared_data: sysconf(_SC_PAGESIZE) failed\n");
        return;
    }
    page_size = (size_t)page_size_long;
    page_start = (void *)((uintptr_t)LINUWUX_KUSER_SHARED_DATA_ADDR & ~(page_size - 1));

    if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE) == -1)
    {
        linuwux_log("legacy kuser_shared_data: mprotect failed: %s\n", strerror(errno));
        return;
    }

    *(uint32_t *)(kuser + 0x2d6) = 0x00010034;
    *(uint32_t *)(kuser + 0x2e8) = 0x00bf9c8f;
    *(uint32_t *)(kuser + 0x3c0) = 0x00000010;
    *(uint32_t *)(kuser + 0x288) = 0x01010101;
    *(uint32_t *)(kuser + 0x268) = 0x00090001;
    *(uint32_t *)(kuser + 0x2f4) = 0x0;
    *(uint32_t *)(kuser + 0x264) = 0x1;
    *(uint32_t *)(kuser + 0x2d0) = 0x00000310;
    *(uint32_t *)(kuser + 0x260) = 0x00006658;
    *(uint32_t *)(kuser + 0x26c) = 0x0a;
    *(uint32_t *)(kuser + 0x270) = 0x0;

    linuwux_log("legacy single-handler KUSER_SHARED_DATA profile: patched\n");
}

static void linuwux_patch_legacy_dual_kuser_shared_data(void)
{
    uint8_t *kuser = (uint8_t *)LINUWUX_KUSER_SHARED_DATA_ADDR;
    long page_size_long = sysconf(_SC_PAGESIZE);
    size_t page_size;
    void *page_start;

    if (page_size_long <= 0)
    {
        linuwux_log("legacy kuser_shared_data: sysconf(_SC_PAGESIZE) failed\n");
        return;
    }
    page_size = (size_t)page_size_long;
    page_start = (void *)((uintptr_t)LINUWUX_KUSER_SHARED_DATA_ADDR & ~(page_size - 1));

    if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE) == -1)
    {
        linuwux_log("legacy kuser_shared_data: mprotect failed: %s\n", strerror(errno));
        return;
    }

    *(uint64_t *)(kuser + 0x26e) = 0;
    *(uint64_t *)(kuser + 0x283) = 0x0101010000010000ULL;
    *(uint64_t *)(kuser + 0x288) = 0x01010101ULL;
    *(uint64_t *)(kuser + 0x268) = 0x0a00090001ULL;
    *(uint64_t *)(kuser + 0x261) = 0x0100000001000066ULL;
    *(uint64_t *)(kuser + 0x272) = 0x010100000000ULL;
    *(uint32_t *)(kuser + 0x3c0) = 0x10;
    *(uint64_t *)(kuser + 0x260) = 0x0100006658ULL;
    *(uint64_t *)(kuser + 0x282) = 0x0101000001000001ULL;
    *(uint32_t *)(kuser + 0x2d0) = 0x0110;
    *(uint32_t *)(kuser + 0x2e8) = 0x7fb10b;
    *(uint32_t *)(kuser + 0x378) = 0;
    *(uint64_t *)(kuser + 0x2e8) = 0x0100007fb10bULL;
    *(uint64_t *)(kuser + 0x273) = 0x0100000101000000ULL;
    *(uint64_t *)(kuser + 0x2d0) = 0x320a0000000110ULL;
    *(uint64_t *)(kuser + 0x000) = 0x0fa0000000000000ULL;
    *(uint64_t *)(kuser + 0x281) = 0x0100000100000101ULL;
    *(uint64_t *)(kuser + 0x378) = 0x0100000000ULL;
    *(uint64_t *)(kuser + 0x3c0) = 0x83000100000010ULL;
    *(uint64_t *)(kuser + 0x26c) = 0x0a;
    *(uint32_t *)(kuser + 0x2f4) = 0;
    *(uint32_t *)(kuser + 0x264) = 1;
    *(uint32_t *)(kuser + 0x270) = 0;

    linuwux_log("legacy dual-handler KUSER_SHARED_DATA profile: patched\n");
}
#endif

/* Real CPUID with faulting briefly disabled. */
static void linuwux_cpuid_passthrough(ucontext_t *ctx, unsigned int leaf, unsigned int subleaf)
{
    syscall(SYS_arch_prctl, ARCH_SET_CPUID, 1);
    __asm__ volatile(
        "cpuid"
        : "=a"(ctx->uc_mcontext.gregs[REG_RAX]),
          "=b"(ctx->uc_mcontext.gregs[REG_RBX]),
          "=c"(ctx->uc_mcontext.gregs[REG_RCX]),
          "=d"(ctx->uc_mcontext.gregs[REG_RDX])
        : "a"(leaf), "c"(subleaf)
        : "memory");
    syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);
}

/* DenuvOwO protocol leaves (not real CPUID leaves). */
#define LINUWUX_CPUID_LEAF_ARM      0x336933
#define LINUWUX_CPUID_LEAF_FAKETIME 0x336967
#ifdef LINUWUX_LEGACY_REFLEX
#define LINUWUX_CPUID_LEAF_LEGACY_INIT  0x69696969
#define LINUWUX_CPUID_LEAF_LEGACY_KUSER 0x1337
#define LINUWUX_CPUID_LEAF_LEGACY_QUERY_SYSTEM_ID 0x336943
#define LINUWUX_CPUID_LEAF_LEGACY_QUERY_FULL_HANDLER 0x336934
#define LINUWUX_CPUID_LEAF_LEGACY_QUERY_FULL_ID 0x336944
#endif

int linuwux_cpuid_spoof(siginfo_t *info, ucontext_t *ctx)
{
    unsigned int spoof_leaf, spoof_subleaf;
    unsigned char *rip = (unsigned char *)ctx->uc_mcontext.gregs[REG_RIP];

    spoof_leaf = (unsigned int)ctx->uc_mcontext.gregs[REG_RAX];
    spoof_subleaf = (unsigned int)ctx->uc_mcontext.gregs[REG_RCX];

    if (!(rip[0] == 0x0F && rip[1] == 0xA2))
        return 0;

    if (!info || info->si_code != SI_KERNEL)
        return 0;

    if (!linuwux_redirect_all_enabled() && linuwux_rip_is_wine_system((unsigned long long)(uintptr_t)rip)) {
        /* Wine system PE range — real CPUID, not spoof. */
        linuwux_cpuid_passthrough(ctx, spoof_leaf, spoof_subleaf);
        ctx->uc_mcontext.gregs[REG_RIP] += 2;
        return 1;
    }

    switch (spoof_leaf) {
    case 1:
#ifdef LINUWUX_LEGACY_REFLEX
        if (atomic_load(&g_legacy_reflex_initialized))
        {
            ctx->uc_mcontext.gregs[REG_RAX] = 0x00a20f10;
            ctx->uc_mcontext.gregs[REG_RBX] = 0x00180800;
            ctx->uc_mcontext.gregs[REG_RCX] = 0x7ad8320b;
            ctx->uc_mcontext.gregs[REG_RDX] = 0x178bfbff;
            break;
        }
#endif
        ctx->uc_mcontext.gregs[REG_RAX] = g_spoof_leaf1_eax;
        ctx->uc_mcontext.gregs[REG_RBX] = g_spoof_leaf1_ebx;
        ctx->uc_mcontext.gregs[REG_RCX] = g_spoof_leaf1_ecx | (atomic_load(&g_target_sys_handler) ? 0 : (0x1 << 31));
        ctx->uc_mcontext.gregs[REG_RDX] = g_spoof_leaf1_edx;
        break;

    case 0x40000000:
        ctx->uc_mcontext.gregs[REG_RAX] = g_spoof_leaf40000000_eax;
        ctx->uc_mcontext.gregs[REG_RBX] = g_spoof_leaf40000000_ebx;
        ctx->uc_mcontext.gregs[REG_RCX] = g_spoof_leaf40000000_ecx;
        ctx->uc_mcontext.gregs[REG_RDX] = g_spoof_leaf40000000_edx;
        break;

    case 0x40000001:
        ctx->uc_mcontext.gregs[REG_RAX] = g_spoof_leaf40000001_eax;
        ctx->uc_mcontext.gregs[REG_RBX] = g_spoof_leaf40000001_ebx;
        ctx->uc_mcontext.gregs[REG_RCX] = g_spoof_leaf40000001_ecx;
        ctx->uc_mcontext.gregs[REG_RDX] = g_spoof_leaf40000001_edx;
        break;

    case 0x80000002:
#ifdef LINUWUX_LEGACY_REFLEX
        if (atomic_load(&g_legacy_reflex_initialized))
        {
            ctx->uc_mcontext.gregs[REG_RAX] = 0x20444d41;
            ctx->uc_mcontext.gregs[REG_RBX] = 0x657a7952;
            ctx->uc_mcontext.gregs[REG_RCX] = 0x2039206e;
            ctx->uc_mcontext.gregs[REG_RDX] = 0x30303935;
            break;
        }
#endif
        ctx->uc_mcontext.gregs[REG_RAX] = 0x756E6544;
        ctx->uc_mcontext.gregs[REG_RBX] = 0x4F774F76;
        ctx->uc_mcontext.gregs[REG_RCX] = 0x55504320;
        ctx->uc_mcontext.gregs[REG_RDX] = 0x31204020;
        break;

    case 0x80000003:
#ifdef LINUWUX_LEGACY_REFLEX
        if (atomic_load(&g_legacy_reflex_initialized))
        {
            ctx->uc_mcontext.gregs[REG_RAX] = 0x32312058;
            ctx->uc_mcontext.gregs[REG_RBX] = 0x726f432d;
            ctx->uc_mcontext.gregs[REG_RCX] = 0x72502065;
            ctx->uc_mcontext.gregs[REG_RDX] = 0x7365636f;
            break;
        }
#endif
        ctx->uc_mcontext.gregs[REG_RAX] = 0x20373333;
        ctx->uc_mcontext.gregs[REG_RBX] = 0x007A4847;
        ctx->uc_mcontext.gregs[REG_RCX] = 0x00000000;
        ctx->uc_mcontext.gregs[REG_RDX] = 0x00000000;
        break;

    case 0x80000004:
#ifdef LINUWUX_LEGACY_REFLEX
        if (atomic_load(&g_legacy_reflex_initialized))
        {
            ctx->uc_mcontext.gregs[REG_RAX] = 0x20726f73;
            ctx->uc_mcontext.gregs[REG_RBX] = 0x20202020;
            ctx->uc_mcontext.gregs[REG_RCX] = 0x20202020;
            ctx->uc_mcontext.gregs[REG_RDX] = 0x00202020;
            break;
        }
#endif
        ctx->uc_mcontext.gregs[REG_RAX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RBX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RCX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RDX] = 0x0;
        break;

#ifdef LINUWUX_LEGACY_REFLEX
    case LINUWUX_CPUID_LEAF_LEGACY_INIT:
        atomic_store(&g_legacy_reflex_initialized, 1);
        linuwux_log("initialized legacy Reflex CPUID protocol\n");
        break;

    case LINUWUX_CPUID_LEAF_LEGACY_KUSER:
        if (atomic_load(&g_legacy_reflex_initialized))
        {
            if (atomic_load(&g_legacy_reflex_dual))
                linuwux_patch_legacy_dual_kuser_shared_data();
            else if (atomic_load(&g_legacy_reflex_single_handler))
                linuwux_patch_legacy_single_kuser_shared_data();
            else
                linuwux_log("legacy KUSER_SHARED_DATA leaf arrived before handler registration\n");
        }
        else
            linuwux_cpuid_passthrough(ctx, spoof_leaf, spoof_subleaf);
        break;
#endif

    case LINUWUX_CPUID_LEAF_ARM:
#ifdef LINUWUX_LEGACY_REFLEX
        if (atomic_load(&g_legacy_reflex_initialized))
        {
            linuwux_log("legacy cpuid arm leaf, single handler=%#llx\n",
                        (unsigned long long)ctx->uc_mcontext.gregs[REG_RCX]);
            atomic_store(&g_legacy_reflex_single_handler,
                         (uint64_t)ctx->uc_mcontext.gregs[REG_RCX]);
        }
        else
        {
            linuwux_log("cpuid arm leaf, TargetSysHandler=%#llx\n",
                        (unsigned long long)ctx->uc_mcontext.gregs[REG_RCX]);
            atomic_store(&g_target_sys_handler, (uint64_t)ctx->uc_mcontext.gregs[REG_RCX]);
            linuwux_patch_kuser_shared_data();
        }
#else
        linuwux_log("cpuid arm leaf, TargetSysHandler=%#llx\n",
                    (unsigned long long)ctx->uc_mcontext.gregs[REG_RCX]);
        atomic_store(&g_target_sys_handler, (uint64_t)ctx->uc_mcontext.gregs[REG_RCX]);
        linuwux_patch_kuser_shared_data();
#endif
        linuwux_set_hwprofile_guid();
        ctx->uc_mcontext.gregs[REG_RAX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RBX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RCX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RDX] = 0x0;
        break;

#ifdef LINUWUX_LEGACY_REFLEX
    case LINUWUX_CPUID_LEAF_LEGACY_QUERY_SYSTEM_ID:
        if (atomic_load(&g_legacy_reflex_initialized))
        {
            atomic_store(&g_legacy_reflex_dual, 1);
            atomic_store(&g_legacy_reflex_query_system_id,
                         (uint32_t)ctx->uc_mcontext.gregs[REG_RCX]);
        }
        else
            linuwux_cpuid_passthrough(ctx, spoof_leaf, spoof_subleaf);
        break;

    case LINUWUX_CPUID_LEAF_LEGACY_QUERY_FULL_HANDLER:
        if (atomic_load(&g_legacy_reflex_initialized))
        {
            atomic_store(&g_legacy_reflex_dual, 1);
            atomic_store(&g_legacy_reflex_query_full_handler,
                         (uint64_t)ctx->uc_mcontext.gregs[REG_RCX]);
        }
        else
            linuwux_cpuid_passthrough(ctx, spoof_leaf, spoof_subleaf);
        break;

    case LINUWUX_CPUID_LEAF_LEGACY_QUERY_FULL_ID:
        if (atomic_load(&g_legacy_reflex_initialized))
        {
            atomic_store(&g_legacy_reflex_dual, 1);
            atomic_store(&g_legacy_reflex_query_full_id,
                         (uint32_t)ctx->uc_mcontext.gregs[REG_RCX]);
        }
        else
            linuwux_cpuid_passthrough(ctx, spoof_leaf, spoof_subleaf);
        break;
#endif

    case LINUWUX_CPUID_LEAF_FAKETIME:
        linuwux_set_faketime((long long)ctx->uc_mcontext.gregs[REG_RCX]);
        ctx->uc_mcontext.gregs[REG_RAX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RBX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RCX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RDX] = 0x0;
        break;

    default:
        linuwux_cpuid_passthrough(ctx, spoof_leaf, spoof_subleaf);
    }

    ctx->uc_mcontext.gregs[REG_RIP] += 2;
    return 1;
}
