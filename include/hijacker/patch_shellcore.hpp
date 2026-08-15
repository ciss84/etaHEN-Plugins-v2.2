#pragma once

// ─────────────────────────────────────────────────────────────────────────────
//  patch_shellcore.hpp — active /data en sandbox + patches SceShellCore
//  Porté depuis etaHEN (cpp_service.cpp / util daemon)
//  A inclure depuis hijacker/patch_shellcore.hpp (via utils.hpp)
//  IMPORTANT: inclure APRES hijacker/hijacker.hpp
//  FW supportés : 4.xx → 12.xx
// ─────────────────────────────────────────────────────────────────────────────

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <unistd.h>
#include "hijacker/hijacker.hpp"
#include "dbg/dbg.hpp"

extern "C" {
    int nmount(struct iovec *iov, unsigned int niov, int flags);
    int unmount(const char *path, int flags);
    // Porté depuis cpp_service.cpp — plus fiable que le scan sysctl seul
    int sceKernelGetProcessName(int pid, char *out);
}

extern void plugin_log(const char* fmt, ...);
extern "C" uint32_t kernel_get_fw_version();

// ── Firmware version constants (4.xx → 12.xx) ────────────────────────────────
static constexpr uint32_t SC_VERSION_MASK = 0xffff0000;
static constexpr uint32_t SC_V400  = 0x04000000;
static constexpr uint32_t SC_V402  = 0x04020000;
static constexpr uint32_t SC_V403  = 0x04030000;
static constexpr uint32_t SC_V450  = 0x04500000;
static constexpr uint32_t SC_V451  = 0x04510000;
static constexpr uint32_t SC_V500  = 0x05000000;
static constexpr uint32_t SC_V502  = 0x05020000;
static constexpr uint32_t SC_V510  = 0x05100000;
static constexpr uint32_t SC_V550  = 0x05500000;
static constexpr uint32_t SC_V600  = 0x06000000;
static constexpr uint32_t SC_V602  = 0x06020000;
static constexpr uint32_t SC_V650  = 0x06500000;
static constexpr uint32_t SC_V700  = 0x07000000;
static constexpr uint32_t SC_V701  = 0x07010000;
static constexpr uint32_t SC_V720  = 0x07200000;
static constexpr uint32_t SC_V740  = 0x07400000;
static constexpr uint32_t SC_V760  = 0x07600000;
static constexpr uint32_t SC_V761  = 0x07610000;
static constexpr uint32_t SC_V800  = 0x08000000;
static constexpr uint32_t SC_V820  = 0x08200000;
static constexpr uint32_t SC_V840  = 0x08400000;
static constexpr uint32_t SC_V860  = 0x08600000;
static constexpr uint32_t SC_V900  = 0x09000000;
static constexpr uint32_t SC_V905  = 0x09050000;
static constexpr uint32_t SC_V920  = 0x09200000;
static constexpr uint32_t SC_V940  = 0x09400000;
static constexpr uint32_t SC_V960  = 0x09600000;
static constexpr uint32_t SC_V1000 = 0x10000000;
static constexpr uint32_t SC_V1001 = 0x10010000;
static constexpr uint32_t SC_V1020 = 0x10200000;
static constexpr uint32_t SC_V1040 = 0x10400000;
static constexpr uint32_t SC_V1060 = 0x10600000;
static constexpr uint32_t SC_V1100 = 0x11000000;
static constexpr uint32_t SC_V1120 = 0x11200000;
static constexpr uint32_t SC_V1140 = 0x11400000;
static constexpr uint32_t SC_V1160 = 0x11600000;
static constexpr uint32_t SC_V1200 = 0x12000000;
static constexpr uint32_t SC_V1202 = 0x12020000;
static constexpr uint32_t SC_V1220 = 0x12200000;
static constexpr uint32_t SC_V1240 = 0x12400000;
static constexpr uint32_t SC_V1260 = 0x12600000;
static constexpr uint32_t SC_V1270 = 0x12700000;

// ── Helpers internes ──────────────────────────────────────────────────────────

// ── Pattern scanning — copie exacte de cpp_service.cpp ───────────────────────
//  sc_pattern_to_byte : parse "e8 ?? ?? 01" → bytes (0xff = wildcard)
//  sc_pattern_scan    : scan buffer copy, retourne ptr dans copy ou nullptr

static uint32_t sc_pattern_to_byte(const char *pattern, uint8_t *bytes)
{
    uint32_t count = 0;
    const char *start = pattern;
    const char *end   = pattern + strlen(pattern);

    for (const char *current = start; current < end; ++current) {
        if (*current == '?') {
            ++current;
            if (*current == '?')
                ++current;
            bytes[count++] = 0xff;
        } else {
            bytes[count++] = (uint8_t)strtoul(current, (char **)&current, 16);
        }
    }
    return count;
}

static uint8_t *sc_pattern_scan(const uint8_t *base, uint64_t size, const char *sig)
{
    uint8_t patternBytes[256];
    memset(patternBytes, 0, sizeof(patternBytes));
    int32_t patternLength = (int32_t)sc_pattern_to_byte(sig, patternBytes);

    if (patternLength <= 0 || patternLength >= 256)
        return nullptr;

    for (uint64_t i = 0; i < size; ++i) {
        bool found = true;
        for (int32_t j = 0; j < patternLength; ++j) {
            if (base[i + j] != patternBytes[j] && patternBytes[j] != 0xff) {
                found = false;
                break;
            }
        }
        if (found)
            return (uint8_t *)&base[i];
    }
    return nullptr;
}

// Identique à write_bytes() de cpp_service — dbg::write direct, pas de Hijacker
static void sc_write_hex(pid_t pid, uint64_t addr, const char *hex)
{
    uint8_t buf[64];
    uint32_t len = sc_pattern_to_byte(hex, buf);
    if (len == 0) return;
    dbg::write(pid, addr, buf, (size_t)len);
}

static bool sc_bytes_already_patched(const uint8_t *at, const char *expected_hex)
{
    uint8_t expected[64];
    int len = sc_pattern_to_byte(expected_hex, expected);
    if (len <= 0 || !at) return false;
    return memcmp(at, expected, len) == 0;
}

// Fallback sysctl — même approche que find_pid() dans cpp_service.cpp
static pid_t sc_find_pid_sysctl(const char *name)
{
    int      mib[4] = {1, 14, 8, 0};
    size_t   buf_size;
    uint8_t *buf;

    if (sysctl(mib, 4, nullptr, &buf_size, nullptr, 0)) return -1;
    if (!(buf = (uint8_t *)malloc(buf_size))) return -1;
    if (sysctl(mib, 4, buf, &buf_size, nullptr, 0)) { free(buf); return -1; }

    pid_t pid = -1;
    for (uint8_t *ptr = buf; ptr < buf + buf_size;) {
        int   ki_structsize = *(int *)ptr;
        pid_t ki_pid        = *(pid_t *)&ptr[72];
        char *ki_tdname     = (char *)&ptr[447];
        ptr += ki_structsize;
        if (!strcmp(name, ki_tdname)) { pid = ki_pid; break; }
    }
    free(buf);
    return pid;
}

// Porté depuis cpp_service.cpp get_shellcore_pid() :
//   1. Boucle sceKernelGetProcessName jusqu'à PID 9999 (plus fiable)
//   2. Fallback sysctl si API SCE échoue
static pid_t sc_find_shellcore_pid()
{
    // Pas de check retour — identique à cpp_service::get_shellcore_pid()
    // sceKernelGetProcessName peut retourner non-zero mais quand même écrire le nom
    char tmp[512];
    for (int j = 0; j <= 9999; j++) {
        memset(tmp, 0, sizeof(tmp));
        sceKernelGetProcessName(j, tmp);
        if (strcmp("SceShellCore", tmp) == 0) {
            plugin_log("[SC_PATCH] SceShellCore via sceKernelGetProcessName pid=%d", j);
            return (pid_t)j;
        }
    }
    plugin_log("[SC_PATCH] sceKernelGetProcessName loop failed, fallback sysctl");
    return sc_find_pid_sysctl("SceShellCore");
}

static uintptr_t sc_find_fn_ptr_in_data(Hijacker *exe, uintptr_t fn_addr)
{
    const SharedLibSection *data_sec = exe->getEboot()->getDataSection();
    if (!data_sec) {
        plugin_log("[SC_NEWPROC] getDataSection() returned null");
        return 0;
    }

    uintptr_t data_base = data_sec->start();
    uint64_t  data_size = data_sec->sectionLength();
    plugin_log("[SC_NEWPROC] data section: base=0x%llx size=0x%llx", data_base, data_size);

    uint8_t *copy = (uint8_t *)malloc(data_size);
    if (!copy) return 0;

    if (!dbg::read(g_ShellCorePid, data_base, copy, data_size)) {
        plugin_log("[SC_NEWPROC] read data section failed");
        free(copy);
        return 0;
    }

    uintptr_t result = 0;
    for (uint64_t i = 0; i + 8 <= data_size; i += 8) {
        if (*(uintptr_t *)(copy + i) == fn_addr) {
            result = data_base + i;
            break;
        }
    }
    free(copy);
    return result;
}

// ── Table patterns /data sandbox (4.xx → 12.xx) ──────────────────────────────
//  pat1/pat2    : appels à patcher → "b8 01 00 00 00"
//  pat_checker  : fonction sandbox checker → CHECKER_PATCH_BYTES (nullptr = skip)
struct sc_patch_set {
    uint32_t    fw_min;
    uint32_t    fw_max;
    const char *pat1;
    const char *pat2;
    const char *pat_checker;
};

static const sc_patch_set sc_patch_table[] = {
    {
        SC_V400, SC_V451,
        "e8 ?? ?? ?? ?? 4c 89 bd ?? ?? ?? ?? 48 89 9d ?? ?? ?? ??",
        "e8 ?? ?? ?? ?? 83 f8 01 75 ?? 41 80 3c 24 00",
        "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec 00 02 00 00 49",
    },
    {
        SC_V500, SC_V550,
        "e8 ?? ?? fb 00 85 c0 75 0d e8 ?? ?? fb 00 85 c0 0f 84 47",
        "e8 ?? ?? c7 00 83 f8 01 75 5e",
        "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec e0 01 00 00 49",
    },
    {
        SC_V600, SC_V650,
        "e8 ?? ?? ?? 01 4c 89 a5 80",
        "e8 ?? ?? ?? 00 83 f8 01 75 66",
        "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec e0 01 00 00 49",
    },
    {
        SC_V700, SC_V761,
        "e8 ?? ?? ?? 01 4c 89 b5 80",
        "e8 ?? ?? d7 00 83 f8 01 0f 85 cd",
        "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec e0 01 00 00 49 89 cd",
    },
    {
        SC_V800, SC_V860,
        "e8 ?? ?? ?? 01 85 c0 75 0d e8 ?? ?? ?? 01 85 c0 0f 84 c1",
        "e8 ?? ?? dc 00 83 f8 01 0f",
        "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec c8 01 00 00 49 89 cd",
    },
    {
        SC_V900, SC_V960,
        "e8 ?? ?? ?? 01 85 c0 75 0d e8 ?? ?? ?? 01 85 c0 0f 84 9a",
        "e8 ?? ?? e2 00 83 f8 01 0f 85",
        "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec c8 01 00 00 49 89 cd",
    },
    {
        SC_V1000, SC_V1060,
        "e8 ?? ?? ?? 01 85 c0 75 0d e8 ?? ?? ?? 01 85 c0 0f 84 10 06 00 00",
        "e8 ?? ?? e2 00 83 f8 01 0f 85",
        "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec c8 01 00 00 49 89",
    },
    {
        SC_V1100, SC_V1160,
        "e8 ?? ?? ?? 01 85 c0 75 0d e8 ?? ?? ?? 01 85 c0 0f 84 17",
        "e8 ?? ?? e2 00 83 f8 01 0f 85",
        "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec c8 01 00 00 4c 8b",
    },
    {
        SC_V1200, SC_V1260,
        "e8 ?? ?? ?? 01 85 c0 75 0d e8 ?? ?? ?? 01 85 c0 0f 84 17",
        "e8 ?? ?? e2 00 83 f8 01 0f 85",
        "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec c8 01 00 00 4c 8b",
    },
    {
        SC_V1270, SC_V1270,
        "e8 ?? ?? ?? 01 85 c0 75 0d e8 ?? ?? ?? 01 85 c0 0f 84 17",
        "e8 ?? ?? e3 00 83 f8 01 0f 85",
        "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec c8 01 00 00 4c 8b",
    },
};

// ── Table patterns onNewProcess (4.xx → 12.xx) ────────────────────────────────
//  Portés depuis etaHEN patchOnNewProcess() ps5_patterns[].
struct sc_newproc_pattern {
    uint32_t    fw_min;
    uint32_t    fw_max;
    const char *pat;
};

static const sc_newproc_pattern sc_newproc_table[] = {
    {
        // 4.xx → 10.xx
        SC_V400, SC_V1060,
        "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 18 49 89 ?? bf 18 00 00 00 49 89 d6 49 89 f5",
    },
    {
        // 11.xx
        SC_V1100, SC_V1160,
        "55 48 89 e5 41 57 41 56 41 55 41 54 53 50 49 89 fd bf 18 00 00 00 49 89 d7 49 89 f4 e8 ?? ?? ?? ??",
    },
    {
        // 12.xx
        SC_V1200, SC_V1270,
        "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 18 49 89 fd bf 18 00 00 00 49 89 d6 49 89 f4 e8 ?? ?? ?? ??",
    },
};

// ── Table patterns AppTimeout (PS5 only, tous FW) ─────────────────────────────
//  Porté depuis etaHEN patchAppTimeoutForMonitoredProcs().
//  Patch : jb → jmp (0x48 0xe9) pour supprimer le timeout des process monitorés.
//  Pattern unique, pas de range FW — fonctionne sur toute la plage 4.xx→12.xx.
static constexpr const char *SC_PAT_APPTIMEOUT =
    "83 f8 0b 0f 82 ?? ?? ?? ?? 42 8b 44 23 f0";
static constexpr size_t      SC_PAT_APPTIMEOUT_OFFSET = 3;
static constexpr const char *SC_PATCH_APPTIMEOUT = "48 e9";

// ── Table patterns MountRoot (4.xx → 9.xx+) ──────────────────────────────────
//  Portés depuis etaHEN patchMountRoot().
//  Localise le call vers mount_root dans SceShellCore pour hook futur.
//  NOTE: hook réel nécessite pid_write_call + frame/shellcode (non implémenté ici).
struct sc_mountroot_pattern {
    const char *pat;
    size_t      offset;  // offset depuis début du match jusqu'au call à hooker
    const char *fw_comment;
};

static const sc_mountroot_pattern sc_mountroot_table[] = {
    {
        "48 8d 35 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? 4c 8d 8d ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ff ff ff ff 45 31 c0 c6 85 ?? ?? ?? ?? 00 e8 ?? ?? ?? ??",
        48,
        "4.xx-5.50, 9.xx+",
    },
    {
        "8d 35 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? 4c 8d 8d ?? ?? ?? ?? 45 31 c0 6a 00 53 e8 ?? ?? ?? ??",
        33,
        "6.xx",
    },
    {
        "8d 35 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? 4c 8d 8d ?? ?? ?? ?? 45 31 c0 6a 00 48 8d 05 ?? ?? ?? ?? 50 e8 ?? ?? ?? ??",
        40,
        "7.xx-8.xx",
    },
};

// ── Table patterns GetAppInfoSfo (4.xx → 12.xx) ──────────────────────────────
//  Portés depuis etaHEN patchGetAppInfoSfo() ps5_patterns[].
//  Localise le call vers getAppInfoFromDB dans SceShellCore pour hook futur.
//  NOTE: hook réel nécessite pid_write_call + frame/shellcode (non implémenté ici).
struct sc_getappinfo_pattern {
    const char *pat;
    size_t      offset;  // offset depuis début du match jusqu'au call à hooker
    const char *fw_comment;
};

static const sc_getappinfo_pattern sc_getappinfo_table[] = {
    {
        "e8 ?? ?? ?? ?? 48 8b 85 ?? ?? ?? ?? 4c 89 ?? ?? 89 ?? 48 8b 70 10 e8 ?? ?? ?? ??",
        22,
        "4.xx-6.xx & 8.xx",
    },
    {
        "49 8b 76 10 4c 89 ef 4c 89 e2 e8 ?? ?? ?? ?? 85 c0 0f 89",
        10,
        "7.xx",
    },
    {
        "48 8b 85 ?? ?? ?? ?? 48 8d 75 ?? 4c 89 ef 4c 89 ?? 48 8b 50 10 e8 ?? ?? ?? ?? 41 89 ??",
        21,
        "9.xx-10.xx",
    },
    {
        "49 8b 55 10 48 8b bd ?? ?? ?? ?? 48 8d 75 ?? 4c 89 e1 e8 ?? ?? ?? ?? 41 89 c6",
        18,
        "11.xx",
    },
    {
        "49 8b 55 10 48 8b bd ?? ?? ?? ?? 48 8b 8d ?? ?? ?? ?? 48 8d 75 ?? e8 ?? ?? ?? ?? 41 89 c6",
        22,
        "12.xx",
    },
};

// ── sc_find_on_new_process ────────────────────────────────────────────────────

static uintptr_t sc_find_on_new_process(uintptr_t sc_base, uint64_t sc_size,
                                        const uint8_t *copy, uint32_t fw_masked)
{
    for (const auto& e : sc_newproc_table) {
        if (fw_masked < e.fw_min || fw_masked > e.fw_max) continue;
        uint8_t *found = sc_pattern_scan(copy, sc_size, e.pat);
        if (found) {
            uintptr_t addr = sc_base + (uintptr_t)(found - copy);
            plugin_log("[SC_NEWPROC] onNewProcess @ 0x%llx (FW range %08x-%08x)",
                       addr, e.fw_min, e.fw_max);
            return addr;
        }
        plugin_log("[SC_NEWPROC] pattern FW %08x-%08x not found", e.fw_min, e.fw_max);
    }
    plugin_log("[SC_NEWPROC] onNewProcess not found for FW 0x%08x", fw_masked);
    return 0;
}

// ── sc_patch_app_timeout ──────────────────────────────────────────────────────
//  Porté depuis etaHEN patchAppTimeoutForMonitoredProcs().
//  Patch le timeout des process monitorés : jb → jmp (0f 82 → 48 e9).
//  Appliqué uniquement sur PS5 (pas de guard is_ps4 ici, on est toujours PS5).

static void sc_patch_app_timeout(pid_t pid,
                                 uintptr_t sc_base, uint64_t sc_size,
                                 const uint8_t *copy)
{
    uint8_t *found = sc_pattern_scan(copy, sc_size, SC_PAT_APPTIMEOUT);
    if (!found) {
        plugin_log("[SC_TIMEOUT] pattern non trouve, skip");
        return;
    }

    uint8_t *target = found + SC_PAT_APPTIMEOUT_OFFSET;

    if (sc_bytes_already_patched(target, SC_PATCH_APPTIMEOUT)) {
        plugin_log("[SC_TIMEOUT] deja patche, skip");
        return;
    }

    uint64_t addr = sc_base + (uint64_t)(target - copy);
    sc_write_hex(pid, addr, SC_PATCH_APPTIMEOUT);
    plugin_log("[SC_TIMEOUT] patched app timeout @ 0x%llx", addr);
}

// ── sc_scan_mount_root ────────────────────────────────────────────────────────
//  Porté depuis etaHEN patchMountRoot().
//  Scan seulement — le hook réel (pid_write_call + frame) est un TODO.

static uintptr_t sc_scan_mount_root(uintptr_t sc_base, uint64_t sc_size,
                                    const uint8_t *copy)
{
    for (const auto& e : sc_mountroot_table) {
        uint8_t *found = sc_pattern_scan(copy, sc_size, e.pat);
        if (found) {
            uintptr_t call_addr = sc_base + (uintptr_t)(found - copy) + e.offset;
            plugin_log("[SC_MOUNTROOT] call site @ 0x%llx (%s)", call_addr, e.fw_comment);
            // TODO: pid_write_call(call_addr, hook_addr) + save original
            return call_addr;
        }
    }
    plugin_log("[SC_MOUNTROOT] non trouve");
    return 0;
}

// ── sc_scan_getappinfo ────────────────────────────────────────────────────────
//  Porté depuis etaHEN patchGetAppInfoSfo().
//  Scan seulement — le hook réel (pid_write_call + frame) est un TODO.

static uintptr_t sc_scan_getappinfo(uintptr_t sc_base, uint64_t sc_size,
                                    const uint8_t *copy)
{
    for (size_t i = 0; i < sizeof(sc_getappinfo_table)/sizeof(sc_getappinfo_table[0]); i++) {
        const auto& e = sc_getappinfo_table[i];
        uint8_t *found = sc_pattern_scan(copy, sc_size, e.pat);
        if (found) {
            uintptr_t call_addr = sc_base + (uintptr_t)(found - copy) + e.offset;
            plugin_log("[SC_GETAPPINFO] call site @ 0x%llx (%s)", call_addr, e.fw_comment);
            // TODO: pid_write_call(call_addr, hook_addr) + save original
            return call_addr;
        }
    }
    plugin_log("[SC_GETAPPINFO] non trouve");
    return 0;
}

// ── Global shellcore pid — accessible après patchShellCore() ──────────────────
static pid_t g_ShellCorePid = 0;

// ── patchShellCore — adapté depuis cpp_service.cpp::patchShellCore() ──────────
//  Structure identique à l'original : pas de suspend/resume, écriture directe,
//  table de patterns à la place du switch, fix du bug return (status → ok).

static bool patchShellCore(bool allow_ftp_dev_access = true)
{
    if (!allow_ftp_dev_access) {
        plugin_log("[SC_PATCH] ALLOW_FTP_DEV_ACCESS disabled, skip");
        return false;
    }
    static bool done = false;
    if (done) return true;

    // ── Hijacker — même flow que cpp_service ─────────────────────────────────
    const UniquePtr<Hijacker> executable = Hijacker::getHijacker(sc_find_shellcore_pid());
    uintptr_t shellcore_base = 0;
    uint64_t  shellcore_size = 0;

    if (executable) {
        shellcore_base = executable->getEboot()->getTextSection()->start();
        shellcore_size = executable->getEboot()->getTextSection()->sectionLength();
        g_ShellCorePid = executable->getPid();
    } else {
        plugin_log("[SC_PATCH] SceShellCore not found!");
        return false;
    }

    plugin_log("[SC_PATCH] shellcore pid=%d base=0x%llx size=0x%llx",
               g_ShellCorePid, shellcore_base, shellcore_size);

    if (!shellcore_base || !shellcore_size)
        return false;

    // ── Lookup dans le tableau de patterns ────────────────────────────────────
    uint32_t fw_masked = kernel_get_fw_version() & SC_VERSION_MASK;
    plugin_log("[SC_PATCH] FW masked: 0x%08x", fw_masked);

    const char *pat1        = nullptr;
    const char *pat2        = nullptr;
    const char *pat_checker = nullptr;

    for (const auto& e : sc_patch_table) {
        if (fw_masked >= e.fw_min && fw_masked <= e.fw_max) {
            pat1 = e.pat1; pat2 = e.pat2; pat_checker = e.pat_checker;
            break;
        }
    }

    if (!pat1) {
        plugin_log("[SC_PATCH] FW 0x%08x non supporte", fw_masked);
        return false;
    }

    // ── Copie locale du text — même approche que cpp_service ──────────────────
    plugin_log("[SC_PATCH] allocating 0x%llx bytes", shellcore_size);
    uint8_t *shellcore_copy = (uint8_t *)malloc(shellcore_size);
    plugin_log("[SC_PATCH] shellcore_copy: 0x%p", shellcore_copy);

    if (!shellcore_copy) {
        plugin_log("[SC_PATCH] shellcore_copy is nullptr");
        return false;
    }

    bool ok = false;

    if (dbg::read(g_ShellCorePid, shellcore_base, shellcore_copy, shellcore_size)) {

        uint8_t *shellcore_offset_data1 = sc_pattern_scan(shellcore_copy, shellcore_size, pat1);
        uint8_t *shellcore_offset_data2 = sc_pattern_scan(shellcore_copy, shellcore_size, pat2);
        uint8_t *patch_checker_offset   = pat_checker
            ? sc_pattern_scan(shellcore_copy, shellcore_size, pat_checker)
            : nullptr;

        plugin_log("[SC_PATCH] data1=%p data2=%p checker=%p",
                   shellcore_offset_data1, shellcore_offset_data2, patch_checker_offset);

        // ── /data sandbox patches — écriture directe sans check préalable ─────
        if (shellcore_offset_data1 && shellcore_offset_data2) {
            const uint64_t off1 = shellcore_base +
                ((uint64_t)shellcore_offset_data1 - (uint64_t)shellcore_copy);
            const uint64_t off2 = shellcore_base +
                ((uint64_t)shellcore_offset_data2 - (uint64_t)shellcore_copy);

            sc_write_hex(g_ShellCorePid, off1, "b8 01 00 00 00");
            sc_write_hex(g_ShellCorePid, off2, "b8 01 00 00 00");

            plugin_log("[SC_PATCH] patched /data: data1=0x%llx data2=0x%llx", off1, off2);
            plugin_log("[SC_PATCH] mkdir /user/devbin: %d  /user/devlog: %d",
                       mkdir("/user/devbin", 0777), mkdir("/user/devlog", 0777));
            ok = true;
        } else {
            plugin_log("[SC_PATCH] patterns data1/data2 non trouves!");
        }

        // ── Checker patch ─────────────────────────────────────────────────────
        if (patch_checker_offset) {
            const uint64_t off_chk = shellcore_base +
                ((uint64_t)patch_checker_offset - (uint64_t)shellcore_copy);
            sc_write_hex(g_ShellCorePid, off_chk,
                         "55 48 89 e5 b8 14 18 26 80 5d c3");
            plugin_log("[SC_PATCH] patched checker=0x%llx", off_chk);
        } else {
            plugin_log("[SC_PATCH] checker non trouve (non fatal)");
        }

        // ── App timeout patch (etaHEN: patchAppTimeoutForMonitoredProcs) ──────
        sc_patch_app_timeout(g_ShellCorePid, shellcore_base, shellcore_size, shellcore_copy);

        // ── Scans MountRoot + GetAppInfoSfo (TODO hook) ───────────────────────
        sc_scan_mount_root(shellcore_base, shellcore_size, shellcore_copy);
        sc_scan_getappinfo(shellcore_base, shellcore_size, shellcore_copy);

        // ── onNewProcess : localiser pour hook PRX injection ──────────────────
        uintptr_t onNewProc_addr = sc_find_on_new_process(
            shellcore_base, shellcore_size, shellcore_copy, fw_masked);
        if (onNewProc_addr) {
            uintptr_t ptr_addr = sc_find_fn_ptr_in_data(executable.get(), onNewProc_addr);
            plugin_log("[SC_PATCH] onNewProcess=0x%llx pOnNewProcess=0x%llx",
                       onNewProc_addr, ptr_addr);
            // TODO: executable->write<uintptr_t>(ptr_addr, (uintptr_t)&my_hook);
        }
    } else {
        plugin_log("[SC_PATCH] dbg::read shellcore failed");
    }

    if (shellcore_copy) {
        plugin_log("[SC_PATCH] freeing shellcore_copy 0x%p", shellcore_copy);
        free(shellcore_copy);
        shellcore_copy = nullptr;
    }

    if (ok) {
        done = true;
        plugin_log("[SC_PATCH] /data sandbox enabled OK");
    }

    return ok;  // cpp_service avait "return status" (toujours false) — bug fixé ici
}

// Alias pour compatibilité avec l'ancien nom d'appel dans utils.cpp
static inline bool patch_shellcore_for_data(bool allow_ftp_dev_access = true) {
    return patchShellCore(allow_ftp_dev_access);
}

// ─────────────────────────────────────────────────────────────────────────────
//  EXPERIMENTAL — nmount nullfs /user/data -> /data
//  Ne bypass PAS le check de permission SceShellCore.
//  A combiner avec patch_shellcore_for_data() pour le FTP dev access.
//
//  Flow :
//    1. Crée /user/data + sous-dossiers si absents
//    2. Vérifie si /data est déjà monté (statfs) → skip si oui
//    3. Monte /user/data sur /data via nullfs
//    4. Vérifie le mount via access("/data", R_OK)
// ─────────────────────────────────────────────────────────────────────────────

// Ne pas inclure <errno.h> ici — errno est un macro qui casse les member
// initializer lists de spawner.cpp/elf.cpp ("errno(...)" → expansion invalide).
// On passe par __error() directement, équivalent PS5/FreeBSD.
#include <sys/mount.h>  // statfs, MNT_FORCE
extern "C" int *__error(void);
static inline int sc_errno() { return *__error(); }

static bool patch_shellcore_for_data_via_mount(bool allow_ftp_dev_access = true)
{
    if (!allow_ftp_dev_access) {
        plugin_log("[SC_MOUNT] ALLOW_FTP_DEV_ACCESS disabled, skip");
        return false;
    }

    static bool done = false;
    if (done) return true;

    // ── 1. Créer la source /user/data + sous-dossiers ─────────────────────────
    mkdir("/user/data",             0777);
    mkdir("/user/data/PluginLoader", 0777);
    plugin_log("[SC_MOUNT] /user/data source prête");

    // ── 2. Vérifier si /data est déjà monté en nullfs ─────────────────────────
    struct statfs sfs;
    if (statfs("/data", &sfs) == 0) {
        if (strcmp(sfs.f_fstypename, "nullfs") == 0) {
            plugin_log("[SC_MOUNT] /data deja monte en nullfs (f_mntonname=%s), skip",
                       sfs.f_mntonname);
            done = true;
            return true;
        }
        plugin_log("[SC_MOUNT] /data existe mais fstype=%s, tentative remount",
                   sfs.f_fstypename);
        // unmount propre avant de remonter
        if (unmount("/data", MNT_FORCE) != 0) {
            plugin_log("[SC_MOUNT] unmount /data echoue errno=%d", sc_errno());
        }
    }

    // ── 3. nmount nullfs /user/data → /data ───────────────────────────────────
    auto mk_iov = [](const char *s) -> struct iovec {
        return { (void *)s, strlen(s) + 1 };
    };
    struct iovec iov[] = {
        mk_iov("fstype"),  mk_iov("nullfs"),
        mk_iov("fspath"),  mk_iov("/data"),
        mk_iov("target"),  mk_iov("/user/data"),
    };

    const int r = nmount(iov, sizeof(iov) / sizeof(iov[0]), 0);
    if (r != 0) {
        plugin_log("[SC_MOUNT] nmount echoue errno=%d", sc_errno());
        return false;
    }

    // ── 4. Vérifier que le mount est effectif ─────────────────────────────────
    if (access("/data", R_OK) != 0) {
        plugin_log("[SC_MOUNT] mount OK mais /data inaccessible errno=%d", sc_errno());
        return false;
    }

    plugin_log("[SC_MOUNT] /user/data monte sur /data (nullfs) OK");
    done = true;
    return true;
}