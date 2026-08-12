#pragma once

// ─────────────────────────────────────────────────────────────────────────────
//  patch_shellcore.hpp — active /data en sandbox + hook onNewProcess
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

// ── Helpers internes ──────────────────────────────────────────────────────────

static int sc_pattern_to_byte(const char *sig, uint8_t *out)
{
    int len = 0;
    const char *p = sig;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (p[0] == '?' && (p[1] == '?' || p[1] == ' ' || !p[1])) {
            out[len++] = 0xff;
            p += (p[1] == '?') ? 2 : 1;
        } else {
            auto hex = [](char c) -> uint8_t {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return 0;
            };
            out[len++] = (hex(p[0]) << 4) | hex(p[1]);
            p += 2;
        }
    }
    return len;
}

static uint8_t *sc_pattern_scan(const uint8_t *base, uint64_t size, const char *sig)
{
    uint8_t pat[256];
    int plen = sc_pattern_to_byte(sig, pat);
    if (plen <= 0) return nullptr;

    for (uint64_t i = 0; i + (uint64_t)plen <= size; i++) {
        bool ok = true;
        for (int j = 0; j < plen; j++) {
            if (pat[j] != 0xff && base[i + j] != pat[j]) { ok = false; break; }
        }
        if (ok) return (uint8_t *)(base + i);
    }
    return nullptr;
}

static void sc_write_hex(Hijacker *exe, uint64_t addr, const char *hex)
{
    uint8_t buf[64];
    int len = sc_pattern_to_byte(hex, buf);
    if (len <= 0) return;
    exe->write(addr, buf, (size_t)len);
}

static bool sc_bytes_already_patched(const uint8_t *at, const char *expected_hex)
{
    uint8_t expected[64];
    int len = sc_pattern_to_byte(expected_hex, expected);
    if (len <= 0 || !at) return false;
    return memcmp(at, expected, len) == 0;
}

static pid_t sc_find_shellcore_pid()
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
        if (!strcmp("SceShellCore", ki_tdname)) { pid = ki_pid; break; }
    }
    free(buf);
    return pid;
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

    if (!exe->read(data_base, copy, data_size)) {
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

static uintptr_t sc_find_on_new_process(Hijacker *exe,
                                        uintptr_t sc_base, uint64_t sc_size,
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

// ── patch_shellcore_for_data ──────────────────────────────────────────────────

static bool patch_shellcore_for_data(bool allow_ftp_dev_access = true)
{
    if (!allow_ftp_dev_access) {
        plugin_log("[SC_PATCH] ALLOW_FTP_DEV_ACCESS disabled, skipping patch");
        return false;
    }
    static bool done = false;
    if (done) return true;

    uint32_t fw        = kernel_get_fw_version();
    uint32_t fw_masked = fw & SC_VERSION_MASK;
    plugin_log("[SC_PATCH] FW: 0x%08x (masked: 0x%08x)", fw, fw_masked);

    pid_t sc_pid = sc_find_shellcore_pid();
    if (sc_pid < 0) {
        plugin_log("[SC_PATCH] SceShellCore not found!");
        return false;
    }
    plugin_log("[SC_PATCH] SceShellCore pid: %d", sc_pid);

    UniquePtr<Hijacker> exe = Hijacker::getHijacker(sc_pid);
    if (!exe) {
        plugin_log("[SC_PATCH] Hijacker::getHijacker failed");
        return false;
    }

    const SharedLibSection *text_sec = exe->getEboot()->getTextSection();
    if (!text_sec) {
        plugin_log("[SC_PATCH] getTextSection() returned null");
        return false;
    }

    uintptr_t sc_base = text_sec->start();
    uint64_t  sc_size = text_sec->sectionLength();
    plugin_log("[SC_PATCH] text base=0x%llx size=0x%llx", sc_base, sc_size);

    if (!sc_base || !sc_size) {
        plugin_log("[SC_PATCH] invalid text section");
        return false;
    }

    const char *pat1        = nullptr;
    const char *pat2        = nullptr;
    const char *pat_checker = nullptr;

    for (const auto& e : sc_patch_table) {
        if (fw_masked >= e.fw_min && fw_masked <= e.fw_max) {
            pat1        = e.pat1;
            pat2        = e.pat2;
            pat_checker = e.pat_checker;
            break;
        }
    }

    if (!pat1) {
        plugin_log("[SC_PATCH] FW 0x%08x non supporte (range: 4.xx-12.xx)", fw_masked);
        return false;
    }

    uint8_t *copy = (uint8_t *)malloc(sc_size);
    if (!copy) { plugin_log("[SC_PATCH] malloc failed"); return false; }

    if (!exe->read(sc_base, copy, sc_size)) {
        plugin_log("[SC_PATCH] read text section failed");
        free(copy);
        return false;
    }

    uint8_t *found1  = sc_pattern_scan(copy, sc_size, pat1);
    uint8_t *found2  = sc_pattern_scan(copy, sc_size, pat2);
    uint8_t *checker = pat_checker ? sc_pattern_scan(copy, sc_size, pat_checker) : nullptr;

    plugin_log("[SC_PATCH] found1=%p found2=%p checker=%p", found1, found2, checker);

    static constexpr const char *PATCH_BYTES         = "b8 01 00 00 00";
    static constexpr const char *CHECKER_PATCH_BYTES = "55 48 89 e5 b8 14 18 26 80 5d c3";

    bool ok = false;

    exe->suspend();

    if (found1 && found2) {
        bool already1 = sc_bytes_already_patched(found1, PATCH_BYTES);
        bool already2 = sc_bytes_already_patched(found2, PATCH_BYTES);

        if (already1 && already2) {
            plugin_log("[SC_PATCH] data1/data2 deja actifs, skip ecriture");
            ok = true;
        } else {
            uint64_t off1 = sc_base + (uint64_t)(found1 - copy);
            uint64_t off2 = sc_base + (uint64_t)(found2 - copy);
            if (!already1) sc_write_hex(exe.get(), off1, PATCH_BYTES);
            if (!already2) sc_write_hex(exe.get(), off2, PATCH_BYTES);
            plugin_log("[SC_PATCH] patched data1=0x%llx (skip=%d) data2=0x%llx (skip=%d)",
                       off1, already1, off2, already2);
            mkdir("/user/devbin", 0777);
            mkdir("/user/devlog", 0777);
            ok = true;
        }
    } else {
        plugin_log("[SC_PATCH] patterns data1/data2 non trouves!");
    }

    if (checker) {
        if (sc_bytes_already_patched(checker, CHECKER_PATCH_BYTES)) {
            plugin_log("[SC_PATCH] checker deja actif, skip ecriture");
        } else {
            uint64_t off_chk = sc_base + (uint64_t)(checker - copy);
            sc_write_hex(exe.get(), off_chk, CHECKER_PATCH_BYTES);
            plugin_log("[SC_PATCH] patched checker=0x%llx", off_chk);
        }
    } else {
        plugin_log("[SC_PATCH] checker non trouve (non fatal)");
    }

    uintptr_t onNewProc_addr = sc_find_on_new_process(exe.get(), sc_base, sc_size, copy, fw_masked);
    if (onNewProc_addr) {
        uintptr_t ptr_addr = sc_find_fn_ptr_in_data(exe.get(), onNewProc_addr);
        plugin_log("[SC_PATCH] onNewProcess=0x%llx pOnNewProcess=0x%llx",
                   onNewProc_addr, ptr_addr);
        // TODO: exe->write<uintptr_t>(ptr_addr, (uintptr_t)&my_hook);
    }

    exe->resume();

    free(copy);

    if (ok) {
        done = true;
        plugin_log("[SC_PATCH] /data sandbox enabled OK");
    }

    return ok;
}

// ─────────────────────────────────────────────────────────────────────────────
//  EXPERIMENTAL — nmount nullfs /user/data -> /data
//  Ne bypass PAS le check de permission SceShellCore.
//  A combiner avec patch_shellcore_for_data() pour le FTP dev access.
// ─────────────────────────────────────────────────────────────────────────────
static bool patch_shellcore_for_data_via_mount(bool allow_ftp_dev_access = true)
{
    if (!allow_ftp_dev_access) {
        plugin_log("[SC_PATCH_TEST] ALLOW_FTP_DEV_ACCESS disabled, skipping mount");
        return false;
    }

    #define SC_IOVEC_ENTRY(x) {(char *)(x), strlen(x) + 1}
    struct iovec iov[] = {
        SC_IOVEC_ENTRY("fstype"), SC_IOVEC_ENTRY("nullfs"),
        SC_IOVEC_ENTRY("fspath"), SC_IOVEC_ENTRY("/data"),
        SC_IOVEC_ENTRY("target"), SC_IOVEC_ENTRY("/user/data"),
    };
    #undef SC_IOVEC_ENTRY

    const int r = nmount(iov, sizeof(iov) / sizeof(iov[0]), 0);
    if (r != 0) {
        plugin_log("[SC_PATCH_TEST] nmount /user/data -> /data echoue: %d", r);
        return false;
    }
    plugin_log("[SC_PATCH_TEST] /user/data monte sur /data (nullfs) OK");
    return true;
}