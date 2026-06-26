#pragma once

// ─────────────────────────────────────────────────────────────────────────────
//  patch_shellcore.hpp — active /data en sandbox sans etaHEN
//  Porté depuis etaHEN (cpp_service.cpp / util daemon)
//  A inclure/appeler UNE SEULE FOIS au démarrage de Plugin-Loader
// ─────────────────────────────────────────────────────────────────────────────

#include "utils.hpp"       // Hijacker, UniquePtr, plugin_log
#include <ps5/kernel.h>    // kernel_get_fw_version
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

// ── Firmware version constants ────────────────────────────────────────────────
static constexpr uint32_t SC_VERSION_MASK = 0xffff0000;
static constexpr uint32_t SC_V200  = 0x2000000;
static constexpr uint32_t SC_V220  = 0x2200000;
static constexpr uint32_t SC_V225  = 0x2250000;
static constexpr uint32_t SC_V226  = 0x2260000;
static constexpr uint32_t SC_V230  = 0x2300000;
static constexpr uint32_t SC_V250  = 0x2500000;
static constexpr uint32_t SC_V270  = 0x2700000;
static constexpr uint32_t SC_V300  = 0x3000000;
static constexpr uint32_t SC_V310  = 0x3100000;
static constexpr uint32_t SC_V320  = 0x3200000;
static constexpr uint32_t SC_V321  = 0x3210000;
static constexpr uint32_t SC_V400  = 0x4000000;
static constexpr uint32_t SC_V402  = 0x4020000;
static constexpr uint32_t SC_V403  = 0x4030000;
static constexpr uint32_t SC_V450  = 0x4500000;
static constexpr uint32_t SC_V451  = 0x4510000;
static constexpr uint32_t SC_V500  = 0x5000000;
static constexpr uint32_t SC_V502  = 0x5020000;
static constexpr uint32_t SC_V510  = 0x5100000;
static constexpr uint32_t SC_V550  = 0x5500000;
static constexpr uint32_t SC_V600  = 0x6000000;
static constexpr uint32_t SC_V602  = 0x6020000;
static constexpr uint32_t SC_V650  = 0x6500000;
static constexpr uint32_t SC_V700  = 0x7000000;
static constexpr uint32_t SC_V701  = 0x7010000;
static constexpr uint32_t SC_V720  = 0x7200000;
static constexpr uint32_t SC_V740  = 0x7400000;
static constexpr uint32_t SC_V760  = 0x7600000;
static constexpr uint32_t SC_V761  = 0x7610000;
static constexpr uint32_t SC_V800  = 0x8000000;
static constexpr uint32_t SC_V820  = 0x8200000;

// ── Helpers internes ──────────────────────────────────────────────────────────

static int sc_pattern_to_byte(const char *sig, uint8_t *out)
{
    int len = 0;
    const char *p = sig;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (p[0] == '?' && (p[1] == '?' || p[1] == ' ' || !p[1])) {
            out[len++] = 0xff; // wildcard
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

    for (uint64_t i = 0; i + plen <= size; i++) {
        bool ok = true;
        for (int j = 0; j < plen; j++) {
            if (pat[j] != 0xff && base[i + j] != pat[j]) { ok = false; break; }
        }
        if (ok) return (uint8_t *)(base + i);
    }
    return nullptr;
}

static void sc_write_hex(pid_t pid, uint64_t addr, const char *hex)
{
    uint8_t buf[64];
    int len = sc_pattern_to_byte(hex, buf);
    if (len <= 0) return;
    dbg::write(pid, addr, buf, len);
}

// ── Trouve SceShellCore (même logique que find_pid dans main.cpp) ─────────────
static pid_t sc_find_shellcore_pid()
{
    int      mib[4] = {1, 14, 8, 0};
    size_t   buf_size;
    uint8_t *buf;

    if (sysctl(mib, 4, 0, &buf_size, 0, 0)) return -1;
    if (!(buf = (uint8_t *)malloc(buf_size))) return -1;
    if (sysctl(mib, 4, buf, &buf_size, 0, 0)) { free(buf); return -1; }

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

// ── Fonction principale ───────────────────────────────────────────────────────
//
//  Appelle une seule fois au démarrage, APRES payload_get_args() / kernel_base.
//  Retourne true si le patch a réussi.
//
static bool patch_shellcore_for_data()
{
    uint32_t fw = kernel_get_fw_version();
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

    uintptr_t sc_base = exe->getEboot()->getTextSection()->start();
    uint64_t  sc_size = exe->getEboot()->getTextSection()->sectionLength();
    plugin_log("[SC_PATCH] text base=0x%llx size=0x%llx", sc_base, sc_size);

    if (!sc_base || !sc_size) {
        plugin_log("[SC_PATCH] invalid text section");
        return false;
    }

    uint8_t *copy = (uint8_t *)malloc(sc_size);
    if (!copy) { plugin_log("[SC_PATCH] malloc failed"); return false; }

    if (!dbg::read(sc_pid, sc_base, copy, sc_size)) {
        plugin_log("[SC_PATCH] dbg::read failed");
        free(copy);
        return false;
    }

    // Sélection des patterns selon la FW
    const char *pat1 = nullptr, *pat2 = nullptr, *pat_checker = nullptr;

    switch (fw_masked) {
    case SC_V200: case SC_V220: case SC_V225: case SC_V226:
    case SC_V230: case SC_V250: case SC_V270:
        pat1        = "e8 ?? ?? ec 00 48 89 9d";
        pat2        = "e8 ?? ?? b1 00 83 f8";
        pat_checker = "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec 00 02 00 00 49";
        break;
    case SC_V300: case SC_V310: case SC_V320: case SC_V321:
        pat1        = "e8 ?? ?? 00 01 ?? 89 ?? 40";
        pat2        = "e8 ?? ?? c5 00 83 f8 01 75 5f";
        pat_checker = "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec 00 02 00 00 49";
        break;
    case SC_V400: case SC_V402: case SC_V403: case SC_V450: case SC_V451:
        pat1        = "e8 ?? ?? ?? ?? 4c 89 bd ?? ?? ?? ?? 48 89 9d ?? ?? ?? ??";
        pat2        = "e8 ?? ?? ?? ?? 83 f8 01 75 ?? 41 80 3c 24 00";
        pat_checker = "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec 00 02 00 00 49";
        break;
    case SC_V500: case SC_V502: case SC_V510: case SC_V550:
        pat1        = "e8 ?? ?? fb 00 85 c0 75 0d e8 ?? ?? fb 00 85 c0 0f 84 47";
        pat2        = "e8 ?? ?? c7 00 83 f8 01 75 5e";
        pat_checker = "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec e0 01 00 00 49";
        break;
    case SC_V600: case SC_V602: case SC_V650:
        pat1        = "e8 ?? ?? ?? 01 4c 89 a5 80";
        pat2        = "e8 ?? ?? ?? 00 83 f8 01 75 66";
        pat_checker = "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec e0 01 00 00 49";
        break;
    case SC_V700: case SC_V701: case SC_V720: case SC_V740:
    case SC_V760: case SC_V761:
        pat1        = "e8 ?? ?? ?? 01 4c 89 b5 80";
        pat2        = "e8 ?? ?? d7 00 83 f8 01 0f 85 cd";
        pat_checker = "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec e0 01 00 00 49 89 cd";
        break;
    case SC_V800: case SC_V820:
        pat1        = "e8 ?? ?? ?? 01 85 c0 75 0d e8 ?? ?? ?? 01 85 c0 0f 84 c1";
        pat2        = "e8 ?? ?? dc 00 83 f8 01 0f";
        pat_checker = "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec c8 01 00 00 49 89 cd";
        break;
    default:
        plugin_log("[SC_PATCH] FW 0x%08x non supportee, skip", fw_masked);
        free(copy);
        return false;
    }

    uint8_t *found1   = sc_pattern_scan(copy, sc_size, pat1);
    uint8_t *found2   = sc_pattern_scan(copy, sc_size, pat2);
    uint8_t *checker  = sc_pattern_scan(copy, sc_size, pat_checker);

    plugin_log("[SC_PATCH] found1=%p found2=%p checker=%p", found1, found2, checker);

    bool ok = false;

    if (found1 && found2) {
        uint64_t off1 = sc_base + (uint64_t)(found1 - copy);
        uint64_t off2 = sc_base + (uint64_t)(found2 - copy);
        // MOV EAX, 1  (b8 01 00 00 00)
        sc_write_hex(sc_pid, off1, "b8 01 00 00 00");
        sc_write_hex(sc_pid, off2, "b8 01 00 00 00");
        plugin_log("[SC_PATCH] patched data1=0x%llx data2=0x%llx", off1, off2);
        mkdir("/user/devbin", 0777);
        mkdir("/user/devlog", 0777);
        ok = true;
    } else {
        plugin_log("[SC_PATCH] patterns data1/data2 non trouves!");
    }

    if (checker) {
        uint64_t off_chk = sc_base + (uint64_t)(checker - copy);
        // push rbp / mov rbp,rsp / mov eax,0x80261814 / pop rbp / ret
        sc_write_hex(sc_pid, off_chk, "55 48 89 e5 b8 14 18 26 80 5d c3");
        plugin_log("[SC_PATCH] patched checker=0x%llx", off_chk);
    } else {
        plugin_log("[SC_PATCH] checker pattern non trouve (non fatal)");
    }

    free(copy);

    if (ok)
        plugin_log("[SC_PATCH] /data sandbox enabled OK");

    return ok;
}
