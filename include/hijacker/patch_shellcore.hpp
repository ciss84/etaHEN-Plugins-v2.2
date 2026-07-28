#pragma once

// ─────────────────────────────────────────────────────────────────────────────
//  patch_shellcore.hpp — active /data en sandbox sans etaHEN
//  Porté depuis etaHEN (cpp_service.cpp / util daemon)
//  A inclure/appeler UNE SEULE FOIS au démarrage de Plugin-Loader
//  NOTE: ne pas inclure utils.hpp ici (pas de include guard dessus)
//        On utilise directement les headers système + hijacker
//  IMPORTANT: ce header doit être inclus APRES hijacker/hijacker.hpp
//             (voir include/hijacker.hpp, qui garantit l'ordre)
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

// plugin_log est défini dans utils.cpp, déclaration externe
extern void plugin_log(const char* fmt, ...);

// kernel_get_fw_version depuis ps5/kernel.h (déjà inclus dans main.cpp avant nous)
extern "C" uint32_t kernel_get_fw_version();

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
static constexpr uint32_t SC_V840  = 0x8400000;
static constexpr uint32_t SC_V860  = 0x8600000;
static constexpr uint32_t SC_V900  = 0x9000000;
static constexpr uint32_t SC_V905  = 0x9050000;
static constexpr uint32_t SC_V920  = 0x9200000;
static constexpr uint32_t SC_V940  = 0x9400000;
static constexpr uint32_t SC_V960  = 0x9600000;
static constexpr uint64_t SC_V1000  = 0x10000000;
static constexpr uint64_t SC_V1001  = 0x10010000;
static constexpr uint64_t SC_V1020  = 0x10200000;
static constexpr uint64_t SC_V1040  = 0x10400000;
static constexpr uint64_t SC_V1060  = 0x10600000;
static constexpr uint64_t SC_V1100  = 0x11000000;
static constexpr uint64_t SC_V1120  = 0x11200000;
static constexpr uint64_t SC_V1140  = 0x11400000;
static constexpr uint64_t SC_V1160  = 0x11600000;
static constexpr uint64_t SC_V1200  = 0x12000000;
static constexpr uint64_t SC_V1202  = 0x12020000;
static constexpr uint64_t SC_V1220  = 0x12200000;
static constexpr uint64_t SC_V1240  = 0x12400000;
static constexpr uint64_t SC_V1260  = 0x12600000;
static constexpr uint64_t SC_V1270  = 0x12700000;

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

static void sc_write_hex(pid_t pid, uint64_t addr, const char *hex)
{
    uint8_t buf[64];
    int len = sc_pattern_to_byte(hex, buf);
    if (len <= 0) return;
    dbg::write(pid, addr, buf, len);
}

// Compare les bytes déjà présents en mémoire (copie locale "copy") avec le
// pattern hex attendu (ex: "b8 01 00 00 00"). Retourne true si ça matche déjà,
// ce qui signifie que le patch a déjà été appliqué (par un run précédent,
// par etaHEN, ou autre) et qu'il n'y a pas besoin de réécrire.
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

static bool patch_shellcore_for_data(bool allow_ftp_dev_access = true)
{
    if (!allow_ftp_dev_access) {
        plugin_log("[SC_PATCH] ALLOW_FTP_DEV_ACCESS disabled, skipping patch");
        return false;
    }
    static bool done = false;
    if (done) return true;
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

    const char *pat1 = nullptr, *pat2 = nullptr, *pat_checker = nullptr;

    switch (fw_masked) {
    case SC_V200: case SC_V220: case SC_V225: case SC_V226: case SC_V230: case SC_V250: case SC_V270:
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
    case SC_V700: case SC_V701: case SC_V720: case SC_V740: case SC_V760: case SC_V761:
        pat1        = "e8 ?? ?? ?? 01 4c 89 b5 80";
        pat2        = "e8 ?? ?? d7 00 83 f8 01 0f 85 cd";
        pat_checker = "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec e0 01 00 00 49 89 cd";
        break;
    case SC_V800: case SC_V820:  case SC_V840: case SC_V860:
        pat1        = "e8 ?? ?? ?? 01 85 c0 75 0d e8 ?? ?? ?? 01 85 c0 0f 84 c1";
        pat2        = "e8 ?? ?? dc 00 83 f8 01 0f";
        pat_checker = "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec c8 01 00 00 49 89 cd";
        break;        
    case SC_V900: case SC_V905: case SC_V920: case SC_V940: case SC_V960:
        pat1        = "E8 ?? ?? ?? 01 85 C0 75 0D E8 ?? ?? ?? 01 85 C0 0F 84 9A";
        pat2        = "E8 ?? ?? E2 00 83 F8 01 0F 85";
        pat_checker = "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC C8 01 00 00 49 89 CD";
        break;   
    case SC_V1000: case SC_V1001: case SC_V1020: case SC_V1040: case SC_V1060:
        pat1        = "E8 ?? ?? ?? 01 85 C0 75 0D E8 ?? ?? ?? 01 85 C0 0F 84 10 06 00 00";
        pat2        = "E8 ?? ?? E2 00 83 F8 01 0F 85";
        pat_checker = "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC C8 01 00 00 49 89";
        break;
    case SC_V1100: case SC_V1120: case SC_V1140: case SC_V1160:
        pat1        = "E8 ?? ?? ?? 01 85 C0 75 0D E8 ?? ?? ?? 01 85 C0 0F 84 17";
        pat2        = "E8 ?? ?? E2 00 83 F8 01 0F 85";
        pat_checker = "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC C8 01 00 00 4C 8B";
        break;
    case SC_V1200: case SC_V1202: case SC_V1220: case SC_V1240: case SC_V1260:
        pat1        = "E8 ?? ?? ?? 01 85 C0 75 0D E8 ?? ?? ?? 01 85 C0 0F 84 17";
        pat2        = "E8 ?? ?? E2 00 83 F8 01 0F 85";
        pat_checker = "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC C8 01 00 00 4C 8B";
        break;
    case SC_V1270:
        pat1        = "E8 ?? ?? ?? 01 85 C0 75 0D E8 ?? ?? ?? 01 85 C0 0F 84 17";
        pat2        = "E8 ?? ?? E3 00 83 F8 01 0F 85";
        pat_checker = "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC C8 01 00 00 4C 8B";
        break;
    default:
        plugin_log("[SC_PATCH] FW 0x%08x non supportee, skip", fw_masked);
        free(copy);
        return false;
    }

    uint8_t *found1  = sc_pattern_scan(copy, sc_size, pat1);
    uint8_t *found2  = sc_pattern_scan(copy, sc_size, pat2);
    uint8_t *checker = sc_pattern_scan(copy, sc_size, pat_checker);

    plugin_log("[SC_PATCH] found1=%p found2=%p checker=%p", found1, found2, checker);

    bool ok = false;
    static constexpr const char *PATCH_BYTES = "b8 01 00 00 00";
    static constexpr const char *CHECKER_PATCH_BYTES = "55 48 89 e5 b8 14 18 26 80 5d c3";

    if (found1 && found2) {
        bool already1 = sc_bytes_already_patched(found1, PATCH_BYTES);
        bool already2 = sc_bytes_already_patched(found2, PATCH_BYTES);

        if (already1 && already2) {
            plugin_log("[SC_PATCH] data1/data2 deja actifs, skip ecriture");
            ok = true;
        } else {
            uint64_t off1 = sc_base + (uint64_t)(found1 - copy);
            uint64_t off2 = sc_base + (uint64_t)(found2 - copy);
            if (!already1) sc_write_hex(sc_pid, off1, PATCH_BYTES);
            if (!already2) sc_write_hex(sc_pid, off2, PATCH_BYTES);
            plugin_log("[SC_PATCH] patched data1=0x%llx (deja_actif=%d) data2=0x%llx (deja_actif=%d)",
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
            sc_write_hex(sc_pid, off_chk, CHECKER_PATCH_BYTES);
            plugin_log("[SC_PATCH] patched checker=0x%llx", off_chk);
        }
    } else {
        plugin_log("[SC_PATCH] checker non trouve (non fatal)");
    }

    free(copy);

    if (ok) {
        done = true;
        plugin_log("[SC_PATCH] /data sandbox enabled OK");
    }

    return ok;
}

// ─────────────────────────────────────────────────────────────────────────────
//  EXPERIMENTAL — a tester uniquement, ne remplace PAS forcement le patch au-dessus
//  Contrairement a patch_shellcore_for_data() (qui bypass le CHECK de permission
//  dans SceShellCore), cette variante ne touche a aucune logique interne:
//  elle monte juste "/user/data" en nullfs sur "/data" (meme mecanisme que le
//  hook mount_root de ps-patch-system, mais fait directement en syscall nmount
//  depuis le process courant, sans hook/trampoline sur SceShellCore).
//  Utilise le meme IOVEC_ENTRY/IOVEC_SIZE style que mount_unionfs() dans main.cpp.
//  A tester: si le check de sandbox dans SceShellCore n'est pas bypass, ce mount
//  seul risque de ne rien changer pour le FTP dev access (le check refusera
//  quand meme l'acces, meme si le mount existe).
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
        plugin_log("[SC_PATCH_TEST] nmount /user/data -> /data a echoue: %d", r);
        return false;
    }
    plugin_log("[SC_PATCH_TEST] /user/data monte sur /data (nullfs) OK");
    return true;
}
