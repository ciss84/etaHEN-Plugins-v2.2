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
#include <unistd.h>
#include "hijacker/hijacker.hpp"
#include "dbg/dbg.hpp"

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

// Comme sc_pattern_scan, mais échoue (retourne nullptr) si le pattern matche
// plus d'une fois dans la région scannée. Utile pour les patterns courts
// (peu de wildcards) qui risquent de matcher un mauvais call site ailleurs
// dans le .text — mieux vaut ne rien patcher que patcher au mauvais endroit.
static uint8_t *sc_pattern_scan_unique(const uint8_t *base, uint64_t size, const char *sig, int *out_match_count = nullptr)
{
    uint8_t pat[256];
    int plen = sc_pattern_to_byte(sig, pat);
    if (plen <= 0) {
        if (out_match_count) *out_match_count = 0;
        return nullptr;
    }

    uint8_t *first = nullptr;
    int count = 0;
    for (uint64_t i = 0; i + (uint64_t)plen <= size; i++) {
        bool ok = true;
        for (int j = 0; j < plen; j++) {
            if (pat[j] != 0xff && base[i + j] != pat[j]) { ok = false; break; }
        }
        if (ok) {
            if (!first) first = (uint8_t *)(base + i);
            count++;
            if (count > 1) break;  // pas besoin d'aller plus loin, déjà ambigu
        }
    }
    if (out_match_count) *out_match_count = count;
    return (count == 1) ? first : nullptr;
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

// ─────────────────────────────────────────────────────────────────────────────
//  Hook mount_root — intercepte la fonction elle-meme (pas un call site),
//  installe UNE SEULE FOIS au boot comme patch_shellcore_for_data().
//  Une fois patchee, TOUT futur appel a mount_root (n'importe quel process,
//  n'importe quand) passe par notre hook automatiquement.
//
//  Pattern de call site + taille de patch (6 bytes) repris de ps-patch-system
//  (confirme PS5 3.00 -> 12.70). Le hook lui-meme a ete compile avec
//  clang-18 --target=x86_64-freebsd-pc-elf -ffreestanding -O2 et verifie
//  via objdump -d -r (offsets de relocation ci-dessous = valeurs reelles).
// ─────────────────────────────────────────────────────────────────────────────

// call site vers mount_root : "48 8d 35 ... e8 ?? ?? ?? ??" (call a l'offset 48)
static constexpr const char *MOUNTROOT_CALLSITE_PAT =
    "48 8d 35 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? "
    "4c 8d 8d ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ff ff ff ff 45 31 c0 "
    "c6 85 ?? ?? ?? ?? 00 e8 ?? ?? ?? ??";
static constexpr size_t MOUNTROOT_CALLSITE_CALL_OFFSET = 48;
static constexpr size_t MOUNTROOT_PROLOGUE_BACKUP_SIZE = 6;  // meme valeur que ps-patch-system

// bytes .text du hook (mount_root_hook), compiles + verifies via clang-18/objdump
static constexpr uint8_t MOUNTROOT_HOOK_TEXT[313] = {
    0x55, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x50, 0x49, 0xbc, 0x88, 0x77, 0x66,
    0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x85, 0xd2, 0x0f, 0x84, 0x08, 0x01, 0x00, 0x00, 0x48, 0x85,
    0xc9, 0x0f, 0x84, 0xff, 0x00, 0x00, 0x00, 0x44, 0x0f, 0xb6, 0x1a, 0x45, 0x84, 0xdb, 0x0f, 0x84,
    0xf2, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00, 0x49, 0x89, 0xd2, 0x66, 0x90,
    0x31, 0xdb, 0x66, 0x66, 0x66, 0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0f, 0xb6, 0x2c, 0x03, 0x41, 0x38, 0xeb, 0x75, 0x12, 0x45, 0x0f, 0xb6, 0x5c, 0x1a, 0x01, 0x48,
    0xff, 0xc3, 0x45, 0x84, 0xdb, 0x75, 0xe9, 0x0f, 0xb6, 0x2c, 0x03, 0x40, 0x84, 0xed, 0x74, 0x12,
    0x45, 0x0f, 0xb6, 0x5a, 0x01, 0x49, 0xff, 0xc2, 0x45, 0x84, 0xdb, 0x75, 0xc3, 0xe9, 0xa4, 0x00,
    0x00, 0x00, 0x44, 0x0f, 0xb6, 0x19, 0x45, 0x84, 0xdb, 0x0f, 0x84, 0x97, 0x00, 0x00, 0x00, 0x49,
    0x89, 0xca, 0x66, 0x66, 0x66, 0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x31, 0xdb, 0x66, 0x66, 0x66, 0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0f, 0xb6, 0x2c, 0x03, 0x41, 0x38, 0xeb, 0x75, 0x12, 0x45, 0x0f, 0xb6, 0x5c, 0x1a, 0x01, 0x48,
    0xff, 0xc3, 0x45, 0x84, 0xdb, 0x75, 0xe9, 0x0f, 0xb6, 0x2c, 0x03, 0x40, 0x84, 0xed, 0x74, 0x0f,
    0x45, 0x0f, 0xb6, 0x5a, 0x01, 0x49, 0xff, 0xc2, 0x45, 0x84, 0xdb, 0x75, 0xc3, 0xeb, 0x47, 0x48,
    0x8d, 0x05, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x8d, 0x15, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x8d, 0x1d,
    0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0xfb, 0x48, 0x89, 0x34, 0x24, 0x48, 0x89, 0xc6, 0x49, 0x89,
    0xd5, 0x4c, 0x89, 0xd2, 0x48, 0x89, 0xcd, 0x4c, 0x89, 0xd9, 0x4d, 0x89, 0xc6, 0x4d, 0x89, 0xcf,
    0x41, 0xff, 0xd4, 0x48, 0x89, 0xdf, 0x48, 0x8b, 0x34, 0x24, 0x4c, 0x89, 0xea, 0x48, 0x89, 0xe9,
    0x4d, 0x89, 0xf0, 0x4d, 0x89, 0xf9, 0x4c, 0x89, 0xe0, 0x48, 0x83, 0xc4, 0x08, 0x5b, 0x41, 0x5c,
    0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0x5d, 0xff, 0xe0
};

// bytes .rodata : "/system_tmp\0nullfs\0/user/data\0/data\0"
static constexpr uint8_t MOUNTROOT_HOOK_RODATA[36] = {
    0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x5f, 0x74, 0x6d, 0x70, 0x00, 0x6e, 0x75, 0x6c, 0x6c,
    0x66, 0x73, 0x00, 0x2f, 0x75, 0x73, 0x65, 0x72, 0x2f, 0x64, 0x61, 0x74, 0x61, 0x00, 0x2f, 0x64,
    0x61, 0x74, 0x61, 0x00
};
// offsets des strings dans MOUNTROOT_HOOK_RODATA
static constexpr size_t RODATA_OFF_SYSTEM_TMP = 0x00;  // "/system_tmp"
static constexpr size_t RODATA_OFF_NULLFS     = 0x0c;  // "nullfs"
static constexpr size_t RODATA_OFF_USER_DATA  = 0x13;  // "/user/data"
static constexpr size_t RODATA_OFF_DATA       = 0x1e;  // "/data"

// offsets des 4 relocations R_X86_64_PC32 dans MOUNTROOT_HOOK_TEXT (verifies via objdump -d -r)
struct mountroot_reloc { size_t code_offset; size_t rodata_offset; };
static constexpr mountroot_reloc MOUNTROOT_RELOCS[4] = {
    {0x37, RODATA_OFF_SYSTEM_TMP},  // lea rax, [rip + "/system_tmp"]
    {0xe2, RODATA_OFF_NULLFS},      // lea rax, [rip + "nullfs"]
    {0xe9, RODATA_OFF_USER_DATA},   // lea r10, [rip + "/user/data"]
    {0xf0, RODATA_OFF_DATA},        // lea r11, [rip + "/data"]
};
// offset de l'immediate "orig_fn" (movabs r12, 0x1122334455667788) a patcher
// avec l'adresse du trampoline une fois alloue
static constexpr size_t MOUNTROOT_ORIGFN_IMM_OFFSET = 0xd;

static uintptr_t sc_decode_call_target(const uint8_t *at, uintptr_t call_site_vaddr)
{
    if (!at || at[0] != 0xe8) return 0;
    int32_t rel32 = 0;
    memcpy(&rel32, at + 1, sizeof(rel32));
    return call_site_vaddr + 5 + (int64_t)rel32;
}

static bool patch_shellcore_mountroot_hook()
{
    static bool done = false;
    if (done) return true;

    pid_t sc_pid = sc_find_shellcore_pid();
    if (sc_pid < 0) {
        plugin_log("[SC_MOUNTROOT] SceShellCore not found!");
        return false;
    }

    UniquePtr<Hijacker> exe = Hijacker::getHijacker(sc_pid);
    if (!exe) {
        plugin_log("[SC_MOUNTROOT] Hijacker::getHijacker failed");
        return false;
    }
    Hijacker &hijacker = *exe;

    uintptr_t sc_base = hijacker.getEboot()->getTextSection()->start();
    uint64_t  sc_size = hijacker.getEboot()->getTextSection()->sectionLength();
    if (!sc_base || !sc_size) {
        plugin_log("[SC_MOUNTROOT] invalid text section");
        return false;
    }

    uint8_t *copy = (uint8_t *)malloc(sc_size);
    if (!copy) { plugin_log("[SC_MOUNTROOT] malloc failed"); return false; }
    if (!hijacker.read(sc_base, copy, sc_size)) {
        plugin_log("[SC_MOUNTROOT] read failed");
        free(copy);
        return false;
    }

    int n_matches = 0;
    uint8_t *match = sc_pattern_scan_unique(copy, sc_size, MOUNTROOT_CALLSITE_PAT, &n_matches);
    if (!match) {
        plugin_log("[SC_MOUNTROOT] callsite pattern non trouve ou ambigu (n=%d), abandon", n_matches);
        free(copy);
        return false;
    }

    uintptr_t call_site_vaddr = sc_base + (uint64_t)(match - copy) + MOUNTROOT_CALLSITE_CALL_OFFSET;
    uint8_t call_bytes[5] = {};
    if (!hijacker.read(call_site_vaddr, call_bytes, sizeof(call_bytes))) {
        plugin_log("[SC_MOUNTROOT] impossible de lire le call site");
        free(copy);
        return false;
    }
    uintptr_t mount_root_addr = sc_decode_call_target(call_bytes, call_site_vaddr);
    free(copy);

    if (!mount_root_addr) {
        plugin_log("[SC_MOUNTROOT] decode call target echoue (byte 0 != e8 ?)");
        return false;
    }
    plugin_log("[SC_MOUNTROOT] mount_root reel @ 0x%llx", mount_root_addr);

    // deja patche ? (si le premier byte n'est plus dans les instructions
    // originales attendues et ressemble deja a notre jmp, on skip)
    uint8_t existing[6] = {};
    hijacker.read(mount_root_addr, existing, sizeof(existing));

    ProcessMemoryAllocator &alloc = hijacker.getTextAllocator();
    uintptr_t code_addr       = alloc.allocate(sizeof(MOUNTROOT_HOOK_TEXT));
    uintptr_t rodata_addr     = alloc.allocate(sizeof(MOUNTROOT_HOOK_RODATA));
    uintptr_t trampoline_addr = alloc.allocate(16);

    plugin_log("[SC_MOUNTROOT] code=0x%llx rodata=0x%llx trampoline=0x%llx",
               code_addr, rodata_addr, trampoline_addr);

    // ── construire .text patche localement (relocs + pointeur trampoline) ──
    uint8_t text_buf[sizeof(MOUNTROOT_HOOK_TEXT)];
    memcpy(text_buf, MOUNTROOT_HOOK_TEXT, sizeof(text_buf));

    for (const auto &r : MOUNTROOT_RELOCS) {
        int32_t disp = (int32_t)((int64_t)(rodata_addr + r.rodata_offset)
                                  - (int64_t)(code_addr + r.code_offset) - 4);
        memcpy(text_buf + r.code_offset, &disp, sizeof(disp));
    }
    memcpy(text_buf + MOUNTROOT_ORIGFN_IMM_OFFSET, &trampoline_addr, sizeof(trampoline_addr));

    // ── trampoline: 6 bytes originaux de mount_root + jmp vers mount_root+6 ──
    uint8_t tramp_buf[16] = {};
    memcpy(tramp_buf, existing, MOUNTROOT_PROLOGUE_BACKUP_SIZE);
    int32_t back_disp = (int32_t)((int64_t)(mount_root_addr + MOUNTROOT_PROLOGUE_BACKUP_SIZE)
                                   - (int64_t)(trampoline_addr + MOUNTROOT_PROLOGUE_BACKUP_SIZE + 5));
    tramp_buf[MOUNTROOT_PROLOGUE_BACKUP_SIZE] = 0xe9;
    memcpy(tramp_buf + MOUNTROOT_PROLOGUE_BACKUP_SIZE + 1, &back_disp, sizeof(back_disp));

    // ── ecriture: rodata, text, trampoline, puis le patch de mount_root ────
    hijacker.write(rodata_addr, MOUNTROOT_HOOK_RODATA, sizeof(MOUNTROOT_HOOK_RODATA));
    hijacker.write(code_addr, text_buf, sizeof(text_buf));
    hijacker.write(trampoline_addr, tramp_buf, MOUNTROOT_PROLOGUE_BACKUP_SIZE + 5);

    uint8_t redirect[MOUNTROOT_PROLOGUE_BACKUP_SIZE] = {};
    int32_t fwd_disp = (int32_t)((int64_t)code_addr - (int64_t)(mount_root_addr + 5));
    redirect[0] = 0xe9;
    memcpy(redirect + 1, &fwd_disp, sizeof(fwd_disp));
    redirect[5] = 0x90;  // NOP padding pour completer les 6 bytes sauvegardes

    hijacker.suspend();
    hijacker.write(mount_root_addr, redirect, sizeof(redirect));
    hijacker.resume();

    plugin_log("[SC_MOUNTROOT] hook installe @ 0x%llx -> 0x%llx", mount_root_addr, code_addr);
    done = true;
    return true;
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
    case SC_V800: case SC_V820: case SC_V840: case SC_V860:
        pat1        = "e8 ?? ?? ?? 01 85 c0 75 0d e8 ?? ?? ?? 01 85 c0 0f 84 c1";
        pat2        = "e8 ?? ?? dc 00 83 f8 01 0f";
        pat_checker = "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec c8 01 00 00 49 89 cd";
        break;
    case SC_V900: case SC_V905: case SC_V920: case SC_V940: case SC_V960:
        pat1        = "e8 ?? ?? ?? 01 85 c0 75 0d e8 ?? ?? ?? 01 85 c0 0f 84 7e";
        pat2        = "e8 ?? ?? dc 00 83 f8 01 0f";
        pat_checker = "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec c8 01 00 00 49 89 cc";
        break;   
    case SC_V1000: case SC_V1001: case SC_V1020: case SC_V1040: case SC_V1060:
        pat1        = "e8 ?? ?? ?? 01 85 c0 75 0d e8 ?? ?? ?? 01 85 c0 0f 84 7e";
        pat2        = "e8 ?? ?? dc 00 83 f8 01 0f";
        pat_checker = "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec c8 01 00 00 49 89 cc";
        break;
    case SC_V1100: case SC_V1120:
        pat1        = "e8 ?? ?? ?? 01 85 c0 75 0d e8 ?? ?? ?? 01 85 c0 0f 84 7e";
        pat2        = "e8 ?? ?? dc 00 83 f8 01 0f";
        pat_checker = "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec c8 01 00 00 49 89 cc";
        break;
    case SC_V1200: case SC_V1202: case SC_V1220: case SC_V1240: case SC_V1260: case SC_V1270:
        pat1        = "e8 ?? ?? ?? 01 85 c0 75 0d e8 ?? ?? ?? 01 85 c0 0f 84 7e";
        pat2        = "e8 ?? ?? dc 00 83 f8 01 0f";
                   //  e8 ?? ?? dc 00 83 f8
        pat_checker = "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec c8 01 00 00 49 89 cc";
        break;
    default:
        plugin_log("[SC_PATCH] FW 0x%08x non supportee, skip", fw_masked);
        free(copy);
        return false;
    }

    int n1 = 0, n2 = 0, n_chk = 0;
    uint8_t *found1  = sc_pattern_scan_unique(copy, sc_size, pat1, &n1);
    uint8_t *found2  = sc_pattern_scan_unique(copy, sc_size, pat2, &n2);
    uint8_t *checker = sc_pattern_scan_unique(copy, sc_size, pat_checker, &n_chk);

    plugin_log("[SC_PATCH] found1=%p (n=%d) found2=%p (n=%d) checker=%p (n=%d)",
               found1, n1, found2, n2, checker, n_chk);
    if (n1 > 1) plugin_log("[SC_PATCH] WARN pat1 ambigu (%d matches), skip pour eviter mauvais offset", n1);
    if (n2 > 1) plugin_log("[SC_PATCH] WARN pat2 ambigu (%d matches), skip pour eviter mauvais offset", n2);
    if (n_chk > 1) plugin_log("[SC_PATCH] WARN pat_checker ambigu (%d matches), skip pour eviter mauvais offset", n_chk);

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