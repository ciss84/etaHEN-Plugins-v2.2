#pragma once

// ─────────────────────────────────────────────────────────────────────────────
//  patch_shellcore_for_ftp() — FTP dev access pour FW 8.xx → 12.xx
//
//  Bypasse deux gates dans SceShellCore qui bloquent le FTP sur retail :
//    1. JNZ gate : [rbp-0x20c] non-zero sur retail → return immédiat sans FTP
//    2. devkit_check : vérifie sysctl machdep.check_genuine_devkit_for_psm
//
//  Dépend des helpers déjà définis dans hijacker/hijacker.hpp :
//    sc_pattern_scan, sc_write_hex, sc_bytes_already_patched,
//    sc_find_shellcore_pid, SC_VERSION_MASK, SC_V*
//
//  FW 4.xx–7.xx fonctionnent sans patch → non touchés
// ─────────────────────────────────────────────────────────────────────────────

static bool patch_shellcore_for_ftp()
{
    static bool done = false;
    if (done) return true;

    uint32_t fw        = kernel_get_fw_version();
    uint32_t fw_masked = fw & SC_VERSION_MASK;
    plugin_log("[SC_FTP] FW: 0x%08x (masked: 0x%08x)", fw, fw_masked);

    const char *pat_ftp    = nullptr;   // pattern → devkit_check function
    const char *ftp_patch  = nullptr;   // patch bytes pour devkit_check
    const char *pat_gate   = nullptr;   // pattern → JNZ gate avant devkit_check
    int         gate_jnz   = 0;        // offset du JNZ dans pat_gate

    switch (fw_masked) {
    // FW 8.xx et 9.xx : gate = MOV R14D,[rbp-0x20c]; VMOVUPS; TEST R14D,R14D; JNZ +0x2d
    // devkit_check retourne 0 si devkit → patch: xor eax,eax; ret
    // vérifié FW 8.20 : devkit_check @ 0x13a41f0 | gate JNZ @ 0x13a3f26
    // vérifié FW 9.00 : devkit_check @ 0x142d630 | gate JNZ @ 0x142d366
    case SC_V800: case SC_V820: case SC_V840: case SC_V860:
    case SC_V900: case SC_V905: case SC_V920: case SC_V940: case SC_V960:
        pat_ftp =
            "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 18 "
            "4c 8b 2d ?? ?? ?? ?? "
            "49 89 d6 49 89 f7 31 f6 31 d2 "
            "49 8b 45 00 48 89 45 d0 "
            "e8 ?? ?? ?? ?? 85 c0 78 71";
        ftp_patch = "31 c0 c3";
        pat_gate  = "44 8b b5 f4 fd ff ff c5 f8 11 45 c0 45 85 f6 75 2d";
        gate_jnz  = 15;
        break;

    // FW 10.xx – 12.xx : gate = MOV EAX,[rbp-0x20c]; VMOVUPS; TEST EAX,EAX; JNZ +0x2e
    // vérifié FW 10.00 : devkit_check @ 0x1432250 | gate JNZ @ 0x1431fa2
    // vérifié FW 11.00 : devkit_check @ 0x14a05b0 | gate JNZ @ 0x14a0302
    // vérifié FW 12.00 : devkit_check @ 0x14bf060 | gate JNZ @ 0x14bedb2
    case SC_V1000: case SC_V1001: case SC_V1020: case SC_V1040: case SC_V1060:
    case SC_V1100: case SC_V1120:
    case SC_V1200: case SC_V1202: case SC_V1220: case SC_V1240: case SC_V1260: case SC_V1270:
        pat_ftp =
            "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 18 "
            "4c 8b 2d ?? ?? ?? ?? "
            "49 89 d6 49 89 f7 31 f6 31 d2 "
            "49 8b 45 00 48 89 45 d0 "
            "e8 ?? ?? ?? ?? 85 c0 78 71";
        ftp_patch = "31 c0 c3";
        pat_gate  = "8b 85 f4 fd ff ff c5 f8 11 45 c0 85 c0 75 2e";
        gate_jnz  = 13;
        break;

    default:
        plugin_log("[SC_FTP] FW 0x%08x non supporte (ou pas besoin), skip", fw_masked);
        return false;
    }

    pid_t sc_pid = sc_find_shellcore_pid();
    if (sc_pid < 0) {
        plugin_log("[SC_FTP] SceShellCore not found!");
        return false;
    }
    plugin_log("[SC_FTP] SceShellCore pid: %d", sc_pid);

    UniquePtr<Hijacker> exe = Hijacker::getHijacker(sc_pid);
    if (!exe) {
        plugin_log("[SC_FTP] Hijacker::getHijacker failed");
        return false;
    }

    uintptr_t sc_base = exe->getEboot()->getTextSection()->start();
    uint64_t  sc_size = exe->getEboot()->getTextSection()->sectionLength();
    plugin_log("[SC_FTP] text base=0x%llx size=0x%llx", sc_base, sc_size);

    if (!sc_base || !sc_size) {
        plugin_log("[SC_FTP] invalid text section");
        return false;
    }

    uint8_t *copy = (uint8_t *)malloc(sc_size);
    if (!copy) { plugin_log("[SC_FTP] malloc failed"); return false; }

    if (!dbg::read(sc_pid, sc_base, copy, sc_size)) {
        plugin_log("[SC_FTP] dbg::read failed");
        free(copy);
        return false;
    }

    bool ok = false;

    // Patch 1 : devkit_check → xor eax,eax; ret (return 0 = devkit confirmé)
    uint8_t *found = sc_pattern_scan(copy, sc_size, pat_ftp);
    plugin_log("[SC_FTP] devkit_check=%p", found);
    if (found) {
        if (sc_bytes_already_patched(found, ftp_patch)) {
            plugin_log("[SC_FTP] devkit_check deja patche, skip");
            ok = true;
        } else {
            uint64_t off = sc_base + (uint64_t)(found - copy);
            sc_write_hex(sc_pid, off, ftp_patch);
            plugin_log("[SC_FTP] patched devkit_check @ 0x%llx", off);
            ok = true;
        }
    } else {
        plugin_log("[SC_FTP] pattern devkit_check non trouve!");
    }

    // Patch 2 : NOP le JNZ qui bypasse devkit_check quand [rbp-0x20c] != 0
    if (pat_gate && gate_jnz > 0) {
        uint8_t *gate = sc_pattern_scan(copy, sc_size, pat_gate);
        plugin_log("[SC_FTP] gate_jnz=%p", gate);
        if (gate) {
            uint8_t *jnz_ptr = gate + gate_jnz;
            if (sc_bytes_already_patched(jnz_ptr, "90 90")) {
                plugin_log("[SC_FTP] gate deja patche, skip");
            } else {
                uint64_t off_gate = sc_base + (uint64_t)(jnz_ptr - copy);
                sc_write_hex(sc_pid, off_gate, "90 90");
                plugin_log("[SC_FTP] patched gate JNZ @ 0x%llx", off_gate);
            }
        } else {
            plugin_log("[SC_FTP] pattern gate non trouve!");
            ok = false;
        }
    }

    free(copy);
    if (ok) {
        done = true;
        plugin_log("[SC_FTP] FTP dev access enabled OK");
    }
    return ok;
}
