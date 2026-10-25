// utils.hpp — Plugin-Loader v3.03
// Nettoyé : suppression de tout le code PLT hook (GameStuff, GameBuilder,
// BUILDER_TEMPLATE, BUILDER_TEMPLATE_AUTO, HookGame, OrbisPad*).
// L'injection est maintenant purement ptrace dans main.cpp.
// On garde : patch_shellcore, TOML parser, plugin_log, Is_Game_Running.

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/signal.h>
#include <unistd.h>

// Hijacker (libelfloader) — toujours nécessaire pour patch_shellcore_for_data()
#include "dbg.hpp"
#include "dbg/dbg.hpp"
#include "elf/elf.hpp"
#include "hijacker/hijacker.hpp"
#include "hijacker/patch_shellcore.hpp"
#include "notify.hpp"
#include "backtrace.hpp"

#include <map>
#include <string>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
//  Structures de configuration (TOML parser)
// ─────────────────────────────────────────────────────────────────────────────

struct PRXConfig {
    std::string path;
    bool suspend_game = false;   // ptrace : suspend les autres threads du jeu pendant le chargement
    bool plt = false;             // true = PLT hook scePadReadState (méthode v2.02, chargé par le thread du jeu)
                                 // false = injection ptrace (v3)
    int delay_ms;   // délai (ms) depuis le lancement du jeu avant la 1re tentative
    bool sync_load = true;       // true = appel direct dans le thread du jeu (méthode ploader)
                                 // false = pthread transitoire (ancienne méthode)
    bool restore_sandbox = true; // restaurer ucred/rootdir/jaildir du jeu après injection
};

struct GameInjectorConfig {
    std::map<std::string, std::vector<PRXConfig>> games;
    std::map<std::string, bool>                   fakelib_enabled;
    bool                                          default_restore = true; // [loader] default_restore_sandbox
};

// ─────────────────────────────────────────────────────────────────────────────
//  Fonctions (implémentées dans utils.cpp)
// ─────────────────────────────────────────────────────────────────────────────

// ── PLT hook (méthode v2.02) ────────────────────────────────────────────────
struct GameStuff {
  uintptr_t scePadReadState;          // +0x00
  uintptr_t debugout;                  // +0x08
  uintptr_t sceKernelLoadStartModule;  // +0x10
  uintptr_t sceKernelDlsym;           // +0x18
  uint64_t ASLR_Base = 0;             // +0x20
  char prx_path[256];                  // +0x28
  int loaded = 0;                      // +0x128
  uint32_t _pad = 0;                   // +0x12C (explicit padding)
  uint64_t game_hash = 0;             // +0x130
  int frame_delay = 300;              // +0x138
  int frame_counter = 0;              // +0x13C

  GameStuff(Hijacker &hijacker) noexcept
      : debugout(hijacker.getLibKernelAddress(nid::sceKernelDebugOutText)),
        sceKernelLoadStartModule(hijacker.getLibKernelAddress(nid::sceKernelLoadStartModule)),
        sceKernelDlsym(hijacker.getLibKernelAddress(nid::sceKernelDlsym)) {}
};

// Verify offsets at compile time
static_assert(offsetof(GameStuff, prx_path)               == 0x28,  "GameStuff::prx_path offset wrong");
static_assert(offsetof(GameStuff, loaded)                  == 0x128, "GameStuff::loaded offset wrong");
static_assert(offsetof(GameStuff, game_hash)               == 0x130, "GameStuff::game_hash offset wrong");
static_assert(offsetof(GameStuff, frame_delay)             == 0x138, "GameStuff::frame_delay offset wrong");
static_assert(offsetof(GameStuff, frame_counter)           == 0x13C, "GameStuff::frame_counter offset wrong");

struct GameBuilder {
  static constexpr size_t SHELLCODE_SIZE      = 137;
  static constexpr size_t SHELLCODE_SIZE_AUTO = 210;
  static constexpr size_t EXTRA_STUFF_ADDR_OFFSET = 2;

  uint8_t shellcode[256];

  void setExtraStuffAddr(uintptr_t addr) noexcept {
    *reinterpret_cast<uintptr_t *>(shellcode + EXTRA_STUFF_ADDR_OFFSET) = addr;
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  Standard shellcode — connected check REMOVED (NOPed bytes [71-77])
//  Raison: sur FW 10.00 le check connected=0x4C peut etre faux si Sony a
//  change la structure OrbisPadData, ce qui bloque module_start pour toujours.
//
//  Ancien code (bytes 71-77):
//    41 80 7e 4c 00  = CMP BYTE PTR [R14+0x4C], 0  ; connected check
//    74 2e           = JE skip_load                 ; skip si non connecte
//  Nouveau code:
//    90 90 90 90 90  = NOP x5
//    90 90           = NOP x2
// ─────────────────────────────────────────────────────────────────────────────
static constexpr GameBuilder BUILDER_TEMPLATE {
    // [0-9]   MOV RDX, stuffAddr (patché par setExtraStuffAddr)
    0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // [10-19] prologue
    0x55, 0x41, 0x57, 0x41, 0x56, 0x53, 0x48, 0x83, 0xec, 0x18,
    // [20-29] MOV RAX, "Hello fr"
    0x48, 0xb8, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x66, 0x72,
    // [30-32] MOV RBX, RDX
    0x48, 0x89, 0xd3,
    // [33-35] MOV R14, RSI  (data ptr)
    0x49, 0x89, 0xf6,
    // [36-38] MOV R15D, EDI (handle)
    0x41, 0x89, 0xff,
    // [39-42] MOV [RSP], RAX
    0x48, 0x89, 0x04, 0x24,
    // [43-52] MOV RAX, "om BO6\0\0"
    0x48, 0xb8, 0x6f, 0x6d, 0x20, 0x42, 0x4f, 0x36, 0x00, 0x00,
    // [53-57] MOV [RSP+8], RAX
    0x48, 0x89, 0x44, 0x24, 0x08,
    // [58-59] CALL [RDX] = scePadReadState (original)
    0xff, 0x12,
    // [60-61] MOV EBP, EAX (save return value)
    0x89, 0xc5,
    // [62-70] NOP x9 — bypass handle + retval checks (test FW7.6x+)
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    // [71-77] FIX FW10: connected check supprime (7x NOP)
    // Ancien: CMP BYTE PTR [R14+0x4C],0 / JE skip
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    // [78-84] CMP DWORD PTR [RBX+0x128], 0  (loaded ?)
    0x83, 0xbb, 0x28, 0x01, 0x00, 0x00, 0x00,
    // [85-86] JNZ epilogue (deja charge)
    0x75, 0x25,
    // [87-90] LEA RDI, [RBX+0x28]  (prx_path)
    0x48, 0x8d, 0x7b, 0x28,
    // [91-92] XOR ESI, ESI  (args = 0)
    0x31, 0xf6,
    // [93-94] XOR EDX, EDX  (argp = NULL)
    0x31, 0xd2,
    // [95-96] XOR ECX, ECX  (flags = 0)
    0x31, 0xc9,
    // [97-99] XOR R8D, R8D  (pOpt = NULL)
    0x45, 0x31, 0xc0,
    // [100-102] XOR R9D, R9D  (pRes = NULL)
    0x45, 0x31, 0xc9,  
    // [103-105] CALL [RBX+0x10]  = sceKernelLoadStartModule
    0xff, 0x53, 0x10,
    // [106-108] MOV RSI, RSP
    0x48, 0x89, 0xe6,
    // [109-110] XOR EDI, EDI
    0x31, 0xff,
    // [111-113] CALL [RBX+0x08]  = debugout
    0xff, 0x53, 0x08,
    // [114-123] MOV DWORD PTR [RBX+0x128], 1  (loaded = 1)
    0xc7, 0x83, 0x28, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    // [124-125] MOV EAX, EBP  (restore scePadReadState retval)
    0x89, 0xe8,
    // [126-129] ADD RSP, 24
    0x48, 0x83, 0xc4, 0x18,
    // [130]     POP RBX
    0x5b,
    // [131-132] POP R14
    0x41, 0x5e,
    // [133-134] POP R15
    0x41, 0x5f,
    // [135]     POP RBP
    0x5d,
    // [136]     RET
    0xc3
};


bool HookGame(UniquePtr<Hijacker> &hijacker, uint64_t alsr_b, const char* prx_path,
              bool auto_load, int frame_delay = 300, uintptr_t* out_stuff_addr = nullptr);

void               plugin_log(const char *fmt, ...);
bool               Is_Game_Running(int &BigAppid, const char *title_id);
GameInjectorConfig parse_injector_config();
