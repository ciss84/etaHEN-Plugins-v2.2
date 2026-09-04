// utils.hpp — Plugin-Loader v3.00
// Nettoyé : suppression de tout le code PLT hook (GameStuff, GameBuilder,
// BUILDER_TEMPLATE, BUILDER_TEMPLATE_AUTO, HookGame, OrbisPad*).
// L'injection est maintenant purement ptrace dans main.cpp.
// On garde : patch_shellcore, INI parser, plugin_log, Is_Game_Running.

#pragma once

#include <stddef.h>
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
//  Structures de configuration (INI parser)
// ─────────────────────────────────────────────────────────────────────────────

struct PRXConfig {
    std::string path;
    int frame_delay;
};

struct GameInjectorConfig {
    std::map<std::string, std::vector<PRXConfig>> games;
    std::map<std::string, bool>                   fakelib_enabled;
    std::map<std::string, bool>                   game_thread_loader;
    std::map<std::string, bool>                   restore_credentials;
    std::map<std::string, bool>                   native_np_callbacks;
    std::map<std::string, bool>                   repair_cpp_webapi_hooks;
    std::map<std::string, bool>                   synthetic_np_signed_in;
    std::map<std::string, bool>                   preserve_lso_requests;
    std::map<std::string, bool>                   emulate_lso_missing_ps5_routes;
    std::map<std::string, uint32_t>               emulate_lso_route_mask;
    std::map<std::string, bool>                   emulate_np_push_events;
    std::map<std::string, bool>                   trace_lso_webapi_calls;
    std::map<std::string, bool>                   trace_lso_np_calls;
    std::map<std::string, uint64_t>               restore_watch_offset;
    std::map<std::string, int>                    restore_timeout_ms;
    std::map<std::string, int>                    inject_delay_ms; // clé INI: delay=X (secondes)
};

// ─────────────────────────────────────────────────────────────────────────────
//  Fonctions (implémentées dans utils.cpp)
// ─────────────────────────────────────────────────────────────────────────────

void               plugin_log(const char *fmt, ...);
bool               Is_Game_Running(int &BigAppid, const char *title_id);
GameInjectorConfig parse_injector_config();
