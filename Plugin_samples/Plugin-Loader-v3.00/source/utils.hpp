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
    int delay_ms;   // valeur après ':' dans l'INI, interprétée en millisecondes
                    // ex: prx/BeachMenu.prx:10000  → attendre 10s avant injection
};

struct GameInjectorConfig {
    std::map<std::string, std::vector<PRXConfig>> games;
    std::map<std::string, bool>                   fakelib_enabled;
};

// ─────────────────────────────────────────────────────────────────────────────
//  Fonctions (implémentées dans utils.cpp)
// ─────────────────────────────────────────────────────────────────────────────

void               plugin_log(const char *fmt, ...);
bool               Is_Game_Running(int &BigAppid, const char *title_id);
GameInjectorConfig parse_injector_config();
