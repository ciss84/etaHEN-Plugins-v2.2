#pragma once

#include <stddef.h>
#include <stdio.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include "hijacker/patch_shellcore.hpp"
#include "notify.hpp"
#include "backtrace.hpp"

#include <map>
#include <string>
#include <vector>

struct PRXConfig {
    std::string path;
    int         frame_delay;  // conservé pour compatibilité config INI, non utilisé en TCP
};

struct GameInjectorConfig {
    std::map<std::string, std::vector<PRXConfig>> games;
    std::map<std::string, bool>                   fakelib_enabled;
};

void               plugin_log(const char* fmt, ...);
GameInjectorConfig parse_injector_config();
