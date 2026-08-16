#pragma once

#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include "notify.hpp"

#include <map>
#include <string>
#include <vector>

struct PRXConfig {
    std::string path;
    int         frame_delay;
};

struct GameInjectorConfig {
    std::map<std::string, std::vector<PRXConfig>> games;
    std::map<std::string, bool>                   fakelib_enabled;
};

void               plugin_log(const char* fmt, ...);
GameInjectorConfig parse_injector_config();