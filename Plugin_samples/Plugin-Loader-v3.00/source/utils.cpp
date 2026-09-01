// utils.cpp — Plugin-Loader v3.00
// HookGame() supprimé (PLT hook remplacé par ptrace dans main.cpp).
// Contient : plugin_log, Is_Game_Running, parse_injector_config.

#include "utils.hpp"
#include <cstdio>
#include <cstring>
#include <nid.hpp>
#include <fcntl.h>
#include <string>

// ─────────────────────────────────────────────────────────────────────────────
//  Logging vers fichier
// ─────────────────────────────────────────────────────────────────────────────

static void write_log(const char *text)
{
    int fd = open("/data/PluginLoader/PluginLoader.log",
                  O_WRONLY | O_CREAT | O_APPEND, 0777);
    if (fd < 0) return;
    write(fd, text, strlen(text));
    close(fd);
}

void plugin_log(const char *fmt, ...)
{
    char msg[0x1000]{};
    va_list args;
    va_start(args, fmt);
    int msg_len = vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    if (msg_len > 0 && msg[msg_len - 1] == '\n') {
        write_log(msg);
    } else {
        strcat(msg, "\n");
        write_log(msg);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Vérification si un jeu est en cours via SystemService
// ─────────────────────────────────────────────────────────────────────────────

extern "C" int sceSystemServiceGetAppIdOfRunningBigApp();
extern "C" int sceSystemServiceGetAppTitleId(int app_id, char *title_id);

bool Is_Game_Running(int &BigAppid, const char *title_id)
{
    char tid[256]{};
    BigAppid = sceSystemServiceGetAppIdOfRunningBigApp();
    if (BigAppid < 0) return false;
    if (sceSystemServiceGetAppTitleId(BigAppid, &tid[0]) != 0) return false;
    tid[255] = '\0';

    if (std::string(tid) == std::string(title_id)) {
        plugin_log("%s is running, appid 0x%X", title_id, BigAppid);
        return true;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Parser INI — /data/PluginLoader/PluginLoader.ini
//
//  Format :
//    [CUSAXXXXX]
//    monplugin.prx:60        ; 60 = frame_delay (ignoré en mode ptrace)
//    autreplugin.prx         ; frame_delay par défaut = 60
//    fakelib = false         ; désactiver fakelib pour ce titre (PPSA seulement)
//
//    [PPSAXXXXX]
//    fakelib = true          ; fakelib activée (défaut pour PPSA)
//    plugin.prx
// ─────────────────────────────────────────────────────────────────────────────

GameInjectorConfig parse_injector_config()
{
    GameInjectorConfig config;

    int fd = open("/data/PluginLoader/PluginLoader.ini", O_RDONLY);
    if (fd < 0) {
        plugin_log("Aucun PluginLoader.ini trouvé à /data/PluginLoader/PluginLoader.ini");
        return config;
    }

    char buffer[8192];
    int bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);

    if (bytes_read <= 0) {
        plugin_log("Échec lecture PluginLoader.ini");
        return config;
    }
    buffer[bytes_read] = '\0';
    plugin_log("Config lue: %d octets", bytes_read);

    std::string current_tid;
    char *ptr        = buffer;
    char *line_start = ptr;

    while (ptr < buffer + bytes_read)
    {
        if (*ptr == '\n' || *ptr == '\r' || ptr >= buffer + bytes_read - 1)
        {
            size_t line_len = ptr - line_start;
            if (ptr >= buffer + bytes_read - 1 &&
                *ptr != '\n' && *ptr != '\r')
                line_len++;

            std::string line(line_start, line_len);

            size_t start = line.find_first_not_of(" \t\r");
            size_t end   = line.find_last_not_of(" \t\r");
            if (start != std::string::npos && end != std::string::npos)
                line = line.substr(start, end - start + 1);
            else
                line = "";

            if (!line.empty() && line[0] != ';' && line[0] != '#')
            {
                // Section [TITLEID]
                if (line[0] == '[' && line[line.length() - 1] == ']') {
                    current_tid = line.substr(1, line.length() - 2);
                    plugin_log("Config: section [%s]", current_tid.c_str());
                }
                // Clé fakelib = true/false
                else if (!current_tid.empty() && line.find("fakelib") == 0) {
                    size_t eq = line.find('=');
                    if (eq != std::string::npos) {
                        std::string val = line.substr(eq + 1);
                        size_t vs = val.find_first_not_of(" \t");
                        if (vs != std::string::npos) val = val.substr(vs);
                        bool enabled = !(val == "false" || val == "0");
                        config.fakelib_enabled[current_tid] = enabled;
                        plugin_log("Config: [%s] fakelib = %s",
                                   current_tid.c_str(), enabled ? "true" : "false");
                    }
                }
                // Clé delay = X  (délai en secondes avant injection ptrace)
                else if (!current_tid.empty() && line.find("delay") == 0) {
                    size_t eq = line.find('=');
                    if (eq != std::string::npos) {
                        std::string val = line.substr(eq + 1);
                        size_t vs = val.find_first_not_of(" \t");
                        if (vs != std::string::npos) val = val.substr(vs);
                        int secs = atoi(val.c_str());
                        if (secs < 1) secs = 1;
                        config.inject_delay_ms[current_tid] = secs * 1000;
                        plugin_log("Config: [%s] delay = %ds (%dms)",
                                   current_tid.c_str(), secs, secs * 1000);
                    }
                }
                // Ligne PRX (format: fichier.prx ou fichier.prx:delay)
                else if (!current_tid.empty()) {
                    size_t colon_pos = line.find(':');
                    std::string prx_file;
                    int frame_delay = 60;

                    if (colon_pos != std::string::npos) {
                        prx_file    = line.substr(0, colon_pos);
                        frame_delay = atoi(line.substr(colon_pos + 1).c_str());
                    } else {
                        prx_file = line;
                    }

                    std::string full_path = "/data/PluginLoader/" + prx_file;

                    PRXConfig prx;
                    prx.path        = full_path;
                    prx.frame_delay = frame_delay; // conservé, non utilisé en ptrace

                    config.games[current_tid].push_back(prx);
                    plugin_log("Config: [%s] → %s",
                               current_tid.c_str(), full_path.c_str());
                }
            }

            // Avancer au-delà du séparateur de ligne
            if (*ptr == '\r' && ptr + 1 < buffer + bytes_read &&
                *(ptr + 1) == '\n')
                ptr += 2;
            else
                ptr++;

            line_start = ptr;
        }
        else {
            ptr++;
        }
    }

    plugin_log("Config parsée: %zu jeu(x)", config.games.size());
    return config;
}
