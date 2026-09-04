// utils.cpp — Plugin-Loader v3.00
// HookGame() supprimé (PLT hook remplacé par ptrace dans main.cpp).
// Contient : plugin_log, Is_Game_Running, parse_injector_config.

#include "utils.hpp"
#include <cstdio>
#include <cstdlib>
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
//    plugin.prx
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
        plugin_log("PluginLoader.ini not found at /data/PluginLoader/PluginLoader.ini");
        return config;
    }

    char buffer[8192];
    int bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);

    if (bytes_read <= 0) {
        plugin_log("Failed to read PluginLoader.ini");
        return config;
    }
    buffer[bytes_read] = '\0';
    plugin_log("Read configuration: %d bytes", bytes_read);

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
                // Load the PRX from a normal game thread through the title's
                // scePadReadState import. This preserves the game's original
                // identity throughout module startup.
                else if (!current_tid.empty() &&
                         line.find("game_thread_loader") == 0) {
                    size_t eq = line.find('=');
                    if (eq != std::string::npos) {
                        std::string val = line.substr(eq + 1);
                        size_t vs = val.find_first_not_of(" \t");
                        if (vs != std::string::npos) val = val.substr(vs);
                        bool enabled = !(val == "false" || val == "0");
                        config.game_thread_loader[current_tid] = enabled;
                        plugin_log("Config: [%s] game_thread_loader = %s",
                                   current_tid.c_str(),
                                   enabled ? "true" : "false");
                    }
                }
                // Clé restore_credentials = true/false
                // Restaure l'identité originale du jeu après LoadStartModule.
                else if (!current_tid.empty() && line.find("restore_credentials") == 0) {
                    size_t eq = line.find('=');
                    if (eq != std::string::npos) {
                        std::string val = line.substr(eq + 1);
                        size_t vs = val.find_first_not_of(" \t");
                        if (vs != std::string::npos) val = val.substr(vs);
                        bool enabled = !(val == "false" || val == "0");
                        config.restore_credentials[current_tid] = enabled;
                        plugin_log("Config: [%s] restore_credentials = %s",
                                   current_tid.c_str(), enabled ? "true" : "false");
                    }
                }
                // Keep GTA's native NP callback registration/dispatch imports
                // after LSO has installed its other compatibility hooks.
                else if (!current_tid.empty() && line.find("native_np_callbacks") == 0) {
                    size_t eq = line.find('=');
                    if (eq != std::string::npos) {
                        std::string val = line.substr(eq + 1);
                        size_t vs = val.find_first_not_of(" \t");
                        if (vs != std::string::npos) val = val.substr(vs);
                        bool enabled = !(val == "false" || val == "0");
                        config.native_np_callbacks[current_tid] = enabled;
                        plugin_log("Config: [%s] native_np_callbacks = %s",
                                   current_tid.c_str(), enabled ? "true" : "false");
                    }
                }
                // Complete LSO's libSceNpCppWebApi hook set. LSO 1.010.002
                // stops its own lazy-import poll after the first successful
                // slot, which can leave later request-lifecycle calls native.
                else if (!current_tid.empty() &&
                         line.find("repair_cpp_webapi_hooks") == 0) {
                    size_t eq = line.find('=');
                    if (eq != std::string::npos) {
                        std::string val = line.substr(eq + 1);
                        size_t vs = val.find_first_not_of(" \t");
                        if (vs != std::string::npos) val = val.substr(vs);
                        bool enabled = !(val == "false" || val == "0");
                        config.repair_cpp_webapi_hooks[current_tid] = enabled;
                        plugin_log("Config: [%s] repair_cpp_webapi_hooks = %s",
                                   current_tid.c_str(),
                                   enabled ? "true" : "false");
                    }
                }
                // Queue one signed-in transition through GTA's own NP state
                // machine after LSO is initialized. This avoids dispatching
                // the real FW 8.60 PSN state over LSO's synthetic identity.
                else if (!current_tid.empty() && line.find("synthetic_np_signed_in") == 0) {
                    size_t eq = line.find('=');
                    if (eq != std::string::npos) {
                        std::string val = line.substr(eq + 1);
                        size_t vs = val.find_first_not_of(" \t");
                        if (vs != std::string::npos) val = val.substr(vs);
                        bool enabled = !(val == "false" || val == "0");
                        config.synthetic_np_signed_in[current_tid] = enabled;
                        plugin_log("Config: [%s] synthetic_np_signed_in = %s",
                                   current_tid.c_str(), enabled ? "true" : "false");
                    }
                }
                // Diagnostic for LSO 1.010.002: retain completed request-table
                // records so the loader's read-only poll can observe the final
                // numeric HTTP state before the game deletes each record.
                else if (!current_tid.empty() && line.find("preserve_lso_requests") == 0) {
                    size_t eq = line.find('=');
                    if (eq != std::string::npos) {
                        std::string val = line.substr(eq + 1);
                        size_t vs = val.find_first_not_of(" \t");
                        if (vs != std::string::npos) val = val.substr(vs);
                        bool enabled = !(val == "false" || val == "0");
                        config.preserve_lso_requests[current_tid] = enabled;
                        plugin_log("Config: [%s] preserve_lso_requests = %s",
                                   current_tid.c_str(), enabled ? "true" : "false");
                    }
                }
                // FW 8.60 compatibility test for LSO 1.010.002. BlueSphere's
                // production proxy rejects or does not implement four PS5-only
                // startup routes. When enabled, the loader supplies the exact
                // empty/unrestricted response objects for only those routes.
                else if (!current_tid.empty() &&
                         line.find("emulate_lso_missing_ps5_routes") == 0) {
                    size_t eq = line.find('=');
                    if (eq != std::string::npos) {
                        std::string val = line.substr(eq + 1);
                        size_t vs = val.find_first_not_of(" \t");
                        if (vs != std::string::npos) val = val.substr(vs);
                        bool enabled = !(val == "false" || val == "0");
                        config.emulate_lso_missing_ps5_routes[current_tid] = enabled;
                        plugin_log(
                            "Config: [%s] emulate_lso_missing_ps5_routes = %s",
                            current_tid.c_str(), enabled ? "true" : "false");
                    }
                }
                // Select individual PS5 startup responses for isolation tests.
                // Bits follow observed request order: restriction=1, blocks=2,
                // invitations=4, friends=8. Omitted means all four (0x0f).
                else if (!current_tid.empty() &&
                         line.find("emulate_lso_route_mask") == 0) {
                    size_t eq = line.find('=');
                    if (eq != std::string::npos) {
                        std::string val = line.substr(eq + 1);
                        size_t vs = val.find_first_not_of(" \t");
                        if (vs != std::string::npos) val = val.substr(vs);
                        uint32_t mask = (uint32_t)strtoul(val.c_str(), nullptr, 0);
                        mask &= 0x0f;
                        config.emulate_lso_route_mask[current_tid] = mask;
                        plugin_log("Config: [%s] emulate_lso_route_mask = 0x%x",
                                   current_tid.c_str(), mask);
                    }
                }
                // PS5 fake-sign-in compatibility: replace only the native
                // PushEvent API imports that LSO 1.010.002 leaves untouched.
                else if (!current_tid.empty() &&
                         line.find("emulate_np_push_events") == 0) {
                    size_t eq = line.find('=');
                    if (eq != std::string::npos) {
                        std::string value = line.substr(eq + 1);
                        size_t vs = value.find_first_not_of(" \t");
                        if (vs != std::string::npos) value = value.substr(vs);
                        std::transform(value.begin(), value.end(), value.begin(),
                                       [](unsigned char c) { return std::tolower(c); });
                        bool enabled = value == "1" || value == "true" ||
                                       value == "yes" || value == "on";
                        config.emulate_np_push_events[current_tid] = enabled;
                        plugin_log("Config: [%s] emulate_np_push_events = %s",
                                   current_tid.c_str(), enabled ? "true" : "false");
                    }
                }
                // Diagnostic-only wrappers around GTA's eight ordinary
                // sceNpWebApi2 imports. Only call counts and numeric returns
                // are retained; request contents and credentials are not read.
                else if (!current_tid.empty() &&
                         line.find("trace_lso_webapi_calls") == 0) {
                    size_t eq = line.find('=');
                    if (eq != std::string::npos) {
                        std::string value = line.substr(eq + 1);
                        size_t vs = value.find_first_not_of(" \t");
                        if (vs != std::string::npos) value = value.substr(vs);
                        std::transform(value.begin(), value.end(), value.begin(),
                                       [](unsigned char c) { return std::tolower(c); });
                        bool enabled = value == "1" || value == "true" ||
                                       value == "yes" || value == "on";
                        config.trace_lso_webapi_calls[current_tid] = enabled;
                        plugin_log("Config: [%s] trace_lso_webapi_calls = %s",
                                   current_tid.c_str(), enabled ? "true" : "false");
                    }
                }
                // Diagnostic-only wrappers around LSO's 19 NP replacements.
                // Only call counts and numeric returns are retained.
                else if (!current_tid.empty() &&
                         line.find("trace_lso_np_calls") == 0) {
                    size_t eq = line.find('=');
                    if (eq != std::string::npos) {
                        std::string value = line.substr(eq + 1);
                        size_t vs = value.find_first_not_of(" \t");
                        if (vs != std::string::npos) value = value.substr(vs);
                        std::transform(value.begin(), value.end(), value.begin(),
                                       [](unsigned char c) { return std::tolower(c); });
                        bool enabled = value == "1" || value == "true" ||
                                       value == "yes" || value == "on";
                        config.trace_lso_np_calls[current_tid] = enabled;
                        plugin_log("Config: [%s] trace_lso_np_calls = %s",
                                   current_tid.c_str(), enabled ? "true" : "false");
                    }
                }
                // Offset relatif au module d'un état à surveiller avant restauration.
                // Pour LSO 1.010, l'état des hooks WebAPI vaut 2 une fois terminé.
                else if (!current_tid.empty() && line.find("restore_watch_offset") == 0) {
                    size_t eq = line.find('=');
                    if (eq != std::string::npos) {
                        std::string val = line.substr(eq + 1);
                        size_t vs = val.find_first_not_of(" \t");
                        if (vs != std::string::npos) val = val.substr(vs);
                        uint64_t offset = strtoull(val.c_str(), nullptr, 0);
                        config.restore_watch_offset[current_tid] = offset;
                        plugin_log("Config: [%s] restore_watch_offset = 0x%llx",
                                   current_tid.c_str(), (unsigned long long)offset);
                    }
                }
                // Temps maximum pendant lequel le jeu tourne avec les droits
                // temporaires pendant que l'état des hooks est surveillé.
                else if (!current_tid.empty() && line.find("restore_timeout") == 0) {
                    size_t eq = line.find('=');
                    if (eq != std::string::npos) {
                        std::string val = line.substr(eq + 1);
                        size_t vs = val.find_first_not_of(" \t");
                        if (vs != std::string::npos) val = val.substr(vs);
                        int secs = atoi(val.c_str());
                        if (secs < 1) secs = 1;
                        if (secs > 180) secs = 180;
                        config.restore_timeout_ms[current_tid] = secs * 1000;
                        plugin_log("Config: [%s] restore_timeout = %ds (%dms)",
                                   current_tid.c_str(), secs, secs * 1000);
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
                // Ligne PRX
                else if (!current_tid.empty()) {
                    size_t colon_pos = line.find(':');
                    std::string prx_file;
                    int frame_delay = 60;

                    if (colon_pos != std::string::npos) {
                        prx_file = line.substr(0, colon_pos);
                        frame_delay = atoi(line.substr(colon_pos + 1).c_str());
                    } else {
                        prx_file = line;
                    }

                    std::string full_path = "/data/PluginLoader/" + prx_file;

                    PRXConfig prx;
                    prx.path = full_path;
                    prx.frame_delay = frame_delay;

                    config.games[current_tid].push_back(prx);
                    plugin_log("Config: [%s] -> %s", current_tid.c_str(),
                               full_path.c_str());
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

    plugin_log("Parsed configuration: %zu game(s)", config.games.size());
    return config;
}
