#include "utils.hpp"
#include <cstring>
#include <fcntl.h>
#include <string>
#include <stdarg.h>
#include <sys/sysctl.h>
#include <ps5/klog.h>

// ── plugin_log ────────────────────────────────────────────────────────────────

static void write_log(const char* text)
{
    int fd = open("/data/PluginLoader/PluginLoader.log", O_WRONLY | O_CREAT | O_APPEND, 0777);
    klog_puts(text);
    if (fd < 0) return;
    write(fd, text, strlen(text));
    close(fd);
}

void plugin_log(const char* fmt, ...)
{
    char msg[0x1000]{};
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    if (len > 0 && msg[len - 1] != '\n')
        strncat(msg, "\n", sizeof(msg) - len - 1);
    write_log(msg);
}

// ── parse_injector_config ─────────────────────────────────────────────────────

GameInjectorConfig parse_injector_config()
{
    GameInjectorConfig config;

    int fd = open("/data/PluginLoader/PluginLoader.ini", O_RDONLY);
    if (fd < 0) {
        plugin_log("No PluginLoader.ini found");
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
    plugin_log("Config: %d bytes", bytes_read);

    std::string current_tid;
    char *ptr = buffer, *line_start = ptr;

    while (ptr < buffer + bytes_read) {
        if (*ptr == '\n' || *ptr == '\r' || ptr >= buffer + bytes_read - 1) {
            size_t line_len = ptr - line_start;
            if (ptr >= buffer + bytes_read - 1 && *ptr != '\n' && *ptr != '\r')
                line_len++;

            std::string line(line_start, line_len);
            size_t s = line.find_first_not_of(" \t\r");
            size_t e = line.find_last_not_of(" \t\r");
            line = (s != std::string::npos) ? line.substr(s, e - s + 1) : "";

            if (!line.empty() && line[0] != ';' && line[0] != '#') {
                if (line[0] == '[' && line.back() == ']') {
                    current_tid = line.substr(1, line.size() - 2);
                    plugin_log("Config: section [%s]", current_tid.c_str());
                }
                else if (!current_tid.empty() && line.find("fakelib") == 0) {
                    size_t eq = line.find('=');
                    if (eq != std::string::npos) {
                        std::string val = line.substr(eq + 1);
                        size_t vs = val.find_first_not_of(" \t");
                        if (vs != std::string::npos) val = val.substr(vs);
                        bool enabled = !(val == "false" || val == "0");
                        config.fakelib_enabled[current_tid] = enabled;
                        plugin_log("Config: [%s] fakelib = %s", current_tid.c_str(), enabled ? "true" : "false");
                    }
                }
                else if (!current_tid.empty()) {
                    size_t colon = line.find(':');
                    std::string prx_file;
                    int frame_delay = 60;
                    if (colon != std::string::npos) {
                        prx_file    = line.substr(0, colon);
                        frame_delay = atoi(line.substr(colon + 1).c_str());
                    } else {
                        prx_file = line;
                    }

                    PRXConfig prx;
                    prx.path        = "/data/PluginLoader/" + prx_file;
                    prx.frame_delay = frame_delay;
                    config.games[current_tid].push_back(prx);
                    plugin_log("Config: [%s] -> %s", current_tid.c_str(), prx.path.c_str());
                }
            }

            if (*ptr == '\r' && ptr + 1 < buffer + bytes_read && *(ptr + 1) == '\n')
                ptr += 2;
            else
                ptr++;
            line_start = ptr;
        } else {
            ptr++;
        }
    }

    plugin_log("Config done: %zu game(s)", config.games.size());
    return config;
}
