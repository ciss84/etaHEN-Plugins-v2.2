// utils.cpp — Plugin-Loader v3.01
// HookGame() supprimé (PLT hook remplacé par ptrace dans main.cpp).
// Contient : plugin_log, Is_Game_Running, parse_injector_config (TOML).

#include "utils.hpp"
#include <cstdio>
#include <cstring>
#include <nid.hpp>
#include <fcntl.h>
#include <string>
#include <cstdlib>
#include <unistd.h>

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
//  Parser TOML — /data/PluginLoader/PluginLoader.toml
//
//  Format :
//    [[plugin]]
//    title    = "CUSA01234"                 # obligatoire
//    path     = "BeachMenu.prx"             # relatif => /data/PluginLoader/  (ou chemin absolu)
//    delay_ms = 10000                       # défaut 10000 (0 - 3600000)
//    inject   = true                        # false => PRX ignoré (défaut true)
//    fakelib  = true                        # optionnel, PPSA seulement (défaut true)
//
//  Plusieurs [[plugin]] pour le même title = multi-PRX.
//  Commentaires : # ou ; (hors guillemets). Les sections inconnues sont ignorées.
// ─────────────────────────────────────────────────────────────────────────────

#define PL_CONFIG_PATH "/data/PluginLoader/PluginLoader.toml"
#define PL_CONFIG_DIR  "/data/PluginLoader/"

static std::string toml_trim(const std::string &s)
{
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// Retire le commentaire de fin de ligne (# ou ;) en respectant les guillemets
static std::string toml_strip_comment(const std::string &line)
{
    bool inq = false;
    for (size_t i = 0; i < line.size(); i++) {
        char c = line[i];
        if (c == '"') inq = !inq;
        else if (!inq && (c == '#' || c == ';')) return line.substr(0, i);
    }
    return line;
}

static std::string toml_string(const std::string &v)
{
    std::string s = toml_trim(v);
    if (s.size() >= 2 && (s[0] == '"' || s[0] == '\'')) {
        size_t end = s.rfind(s[0]);
        if (end > 0) return s.substr(1, end - 1);
    }
    return s;
}

static bool toml_bool(const std::string &v, bool &out)
{
    std::string s = toml_trim(v);
    if (s == "true"  || s == "1") { out = true;  return true; }
    if (s == "false" || s == "0") { out = false; return true; }
    return false;
}

struct PendingPlugin {
    bool        active      = false;
    std::string title;
    std::string path;
    int         delay_ms    = 10000;
    bool        inject      = true;
    bool        has_fakelib = false;
    bool        fakelib     = true;
};

static void flush_plugin(PendingPlugin &p, GameInjectorConfig &config)
{
    if (!p.active) return;
    p.active = false;

    if (p.title.empty()) {
        plugin_log("Config: [[plugin]] sans title, ignoré");
        return;
    }
    if (p.has_fakelib) {
        config.fakelib_enabled[p.title] = p.fakelib;
        plugin_log("Config: [%s] fakelib = %s", p.title.c_str(), p.fakelib ? "true" : "false");
    }
    if (!p.inject) {
        plugin_log("Config: [%s] %s inject=false, ignoré", p.title.c_str(), p.path.c_str());
        return;
    }
    if (p.path.empty()) {
        plugin_log("Config: [%s] [[plugin]] sans path, ignoré", p.title.c_str());
        return;
    }

    PRXConfig prx;
    prx.path     = (p.path[0] == '/') ? p.path : std::string(PL_CONFIG_DIR) + p.path;
    prx.delay_ms = p.delay_ms;
    config.games[p.title].push_back(prx);
    plugin_log("Config: [%s] → %s (delay %dms)", p.title.c_str(), prx.path.c_str(), prx.delay_ms);
}

GameInjectorConfig parse_injector_config()
{
    GameInjectorConfig config;

    int fd = open(PL_CONFIG_PATH, O_RDONLY);
    if (fd < 0) {
        plugin_log("Aucun PluginLoader.toml trouvé à %s", PL_CONFIG_PATH);
        return config;
    }

    std::string data;
    char buf[1024];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0 && data.size() < (256 * 1024))
        data.append(buf, (size_t)n);
    close(fd);

    if (data.empty()) {
        plugin_log("PluginLoader.toml vide ou illisible");
        return config;
    }
    plugin_log("Config lue: %zu octets", data.size());

    // BOM UTF-8
    if (data.size() >= 3 && (unsigned char)data[0] == 0xEF &&
        (unsigned char)data[1] == 0xBB && (unsigned char)data[2] == 0xBF)
        data.erase(0, 3);

    PendingPlugin pend;
    bool in_plugin = false;
    size_t pos = 0;

    while (pos <= data.size()) {
        size_t nl = data.find('\n', pos);
        std::string line = data.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        pos = (nl == std::string::npos) ? data.size() + 1 : nl + 1;

        line = toml_trim(toml_strip_comment(line));
        if (line.empty()) continue;

        // [[plugin]]
        if (line.size() >= 4 && line[0] == '[' && line[1] == '[' &&
            line[line.size() - 1] == ']' && line[line.size() - 2] == ']')
        {
            flush_plugin(pend, config);
            pend = PendingPlugin();
            std::string name = toml_trim(line.substr(2, line.size() - 4));
            in_plugin = (name == "plugin");
            pend.active = in_plugin;
            continue;
        }
        // [table] ([loader], etc.) : ignorée
        if (line[0] == '[') {
            flush_plugin(pend, config);
            pend = PendingPlugin();
            in_plugin = false;
            continue;
        }

        if (!in_plugin) continue;

        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = toml_trim(line.substr(0, eq));
        std::string val = toml_trim(line.substr(eq + 1));

        if (key == "title")         pend.title = toml_string(val);
        else if (key == "path")     pend.path  = toml_string(val);
        else if (key == "delay_ms") {
            char *endp = nullptr;
            long v = strtol(val.c_str(), &endp, 10);
            if (endp != val.c_str() && v >= 0 && v <= 3600000) pend.delay_ms = (int)v;
            else plugin_log("Config: delay_ms invalide '%s'", val.c_str());
        }
        else if (key == "inject")   { bool b; if (toml_bool(val, b)) pend.inject  = b; }
        else if (key == "fakelib")  { bool b; if (toml_bool(val, b)) { pend.fakelib = b; pend.has_fakelib = true; } }
    }
    flush_plugin(pend, config);

    plugin_log("Config parsée: %zu jeu(x)", config.games.size());
    return config;
}
