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
    bool        sync_load   = true;
    bool        plt         = false;
    bool        suspend_game = false;
    bool        has_restore = false;
    bool        restore     = true;
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
    prx.sync_load = p.sync_load;
    prx.plt = p.plt;
    prx.suspend_game = p.suspend_game;
    prx.restore_sandbox = p.has_restore ? p.restore : config.default_restore;
    config.games[p.title].push_back(prx);
    plugin_log("Config: [%s] → %s (delay %dms, restore_sandbox=%d, sync_load=%d, method=%s, suspend_game=%d)", p.title.c_str(), prx.path.c_str(), prx.delay_ms, (int)prx.restore_sandbox, (int)prx.sync_load, prx.plt ? "plt" : "ptrace", (int)prx.suspend_game);
}

bool HookGame(UniquePtr<Hijacker> &hijacker, uint64_t alsr_b, const char* prx_path,
              bool auto_load, int frame_delay, uintptr_t* out_stuff_addr)
{
  static uintptr_t first_stuffAddr = 0;
  static bool already_hooked = false;
  static pid_t last_pid = 0;

  plugin_log("[HookGame] PRX: %s | auto_load: %d | frame_delay: %d", prx_path, auto_load, frame_delay);

  pid_t current_pid = hijacker->getPid();
  if (current_pid != last_pid) {
    plugin_log("[HookGame] === NEW GAME PROCESS: PID %d → %d, reset state ===", last_pid, current_pid);
    already_hooked = false;
    first_stuffAddr = 0;
    last_pid = current_pid;
  }

  (void)auto_load;   // seul le shellcode standard est conservé (comme v2.02 en production)
  GameBuilder builder = BUILDER_TEMPLATE;
  size_t shellcode_size = GameBuilder::SHELLCODE_SIZE;

  GameStuff stuff{*hijacker};

  // ── Recuperer scePadReadState depuis libScePad.sprx EN PREMIER ──────────
  UniquePtr<SharedLib> lib = hijacker->getLib("libScePad.sprx");
  stuff.scePadReadState = hijacker->getFunctionAddress(lib.get(), nid::scePadReadState);

  // ── Diagnostic adresses critiques ────────────────────────────────────────
  plugin_log("[HookGame] scePadReadState addr         : 0x%llx", stuff.scePadReadState);
  plugin_log("[HookGame] sceKernelLoadStartModule addr : 0x%llx", stuff.sceKernelLoadStartModule);
  plugin_log("[HookGame] sceKernelDlsym addr           : 0x%llx", stuff.sceKernelDlsym);
  plugin_log("[HookGame] debugout addr                 : 0x%llx", stuff.debugout);

  if (stuff.sceKernelLoadStartModule == 0) {
    plugin_log("[HookGame] FATAL: sceKernelLoadStartModule == 0 ! NID introuvable dans libkernel.");
    plugin_log("[HookGame] module_start NE SERA JAMAIS APPELE.");
    return false;
  }

  if (stuff.scePadReadState == 0) {
    plugin_log("[HookGame] FATAL: scePadReadState introuvable dans libScePad.sprx");
    return false;
  }

  if (stuff.scePadReadState == 0) {
    plugin_log("[HookGame] FAILED: scePadReadState introuvable dans libScePad.sprx");
    return false;
  }

  stuff.ASLR_Base = alsr_b;
  strncpy(stuff.prx_path, prx_path, sizeof(stuff.prx_path) - 1);
  stuff.prx_path[sizeof(stuff.prx_path) - 1] = '\0';
  stuff.frame_delay = frame_delay;
  stuff.frame_counter = 0;
  stuff.loaded = 0;
  stuff.game_hash = 0;

  auto meta = hijacker->getEboot()->getMetaData();
  const auto &plttab = meta->getPltTable();
  auto index = meta->getSymbolTable().getSymbolIndex(nid::scePadReadState);

  plugin_log("[HookGame] PLT symbol index pour scePadReadState: %u", index);

  for (const auto &plt : plttab) {
    if (ELF64_R_SYM(plt.r_info) == index) {
      uintptr_t hook_adr = hijacker->getEboot()->imagebase() + plt.r_offset;

      plugin_log("[HookGame] PLT entry trouvee: r_offset=0x%llx | hook_adr=0x%llx", plt.r_offset, hook_adr);

      if (already_hooked && first_stuffAddr != 0) {
        plugin_log("[HookGame] Hook existant pour PID %d — UPDATE GameStuff @ 0x%llx", current_pid, first_stuffAddr);
        hijacker->write(first_stuffAddr, stuff);
        plugin_log("[HookGame] GameStuff UPDATE OK: %s", stuff.prx_path);
        if (out_stuff_addr) *out_stuff_addr = first_stuffAddr;
        return true;
      }
      
      // ── Check si le PRX est déjà chargé dans le process cible ────────────
      const char *basename = strrchr(prx_path, '/');
      basename = basename ? basename + 1 : prx_path;
      unsigned int existing_handle = 0;
      if (kernel_dynlib_handle(current_pid, basename, &existing_handle) == 0) {
          plugin_log("[HookGame] %s deja charge dans pid %d (handle 0x%x), skip", basename, current_pid, existing_handle);
          if (out_stuff_addr) *out_stuff_addr = 0;
          return true;
      }
      // ─────────────────────────────────────────────────────────────────────

      plugin_log("[HookGame] Creation du PREMIER hook pour PID %d", current_pid);

      // ── DIAG FW8+ : verifier la marge reelle avant d'ecrire quoi que ce soit ──
      // NOTE temporaire : a retirer une fois le vrai probleme confirme/infirme.
      // start()/end() sont deja utilises ailleurs dans ce code (patch_shellcore.hpp),
      // donc on reste sur des methodes confirmees existantes.
      uintptr_t text_start = hijacker->getEboot()->getTextSection()->start();
      uintptr_t text_end   = hijacker->getEboot()->getTextSection()->end();
      plugin_log("[HookGame][DIAG] text section: start=0x%llx end=0x%llx (taille totale: 0x%llx)",
                 text_start, text_end, text_end - text_start);

      auto code = hijacker->getTextAllocator().allocate(shellcode_size);
      auto stuffAddr = hijacker->getDataAllocator().allocate(sizeof(GameStuff));

      plugin_log("[HookGame] Shellcode alloue @ 0x%llx (size: %zu)", code, shellcode_size);
      plugin_log("[HookGame] GameStuff alloue  @ 0x%llx (size: %zu)", stuffAddr, sizeof(GameStuff));
      plugin_log("[HookGame] PLT hook: 0x%llx → shellcode 0x%llx", hook_adr, code);
      plugin_log("[HookGame][DIAG] gap texte carve = 0x%llx (code=0x%llx, text_end=0x%llx) — si negatif ou proche de 0, l'allocateur deborde",
                 text_end - code, code, text_end);

      builder.setExtraStuffAddr(stuffAddr);

      uint8_t shellcode_buffer[256];
      memset(shellcode_buffer, 0, sizeof(shellcode_buffer));
      memcpy(shellcode_buffer, builder.shellcode, shellcode_size);

      hijacker->write(code, shellcode_buffer);
      hijacker->write(stuffAddr, stuff);
      hijacker->write<uintptr_t>(hook_adr, code);

      already_hooked = true;
      first_stuffAddr = stuffAddr;

      if (out_stuff_addr) *out_stuff_addr = stuffAddr;

      plugin_log("[HookGame] SUCCESS: hook installe, shellcode pret");
      plugin_log("[HookGame] NOTE: connected check SUPPRIME (FW10 fix) — chargement des le 1er scePadReadState valide");
      return true;
    }
  }

  plugin_log("[HookGame] FAILED: scePadReadState introuvable dans la PLT table");
  return false;
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
    bool in_loader = false;
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
            in_loader = false;
            pend.active = in_plugin;
            continue;
        }
        // [table] ([loader], etc.) : ignorée
        if (line[0] == '[') {
            flush_plugin(pend, config);
            pend = PendingPlugin();
            in_plugin = false;
            in_loader = (toml_trim(line.substr(1, line.size() - 2)) == "loader");
            continue;
        }

        if (in_loader) {
            size_t leq = line.find('=');
            if (leq != std::string::npos &&
                toml_trim(line.substr(0, leq)) == "default_restore_sandbox") {
                bool b; if (toml_bool(line.substr(leq + 1), b)) config.default_restore = b;
            }
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
        else if (key == "method")   { std::string m = toml_string(val); pend.plt = (m == "plt"); }
        else if (key == "suspend_game") { bool b; if (toml_bool(val, b)) pend.suspend_game = b; }
        else if (key == "sync_load") { bool b; if (toml_bool(val, b)) pend.sync_load = b; }
        else if (key == "restore_sandbox") { bool b; if (toml_bool(val, b)) { pend.restore = b; pend.has_restore = true; } }
        else if (key == "fakelib")  { bool b; if (toml_bool(val, b)) { pend.fakelib = b; pend.has_fakelib = true; } }
    }
    flush_plugin(pend, config);

    plugin_log("Config parsée: %zu jeu(x)", config.games.size());
    return config;
}
