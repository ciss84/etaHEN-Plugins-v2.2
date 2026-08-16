#include "utils.hpp"
#include <notify.hpp>
#include <signal.h>
#include <string>
#include <ps5/kernel.h>

#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

// ─────────────────────────────────────────────────────────────────────────────
//  Externs
// ─────────────────────────────────────────────────────────────────────────────

#define IOVEC_ENTRY(x) {x ? (char *)x : 0, x ? strlen(x) + 1 : 0}
#define IOVEC_SIZE(x)  (sizeof(x) / sizeof(struct iovec))

extern "C" {
    int sceSystemServiceGetAppIdOfRunningBigApp();
    int sceSystemServiceGetAppTitleId(int app_id, char *title_id);

    int nmount(struct iovec *iov, unsigned int niov, int flags);
    int unmount(const char *path, int flags);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Signal handler
// ─────────────────────────────────────────────────────────────────────────────

void sig_handler(int signo)
{
    printf_notification("Plugin Loader crashed: signal %d    ", signo);
    exit(-1);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Game detection — porté depuis Injector (sceSystemServiceGetAppIdOfRunningBigApp)
// ─────────────────────────────────────────────────────────────────────────────

static bool Get_Running_App_TID(std::string &title_id, int &bappid)
{
    char tid[255] = {};
    bappid = sceSystemServiceGetAppIdOfRunningBigApp();
    if (bappid < 0)
        return false;
    if (sceSystemServiceGetAppTitleId(bappid, tid) != 0)
        return false;
    title_id = std::string(tid);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  TCP send — porté depuis Injector send_injector_data()
//  Envoie un payload binaire au daemon etaHEN sur 127.0.0.1:9033
//  Header = nom du process (proc_name, MAX_PROC_NAME bytes)
//  Body   = données binaires (PRX ou ELF)
// ─────────────────────────────────────────────────────────────────────────────

#define MAX_PROC_NAME 0x100
#define INJECTOR_PORT 9033

static int send_injector_data(const char *proc_name,
                               const uint8_t *data, size_t data_size)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        plugin_log("[TCP] socket() failed");
        return -1;
    }

    struct sockaddr_in addr = {};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(INJECTOR_PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        plugin_log("[TCP] connect() failed — etaHEN daemon actif ?");
        close(sock);
        return -1;
    }

    // Header : proc_name padded à MAX_PROC_NAME bytes
    uint8_t header[MAX_PROC_NAME] = {};
    size_t  name_len = strlen(proc_name);
    if (name_len > MAX_PROC_NAME) name_len = MAX_PROC_NAME;
    memcpy(header, proc_name, name_len);

    if (send(sock, header, MAX_PROC_NAME, 0) != MAX_PROC_NAME) {
        plugin_log("[TCP] send header failed");
        close(sock);
        return -1;
    }

    ssize_t sent = send(sock, data, data_size, 0);
    if (sent < 0 || (size_t)sent != data_size) {
        plugin_log("[TCP] send data failed");
        close(sock);
        return -1;
    }

    plugin_log("[TCP] Sent %zu bytes to 127.0.0.1:%d (proc: %s)",
               MAX_PROC_NAME + data_size, INJECTOR_PORT, proc_name);
    close(sock);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Injection d'un PRX via TCP — lit le fichier et envoie à etaHEN
// ─────────────────────────────────────────────────────────────────────────────

static bool inject_prx_tcp(const char *title_id, const char *prx_path)
{
    struct stat st;
    if (stat(prx_path, &st) < 0) {
        plugin_log("[TCP] File not found: %s", prx_path);
        return false;
    }

    FILE *f = fopen(prx_path, "rb");
    if (!f) {
        plugin_log("[TCP] fopen failed: %s", prx_path);
        return false;
    }

    uint8_t *buf = (uint8_t *)malloc(st.st_size);
    if (!buf) { fclose(f); return false; }

    fread(buf, 1, st.st_size, f);
    fclose(f);

    plugin_log("[TCP] Injecting %s -> %s", prx_path, title_id);
    int ret = send_injector_data("eboot.bin", buf, st.st_size);
    free(buf);

    return ret == 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Envoie tous les payloads pour un title_id
// ─────────────────────────────────────────────────────────────────────────────

static void send_all_payloads(const char *title_id, const GameInjectorConfig &config)
{
    plugin_log("========================================");
    plugin_log("Injecting into %s", title_id);
    plugin_log("========================================");

    int ok = 0, total = 0;

    // Section [default] si elle existe
    auto def = config.games.find("default");
    if (def != config.games.end()) {
        for (const auto &prx : def->second) {
            total++;
            if (inject_prx_tcp(title_id, prx.path.c_str())) ok++;
        }
    }

    // Section [TITLE_ID]
    auto it = config.games.find(std::string(title_id));
    if (it != config.games.end()) {
        for (const auto &prx : it->second) {
            total++;
            if (inject_prx_tcp(title_id, prx.path.c_str())) ok++;
        }
    }

    if (total == 0) {
        plugin_log("[TCP] No config for %s", title_id);
        return;
    }

    plugin_log("[TCP] %d/%d injected into %s", ok, total, title_id);
    printf_notification("%d/%d injected into %s     \nBy @84Ciss", ok, total, title_id);
}

// ─────────────────────────────────────────────────────────────────────────────
//  main
// ─────────────────────────────────────────────────────────────────────────────

uintptr_t kernel_base = 0;

int main()
{
    plugin_log("=== PLUGIN LOADER v1.17 [Injector Mode] ===");

    payload_args_t *args = payload_get_args();
    kernel_base = args->kdata_base_addr;

    // ── FW detection ─────────────────────────────────────────────────────────
    uint32_t fw       = kernel_get_fw_version();
    uint32_t fw_major = (fw >> 24) & 0xFF;
    uint32_t fw_minor = (fw >> 16) & 0xFF;
    plugin_log("FW: 0x%08x (%x.%02x)", fw, fw_major, fw_minor);

    // ── Signal handler ────────────────────────────────────────────────────────
    struct sigaction sa{};
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    for (int i = 0; i < 12; i++)
        sigaction(i, &sa, nullptr);

    // ── patchShellCore ────────────────────────────────────────────────────────
    // DISABLED FOR TEST — remettre pour prod
    //if (!patchShellCore())
    //    plugin_log("[SC_PATCH] echec patch SceShellCore");
    //usleep(750000);

    printf_notification("Prx-Loader [TCP] FW: %x.%02x     \nVer:1.17 By @84Ciss", fw_major, fw_minor);

    // ── Main loop — poll comme l'Injector ────────────────────────────────────
    std::string tid;
    int bappid, last_bappid = -1;
    bool just_started = true;

    while (true)
    {
        if (Get_Running_App_TID(tid, bappid))
        {
            if (bappid != last_bappid &&
                (tid.rfind("PPSA", 0) == 0 ||
                 tid.rfind("CUSA", 0) == 0 ||
                 tid.rfind("SCUS", 0) == 0))
            {
                plugin_log("Game detected: %s (bappid=%d)", tid.c_str(), bappid);
                printf_notification("Game detected: %s\\nInjecting in %ds...", tid.c_str(), just_started ? 1 : 10);

                sleep(just_started ? 1 : 10);

                // Vérifier que le jeu tourne encore
                std::string tid2;
                int bappid2;
                if (!Get_Running_App_TID(tid2, bappid2) || bappid != bappid2) {
                    plugin_log("Game closed before injection");
                    just_started = false;
                    continue;
                }

                GameInjectorConfig config = parse_injector_config();
                send_all_payloads(tid.c_str(), config);
                last_bappid = bappid;
            }
        }

        just_started = false;
        sleep(5);
    }

    return 0;
}
