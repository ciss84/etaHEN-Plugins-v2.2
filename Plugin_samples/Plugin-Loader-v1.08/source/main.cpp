#include "utils.hpp"
#include <notify.hpp>
#include <signal.h>
#include <string>
#include <ps5/kernel.h>

#include <dirent.h>
#include <stdarg.h>
#include <sys/event.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>

// ─────────────────────────────────────────────────────────────────────────────
//  Structures / externs from backpork
// ─────────────────────────────────────────────────────────────────────────────

#define IOVEC_ENTRY(x) {x ? (char *)x : 0, x ? strlen(x) + 1 : 0}
#define IOVEC_SIZE(x)  (sizeof(x) / sizeof(struct iovec))

typedef struct app_info {
    uint32_t app_id;
    uint64_t unknown1;
    char     title_id[14];
    char     unknown2[0x3c];
} app_info_t;

extern "C" {
    int sceKernelGetAppInfo(pid_t pid, app_info_t *info);

    // Plugin Loader originals
    int sceSystemServiceGetAppIdOfRunningBigApp();
    int sceSystemServiceGetAppTitleId(int app_id, char *title_id);

    int32_t sceKernelPrepareToSuspendProcess(pid_t pid);
    int32_t sceKernelSuspendProcess(pid_t pid);
    int32_t sceKernelPrepareToResumeProcess(pid_t pid);
    int32_t sceKernelResumeProcess(pid_t pid);

    int _sceApplicationGetAppId(int pid, int *appId);
    int sceSystemServiceKillApp(int, int, int, int);

    int nmount(struct iovec *iov, unsigned int niov, int flags);
    int unmount(const char *path, int flags);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Signal handler / crash reporter
// ─────────────────────────────────────────────────────────────────────────────

void sig_handler(int signo)
{
    printf_notification("Plugin Loader crashed with signal %d    ", signo);
    printBacktraceForCrash();
    exit(-1);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers from backpork: find SceSysCore PID
// ─────────────────────────────────────────────────────────────────────────────

static pid_t find_pid(const char *name)
{
    int      mib[4] = {1, 14, 8, 0};
    pid_t    mypid  = getpid();
    pid_t    pid    = -1;
    size_t   buf_size;
    uint8_t *buf;

    if (sysctl(mib, 4, 0, &buf_size, 0, 0))
        return -1;

    if (!(buf = (uint8_t *)malloc(buf_size)))
        return -1;

    if (sysctl(mib, 4, buf, &buf_size, 0, 0)) {
        free(buf);
        return -1;
    }

    for (uint8_t *ptr = buf; ptr < (buf + buf_size);) {
        int   ki_structsize = *(int *)ptr;
        pid_t ki_pid        = *(pid_t *)&ptr[72];
        char *ki_tdname     = (char *)&ptr[447];
        ptr += ki_structsize;
        if (!strcmp(name, ki_tdname) && ki_pid != mypid)
            pid = ki_pid;
    }

    free(buf);
    return pid;
}

// ─────────────────────────────────────────────────────────────────────────────
//  fakelib / unionfs helpers (backpork)
// ─────────────────────────────────────────────────────────────────────────────

static int mount_unionfs(const char *src, const char *dst)
{
    struct iovec iov[] = {
        IOVEC_ENTRY("fstype"), IOVEC_ENTRY("unionfs"),
        IOVEC_ENTRY("from"),   IOVEC_ENTRY(src),
        IOVEC_ENTRY("fspath"), IOVEC_ENTRY(dst),
    };
    return nmount(iov, IOVEC_SIZE(iov), 0);
}

static int find_highest_sandbox_number(const char *title_id)
{
    char path[PATH_MAX];
    int  highest = -1;

    for (int i = 0; i < 1000; i++) {
        snprintf(path, sizeof(path), "/mnt/sandbox/%s_%03d", title_id, i);
        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
            highest = i;
        else
            break;
    }
    return highest;
}

static char *find_random_folder(const char *title_id, int sandbox_num)
{
    char base[PATH_MAX];
    snprintf(base, sizeof(base), "/mnt/sandbox/%s_%03d", title_id, sandbox_num);

    DIR *dir = opendir(base);
    if (!dir) return nullptr;

    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.') continue;
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s/common/lib", base, entry->d_name);
        struct stat st;
        if (stat(full, &st) == 0 && S_ISDIR(st.st_mode)) {
            closedir(dir);
            plugin_log("[Fakelib] Random folder: %s", entry->d_name);
            return strdup(entry->d_name);
        }
    }
    closedir(dir);
    return nullptr;
}

// Returns heap-allocated mount path on success, nullptr on failure.
static char *try_mount_fakelib(const char *title_id, const char *sandbox_id)
{
    char fakelib_src[PATH_MAX];
    snprintf(fakelib_src, sizeof(fakelib_src),
             "/mnt/sandbox/%s/app0/fakelib", sandbox_id);

    struct stat st;
    if (stat(fakelib_src, &st) != 0) {
        plugin_log("[Fakelib] No fakelib dir in app0 (%s), skipping", sandbox_id);
        return nullptr;
    }

    int  sandbox_num   = find_highest_sandbox_number(title_id);
    if  (sandbox_num < 0) return nullptr;

    char *random_folder = find_random_folder(title_id, sandbox_num);
    if  (!random_folder) return nullptr;

    char *mount_dst = (char *)malloc(PATH_MAX + 1);
    if  (!mount_dst) { free(random_folder); return nullptr; }

    snprintf(mount_dst, PATH_MAX + 1,
             "/mnt/sandbox/%s/%s/common/lib", sandbox_id, random_folder);
    free(random_folder);

    int res = mount_unionfs(fakelib_src, mount_dst);
    if (res != 0) {
        plugin_log("[Fakelib] mount_unionfs failed: %d (errno %d)", res, errno);
        unmount(mount_dst, MNT_FORCE);
        free(mount_dst);
        return nullptr;
    }

    plugin_log("[Fakelib] Mounted %s -> %s", fakelib_src, mount_dst);
    printf_notification("Fakelib mounted for %s     ", title_id);
    return mount_dst;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Wait for a process to exit (kqueue / EVFILT_PROC)
// ─────────────────────────────────────────────────────────────────────────────

static void wait_for_pid_exit(pid_t pid)
{
    int kq = kqueue();
    if (kq == -1) { sleep(3); return; }

    struct kevent kev;
    EV_SET(&kev, pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_CLEAR, NOTE_EXIT, 0, nullptr);

    if (kevent(kq, &kev, 1, nullptr, 0, nullptr) == -1) {
        plugin_log("[Wait] kevent registration failed for pid %d: %s", pid, strerror(errno));
        close(kq);
        sleep(3);
        return;
    }

    plugin_log("[Wait] Watching pid %d for exit...", pid);
    while (1) {
        struct kevent ev;
        int nev = kevent(kq, nullptr, 0, &ev, 1, nullptr);
        if (nev > 0 && (ev.fflags & NOTE_EXIT)) {
            plugin_log("[Wait] pid %d exited", pid);
            break;
        }
        if (nev < 0) break;
    }
    close(kq);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Sandbox cleanup (backpork)
// ─────────────────────────────────────────────────────────────────────────────

static int cleanup_directory(const char *path)
{
    DIR *d = opendir(path);
    if (!d) return -1;

    int           result = 0;
    struct dirent *entry;

    while ((entry = readdir(d))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;

        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", path, entry->d_name);

        struct stat st;
        if (stat(full, &st) != 0) { result = -1; break; }

        if (S_ISDIR(st.st_mode))
            if (cleanup_directory(full) != 0) { result = -1; break; }
    }
    closedir(d);
    if (result == 0) result = rmdir(path);
    return result;
}

static void cleanup_after_game(pid_t pid, const char *sandbox_id, char *fakelib_mount)
{
    if (fakelib_mount) {
        char sandbox_app0[PATH_MAX];
        snprintf(sandbox_app0, sizeof(sandbox_app0),
                 "/mnt/sandbox/%s/app0", sandbox_id);

        int wait_count = 0;
        struct stat st;
        while (stat(sandbox_app0, &st) == 0 && wait_count < 30) {
            sleep(1);
            wait_count++;
        }

        plugin_log("[Cleanup] Unmounting %s", fakelib_mount);
        unmount(fakelib_mount, 0);

        char sandbox_dir[PATH_MAX];
        snprintf(sandbox_dir, sizeof(sandbox_dir), "/mnt/sandbox/%s", sandbox_id);
        plugin_log("[Cleanup] Removing %s", sandbox_dir);
        if (cleanup_directory(sandbox_dir) == 0) {
            plugin_log("[Cleanup] Sandbox removed");
            printf_notification("Sandbox %s cleaned up     ", sandbox_id);
        } else {
            plugin_log("[Cleanup] Failed to remove sandbox: %s", strerror(errno));
        }
        free(fakelib_mount);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Core injection: PLT hook (Plugin Loader) + optional fakelib (backpork)
// ─────────────────────────────────────────────────────────────────────────────

static bool IsProcessRunning(pid_t pid)
{
    int bappid = 0;
    return (_sceApplicationGetAppId(pid, &bappid) >= 0);
}

uintptr_t kernel_base = 0;

// Returns sandbox_id built from title_id + highest sandbox number.
// sandbox_id must be at least 32 bytes.
static bool resolve_sandbox_id(const char *title_id, char *sandbox_id, size_t sandbox_id_size)
{
    // Retry until sandbox directory appears (game creates it right after exec).
    int sandbox_num = -1;
    for (int attempt = 0; attempt < 20 && sandbox_num < 0; attempt++) {
        sandbox_num = find_highest_sandbox_number(title_id);
        if (sandbox_num < 0)
            usleep(50000); // 50ms
    }

    if (sandbox_num < 0) {
        plugin_log("[Sandbox] No sandbox found for %s after 1s", title_id);
        return false;
    }

    snprintf(sandbox_id, sandbox_id_size, "%s_%03d", title_id, sandbox_num);
    plugin_log("[Sandbox] Resolved: %s", sandbox_id);
    return true;
}

static void inject_into_game(pid_t pid, const char *title_id,
                              const std::vector<PRXConfig> &prx_list)
{
    plugin_log("========================================");
    plugin_log("Injecting into %s (pid %d)", title_id, pid);
    plugin_log("========================================");

    // ── 1. FAKELIB FIRST — must be mounted before game loads its libs ─────
    //    The dynamic linker runs right after exec, so we have very little time.
    char sandbox_id[32] = {};
    char *fakelib_mount = nullptr;

    if (resolve_sandbox_id(title_id, sandbox_id, sizeof(sandbox_id))) {
        // Wait for app0/fakelib to be visible (sandbox is being set up)
        char fakelib_check[PATH_MAX];
        snprintf(fakelib_check, sizeof(fakelib_check),
                 "/mnt/sandbox/%s/app0/fakelib", sandbox_id);

        struct stat st;
        for (int t = 0; t < 30 && stat(fakelib_check, &st) != 0; t++)
            usleep(50000); // up to 1.5s

        if (stat(fakelib_check, &st) == 0) {
            plugin_log("[Fakelib] app0/fakelib found, mounting NOW");
            fakelib_mount = try_mount_fakelib(title_id, sandbox_id);
            if (!fakelib_mount)
                plugin_log("[Fakelib] mount failed");
        } else {
            plugin_log("[Fakelib] No app0/fakelib for %s, skipping", title_id);
        }
    }

    // ── 2. Wait a bit for process to reach a hookable state ───────────────
    plugin_log("[PLT] Waiting for process initialization...");
    int alive = 0;
    for (int i = 0; i < 10; i++) {
        usleep(100000); // 100ms × 10 = 1s
        if (IsProcessRunning(pid)) alive++;
    }
    plugin_log("[PLT] Process alive: %d/10 checks", alive);

    // ── 3. PLT Hook (Plugin Loader) ───────────────────────────────────────
    UniquePtr<Hijacker> hijacker = Hijacker::getHijacker(pid);
    if (!hijacker) {
        plugin_log("[PLT] First Hijacker attempt failed, retrying in 1s...");
        sleep(1);
        hijacker = Hijacker::getHijacker(pid);
    }

    int success_count = 0;

    if (hijacker) {
        uint64_t text_base = hijacker->getEboot()->imagebase();
        plugin_log("[PLT] Hijacker OK - text_base: 0x%llx", text_base);

        // Suspend before injection
        sceKernelPrepareToSuspendProcess(pid);
        sceKernelSuspendProcess(pid);
        usleep(500000);

        for (const auto &prx : prx_list) {
            plugin_log("[PLT] Injecting: %s (delay: %d)", prx.path.c_str(), prx.frame_delay);

            if (HookGame(hijacker, text_base, prx.path.c_str(), false, prx.frame_delay)) {
                plugin_log("[PLT] SUCCESS: %s", prx.path.c_str());
                success_count++;

                sceKernelPrepareToResumeProcess(pid);
                sceKernelResumeProcess(pid);

                if (&prx != &prx_list.back()) {
                    sleep(3);
                    sceKernelPrepareToSuspendProcess(pid);
                    sceKernelSuspendProcess(pid);
                    usleep(500000);
                }
            } else {
                plugin_log("[PLT] FAILED: %s", prx.path.c_str());
            }
        }

        // Final resume
        usleep(500000);
        sceKernelPrepareToResumeProcess(pid);
        sceKernelResumeProcess(pid);

        plugin_log("[PLT] %d/%zu PRX injected", success_count, prx_list.size());
        printf_notification("%d/%zu PRX injected into %s     \nFakelib: %s",
                            success_count, prx_list.size(), title_id,
                            fakelib_mount ? "OK" : "none");
    } else {
        plugin_log("[PLT] FAILED to create Hijacker for pid %d", pid);
        printf_notification("PLT hook failed for %s     \nFakelib: %s",
                            title_id, fakelib_mount ? "OK" : "none");
    }

    // ── 4. Wait for game exit then cleanup fakelib ────────────────────────
    plugin_log("[Wait] Waiting for game (pid %d) to exit...", pid);
    wait_for_pid_exit(pid);

    if (fakelib_mount)
        cleanup_after_game(pid, sandbox_id, fakelib_mount);

    plugin_log("Game %s closed - ready for next launch", title_id);
}

// ─────────────────────────────────────────────────────────────────────────────
//  main: kqueue monitoring on SceSysCore (backpork approach)
// ─────────────────────────────────────────────────────────────────────────────

int main()
{
    plugin_log("=== PLUGIN LOADER v1.08 + BACKPORK ===");

    payload_args_t *args = payload_get_args();
    kernel_base = args->kdata_base_addr;

    // Signal handlers
    struct sigaction sa{};
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    for (int i = 0; i < 12; i++)
        sigaction(i, &sa, nullptr);

    // ── Find SceSysCore.elf ───────────────────────────────────────────────
    pid_t syscore_pid = find_pid("SceSysCore.elf");
    if (syscore_pid == -1) {
        plugin_log("ERROR: SceSysCore.elf not found");
        printf_notification("Plugin Loader: SceSysCore not found!     ");
        return -1;
    }
    plugin_log("SceSysCore.elf pid: %d", syscore_pid);

    // ── kqueue setup on SceSysCore ────────────────────────────────────────
    int kq = kqueue();
    if (kq == -1) { perror("kqueue"); return -1; }

    struct kevent kev;
    EV_SET(&kev, syscore_pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_CLEAR,
           NOTE_FORK | NOTE_EXEC | NOTE_TRACK, 0, nullptr);

    if (kevent(kq, &kev, 1, nullptr, 0, nullptr) == -1) {
        perror("kevent setup");
        close(kq);
        return -1;
    }

    printf_notification("Plugin Loader v1.08 started     \nBy @84Ciss ");
    plugin_log("Monitoring SceSysCore.elf (pid %d) for game launches...", syscore_pid);

    pid_t child_pid = -1;

    // ── Main event loop ───────────────────────────────────────────────────
    while (1)
    {
        struct kevent ev;
        int nev = kevent(kq, nullptr, 0, &ev, 1, nullptr);

        if (nev < 0) { plugin_log("kevent error: %s", strerror(errno)); continue; }
        if (nev == 0) continue;

        // Child forked → remember its pid
        if (ev.fflags & NOTE_CHILD)
            child_pid = (pid_t)ev.ident;

        // Child exec'd → it's a new process, check if it's a game
        if ((ev.fflags & NOTE_EXEC) && child_pid != -1 && (pid_t)ev.ident == child_pid)
        {
            app_info_t appinfo{};
            if (sceKernelGetAppInfo(child_pid, &appinfo) != 0) {
                plugin_log("sceKernelGetAppInfo failed for pid %d", child_pid);
                child_pid = -1;
                continue;
            }

            // title_id is at most 9 chars (e.g. PPSA12345)
            char title_id[10] = {};
            memcpy(title_id, appinfo.title_id, 9);

            if (strncmp(title_id, "PPSA", 4) != 0 &&
                strncmp(title_id, "CUSA", 4) != 0 &&
                strncmp(title_id, "SCUS", 4) != 0)
            {
                child_pid = -1;
                continue;
            }

            plugin_log("Game detected: %s (pid %d)", title_id, child_pid);

            // Load config fresh every time
            GameInjectorConfig config = parse_injector_config();
            auto it = config.games.find(std::string(title_id));

            if (it == config.games.end()) {
                plugin_log("No PLT config for %s - fakelib only", title_id);

                // Mount fakelib ASAP even without PRX config
                char sid[32] = {};
                char *fml = nullptr;
                if (resolve_sandbox_id(title_id, sid, sizeof(sid))) {
                    char fakelib_check[PATH_MAX];
                    snprintf(fakelib_check, sizeof(fakelib_check),
                             "/mnt/sandbox/%s/app0/fakelib", sid);
                    struct stat st2;
                    for (int t = 0; t < 30 && stat(fakelib_check, &st2) != 0; t++)
                        usleep(50000);
                    if (stat(fakelib_check, &st2) == 0)
                        fml = try_mount_fakelib(title_id, sid);
                }

                pid_t game_pid = child_pid;
                child_pid = -1;
                if (fml) {
                    wait_for_pid_exit(game_pid);
                    cleanup_after_game(game_pid, sid, fml);
                }
                continue;
            }

            // We have PRX config → full injection
            pid_t game_pid = child_pid;
            child_pid = -1;

            inject_into_game(game_pid, title_id, it->second);
        }
    }

    close(kq);
    return 0;
}
