#include "utils.hpp"
#include <notify.hpp>
#include <signal.h>
#include <string>

#include <dirent.h>
#include <errno.h>
#include <machine/reg.h>
#include <stdarg.h>
#include <sys/_iovec.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <ps5/kernel.h>
#include <ps5/payload.h>

// ─────────────────────────────────────────────────────────────────────────────
//  Externs
// ─────────────────────────────────────────────────────────────────────────────

typedef struct {
    uint32_t app_id;
    uint64_t unknown1;
    char     title_id[16];
    char     unknown2[0x40];
} app_info_t;

#define IOVEC_ENTRY(x) {x ? (char *)x : 0, x ? strlen(x) + 1 : 0}
#define IOVEC_SIZE(x)  (sizeof(x) / sizeof(struct iovec))

extern "C" {
    int sceSystemServiceGetAppIdOfRunningBigApp();
    int sceSystemServiceGetAppTitleId(int app_id, char *title_id);
    int sceKernelGetAppInfo(pid_t pid, app_info_t *info);
    int nmount(struct iovec *iov, unsigned int niov, int flags);
    int unmount(const char *path, int flags);
}

#define NID_LOADMOD  "wzvqT4UqKX8"
#define NID_SYSCALL  "HoLVWNanBBc"
#define AUTHID_SYSTEM   0x4801000000000013ULL
#define AUTHID_DEBUGGER 0x4800000000010003ULL
#define SHELLCODE_FN_OFFSET 14

static const uint8_t k_shellcode[] = {
    0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xE4, 0xF0,
    0x48, 0x83, 0xEC, 0x28, 0x49, 0xBF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x31, 0xF6, 0x31, 0xD2, 0x31, 0xC9,
    0x45, 0x31, 0xC0, 0x45, 0x31, 0xC9,
    0x41, 0xFF, 0xD7,
    0x48, 0x89, 0xEC, 0x5D, 0xCC
};

// ─────────────────────────────────────────────────────────────────────────────
//  Signal handler
// ─────────────────────────────────────────────────────────────────────────────

void sig_handler(int signo)
{
    printf_notification("Plugin Loader crashed: signal %d    ", signo);
    exit(-1);
}

// ─────────────────────────────────────────────────────────────────────────────
//  ptrace helpers — portés depuis ps5-plugin-loader
// ─────────────────────────────────────────────────────────────────────────────

static int sys_ptrace(int request, pid_t pid, caddr_t addr, int data)
{
    pid_t    mypid  = getpid();
    uint64_t authid = kernel_get_ucred_authid(mypid);
    if (!authid) return -1;
    kernel_set_ucred_authid(mypid, AUTHID_DEBUGGER);
    int ret = (int)syscall(SYS_ptrace, request, pid, addr, data);
    int err = errno;
    kernel_set_ucred_authid(mypid, authid);
    errno = err;
    return ret;
}

static int waitpid_timeout(pid_t pid, int *status, int timeout_ms)
{
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (true) {
        pid_t res = waitpid(pid, status, WNOHANG);
        if (res == pid) return 1;
        if (res < 0)   return -1;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000
                     + (now.tv_nsec - start.tv_nsec) / 1000000;
        if (elapsed >= timeout_ms) return 0;
        usleep(10000);
    }
}

static int pt_attach(pid_t pid)
{
    int retries = 5;
    while (retries-- > 0) {
        if (sys_ptrace(PT_ATTACH, pid, 0, 0) == 0) {
            int status = 0;
            if (waitpid_timeout(pid, &status, 2000) > 0)
                return 0;
            sys_ptrace(PT_DETACH, pid, 0, 0);
        }
        if (errno == ESRCH) { usleep(500000); continue; }
        break;
    }
    return -1;
}

static int pt_detach(pid_t pid) { return sys_ptrace(PT_DETACH, pid, 0, 0); }

static int pt_getregs(pid_t pid, struct reg *r)
{ return sys_ptrace(PT_GETREGS, pid, (caddr_t)r, 0); }

static int pt_setregs(pid_t pid, const struct reg *r)
{ return sys_ptrace(PT_SETREGS, pid, (caddr_t)r, 0); }

static int pt_copyin(pid_t pid, const void *buf, intptr_t addr, size_t len)
{
    struct ptrace_io_desc iod = {
        .piod_op   = PIOD_WRITE_D,
        .piod_offs = (void *)addr,
        .piod_addr = (void *)buf,
        .piod_len  = len
    };
    return sys_ptrace(PT_IO, pid, (caddr_t)&iod, 0);
}

static intptr_t pt_resolve(pid_t pid, const char *nid)
{
    intptr_t a = kernel_dynlib_resolve(pid, 0x1, nid);
    if (a) return a;
    return kernel_dynlib_resolve(pid, 0x2001, nid);
}

static long pt_syscall(pid_t pid, int sysno, ...)
{
    intptr_t addr = pt_resolve(pid, NID_SYSCALL);
    if (!addr) return -1;
    addr += 0xA;
    struct reg jmp, bak;
    if (pt_getregs(pid, &bak)) return -1;
    memcpy(&jmp, &bak, sizeof(jmp));
    jmp.r_rip = addr;
    jmp.r_rax = (uint64_t)sysno;
    va_list ap; va_start(ap, sysno);
    jmp.r_rdi = va_arg(ap, uint64_t);
    jmp.r_rsi = va_arg(ap, uint64_t);
    jmp.r_rdx = va_arg(ap, uint64_t);
    jmp.r_r10 = va_arg(ap, uint64_t);
    jmp.r_r8  = va_arg(ap, uint64_t);
    jmp.r_r9  = va_arg(ap, uint64_t);
    va_end(ap);
    if (pt_setregs(pid, &jmp)) return -1;
    int max = 10000;
    while (jmp.r_rsp <= bak.r_rsp && max-- > 0) {
        if (sys_ptrace(PT_STEP, pid, (caddr_t)1, 0)) return -1;
        if (waitpid_timeout(pid, NULL, 1000) <= 0)   return -1;
        if (pt_getregs(pid, &jmp))                    return -1;
    }
    pt_setregs(pid, &bak);
    return (long)jmp.r_rax;
}

static intptr_t pt_mmap(pid_t pid, intptr_t addr, size_t len,
                         int prot, int flags, int fd, off_t off)
{ return pt_syscall(pid, SYS_mmap, (uint64_t)addr, (uint64_t)len,
    (uint64_t)prot, (uint64_t)flags, (uint64_t)fd, (uint64_t)off); }

static int pt_munmap(pid_t pid, intptr_t addr, size_t len)
{ return (int)pt_syscall(pid, SYS_munmap, (uint64_t)addr, (uint64_t)len); }

static long pt_call_continue(pid_t pid, intptr_t addr, ...)
{
    struct reg jmp, bak;
    if (pt_getregs(pid, &bak)) return -1;
    memcpy(&jmp, &bak, sizeof(jmp));
    jmp.r_rip = addr;
    va_list ap; va_start(ap, addr);
    jmp.r_rdi = va_arg(ap, uint64_t);
    jmp.r_rsi = va_arg(ap, uint64_t);
    jmp.r_rdx = va_arg(ap, uint64_t);
    jmp.r_rcx = va_arg(ap, uint64_t);
    jmp.r_r8  = va_arg(ap, uint64_t);
    jmp.r_r9  = va_arg(ap, uint64_t);
    va_end(ap);
    if (pt_setregs(pid, &jmp)) return -1;
    int status = 0;
    sys_ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
    if (waitpid_timeout(pid, &status, 5000) <= 0) {
        pt_setregs(pid, &bak); return -1;
    }
    if (pt_getregs(pid, &jmp)) return -1;
    plugin_log("[PT] RIP=0x%llx RAX=0x%llx",
               (unsigned long long)jmp.r_rip, (unsigned long long)jmp.r_rax);
    pt_setregs(pid, &bak);
    return (long)jmp.r_rax;
}

// ─────────────────────────────────────────────────────────────────────────────
//  jb_pid — jailbreak un process via kernel (pas de patchShellCore)
// ─────────────────────────────────────────────────────────────────────────────

static int jb_pid(pid_t pid)
{
    intptr_t rv    = kernel_get_root_vnode();
    intptr_t ucred = kernel_get_proc_ucred(pid);
    intptr_t fd    = kernel_get_proc_filedesc(pid);

    plugin_log("[JB] pid=%d rv=0x%llx ucred=0x%llx fd=0x%llx",
               pid, (unsigned long long)rv,
               (unsigned long long)ucred,
               (unsigned long long)fd);

    if (!rv || !ucred || !fd) {
        plugin_log("[JB] missing kernel pointers");
        return -1;
    }

    const uint32_t zero   = 0;
    const int64_t  caps   = -1LL;
    const uint64_t authid = AUTHID_SYSTEM;
    const uint8_t  attr   = 0x80;

    #define KW(src, off, len) \
        if (kernel_copyin(src, ucred + (off), len) < 0) { \
            plugin_log("[JB] copyin failed off=0x%x", (off)); return -1; }

    KW(&zero,   0x04, 4)  KW(&zero,   0x08, 4)
    KW(&zero,   0x0C, 4)  KW(&zero,   0x10, 4)
    KW(&zero,   0x14, 4)  KW(&zero,   0x18, 4)
    KW(&authid, 0x58, 8)  KW(&caps,   0x60, 8)
    KW(&caps,   0x68, 8)  KW(&attr,   0x83, 1)
    #undef KW

    kernel_set_proc_rootdir(pid, rv);
    kernel_set_proc_jaildir(pid, rv);
    plugin_log("[JB] OK pid=%d", pid);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  inject_prx_attached — ptrace + mmap + shellcode INT3
// ─────────────────────────────────────────────────────────────────────────────

static long inject_prx_attached(pid_t pid, const char *prx_path)
{
    plugin_log("[INJ] pid=%d path=%s", pid, prx_path);
    if (access(prx_path, R_OK) != 0) {
        plugin_log("[INJ] file not accessible: %s", prx_path);
        return -1;
    }
    const intptr_t fn = pt_resolve(pid, NID_LOADMOD);
    if (!fn) { plugin_log("[INJ] NID_LOADMOD not resolved"); return -1; }

    const intptr_t rw_page = pt_mmap(pid, 0, 0x4000,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (rw_page == (intptr_t)-1 || rw_page == 0) {
        plugin_log("[INJ] pt_mmap failed errno=%d", errno); return -1;
    }

    const intptr_t remote_path = rw_page;
    const intptr_t remote_sc   = rw_page + 0x1000;
    long mod = -1;

    do {
        if (pt_copyin(pid, prx_path, remote_path, strlen(prx_path) + 1) < 0) break;

        uint8_t sc[sizeof(k_shellcode)];
        memcpy(sc, k_shellcode, sizeof(sc));
        memcpy(sc + SHELLCODE_FN_OFFSET, &fn, sizeof(fn));
        if (pt_copyin(pid, sc, remote_sc, sizeof(sc)) < 0) break;

        if (kernel_mprotect(pid, remote_sc, 0x1000,
                            PROT_READ | PROT_WRITE | PROT_EXEC) != 0) break;

        mod = pt_call_continue(pid, remote_sc,
                               (uint64_t)remote_path,
                               0ULL, 0ULL, 0ULL, 0ULL, 0ULL);

        kernel_mprotect(pid, remote_sc, 0x1000, PROT_READ | PROT_WRITE);
    } while (0);

    pt_munmap(pid, rw_page, 0x4000);
    plugin_log("[INJ] modid=%d", (int32_t)mod);
    return mod;
}

// ─────────────────────────────────────────────────────────────────────────────
//  find_pid_by_title
// ─────────────────────────────────────────────────────────────────────────────

static pid_t find_pid_by_title(const char *title_id)
{
    int    mib[4] = {1, 14, 8, 0};
    size_t sz = 0;
    sysctl(mib, 4, NULL, &sz, NULL, 0);
    uint8_t *buf = (uint8_t *)malloc(sz);
    if (!buf) return -1;
    if (sysctl(mib, 4, buf, &sz, NULL, 0) < 0) { free(buf); return -1; }
    pid_t self = getpid(), found = -1;
    for (uint8_t *p = buf; p + 4 <= buf + sz;) {
        int elen = *(int *)p;
        if (elen <= 0) break;
        pid_t pid = *(pid_t *)(p + 72);
        p += elen;
        if (pid <= 1 || pid == self) continue;
        app_info_t info = {};
        if (sceKernelGetAppInfo(pid, &info) == 0 &&
            strncmp(info.title_id, title_id, 9) == 0) {
            found = pid; break;
        }
    }
    free(buf);
    plugin_log("[PID] [%s] -> %d", title_id, (int)found);
    return found;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Fakelib / unionfs — identique v1.17
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
    char path[PATH_MAX]; int highest = -1;
    for (int i = 0; i < 1000; i++) {
        snprintf(path, sizeof(path), "/mnt/sandbox/%s_%03d", title_id, i);
        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) highest = i;
        else break;
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
            closedir(dir); return strdup(entry->d_name);
        }
    }
    closedir(dir); return nullptr;
}

static bool resolve_sandbox_id(const char *title_id, char *sandbox_id, size_t size)
{
    int n = -1;
    for (int i = 0; i < 20 && n < 0; i++) {
        n = find_highest_sandbox_number(title_id);
        if (n < 0) usleep(50000);
    }
    if (n < 0) return false;
    snprintf(sandbox_id, size, "%s_%03d", title_id, n);
    return true;
}

static char *try_mount_fakelib(const char *title_id, const char *sandbox_id)
{
    char src[PATH_MAX];
    snprintf(src, sizeof(src), "/mnt/sandbox/%s/app0/fakelib", sandbox_id);
    struct stat st;
    if (stat(src, &st) != 0) return nullptr;
    int n = find_highest_sandbox_number(title_id);
    if (n < 0) return nullptr;
    char *rf = find_random_folder(title_id, n);
    if (!rf) return nullptr;
    char *dst = (char *)malloc(PATH_MAX + 1);
    if (!dst) { free(rf); return nullptr; }
    snprintf(dst, PATH_MAX + 1, "/mnt/sandbox/%s/%s/common/lib", sandbox_id, rf);
    free(rf);
    if (mount_unionfs(src, dst) != 0) {
        unmount(dst, MNT_FORCE); free(dst); return nullptr;
    }
    plugin_log("[Fakelib] Mounted %s -> %s", src, dst);
    printf_notification("Fakelib mounted for %s     ", title_id);
    return dst;
}

static void wait_for_pid_exit(pid_t pid)
{
    int kq = kqueue();
    if (kq == -1) { sleep(3); return; }
    struct kevent kev;
    EV_SET(&kev, pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_CLEAR,
           NOTE_EXIT, 0, nullptr);
    if (kevent(kq, &kev, 1, nullptr, 0, nullptr) == -1) {
        close(kq); sleep(3); return;
    }
    while (1) {
        struct kevent ev;
        int nev = kevent(kq, nullptr, 0, &ev, 1, nullptr);
        if (nev > 0 && (ev.fflags & NOTE_EXIT)) break;
        if (nev < 0) break;
    }
    close(kq);
}

static int cleanup_directory(const char *path)
{
    DIR *d = opendir(path);
    if (!d) return -1;
    int result = 0;
    struct dirent *entry;
    while ((entry = readdir(d))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
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
    if (!fakelib_mount) return;
    char app0[PATH_MAX];
    snprintf(app0, sizeof(app0), "/mnt/sandbox/%s/app0", sandbox_id);
    int wc = 0; struct stat st;
    while (stat(app0, &st) == 0 && wc < 30) { sleep(1); wc++; }
    unmount(fakelib_mount, 0);
    char sandbox_dir[PATH_MAX];
    snprintf(sandbox_dir, sizeof(sandbox_dir), "/mnt/sandbox/%s", sandbox_id);
    if (cleanup_directory(sandbox_dir) == 0)
        printf_notification("Sandbox %s cleaned up     ", sandbox_id);
    free(fakelib_mount);
}

// ─────────────────────────────────────────────────────────────────────────────
//  inject_into_game — fakelib + jb_pid + inject_prx_attached
// ─────────────────────────────────────────────────────────────────────────────

static void inject_into_game(pid_t pid, const char *title_id,
                              const std::vector<PRXConfig> &prx_list,
                              const GameInjectorConfig &config)
{
    plugin_log("=== Injecting into %s (pid %d) ===", title_id, pid);

    int delay_sec = prx_list.empty() ? 5 : prx_list[0].frame_delay / 60;
    if (delay_sec < 1) delay_sec = 1;

    // ── Fakelib ───────────────────────────────────────────────────────────────
    char sandbox_id[32] = {};
    char *fakelib_mount = nullptr;
    auto fml_cfg   = config.fakelib_enabled.find(std::string(title_id));
    bool fml_wanted = (strncmp(title_id, "PPSA", 4) == 0) &&
                      (fml_cfg == config.fakelib_enabled.end() || fml_cfg->second);
    if (fml_wanted && resolve_sandbox_id(title_id, sandbox_id, sizeof(sandbox_id))) {
        char fakelib_check[PATH_MAX];
        snprintf(fakelib_check, sizeof(fakelib_check),
                 "/mnt/sandbox/%s/app0/fakelib", sandbox_id);
        struct stat st;
        for (int t = 0; t < 30 && stat(fakelib_check, &st) != 0; t++)
            usleep(50000);
        if (stat(fakelib_check, &st) == 0)
            fakelib_mount = try_mount_fakelib(title_id, sandbox_id);
    }

    // ── Délai post-spawn ──────────────────────────────────────────────────────
    plugin_log("[INJ] waiting %ds before inject...", delay_sec);
    printf_notification("ploader: [%s]\nInject dans %ds...", title_id, delay_sec);
    sleep(delay_sec);

    // ── ptrace + jb_pid + inject ──────────────────────────────────────────────
    if (pt_attach(pid) < 0) {
        plugin_log("[INJ] pt_attach failed");
        if (fakelib_mount) { unmount(fakelib_mount, MNT_FORCE); free(fakelib_mount); }
        return;
    }

    if (jb_pid(pid) != 0) {
        plugin_log("[INJ] jb_pid failed");
        pt_detach(pid);
        if (fakelib_mount) { unmount(fakelib_mount, MNT_FORCE); free(fakelib_mount); }
        return;
    }

    int ok = 0;
    for (const auto &prx : prx_list) {
        long    ret = inject_prx_attached(pid, prx.path.c_str());
        int32_t rc  = (int32_t)ret;
        if (rc > 0)       { ok++; plugin_log("[INJ] OK modid=%d %s", rc, prx.path.c_str()); }
        else if (rc == 0) { ok++; plugin_log("[INJ] already loaded? %s", prx.path.c_str()); }
        else              { plugin_log("[INJ] FAILED 0x%08x %s", (uint32_t)rc, prx.path.c_str()); }
    }

    pt_detach(pid);

    plugin_log("[INJ] %d/%zu done", ok, prx_list.size());
    printf_notification("ploader: %d/%zu injected [%s]%s     \nBy @84Ciss",
                        ok, prx_list.size(), title_id,
                        fakelib_mount ? "\nFakelib: OK" : "");

    if (fakelib_mount) {
        wait_for_pid_exit(pid);
        cleanup_after_game(pid, sandbox_id, fakelib_mount);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  main
// ─────────────────────────────────────────────────────────────────────────────

int main()
{
    plugin_log("=== PLUGIN LOADER v1.17 [ptrace/no-shellcore] ===");

    payload_args_t *args = payload_get_args();
    if (args) plugin_log("kbase=0x%llx", (unsigned long long)args->kdata_base_addr);

    uint32_t fw       = kernel_get_fw_version();
    uint32_t fw_major = (fw >> 24) & 0xFF;
    uint32_t fw_minor = (fw >> 16) & 0xFF;
    plugin_log("FW: 0x%08x (%x.%02x)", fw, fw_major, fw_minor);

    struct sigaction sa{};
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    for (int i = 0; i < 12; i++) sigaction(i, &sa, nullptr);

    // Jailbreak du loader lui-même → accès /data/PluginLoader/
    if (jb_pid(getpid()) != 0)
        plugin_log("[JB] self jb failed - /data may be inaccessible");

    printf_notification("Prx-Loader [ptrace] FW:%x.%02x     \nVer:1.17 By @84Ciss",
                        fw_major, fw_minor);

    // ── Poll loop ─────────────────────────────────────────────────────────────
    int last_bappid = -1;

    while (true)
    {
        int bappid = sceSystemServiceGetAppIdOfRunningBigApp();
        if (bappid < 0 || bappid == last_bappid) { sleep(5); continue; }

        char tid_buf[255] = {};
        if (sceSystemServiceGetAppTitleId(bappid, tid_buf) != 0) { sleep(5); continue; }

        if (strncmp(tid_buf, "PPSA", 4) != 0 &&
            strncmp(tid_buf, "CUSA", 4) != 0 &&
            strncmp(tid_buf, "SCUS", 4) != 0)
        { sleep(5); continue; }

        plugin_log("Game detected: %s (bappid=%d)", tid_buf, bappid);

        // Attendre le spawn du process (max 30s)
        pid_t game_pid = -1;
        for (int i = 0; i < 60 && game_pid < 0; i++) {
            usleep(500000);
            game_pid = find_pid_by_title(tid_buf);
        }

        if (game_pid < 0) {
            plugin_log("Game pid not found for %s", tid_buf);
            last_bappid = bappid;
            sleep(5);
            continue;
        }

        GameInjectorConfig config = parse_injector_config();
        auto it = config.games.find(std::string(tid_buf));

        if (it == config.games.end()) {
            plugin_log("No config for %s - fakelib only", tid_buf);
            char sid[32] = {};
            char *fml = nullptr;
            auto fml_cfg = config.fakelib_enabled.find(std::string(tid_buf));
            bool fml_wanted = (strncmp(tid_buf, "PPSA", 4) == 0) &&
                              (fml_cfg == config.fakelib_enabled.end() || fml_cfg->second);
            if (fml_wanted && resolve_sandbox_id(tid_buf, sid, sizeof(sid))) {
                char fakelib_check[PATH_MAX];
                snprintf(fakelib_check, sizeof(fakelib_check),
                         "/mnt/sandbox/%s/app0/fakelib", sid);
                struct stat st2;
                for (int t = 0; t < 30 && stat(fakelib_check, &st2) != 0; t++)
                    usleep(50000);
                if (stat(fakelib_check, &st2) == 0)
                    fml = try_mount_fakelib(tid_buf, sid);
            }
            if (fml) {
                wait_for_pid_exit(game_pid);
                cleanup_after_game(game_pid, sid, fml);
            }
        } else {
            inject_into_game(game_pid, tid_buf, it->second, config);
        }

        last_bappid = bappid;
        sleep(5);
    }

    return 0;
}