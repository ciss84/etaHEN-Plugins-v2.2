#include "utils.hpp"
#include <notify.hpp>
#include <signal.h>
#include <string>

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <machine/reg.h>
#include <stdarg.h>
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

extern "C" {
    int sceSystemServiceGetAppIdOfRunningBigApp();
    int sceSystemServiceGetAppTitleId(int app_id, char *title_id);
    int sceKernelGetAppInfo(pid_t pid, app_info_t *info);
    int nmount(struct iovec *iov, unsigned int niov, int flags);
    int unmount(const char *path, int flags);
}

// NIDs — porté depuis ps5-plugin-loader
#define NID_LOADMOD  "wzvqT4UqKX8"  // sceKernelLoadStartModule
#define NID_SYSCALL  "HoLVWNanBBc"  // getpid (syscall wrapper)

#define AUTHID_SYSTEM   0x4801000000000013ULL
#define AUTHID_DEBUGGER 0x4800000000010003ULL

// ─────────────────────────────────────────────────────────────────────────────
//  Shellcode ptrace — porté depuis ps5-plugin-loader
//  mmap anonyme + shellcode INT3 → sceKernelLoadStartModule → SIGTRAP → RAX
// ─────────────────────────────────────────────────────────────────────────────

#define SHELLCODE_FN_OFFSET 14

static const uint8_t k_shellcode[] = {
    0x55,                               // push rbp
    0x48, 0x89, 0xE5,                   // mov  rbp, rsp
    0x48, 0x83, 0xE4, 0xF0,             // and  rsp, -16
    0x48, 0x83, 0xEC, 0x28,             // sub  rsp, 0x28
    0x49, 0xBF,                         // mov  r15, imm64 (patché runtime)
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x31, 0xF6,                         // xor  esi, esi
    0x31, 0xD2,                         // xor  edx, edx
    0x31, 0xC9,                         // xor  ecx, ecx
    0x45, 0x31, 0xC0,                   // xor  r8d, r8d
    0x45, 0x31, 0xC9,                   // xor  r9d, r9d
    0x41, 0xFF, 0xD7,                   // call r15  (rdi = path)
    0x48, 0x89, 0xEC,                   // mov  rsp, rbp
    0x5D,                               // pop  rbp
    0xCC                                // int3 → SIGTRAP, RAX = result
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
            if (waitpid_timeout(pid, &status, 2000) > 0) {
                plugin_log("[PT] attached pid=%d status=0x%x", pid, status);
                return 0;
            }
            sys_ptrace(PT_DETACH, pid, 0, 0);
        }
        if (errno == ESRCH) { usleep(500000); continue; }
        break;
    }
    plugin_log("[PT] attach failed pid=%d errno=%d", pid, errno);
    return -1;
}

static int pt_detach(pid_t pid)
{
    return sys_ptrace(PT_DETACH, pid, 0, 0);
}

static int pt_getregs(pid_t pid, struct reg *r)
{
    return sys_ptrace(PT_GETREGS, pid, (caddr_t)r, 0);
}

static int pt_setregs(pid_t pid, const struct reg *r)
{
    return sys_ptrace(PT_SETREGS, pid, (caddr_t)r, 0);
}

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

    va_list ap;
    va_start(ap, sysno);
    jmp.r_rdi = va_arg(ap, uint64_t);
    jmp.r_rsi = va_arg(ap, uint64_t);
    jmp.r_rdx = va_arg(ap, uint64_t);
    jmp.r_r10 = va_arg(ap, uint64_t);
    jmp.r_r8  = va_arg(ap, uint64_t);
    jmp.r_r9  = va_arg(ap, uint64_t);
    va_end(ap);

    if (pt_setregs(pid, &jmp)) return -1;

    int max_steps = 10000;
    while (jmp.r_rsp <= bak.r_rsp && max_steps-- > 0) {
        if (sys_ptrace(PT_STEP, pid, (caddr_t)1, 0)) return -1;
        if (waitpid_timeout(pid, NULL, 1000) <= 0)   return -1;
        if (pt_getregs(pid, &jmp))                    return -1;
    }

    pt_setregs(pid, &bak);
    return (long)jmp.r_rax;
}

static intptr_t pt_mmap(pid_t pid, intptr_t addr, size_t len,
                         int prot, int flags, int fd, off_t off)
{
    return pt_syscall(pid, SYS_mmap,
        (uint64_t)addr, (uint64_t)len, (uint64_t)prot,
        (uint64_t)flags, (uint64_t)fd, (uint64_t)off);
}

static int pt_munmap(pid_t pid, intptr_t addr, size_t len)
{
    return (int)pt_syscall(pid, SYS_munmap, (uint64_t)addr, (uint64_t)len);
}

static long pt_call_continue(pid_t pid, intptr_t addr, ...)
{
    struct reg jmp, bak;
    if (pt_getregs(pid, &bak)) return -1;
    memcpy(&jmp, &bak, sizeof(jmp));

    jmp.r_rip = addr;

    va_list ap;
    va_start(ap, addr);
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
        plugin_log("[PT] pt_call_continue: timeout");
        pt_setregs(pid, &bak);
        return -1;
    }

    if (pt_getregs(pid, &jmp)) return -1;
    plugin_log("[PT] pt_call_continue: RIP=0x%llx RAX=0x%llx",
               (unsigned long long)jmp.r_rip,
               (unsigned long long)jmp.r_rax);

    pt_setregs(pid, &bak);
    return (long)jmp.r_rax;
}

// ─────────────────────────────────────────────────────────────────────────────
//  jb_pid — jailbreak le process game (porté depuis ps5-plugin-loader)
//  Kernel direct : ucred patch + rootvnode, sans toucher SceShellCore
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

    const uint32_t zero  = 0;
    const int64_t  caps  = -1LL;
    const uint64_t authid = AUTHID_SYSTEM;
    const uint8_t  attr   = 0x80;

    #define TRY(src, off, len) \
        if (kernel_copyin(src, ucred + (off), len) < 0) { \
            plugin_log("[JB] copyin failed offset=0x%x", (off)); return -1; }

    TRY(&zero,   0x04, 4);   // cr_uid
    TRY(&zero,   0x08, 4);   // cr_ruid
    TRY(&zero,   0x0C, 4);   // cr_svuid
    TRY(&zero,   0x10, 4);   // cr_ngroups
    TRY(&zero,   0x14, 4);   // cr_rgid
    TRY(&zero,   0x18, 4);   // cr_svgid
    TRY(&authid, 0x58, 8);   // cr_sceAuthID
    TRY(&caps,   0x60, 8);   // cr_sceCaps[0]
    TRY(&caps,   0x68, 8);   // cr_sceCaps[1]
    TRY(&attr,   0x83, 1);   // cr_sceAttrs

    #undef TRY

    kernel_set_proc_rootdir(pid, rv);
    kernel_set_proc_jaildir(pid, rv);

    plugin_log("[JB] OK authid=0x%llx",
               (unsigned long long)kernel_get_ucred_authid(pid));
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  inject_prx_attached — porté depuis ps5-plugin-loader
//  ptrace + mmap anonyme + shellcode INT3 → sceKernelLoadStartModule
//  Zéro modification du code du jeu (pas de PLT hook)
// ─────────────────────────────────────────────────────────────────────────────

static long inject_prx_attached(pid_t pid, const char *prx_path)
{
    plugin_log("[INJ] pid=%d path=%s", pid, prx_path);

    if (access(prx_path, R_OK) != 0) {
        plugin_log("[INJ] file not accessible: %s", prx_path);
        return -1;
    }

    const intptr_t fn = pt_resolve(pid, NID_LOADMOD);
    if (!fn) {
        plugin_log("[INJ] NID_LOADMOD not resolved");
        return -1;
    }
    plugin_log("[INJ] sceKernelLoadStartModule @ 0x%lx", (unsigned long)fn);

    const size_t   path_len = strlen(prx_path) + 1;
    const intptr_t rw_page  = pt_mmap(pid, 0, 0x4000,
                                       PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (rw_page == (intptr_t)-1 || rw_page == 0) {
        plugin_log("[INJ] pt_mmap failed errno=%d", errno);
        return -1;
    }

    const intptr_t remote_path = rw_page;
    const intptr_t remote_sc   = rw_page + 0x1000;
    long mod = -1;

    do {
        if (pt_copyin(pid, prx_path, remote_path, path_len) < 0) {
            plugin_log("[INJ] copyin path failed");
            break;
        }

        uint8_t sc[sizeof(k_shellcode)];
        memcpy(sc, k_shellcode, sizeof(sc));
        memcpy(sc + SHELLCODE_FN_OFFSET, &fn, sizeof(fn));

        if (pt_copyin(pid, sc, remote_sc, sizeof(sc)) < 0) {
            plugin_log("[INJ] copyin shellcode failed");
            break;
        }

        if (kernel_mprotect(pid, remote_sc, 0x1000,
                            PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            plugin_log("[INJ] kernel_mprotect RWX failed");
            break;
        }

        mod = pt_call_continue(pid, remote_sc,
                               (uint64_t)remote_path,
                               0ULL, 0ULL, 0ULL, 0ULL, 0ULL);

        kernel_mprotect(pid, remote_sc, 0x1000, PROT_READ | PROT_WRITE);
    } while (0);

    pt_munmap(pid, rw_page, 0x4000);
    plugin_log("[INJ] modid=0x%llx", (unsigned long long)(uint64_t)mod);
    return mod;
}

// ─────────────────────────────────────────────────────────────────────────────
//  find_pid_by_title — sysctl + sceKernelGetAppInfo (ps5-plugin-loader)
// ─────────────────────────────────────────────────────────────────────────────

static pid_t find_pid_by_title(const char *title_id)
{
    int    mib[4] = {1, 14, 8, 0};
    size_t sz     = 0;
    sysctl(mib, 4, NULL, &sz, NULL, 0);

    uint8_t *buf = (uint8_t *)malloc(sz);
    if (!buf) return -1;
    if (sysctl(mib, 4, buf, &sz, NULL, 0) < 0) { free(buf); return -1; }

    pid_t  self  = getpid();
    pid_t  found = -1;
    uint8_t *p   = buf;

    while (p + 4 <= buf + sz) {
        int   elen = *(int *)p;
        if (elen <= 0 || p + elen > buf + sz) break;
        pid_t pid  = *(pid_t *)(p + 72);
        if (pid > 1 && pid != self) {
            app_info_t info = {};
            if (sceKernelGetAppInfo(pid, &info) == 0 && info.title_id[0]) {
                if (strncmp(info.title_id, title_id, 9) == 0) {
                    found = pid;
                    break;
                }
            }
        }
        p += elen;
    }

    free(buf);
    plugin_log("[PID] [%s] -> pid=%d", title_id, (int)found);
    return found;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Game detection — poll sceSystemServiceGetAppIdOfRunningBigApp
// ─────────────────────────────────────────────────────────────────────────────

static bool Get_Running_App_TID(std::string &title_id, int &bappid)
{
    char tid[255] = {};
    bappid = sceSystemServiceGetAppIdOfRunningBigApp();
    if (bappid < 0) return false;
    if (sceSystemServiceGetAppTitleId(bappid, tid) != 0) return false;
    title_id = std::string(tid);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Fakelib / unionfs — porté depuis Plugin-Loader v1.17
// ─────────────────────────────────────────────────────────────────────────────

#define IOVEC_ENTRY(x) {x ? (char *)x : 0, x ? strlen(x) + 1 : 0}
#define IOVEC_SIZE(x)  (sizeof(x) / sizeof(struct iovec))

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
            return strdup(entry->d_name);
        }
    }
    closedir(dir);
    return nullptr;
}

static bool resolve_sandbox_id(const char *title_id, char *sandbox_id, size_t size)
{
    int sandbox_num = -1;
    for (int attempt = 0; attempt < 20 && sandbox_num < 0; attempt++) {
        sandbox_num = find_highest_sandbox_number(title_id);
        if (sandbox_num < 0) usleep(50000);
    }
    if (sandbox_num < 0) {
        plugin_log("[Fakelib] No sandbox found for %s", title_id);
        return false;
    }
    snprintf(sandbox_id, size, "%s_%03d", title_id, sandbox_num);
    plugin_log("[Fakelib] Sandbox: %s", sandbox_id);
    return true;
}

static char *try_mount_fakelib(const char *title_id, const char *sandbox_id)
{
    char fakelib_src[PATH_MAX];
    snprintf(fakelib_src, sizeof(fakelib_src),
             "/mnt/sandbox/%s/app0/fakelib", sandbox_id);

    struct stat st;
    if (stat(fakelib_src, &st) != 0) {
        plugin_log("[Fakelib] No fakelib in app0 (%s), skip", sandbox_id);
        return nullptr;
    }

    int sandbox_num = find_highest_sandbox_number(title_id);
    if (sandbox_num < 0) return nullptr;

    char *random_folder = find_random_folder(title_id, sandbox_num);
    if (!random_folder) return nullptr;

    char *mount_dst = (char *)malloc(PATH_MAX + 1);
    if (!mount_dst) { free(random_folder); return nullptr; }

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
    plugin_log("[Wait] Watching pid %d for exit...", pid);
    while (1) {
        struct kevent ev;
        int nev = kevent(kq, nullptr, 0, &ev, 1, nullptr);
        if (nev > 0 && (ev.fflags & NOTE_EXIT)) break;
        if (nev < 0) break;
    }
    close(kq);
    plugin_log("[Wait] pid %d exited", pid);
}

static int cleanup_directory(const char *path)
{
    DIR *d = opendir(path);
    if (!d) return -1;
    int result = 0;
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

static void cleanup_after_game(const char *sandbox_id, char *fakelib_mount)
{
    if (!fakelib_mount) return;
    char sandbox_app0[PATH_MAX];
    snprintf(sandbox_app0, sizeof(sandbox_app0),
             "/mnt/sandbox/%s/app0", sandbox_id);
    int wait_count = 0;
    struct stat st;
    while (stat(sandbox_app0, &st) == 0 && wait_count < 30) {
        sleep(1); wait_count++;
    }
    plugin_log("[Cleanup] Unmounting %s", fakelib_mount);
    unmount(fakelib_mount, 0);
    char sandbox_dir[PATH_MAX];
    snprintf(sandbox_dir, sizeof(sandbox_dir), "/mnt/sandbox/%s", sandbox_id);
    plugin_log("[Cleanup] Removing %s", sandbox_dir);
    if (cleanup_directory(sandbox_dir) == 0)
        printf_notification("Sandbox %s cleaned up     ", sandbox_id);
    free(fakelib_mount);
}

// ─────────────────────────────────────────────────────────────────────────────
//  inject_into_game — attend le spawn + jb_pid + inject_prx_attached
// ─────────────────────────────────────────────────────────────────────────────

static void inject_into_game(const char *title_id,
                              const std::vector<PRXConfig> &prx_list,
                              const GameInjectorConfig &config)
{
    plugin_log("========================================");
    plugin_log("Injecting into %s", title_id);
    plugin_log("========================================");

    int delay_sec = prx_list.empty() ? 5 : prx_list[0].frame_delay / 60;
    if (delay_sec < 1) delay_sec = 1;

    // ── Fakelib ───────────────────────────────────────────────────────────────
    char sandbox_id[32]  = {};
    char *fakelib_mount  = nullptr;

    auto fakelib_cfg    = config.fakelib_enabled.find(std::string(title_id));
    bool fakelib_wanted = (strncmp(title_id, "PPSA", 4) == 0) &&
                          (fakelib_cfg == config.fakelib_enabled.end() ||
                           fakelib_cfg->second);

    if (fakelib_wanted && resolve_sandbox_id(title_id, sandbox_id, sizeof(sandbox_id))) {
        char fakelib_check[PATH_MAX];
        snprintf(fakelib_check, sizeof(fakelib_check),
                 "/mnt/sandbox/%s/app0/fakelib", sandbox_id);
        struct stat st;
        for (int t = 0; t < 30 && stat(fakelib_check, &st) != 0; t++)
            usleep(50000);
        if (stat(fakelib_check, &st) == 0)
            fakelib_mount = try_mount_fakelib(title_id, sandbox_id);
        else
            plugin_log("[Fakelib] No app0/fakelib for %s, skip", title_id);
    }

    // ── Attendre le spawn du process ─────────────────────────────────────────
    plugin_log("[INJ] Waiting for game process (delay=%ds)...", delay_sec);
    pid_t pid = -1;
    for (int i = 0; i < 60; i++) {
        usleep(500000);
        pid = find_pid_by_title(title_id);
        if (pid > 0) break;
    }

    if (pid <= 0) {
        plugin_log("[INJ] Game process not found, skip");
        printf_notification("ploader: [%s] process not found     ", title_id);
        if (fakelib_mount) { unmount(fakelib_mount, MNT_FORCE); free(fakelib_mount); }
        return;
    }

    plugin_log("[INJ] pid=%d found, waiting %ds...", pid, delay_sec);
    printf_notification("ploader: [%s] pid=%d\nInject dans %ds...",
                        title_id, pid, delay_sec);
    sleep(delay_sec);

    // ── Attach + jailbreak + inject ───────────────────────────────────────────
    if (pt_attach(pid) < 0) {
        plugin_log("[INJ] pt_attach failed");
        printf_notification("ploader: [%s] attach failed     ", title_id);
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
        if (rc > 0)       { plugin_log("[INJ] OK modid=%d %s", rc, prx.path.c_str()); ok++; }
        else if (rc == 0) { plugin_log("[INJ] modid=0 (already?) %s", prx.path.c_str()); ok++; }
        else              { plugin_log("[INJ] FAILED 0x%08x %s", (uint32_t)rc, prx.path.c_str()); }
    }

    pt_detach(pid);

    plugin_log("[INJ] %d/%zu injected into %s", ok, prx_list.size(), title_id);
    printf_notification("ploader: %d/%zu injected [%s]%s     \nBy @84Ciss",
                        ok, prx_list.size(), title_id,
                        fakelib_mount ? "\nFakelib: OK" : "");

    // ── Wait game exit + cleanup fakelib ─────────────────────────────────────
    if (fakelib_mount) {
        wait_for_pid_exit(pid);
        cleanup_after_game(sandbox_id, fakelib_mount);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  main
// ─────────────────────────────────────────────────────────────────────────────

int main()
{
    plugin_log("=== PLUGIN LOADER v1.17 [ptrace mode] ===");

    payload_args_t *args = payload_get_args();
    if (args)
        plugin_log("kbase=0x%llx", (unsigned long long)args->kdata_base_addr);

    uint32_t fw       = kernel_get_fw_version();
    uint32_t fw_major = (fw >> 24) & 0xFF;
    uint32_t fw_minor = (fw >> 16) & 0xFF;
    plugin_log("FW: 0x%08x (%x.%02x)", fw, fw_major, fw_minor);

    struct sigaction sa{};
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    for (int i = 0; i < 12; i++)
        sigaction(i, &sa, nullptr);

    // Jailbreak du loader lui-même → accès /data/PluginLoader/
    // Identique à ps5-plugin-loader (pas de patchShellCore)
    if (jb_pid(getpid()) != 0)
        plugin_log("[JB] jb_pid self failed, /data access may fail");
    usleep(500000);

    printf_notification("Prx-Loader [ptrace] FW:%x.%02x     \nVer:1.17 By @84Ciss",
                        fw_major, fw_minor);

    // ── Poll loop ─────────────────────────────────────────────────────────────
    std::string tid;
    int bappid, last_bappid = -1;

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

                GameInjectorConfig config = parse_injector_config();

                // Section [default]
                auto def = config.games.find("default");
                if (def != config.games.end())
                    inject_into_game(tid.c_str(), def->second, config);

                // Section [TITLE_ID]
                auto it = config.games.find(tid);
                if (it != config.games.end())
                    inject_into_game(tid.c_str(), it->second, config);
                else if (def == config.games.end())
                    plugin_log("No config for %s", tid.c_str());

                last_bappid = bappid;
            }
        }
        sleep(5);
    }

    return 0;
}