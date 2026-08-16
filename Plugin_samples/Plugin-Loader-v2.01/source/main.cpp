#include "utils.hpp"
#include <notify.hpp>
#include <signal.h>
#include <string>
#include <ps5/kernel.h>

#include <dirent.h>
#include <stdarg.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <machine/reg.h>
#include <ps5/payload.h>
#include <time.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>

// ─────────────────────────────────────────────────────────────────────────────
//  Structures / externs
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
    printf_notification("Plugin Loader crashed: signal %d    ", signo);
    //printBacktraceForCrash();
    exit(-1);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers: find SceSysCore PID
// ─────────────────────────────────────────────────────────────────────────────

static pid_t __attribute__((unused)) find_pid(const char *name)
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
//  fakelib / unionfs helpers
// ─────────────────────────────────────────────────────────────────────────────

#define NID_LOADMOD  "wzvqT4UqKX8"
#define NID_SYSCALL  "HoLVWNanBBc"
#define AUTHID_SYSTEM   0x4801000000000013ULL
#define AUTHID_DEBUGGER 0x4800000000010003ULL
#define SHELLCODE_FN_OFFSET 14
static const uint8_t k_shellcode[] = {
    0x55,0x48,0x89,0xE5,0x48,0x83,0xE4,0xF0,0x48,0x83,0xEC,0x28,0x49,0xBF,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x31,0xF6,0x31,0xD2,0x31,0xC9,0x45,0x31,0xC0,0x45,0x31,0xC9,
    0x41,0xFF,0xD7,0x48,0x89,0xEC,0x5D,0xCC
};
static int sys_ptrace(int q,pid_t p,caddr_t a,int d){
    pid_t mp=getpid();uint64_t au=kernel_get_ucred_authid(mp);if(!au)return -1;
    kernel_set_ucred_authid(mp,AUTHID_DEBUGGER);
    int r=(int)syscall(SYS_ptrace,q,p,a,d);int e=errno;
    kernel_set_ucred_authid(mp,au);errno=e;return r;
}
static int wpt(pid_t pid,int*st,int ms){
    struct timespec s,n;clock_gettime(CLOCK_MONOTONIC,&s);
    while(true){pid_t r=waitpid(pid,st,WNOHANG);
        if(r==pid)return 1;if(r<0)return -1;
        clock_gettime(CLOCK_MONOTONIC,&n);
        long e=(n.tv_sec-s.tv_sec)*1000+(n.tv_nsec-s.tv_nsec)/1000000;
        if(e>=ms)return 0;usleep(10000);}
}
static int pt_attach(pid_t pid){
    for(int r=5;r>0;r--){
        if(sys_ptrace(PT_ATTACH,pid,0,0)==0){int s=0;if(wpt(pid,&s,2000)>0)return 0;sys_ptrace(PT_DETACH,pid,0,0);}
        if(errno==ESRCH){usleep(500000);continue;}break;
    }return -1;
}
static int pt_detach(pid_t p){return sys_ptrace(PT_DETACH,p,0,0);}
static int pt_gr(pid_t p,struct reg*r){return sys_ptrace(PT_GETREGS,p,(caddr_t)r,0);}
static int pt_sr(pid_t p,const struct reg*r){return sys_ptrace(PT_SETREGS,p,(caddr_t)r,0);}
static int pt_ci(pid_t p,const void*b,intptr_t a,size_t l){
    struct ptrace_io_desc d={PIOD_WRITE_D,(void*)a,(void*)b,l};
    return sys_ptrace(PT_IO,p,(caddr_t)&d,0);
}
static intptr_t pt_res(pid_t p,const char*n){
    intptr_t a=kernel_dynlib_resolve(p,0x1,n);return a?a:kernel_dynlib_resolve(p,0x2001,n);
}
static long pt_sc(pid_t pid,int sn,...){
    intptr_t a=pt_res(pid,NID_SYSCALL);if(!a)return -1;a+=0xA;
    struct reg j,b;if(pt_gr(pid,&b))return -1;memcpy(&j,&b,sizeof(j));
    j.r_rip=a;j.r_rax=(uint64_t)sn;
    va_list ap;va_start(ap,sn);
    j.r_rdi=va_arg(ap,uint64_t);j.r_rsi=va_arg(ap,uint64_t);
    j.r_rdx=va_arg(ap,uint64_t);j.r_r10=va_arg(ap,uint64_t);
    j.r_r8=va_arg(ap,uint64_t);j.r_r9=va_arg(ap,uint64_t);va_end(ap);
    if(pt_sr(pid,&j))return -1;
    int mx=10000;
    while(j.r_rsp<=b.r_rsp&&mx-->0){
        if(sys_ptrace(PT_STEP,pid,(caddr_t)1,0))return -1;
        if(wpt(pid,NULL,1000)<=0)return -1;if(pt_gr(pid,&j))return -1;
    }
    pt_sr(pid,&b);return(long)j.r_rax;
}
static intptr_t pt_mmap(pid_t p,intptr_t a,size_t l,int pr,int f,int fd,off_t o){
    return pt_sc(p,SYS_mmap,(uint64_t)a,(uint64_t)l,(uint64_t)pr,(uint64_t)f,(uint64_t)fd,(uint64_t)o);
}
static int pt_munmap(pid_t p,intptr_t a,size_t l){return(int)pt_sc(p,SYS_munmap,(uint64_t)a,(uint64_t)l);}
static long pt_cont(pid_t pid,intptr_t addr,...){
    struct reg j,b;if(pt_gr(pid,&b))return -1;memcpy(&j,&b,sizeof(j));j.r_rip=addr;
    va_list ap;va_start(ap,addr);
    j.r_rdi=va_arg(ap,uint64_t);j.r_rsi=va_arg(ap,uint64_t);
    j.r_rdx=va_arg(ap,uint64_t);j.r_rcx=va_arg(ap,uint64_t);
    j.r_r8=va_arg(ap,uint64_t);j.r_r9=va_arg(ap,uint64_t);va_end(ap);
    if(pt_sr(pid,&j))return -1;
    int st=0;sys_ptrace(PT_CONTINUE,pid,(caddr_t)1,0);
    if(wpt(pid,&st,5000)<=0){pt_sr(pid,&b);return -1;}
    if(pt_gr(pid,&j))return -1;pt_sr(pid,&b);return(long)j.r_rax;
}
static int jb_pid(pid_t pid){
    intptr_t rv=kernel_get_root_vnode(),uc=kernel_get_proc_ucred(pid),fd=kernel_get_proc_filedesc(pid);
    if(!rv||!uc||!fd){plugin_log("[JB] missing ptrs pid=%d",pid);return -1;}
    const uint32_t z=0;const int64_t caps=-1LL;const uint64_t au=AUTHID_SYSTEM;const uint8_t at=0x80;
    #define KW(s,o,l) if(kernel_copyin(s,uc+(o),l)<0)return -1;
    KW(&z,0x04,4)KW(&z,0x08,4)KW(&z,0x0C,4)KW(&z,0x10,4)
    KW(&z,0x14,4)KW(&z,0x18,4)KW(&au,0x58,8)KW(&caps,0x60,8)KW(&caps,0x68,8)KW(&at,0x83,1)
    #undef KW
    kernel_set_proc_rootdir(pid,rv);kernel_set_proc_jaildir(pid,rv);
    plugin_log("[JB] OK pid=%d",pid);return 0;
}
static long inject_prx(pid_t pid,const char*path){
    if(access(path,R_OK)!=0)return -1;
    intptr_t fn=pt_res(pid,NID_LOADMOD);if(!fn)return -1;
    intptr_t rw=pt_mmap(pid,0,0x4000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(rw==(intptr_t)-1||rw==0)return -1;
    long mod=-1;
    do{
        if(pt_ci(pid,path,rw,strlen(path)+1)<0)break;
        uint8_t sc[sizeof(k_shellcode)];memcpy(sc,k_shellcode,sizeof(sc));memcpy(sc+SHELLCODE_FN_OFFSET,&fn,8);
        if(pt_ci(pid,sc,rw+0x1000,sizeof(sc))<0)break;
        if(kernel_mprotect(pid,rw+0x1000,0x1000,PROT_READ|PROT_WRITE|PROT_EXEC)!=0)break;
        mod=pt_cont(pid,rw+0x1000,(uint64_t)rw,0ULL,0ULL,0ULL,0ULL,0ULL);
        kernel_mprotect(pid,rw+0x1000,0x1000,PROT_READ|PROT_WRITE);
    }while(0);
    pt_munmap(pid,rw,0x4000);return mod;
}


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
//  Sandbox cleanup
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
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────

static bool __attribute__((unused)) IsProcessRunning(pid_t pid)
{
    int bappid = 0;
    return (_sceApplicationGetAppId(pid, &bappid) >= 0);
}

uintptr_t kernel_base = 0;

static bool resolve_sandbox_id(const char *title_id, char *sandbox_id, size_t sandbox_id_size)
{
    int sandbox_num = -1;
    for (int attempt = 0; attempt < 20 && sandbox_num < 0; attempt++) {
        sandbox_num = find_highest_sandbox_number(title_id);
        if (sandbox_num < 0)
            usleep(50000);
    }

    if (sandbox_num < 0) {
        plugin_log("[Sandbox] No sandbox found for %s after 1s", title_id);
        return false;
    }

    snprintf(sandbox_id, sandbox_id_size, "%s_%03d", title_id, sandbox_num);
    plugin_log("[Sandbox] Resolved: %s", sandbox_id);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Core injection: PLT hook + fakelib + diagnostic readback
// ─────────────────────────────────────────────────────────────────────────────

static void inject_into_game(pid_t pid, const char *title_id,
                              const std::vector<PRXConfig> &prx_list,
                              const GameInjectorConfig &config)
{
    plugin_log("========================================");
    plugin_log("Injecting into %s (pid %d)", title_id, pid);
    plugin_log("========================================");

    // ── 1. FAKELIB ────────────────────────────────────────────────────────
    char sandbox_id[32] = {};
    char *fakelib_mount = nullptr;

    auto fakelib_cfg  = config.fakelib_enabled.find(std::string(title_id));
    bool fakelib_wanted = (strncmp(title_id, "PPSA", 4) == 0) &&
                          (fakelib_cfg == config.fakelib_enabled.end() || fakelib_cfg->second);

    if (fakelib_wanted && resolve_sandbox_id(title_id, sandbox_id, sizeof(sandbox_id))) {
        char fakelib_check[PATH_MAX];
        snprintf(fakelib_check, sizeof(fakelib_check),
                 "/mnt/sandbox/%s/app0/fakelib", sandbox_id);

        struct stat st;
        for (int t = 0; t < 30 && stat(fakelib_check, &st) != 0; t++)
            usleep(50000);

        if (stat(fakelib_check, &st) == 0) {
            plugin_log("[Fakelib] app0/fakelib found, mounting NOW");
            fakelib_mount = try_mount_fakelib(title_id, sandbox_id);
            if (!fakelib_mount)
                plugin_log("[Fakelib] mount failed");
        } else {
            plugin_log("[Fakelib] No app0/fakelib for %s, skipping", title_id);
        }
    }

    // -- ptrace + jb_pid + inject
    // frame_delay en frames comme l'ancien INI (:60=1s :600=10s :1200=20s)
    // pt_attach = equivalent sceKernelSuspendProcess
    // pt_detach = equivalent sceKernelResumeProcess
    int delay_sec = prx_list.empty() ? 1 : prx_list[0].frame_delay / 60;
    if (delay_sec < 1) delay_sec = 1;
    plugin_log("[INJ] delay=%ds pid=%d", delay_sec, pid);
    sleep(delay_sec);
    int success_count = 0;
    if (kill(pid, 0) == 0) {
        // Suspend propre via SCE (identique original — pas de lag après)
        sceKernelPrepareToSuspendProcess(pid);
        sceKernelSuspendProcess(pid);
        usleep(750000);

        // ptrace uniquement pour l'injection shellcode
        if (pt_attach(pid) == 0) {
            if (jb_pid(pid) == 0) {
                for (size_t idx = 0; idx < prx_list.size(); idx++) {
                    const auto &prx = prx_list[idx];
                    long ret = inject_prx(pid, prx.path.c_str());
                    int32_t rc = (int32_t)ret;
                    if (rc > 0) { success_count++; plugin_log("[INJ] OK modid=%d", rc); }
                    else if (rc == 0) { success_count++; }
                    else { plugin_log("[INJ] FAILED 0x%08x %s",(uint32_t)rc,prx.path.c_str()); }

                    if (idx + 1 < prx_list.size()) {
                        pt_detach(pid);
                        sceKernelPrepareToResumeProcess(pid);
                        sceKernelResumeProcess(pid);
                        sleep(3);
                        sceKernelPrepareToSuspendProcess(pid);
                        sceKernelSuspendProcess(pid);
                        usleep(2500000);
                        if (pt_attach(pid) != 0) break;
                        if (jb_pid(pid) != 0) break;
                    }
                }
            }
            pt_detach(pid);
        }

        // Resume propre via SCE
        sceKernelPrepareToResumeProcess(pid);
        sceKernelResumeProcess(pid);
    } else { plugin_log("[INJ] process dead pid=%d", pid); }
    plugin_log("[INJ] %d/%zu PRX injected", success_count, prx_list.size());
    if (fakelib_wanted)
        printf_notification("%d/%zu PRX injected into %s     \nFakelib: %s",
                            success_count, prx_list.size(), title_id, fakelib_mount ? "OK" : "none");
    else
        printf_notification("%d/%zu PRX injected into %s     ",
                            success_count, prx_list.size(), title_id);
    // ── 4. Attendre exit + cleanup ────────────────────────────────────────
    plugin_log("[Wait] Waiting for game (pid %d) to exit...", pid);
    wait_for_pid_exit(pid);

    if (fakelib_mount)
        cleanup_after_game(pid, sandbox_id, fakelib_mount);

    plugin_log("Game %s closed - ready for next launch", title_id);
}

// ─────────────────────────────────────────────────────────────────────────────
//  main: kqueue monitoring sur SceSysCore
// ─────────────────────────────────────────────────────────────────────────────

int main()
{
    plugin_log("=== PLUGIN LOADER v2.01 + BACKPORK ===");

    payload_args_t *args = payload_get_args();
    kernel_base = args->kdata_base_addr;

    // ── FW detection ─────────────────────────────────────────────────────
    uint32_t fw = kernel_get_fw_version();
    uint32_t fw_major = (fw >> 24) & 0xFF;
    uint32_t fw_minor = (fw >> 16) & 0xFF;
    plugin_log("FW detected: 0x%08x (%x.%02x)", fw, fw_major, fw_minor);
    // ─────────────────────────────────────────────────────────────────────

    // patchShellCore DESACTIVE pour test (jb_pid suffit)
    // if (!patchShellCore())
    //     plugin_log("[SC] patchShellCore failed");
    jb_pid(getpid());
    usleep(750000);
    // ─────────────────────────────────────────────────────────────────────

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

    // ── kqueue setup ─────────────────────────────────────────────────────
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

    printf_notification("Prx-Loader Ver:2.01                       \nBy @84Ciss  FW: %x.%02x", fw_major, fw_minor);
    //printf_notification("Shadow-Prx-Loader FW: %x.%02x      \nVer:1.17 By @84Ciss ", fw_major, fw_minor);

    plugin_log("Monitoring SceSysCore.elf (pid %d)...", syscore_pid);

    pid_t child_pid = -1;

    // ── Main event loop ───────────────────────────────────────────────────
    while (1)
    {
        struct kevent ev;
        int nev = kevent(kq, nullptr, 0, &ev, 1, nullptr);

        if (nev < 0) { plugin_log("kevent error: %s", strerror(errno)); continue; }
        if (nev == 0) continue;

        if (ev.fflags & NOTE_CHILD)
            child_pid = (pid_t)ev.ident;

        if ((ev.fflags & NOTE_EXEC) && child_pid != -1 && (pid_t)ev.ident == child_pid)
        {
            app_info_t appinfo{};
            if (sceKernelGetAppInfo(child_pid, &appinfo) != 0) {
                plugin_log("sceKernelGetAppInfo failed for pid %d", child_pid);
                child_pid = -1;
                continue;
            }

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

            GameInjectorConfig config = parse_injector_config();
            auto it = config.games.find(std::string(title_id));

            if (it == config.games.end()) {
                plugin_log("No PLT config for %s - fakelib only", title_id);

                char sid[32] = {};
                char *fml = nullptr;
                auto fml_cfg = config.fakelib_enabled.find(std::string(title_id));
                bool fml_wanted = (strncmp(title_id, "PPSA", 4) == 0) &&
                                  (fml_cfg == config.fakelib_enabled.end() || fml_cfg->second);
                if (fml_wanted && resolve_sandbox_id(title_id, sid, sizeof(sid))) {
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

            pid_t game_pid = child_pid;
            child_pid = -1;

            inject_into_game(game_pid, title_id, it->second, config);
        }
    }

    close(kq);
    return 0;
}