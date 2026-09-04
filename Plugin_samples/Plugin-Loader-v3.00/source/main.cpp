// Plugin-Loader v3.00 — by @84Ciss
// Fusion: ptrace injection (ploader approach) + kqueue detection (v2.02)
//         + fakelib/unionfs + multi-PRX + patch_shellcore
//
// Remplace l'approche PLT hook (scePadReadState) par une injection ptrace
// directe : pt_attach → jb_pid → inject_prx (mmap+shellcode+INT3) → pt_detach
// Avantages : synchrone, pas de frame_delay, pas de PLT requis dans le jeu.

#include "utils.hpp"
#include <notify.hpp>
#include <signal.h>
#include <string>
#include <ps5/kernel.h>
#include <ps5/payload.h>

#include <dirent.h>
#include <stdarg.h>
#include <sys/event.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <machine/reg.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

// ─────────────────────────────────────────────────────────────────────────────
//  Macros utilitaires
// ─────────────────────────────────────────────────────────────────────────────

#define IOVEC_ENTRY(x) {x ? (char *)x : 0, x ? strlen(x) + 1 : 0}
#define IOVEC_SIZE(x)  (sizeof(x) / sizeof(struct iovec))

// ─────────────────────────────────────────────────────────────────────────────
//  Constantes ptrace / ucred
// ─────────────────────────────────────────────────────────────────────────────

// NIDs libkernel
#define NID_LOADSTARTMODULE  "wzvqT4UqKX8"   // sceKernelLoadStartModule
#define NID_GETPID           "HoLVWNanBBc"   // getpid

// AuthIDs process (bien connus, stables sur toutes FW PS5)
#define AUTHID_SYSTEM        0x4801000000000013ULL
#define AUTHID_DEBUGGER      0x4800000000010003ULL

// Offset du pointeur de fonction dans le shellcode trampoline (voir k_shellcode)
#define SHELLCODE_FN_OFFSET  14

// Offsets du struct ucred (PS5 / orbisOS FreeBSD)
#define UCRED_UID     0x04
#define UCRED_RUID    0x08
#define UCRED_SVUID   0x0C
#define UCRED_NGROUPS 0x10
#define UCRED_RGID    0x14
#define UCRED_SVGID   0x18
#define UCRED_AUTHID  0x58
#define UCRED_CAPS0   0x60
#define UCRED_CAPS1   0x68
// UCRED_ATTR0 : 0x83 si FW < 8.00, 0x88 si FW >= 8.00  (cf. jb_pid)

// ─────────────────────────────────────────────────────────────────────────────
//  Shellcode trampoline (depuis ploader)
//
//  - Préserve RDI (pointeur vers prx_path, déjà en place avant pt_call)
//  - Zéro les args 2-6 (sceKernelLoadStartModule ne les utilise pas ici)
//  - Patch le pointeur de fonction à l'offset 14 au runtime (mov r15, imm64)
//  - INT3 en fin → SIGTRAP → ptrace se réveille, RAX = handle retourné
// ─────────────────────────────────────────────────────────────────────────────

static const uint8_t k_shellcode[] = {
    0x55,                               // push rbp
    0x48, 0x89, 0xE5,                   // mov  rbp, rsp
    0x48, 0x83, 0xE4, 0xF0,             // and  rsp, -16        (alignement ABI)
    0x48, 0x83, 0xEC, 0x28,             // sub  rsp, 0x28       (scratch space)
    0x49, 0xBF,                         // mov  r15, imm64  ←── patché +14
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x31, 0xF6,                         // xor  esi, esi        (arg2 = 0)
    0x31, 0xD2,                         // xor  edx, edx        (arg3 = 0)
    0x31, 0xC9,                         // xor  ecx, ecx        (arg4 = 0)
    0x45, 0x31, 0xC0,                   // xor  r8d, r8d        (arg5 = 0)
    0x45, 0x31, 0xC9,                   // xor  r9d, r9d        (arg6 = 0)
    0x41, 0xFF, 0xD7,                   // call r15             (rdi = path)
    0x48, 0x89, 0xEC,                   // mov  rsp, rbp
    0x5D,                               // pop  rbp
    0xCC                                // int3  ←── SIGTRAP, RAX = handle
};

// ─────────────────────────────────────────────────────────────────────────────
//  Structures
// ─────────────────────────────────────────────────────────────────────────────

typedef struct app_info {
    uint32_t app_id;
    uint64_t unknown1;
    char     title_id[14];
    char     unknown2[0x3c];
} app_info_t;

// ─────────────────────────────────────────────────────────────────────────────
//  Externs
// ─────────────────────────────────────────────────────────────────────────────

extern "C" {
    int sceKernelGetAppInfo(pid_t pid, app_info_t *info);
    int sceSystemServiceGetAppIdOfRunningBigApp();
    int sceSystemServiceGetAppTitleId(int app_id, char *title_id);
    int _sceApplicationGetAppId(int pid, int *appId);
    int nmount(struct iovec *iov, unsigned int niov, int flags);
    int unmount(const char *path, int flags);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Globales
// ─────────────────────────────────────────────────────────────────────────────

uintptr_t kernel_base  = 0;
uint32_t  g_fw_version = 0;   // initialisé dans main(), utilisé dans jb_pid()

// ─────────────────────────────────────────────────────────────────────────────
//  Signal handler
// ─────────────────────────────────────────────────────────────────────────────

static void sig_handler(int signo)
{
    printf_notification("Plugin Loader crashed: signal %d    ", signo);
    exit(-1);
}

// ─────────────────────────────────────────────────────────────────────────────
//  PTRACE — wrappers bas niveau
//
//  sys_ptrace élève temporairement l'authid du loader à AUTHID_DEBUGGER
//  (requis par le kernel PS5 pour autoriser PT_ATTACH sur un autre process).
// ─────────────────────────────────────────────────────────────────────────────

static int sys_ptrace(int req, pid_t pid, caddr_t addr, int data)
{
    pid_t    mypid  = getpid();
    uint64_t authid = kernel_get_ucred_authid(mypid);
    if (!authid) return -1;

    kernel_set_ucred_authid(mypid, AUTHID_DEBUGGER);
    int ret = syscall(SYS_ptrace, req, pid, addr, data);
    int err = errno;
    kernel_set_ucred_authid(mypid, authid);
    errno = err;
    return ret;
}

// waitpid bloquant — attend indéfiniment, utilisé dans pt_step et pt_call
// (même comportement que le ploader original)
static int pt_wait(pid_t pid, int *status)
{
    int st = 0;
    if (!status) status = &st;
    pid_t res = waitpid(pid, status, 0); // bloquant, pas de timeout
    return (res == pid) ? 0 : -1;
}

// waitpid avec timeout — uniquement pour pt_attach (où on veut détecter
// rapidement si le process n'existe pas encore)
static int waitpid_timeout(pid_t pid, int *status, int ms)
{
    for (int i = 0; i < ms / 10; i++) {
        pid_t res = waitpid(pid, status, WNOHANG);
        if (res == pid) return  1;
        if (res <   0)  return -1;
        usleep(10000);
    }
    return 0;
}

static int pt_attach(pid_t pid)
{
    for (int i = 0; i < 5; i++) {
        if (sys_ptrace(PT_ATTACH, pid, 0, 0) == 0 &&
            waitpid_timeout(pid, nullptr, 2000) > 0)
            return 0;
        if (errno == ESRCH)
            usleep(500000);
        else
            break;
    }
    return -1;
}

static int pt_detach(pid_t pid)
{
    // (caddr_t)1 = signal 0 = reprendre sans signal
    return sys_ptrace(PT_DETACH, pid, (caddr_t)1, 0);
}

static int pt_getregs(pid_t pid, struct reg *r)
{
    return sys_ptrace(PT_GETREGS, pid, (caddr_t)r, 0);
}

static int pt_setregs(pid_t pid, const struct reg *r)
{
    return sys_ptrace(PT_SETREGS, pid, (caddr_t)r, 0);
}

// Écriture mémoire dans le process cible via ptrace I/O
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

// Résolution NID dans le process cible (eboot 0x1, ou libkernel 0x2001)
static intptr_t pt_resolve(pid_t pid, const char *nid)
{
    intptr_t a = kernel_dynlib_resolve(pid, 0x1, nid);
    return a ? a : kernel_dynlib_resolve(pid, 0x2001, nid);
}

// Exécution d'un syscall dans le process cible via injection de registres.
// On redirige RIP vers l'instruction SYSCALL de getpid() (+0xA sur FW 12.20).
// Si ça échoue sur ta FW, désassemble getpid dans libkernel.sprx et ajuste l'offset.
static long pt_syscall(pid_t pid, int sysno,
                        uint64_t a1, uint64_t a2, uint64_t a3,
                        uint64_t a4, uint64_t a5, uint64_t a6)
{
    intptr_t addr = pt_resolve(pid, NID_GETPID);
    if (!addr) return -1;
    addr += 0xA; // offset vers SYSCALL dans le wrapper getpid (FW 12.20 = 0xA)

    struct reg jmp, bak;
    if (pt_getregs(pid, &bak)) return -1;

    jmp       = bak;
    jmp.r_rip = addr;
    jmp.r_rax = sysno;
    jmp.r_rdi = a1; jmp.r_rsi = a2; jmp.r_rdx = a3;
    jmp.r_r10 = a4; jmp.r_r8  = a5; jmp.r_r9  = a6;

    if (pt_setregs(pid, &jmp)) return -1;

    // PT_STEP jusqu'au retour du syscall (RSP revenu à sa valeur initiale)
    // Bloquant comme le ploader — pas de timeout artificiel
    for (;;) {
        if (sys_ptrace(PT_STEP, pid, (caddr_t)1, 0) ||
            pt_wait(pid, nullptr))
            return -1;
        if (pt_getregs(pid, &jmp)) return -1;
        if (jmp.r_rsp > bak.r_rsp) break;
    }

    pt_setregs(pid, &bak);
    return jmp.r_rax;
}

static intptr_t pt_mmap(pid_t pid, intptr_t addr, size_t len,
                         int prot, int flags, int fd, off_t off)
{
    return pt_syscall(pid, SYS_mmap, (uint64_t)addr, len, prot, flags, fd, off);
}

static int pt_munmap(pid_t pid, intptr_t addr, size_t len)
{
    return (int)pt_syscall(pid, SYS_munmap, (uint64_t)addr, len, 0, 0, 0, 0);
}

// Appel de fonction dans le process cible.
// Installe les registres, fait PT_CONTINUE, attend INT3 (SIGTRAP), retourne RAX.
static long pt_call(pid_t pid, intptr_t fn,
                     uint64_t a1, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5, uint64_t a6)
{
    struct reg jmp, bak;
    if (pt_getregs(pid, &bak)) return -1;

    jmp       = bak;
    jmp.r_rip = fn;
    jmp.r_rdi = a1; jmp.r_rsi = a2; jmp.r_rdx = a3;
    jmp.r_rcx = a4; jmp.r_r8  = a5; jmp.r_r9  = a6;

    if (pt_setregs(pid, &jmp)) return -1;

    sys_ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);

    // Bloquant — sceKernelLoadStartModule peut prendre plusieurs secondes
    // selon la taille du PRX et l'état d'initialisation du jeu
    int status = 0;
    if (pt_wait(pid, &status) ||
        !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
    {
        pt_setregs(pid, &bak);
        return -1;
    }

    if (pt_getregs(pid, &jmp)) return -1;
    pt_setregs(pid, &bak);
    return jmp.r_rax;
}

// ─────────────────────────────────────────────────────────────────────────────
//  jb_pid — jailbreak d'un process via manipulation ucred kernel
//
//  Copié du ploader, adapté pour être FW-aware sur UCRED_ATTR0 :
//   - 0x83 sur FW < 8.00 (FW 5.50 → 0x83)
//   - 0x88 sur FW >= 8.00
// ─────────────────────────────────────────────────────────────────────────────

static int jb_pid(pid_t pid)
{
    intptr_t rv    = kernel_get_root_vnode();
    intptr_t ucred = kernel_get_proc_ucred(pid);
    if (!rv || !ucred) {
        plugin_log("[JB] kernel_get_root_vnode ou get_proc_ucred échoué pour pid %d", pid);
        return -1;
    }

    uint32_t zero   = 0;
    int64_t  caps   = -1LL;
    uint64_t authid = AUTHID_SYSTEM;
    uint8_t  attr   = 0x80;

    // UCRED_ATTR0 : dépend de la FW (détecté au démarrage dans main)
    uint32_t attr_off = (g_fw_version >= 0x08000000u) ? 0x88u : 0x83u;

    if (kernel_copyin(&zero,   ucred + UCRED_UID,     4) < 0) return -1;
    if (kernel_copyin(&zero,   ucred + UCRED_RUID,    4) < 0) return -1;
    if (kernel_copyin(&zero,   ucred + UCRED_SVUID,   4) < 0) return -1;
    if (kernel_copyin(&zero,   ucred + UCRED_NGROUPS, 4) < 0) return -1;
    if (kernel_copyin(&zero,   ucred + UCRED_RGID,    4) < 0) return -1;
    if (kernel_copyin(&zero,   ucred + UCRED_SVGID,   4) < 0) return -1;
    if (kernel_copyin(&authid, ucred + UCRED_AUTHID,  8) < 0) return -1;
    if (kernel_copyin(&caps,   ucred + UCRED_CAPS0,   8) < 0) return -1;
    if (kernel_copyin(&caps,   ucred + UCRED_CAPS1,   8) < 0) return -1;
    if (kernel_copyin(&attr,   ucred + attr_off,      1) < 0) return -1;

    kernel_set_proc_rootdir(pid, rv);
    kernel_set_proc_jaildir(pid, rv);

    plugin_log("[JB] jb_pid(%d) OK — attr_off=0x%x", pid, attr_off);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  inject_prx — injection ptrace d'un seul PRX dans le process cible
//
//  Flow:
//   1. Allouer une page RW anonyme dans le process (pt_mmap)
//   2. Écrire le path + shellcode (pt_copyin)
//   3. kernel_mprotect → RWX pour la zone shellcode
//   4. pt_call → le process exécute le shellcode → sceKernelLoadStartModule
//      → INT3 → retour ptrace, RAX = handle (> 0 si succès)
//   5. Libérer la page (pt_munmap)
// ─────────────────────────────────────────────────────────────────────────────

static int inject_prx(pid_t pid, const char *prx_path)
{
    // Vérification préalable que le fichier est accessible depuis le loader
    if (access(prx_path, R_OK) != 0) {
        plugin_log("[INJ] Fichier inaccessible: %s (errno %d)", prx_path, errno);
        return -1;
    }

    // Résoudre sceKernelLoadStartModule dans le process cible
    intptr_t fn = pt_resolve(pid, NID_LOADSTARTMODULE);
    if (!fn) {
        plugin_log("[INJ] pt_resolve(LOADSTARTMODULE) = 0 — libkernel pas encore chargé ?");
        return -1;
    }
    plugin_log("[INJ] sceKernelLoadStartModule résolu @ 0x%lx", (unsigned long)fn);

    // Allouer une page 0x4000 RW anonyme dans le process cible
    // Layout: [0x0000..0x0FFF] = prx_path  |  [0x1000..0x1FFF] = shellcode
    intptr_t rw_page = pt_mmap(pid, 0, 0x4000,
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (rw_page <= 0) {
        plugin_log("[INJ] pt_mmap échoué (rc=%ld)", (long)rw_page);
        return -1;
    }
    plugin_log("[INJ] Page RW allouée @ 0x%lx", (unsigned long)rw_page);

    intptr_t remote_path = rw_page;
    intptr_t remote_sc   = rw_page + 0x1000;
    int      mod         = -1;

    // Écrire le path dans la première moitié de la page
    if (pt_copyin(pid, prx_path, remote_path, strlen(prx_path) + 1) < 0) {
        plugin_log("[INJ] pt_copyin(path) échoué");
        goto out;
    }

    // Préparer le shellcode : patch du pointeur de fonction à l'offset 14
    {
        uint8_t sc[sizeof(k_shellcode)];
        memcpy(sc, k_shellcode, sizeof(sc));
        memcpy(sc + SHELLCODE_FN_OFFSET, &fn, sizeof(fn)); // patch fn ptr

        if (pt_copyin(pid, sc, remote_sc, sizeof(sc)) < 0) {
            plugin_log("[INJ] pt_copyin(shellcode) échoué");
            goto out;
        }
    }

    // Rendre la zone shellcode exécutable (kernel bypasse les protections)
    kernel_mprotect(pid, remote_sc, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);

    // Appeler le shellcode : sceKernelLoadStartModule(path, 0, 0, 0, 0, 0)
    // PT_CONTINUE → le process tourne librement → shellcode s'exécute
    // INT3 à la fin → SIGTRAP → ptrace récupère RAX = handle module
    mod = (int)pt_call(pid, remote_sc, (uint64_t)remote_path, 0, 0, 0, 0, 0);

    plugin_log("[INJ] sceKernelLoadStartModule → handle %d", mod);

    // Remettre la zone en RW (sécurité)
    kernel_mprotect(pid, remote_sc, 0x1000, PROT_READ | PROT_WRITE);

out:
    pt_munmap(pid, rw_page, 0x4000);
    return mod;
}

// ─────────────────────────────────────────────────────────────────────────────
//  find_pid — cherche un process par nom dans la table des process kernel
// ─────────────────────────────────────────────────────────────────────────────

static pid_t find_pid(const char *name)
{
    int      mib[4]    = {1, 14, 8, 0};
    pid_t    mypid     = getpid();
    pid_t    pid       = -1;
    size_t   buf_size  = 0;
    uint8_t *buf       = nullptr;

    if (sysctl(mib, 4, nullptr, &buf_size, nullptr, 0)) return -1;
    if (!(buf = (uint8_t *)malloc(buf_size)))            return -1;
    if (sysctl(mib, 4, buf, &buf_size, nullptr, 0)) { free(buf); return -1; }

    for (uint8_t *ptr = buf; ptr < buf + buf_size;) {
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
//  fakelib / unionfs (inchangé depuis v2.02)
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

static char *try_mount_fakelib(const char *title_id, const char *sandbox_id)
{
    char fakelib_src[PATH_MAX];
    snprintf(fakelib_src, sizeof(fakelib_src),
             "/mnt/sandbox/%s/app0/fakelib", sandbox_id);

    struct stat st;
    if (stat(fakelib_src, &st) != 0) {
        plugin_log("[Fakelib] Pas de fakelib dans app0 (%s), skip", sandbox_id);
        return nullptr;
    }

    int sandbox_num = find_highest_sandbox_number(title_id);
    if (sandbox_num < 0) return nullptr;

    char *random_folder = find_random_folder(title_id, sandbox_num);
    if (!random_folder)  return nullptr;

    char *mount_dst = (char *)malloc(PATH_MAX + 1);
    if (!mount_dst) { free(random_folder); return nullptr; }

    snprintf(mount_dst, PATH_MAX + 1,
             "/mnt/sandbox/%s/%s/common/lib", sandbox_id, random_folder);
    free(random_folder);

    int res = mount_unionfs(fakelib_src, mount_dst);
    if (res != 0) {
        plugin_log("[Fakelib] mount_unionfs échec: %d (errno %d)", res, errno);
        unmount(mount_dst, MNT_FORCE);
        free(mount_dst);
        return nullptr;
    }

    plugin_log("[Fakelib] Monté %s → %s", fakelib_src, mount_dst);
    printf_notification("Fakelib monté pour %s     ", title_id);
    return mount_dst;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Attente exit jeu via kqueue (EVFILT_PROC / NOTE_EXIT)
// ─────────────────────────────────────────────────────────────────────────────

static void wait_for_pid_exit(pid_t pid)
{
    int kq = kqueue();
    if (kq == -1) { sleep(3); return; }

    struct kevent kev;
    EV_SET(&kev, pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_CLEAR,
           NOTE_EXIT, 0, nullptr);

    if (kevent(kq, &kev, 1, nullptr, 0, nullptr) == -1) {
        plugin_log("[Wait] kevent registration failed pour pid %d: %s",
                   pid, strerror(errno));
        close(kq);
        sleep(3);
        return;
    }

    plugin_log("[Wait] Surveillance pid %d...", pid);
    while (1) {
        struct kevent ev;
        int nev = kevent(kq, nullptr, 0, &ev, 1, nullptr);
        if (nev > 0 && (ev.fflags & NOTE_EXIT)) {
            plugin_log("[Wait] pid %d terminé", pid);
            break;
        }
        if (nev < 0) break;
    }
    close(kq);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Cleanup sandbox après fermeture du jeu
// ─────────────────────────────────────────────────────────────────────────────

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

static void cleanup_after_game(pid_t pid, const char *sandbox_id,
                                char *fakelib_mount)
{
    if (!fakelib_mount) return;
    (void)pid; // garde le paramètre pour éventuelle extension future

    char sandbox_app0[PATH_MAX];
    snprintf(sandbox_app0, sizeof(sandbox_app0),
             "/mnt/sandbox/%s/app0", sandbox_id);

    // Attendre que le sandbox soit démonté par le système (max 30s)
    int wait_count = 0;
    struct stat st;
    while (stat(sandbox_app0, &st) == 0 && wait_count < 30) {
        sleep(1);
        wait_count++;
    }

    plugin_log("[Cleanup] Unmount %s", fakelib_mount);
    unmount(fakelib_mount, 0);

    char sandbox_dir[PATH_MAX];
    snprintf(sandbox_dir, sizeof(sandbox_dir), "/mnt/sandbox/%s", sandbox_id);
    plugin_log("[Cleanup] Suppression %s", sandbox_dir);
    if (cleanup_directory(sandbox_dir) == 0) {
        plugin_log("[Cleanup] Sandbox supprimé");
        printf_notification("Sandbox %s nettoyé     ", sandbox_id);
    } else {
        plugin_log("[Cleanup] Échec suppression: %s", strerror(errno));
    }
    free(fakelib_mount);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────

static bool IsProcessRunning(pid_t pid)
{
    int bappid = 0;
    return (_sceApplicationGetAppId(pid, &bappid) >= 0);
}

static bool resolve_sandbox_id(const char *title_id, char *sandbox_id,
                                size_t sandbox_id_size)
{
    int sandbox_num = -1;
    for (int attempt = 0; attempt < 20 && sandbox_num < 0; attempt++) {
        sandbox_num = find_highest_sandbox_number(title_id);
        if (sandbox_num < 0) usleep(50000);
    }
    if (sandbox_num < 0) {
        plugin_log("[Sandbox] Aucun sandbox trouvé pour %s", title_id);
        return false;
    }
    snprintf(sandbox_id, sandbox_id_size, "%s_%03d", title_id, sandbox_num);
    plugin_log("[Sandbox] Résolu: %s", sandbox_id);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  inject_into_game — injection ptrace multi-PRX + fakelib
//
//  Flow complet :
//    ① Fakelib (PPSA uniquement, si app0/fakelib présent)
//    ② Attente init process (dynld charge les sprx ~2s)
//    ③ jb_pid(loader) → accès /data (safety, souvent déjà fait par l'exploit)
//    ④ pt_attach(game) → process s'arrête
//    ⑤ jb_pid(game) → le process jeu peut voir /data via loadstartmodule
//    ⑥ inject_prx × N (synchrone, pas de frame_delay)
//    ⑦ pt_detach → jeu reprend normalement
//    ⑧ wait_for_pid_exit + cleanup fakelib
// ─────────────────────────────────────────────────────────────────────────────

static void inject_into_game(pid_t pid, const char *title_id,
                              const std::vector<PRXConfig> &prx_list,
                              const GameInjectorConfig &config)
{
    plugin_log("========================================");
    plugin_log("Injection dans %s (pid %d) — %zu PRX", title_id, pid, prx_list.size());
    plugin_log("========================================");

    // ── ① FAKELIB (jeux PS5 natifs PPSA uniquement) ───────────────────────
    char  sandbox_id[32] = {};
    char *fakelib_mount  = nullptr;

    auto fakelib_cfg    = config.fakelib_enabled.find(std::string(title_id));
    bool fakelib_wanted = (strncmp(title_id, "PPSA", 4) == 0) &&
                          (fakelib_cfg == config.fakelib_enabled.end() ||
                           fakelib_cfg->second);

    if (fakelib_wanted &&
        resolve_sandbox_id(title_id, sandbox_id, sizeof(sandbox_id)))
    {
        char fakelib_check[PATH_MAX];
        snprintf(fakelib_check, sizeof(fakelib_check),
                 "/mnt/sandbox/%s/app0/fakelib", sandbox_id);

        struct stat st;
        for (int t = 0; t < 30 && stat(fakelib_check, &st) != 0; t++)
            usleep(50000);

        if (stat(fakelib_check, &st) == 0) {
            plugin_log("[Fakelib] app0/fakelib trouvé, montage...");
            fakelib_mount = try_mount_fakelib(title_id, sandbox_id);
            if (!fakelib_mount)
                plugin_log("[Fakelib] montage échoué");
        } else {
            plugin_log("[Fakelib] Pas de app0/fakelib pour %s", title_id);
        }
    }

    // ── ② Attente + injection avec retry
    //  On essaie d'injecter dès que le process est prêt (handle > 0).
    //  La valeur ':' dans l'INI devient le délai entre chaque tentative (ms).
    //  Si handle < 0 → on attend delay_ms et on réessaie (max 60 tentatives = ~1 min).
    //  Dès que handle > 0 → PRX chargé, on passe au suivant.
    {
        int delay_ms = 10000; // défaut entre retry
        for (const auto &prx : prx_list)
            delay_ms = std::max(delay_ms, prx.delay_ms);

        plugin_log("[PT] Délai entre retry: %dms (valeur ':' dans l'INI)", delay_ms);

        // Attente initiale minimale — laisser dynld charger libkernel
        usleep(500000); // 500ms toujours, pour éviter pt_resolve = 0

        // jb du loader (accès /data)
        jb_pid(getpid());

        for (const auto &prx : prx_list)
        {
            const char *basename = strrchr(prx.path.c_str(), '/');
            basename = basename ? basename + 1 : prx.path.c_str();

            int  mod     = -1;
            int  attempt = 0;

            while (mod <= 0 && attempt < 60)
            {
                attempt++;
                plugin_log("[RETRY] %s — tentative %d/60", basename, attempt);

                // Attacher
                if (pt_attach(pid) < 0) {
                    plugin_log("[RETRY] pt_attach échoué, attente %dms...", delay_ms);
                    usleep(delay_ms * 1000);
                    continue;
                }

                if (jb_pid(pid) != 0) {
                    plugin_log("[RETRY] jb_pid échoué");
                    pt_detach(pid);
                    usleep(delay_ms * 1000);
                    continue;
                }

                // Tentative d'injection
                mod = inject_prx(pid, prx.path.c_str());

                pt_detach(pid);

                if (mod > 0) {
                    plugin_log("[RETRY] OK: %s (handle %d) à la tentative %d",
                               basename, mod, attempt);
                } else {
                    plugin_log("[RETRY] handle %d — attente %dms avant retry",
                               mod, delay_ms);
                    // Sortir si le process n'existe plus (jeu crashé / fermé)
                    if (!IsProcessRunning(pid)) {
                        plugin_log("[RETRY] process %d disparu, abandon", pid);
                        break;
                    }
                    usleep(delay_ms * 1000);
                }
            }

            if (mod <= 0)
                plugin_log("[RETRY] ECHEC définitif: %s après 60 tentatives", basename);
        }
    }

    // ── Attendre fermeture du jeu, puis cleanup fakelib ───────────────────
    plugin_log("[Wait] En attente fermeture jeu (pid %d)...", pid);
    wait_for_pid_exit(pid);

    if (fakelib_mount)
        cleanup_after_game(pid, sandbox_id, fakelib_mount);

    plugin_log("Jeu %s fermé — prêt pour prochain lancement", title_id);
}

// ─────────────────────────────────────────────────────────────────────────────
//  main — détection kqueue sur SceSysCore + boucle événements
// ─────────────────────────────────────────────────────────────────────────────

int main()
{
    plugin_log("=== SHADOW PRX TROPHEE BACKPORK LOADER v3.00 ===");

    // Initialisation kernel
    payload_args_t *args = payload_get_args();
    kernel_base   = args->kdata_base_addr;
    g_fw_version  = kernel_get_fw_version();

    uint32_t fw_major = (g_fw_version >> 24) & 0xFF;
    uint32_t fw_minor = (g_fw_version >> 16) & 0xFF;
    plugin_log("Kernel base: 0x%llx", (unsigned long long)kernel_base);
    plugin_log("FW détecté: 0x%08x (%x.%02x)", g_fw_version, fw_major, fw_minor);
    plugin_log("UCRED_ATTR0 offset: 0x%x",
               (g_fw_version >= 0x08000000u) ? 0x88u : 0x83u);

    // patch_shellcore (sauf si etaHEN a déjà tout fait)
    {
        struct stat eta_st{};
        bool eta_present = (stat("/download0/etahen_jailbreak", &eta_st) == 0);
        if (eta_present) {
            plugin_log("[SC_PATCH] etaHEN détecté → patch shellcore sauté");
        } else {
            if (!patch_shellcore_for_data())
                plugin_log("[SC_PATCH] Échec patch SceShellCore — /data restera sandboxé");
            usleep(750000);
        }
    }

    // Signals crash
    struct sigaction sa{};
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    for (int i = 0; i < 12; i++)
        sigaction(i, &sa, nullptr);

    // Trouver SceSysCore.elf
    pid_t syscore_pid = find_pid("SceSysCore.elf");
    if (syscore_pid == -1) {
        plugin_log("ERREUR: SceSysCore.elf introuvable");
        printf_notification("Plugin Loader: SceSysCore not found!     ");
        return -1;
    }
    plugin_log("SceSysCore.elf pid: %d", syscore_pid);

    // kqueue — surveille SceSysCore pour tout fork/exec
    int kq = kqueue();
    if (kq == -1) { perror("kqueue"); return -1; }

    struct kevent kev;
    EV_SET(&kev, syscore_pid, EVFILT_PROC,
           EV_ADD | EV_ENABLE | EV_CLEAR,
           NOTE_FORK | NOTE_EXEC | NOTE_TRACK, 0, nullptr);

    if (kevent(kq, &kev, 1, nullptr, 0, nullptr) == -1) {
        perror("kevent setup");
        close(kq);
        return -1;
    }

    printf_notification("Shadow-Prx-Loader FW: %x.%02x      \nVer:3.00 By @84Ciss",
                        fw_major, fw_minor);
    plugin_log("Surveillance SceSysCore.elf (pid %d)...", syscore_pid);

    pid_t child_pid = -1;

    // ── Boucle principale événements ──────────────────────────────────────
    while (1)
    {
        struct kevent ev;
        int nev = kevent(kq, nullptr, 0, &ev, 1, nullptr);

        if (nev < 0) { plugin_log("kevent error: %s", strerror(errno)); continue; }
        if (nev == 0) continue;

        // NOTE_CHILD : capturer le PID du child forké
        if (ev.fflags & NOTE_CHILD)
            child_pid = (pid_t)ev.ident;

        // NOTE_EXEC sur le child attendu → jeu lancé
        if ((ev.fflags & NOTE_EXEC) &&
            child_pid != -1 && (pid_t)ev.ident == child_pid)
        {
            app_info_t appinfo{};
            if (sceKernelGetAppInfo(child_pid, &appinfo) != 0) {
                plugin_log("sceKernelGetAppInfo échoué pour pid %d", child_pid);
                child_pid = -1;
                continue;
            }

            char title_id[10] = {};
            memcpy(title_id, appinfo.title_id, 9);

            // Filtrer : on ne traite que PPSA / CUSA / SCUS
            if (strncmp(title_id, "PPSA", 4) != 0 &&
                strncmp(title_id, "CUSA", 4) != 0 &&
                strncmp(title_id, "SCUS", 4) != 0)
            {
                child_pid = -1;
                continue;
            }

            plugin_log("Jeu détecté: %s (pid %d)", title_id, child_pid);

            GameInjectorConfig config = parse_injector_config();
            auto it = config.games.find(std::string(title_id));

            if (it == config.games.end()) {
                // Pas de PRX configuré pour ce titre → fakelib only (PPSA)
                plugin_log("Aucun PRX pour %s — fakelib only", title_id);

                char sid[32] = {};
                char *fml    = nullptr;
                auto fml_cfg = config.fakelib_enabled.find(std::string(title_id));
                bool fml_wanted = (strncmp(title_id, "PPSA", 4) == 0) &&
                                  (fml_cfg == config.fakelib_enabled.end() ||
                                   fml_cfg->second);

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
