// Plugin-Loader v3.04 — by @84Ciss
// Fusion: ptrace injection (ploader approach) + kqueue detection (v2.02)
//         + fakelib/unionfs + multi-PRX + patch_shellcore
//
// Remplace l'approche PLT hook (scePadReadState) par une injection ptrace
// directe : pt_attach → jb_pid → inject_prx (pthread transitoire, méthode HYPERHEN) → pt_detach
// Avantages : synchrone, pas de frame_delay, pas de PLT requis dans le jeu.

#include "utils.hpp"
#include <notify.hpp>
#include <time.h>
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
#include <stdint.h>

static bool IsProcessRunning(pid_t pid); // défini plus bas

extern "C" {
    int32_t sceKernelPrepareToSuspendProcess(pid_t pid);
    int32_t sceKernelSuspendProcess(pid_t pid);
    int32_t sceKernelPrepareToResumeProcess(pid_t pid);
    int32_t sceKernelResumeProcess(pid_t pid);
}

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
#define NID_PTHREAD_CREATE   "OxhIB8LB-PQ"   // pthread_create (HYPERHEN)

// AuthIDs process (bien connus, stables sur toutes FW PS5)
#define AUTHID_SYSTEM        0x4801000000000013ULL
#define AUTHID_DEBUGGER      0x4800000000010003ULL

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
//  Thread stub (porté de HYPERHEN / libonion_sprx)
//
//  Routine de départ d'un pthread transitoire créé dans le jeu. Son unique
//  argument (RDI) pointe sur un RemoteCtx :
//      [+0x00] adresse de sceKernelLoadStartModule
//      [+0x08] adresse du path du PRX
//      [+0x10] résultat (écrit par le stub)
//  Le stub appelle LoadStartModule(path,0,0,0,0,0), stocke RAX dans ctx->result
//  puis retourne normalement : le thread principal du jeu n'est JAMAIS bloqué
//  ni détourné (plus d'INT3 / PT_CONTINUE bloquant).
// ─────────────────────────────────────────────────────────────────────────────

static const uint8_t k_thread_stub[] = {
    0x55,                               // push rbp
    0x48, 0x89, 0xE5,                   // mov  rbp, rsp
    0x48, 0x83, 0xE4, 0xF0,             // and  rsp, -16
    0x48, 0x83, 0xEC, 0x30,             // sub  rsp, 0x30
    0x48, 0x89, 0x7C, 0x24, 0x20,       // mov  [rsp+0x20], rdi   (ctx)
    0x48, 0x8B, 0x07,                   // mov  rax, [rdi]        (LoadStartModule)
    0x48, 0x8B, 0x4F, 0x08,             // mov  rcx, [rdi+8]      (path)
    0x48, 0x89, 0xCF,                   // mov  rdi, rcx
    0x31, 0xF6,                         // xor  esi, esi
    0x31, 0xD2,                         // xor  edx, edx
    0x31, 0xC9,                         // xor  ecx, ecx
    0x45, 0x31, 0xC0,                   // xor  r8d, r8d
    0x45, 0x31, 0xC9,                   // xor  r9d, r9d
    0xFF, 0xD0,                         // call rax
    0x48, 0x8B, 0x54, 0x24, 0x20,       // mov  rdx, [rsp+0x20]
    0x48, 0x89, 0x42, 0x10,             // mov  [rdx+0x10], rax   (ctx->result)
    0x48, 0x89, 0xEC,                   // mov  rsp, rbp
    0x5D,                               // pop  rbp
    0xC3                                // ret
};

struct RemoteCtx {
    uint64_t load_start_module;
    uint64_t path;
    int64_t  result;
};

#define CTX_PENDING        INT64_MIN
#define CTX_PATH_OFFSET    0x100
#define INJ_PAGE_SIZE      0x1000
#define INJ_TIMEOUT_MS     30000
#define INJ_POLL_MS        100

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

// waitpid avec timeout (WNOHANG + poll 10ms)
static int waitpid_timeout(pid_t pid, int *status, int ms)
{
    for (int i = 0; i < ms / 10; i++) {
        pid_t res = waitpid(pid, status, WNOHANG);
        if (res == pid) return  1;
        if (res <   0) {
            if (errno == EINTR) continue;
            return -1;
        }
        usleep(10000);
    }
    return 0;
}

// Attente bornée d'un stop du process tracé (utilisé par pt_syscall / pt_call).
// Un wait infini + process arrêté = jeu gelé ET loader bloqué : on borne toujours.
static int pt_wait(pid_t pid, int *status, int ms)
{
    int st = 0;
    if (!status) status = &st;
    return (waitpid_timeout(pid, status, ms) > 0) ? 0 : -1;
}

static int pt_attach(pid_t pid)
{
    for (int i = 0; i < 5; i++) {
        if (sys_ptrace(PT_ATTACH, pid, 0, 0) == 0) {
            if (waitpid_timeout(pid, nullptr, 2000) > 0)
                return 0;
            // attach OK mais pas de stop reçu : ne PAS laisser le process tracé
            sys_ptrace(PT_DETACH, pid, (caddr_t)1, 0);
            usleep(300000);
            continue;
        }
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

// Lecture mémoire dans le process cible via ptrace I/O
static int pt_copyout(pid_t pid, intptr_t addr, void *buf, size_t len)
{
    struct ptrace_io_desc iod = {
        .piod_op   = PIOD_READ_D,
        .piod_offs = (void *)addr,
        .piod_addr = buf,
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

    if (pt_setregs(pid, &jmp)) { pt_setregs(pid, &bak); return -1; }

    // PT_STEP jusqu'au retour du syscall (RSP > RSP initial).
    // Borné (10000 pas, 1s par pas) : si l'offset +0xA est faux sur une FW,
    // on abandonne proprement au lieu de geler le jeu et le loader.
    bool done = false;
    for (int i = 0; i < 10000; i++) {
        int status = 0;
        if (sys_ptrace(PT_STEP, pid, (caddr_t)1, 0) ||
            pt_wait(pid, &status, 1000) ||
            !WIFSTOPPED(status) ||
            pt_getregs(pid, &jmp))
            break;
        if (jmp.r_rsp > bak.r_rsp) { done = true; break; }
    }

    long ret = done ? (long)jmp.r_rax : -1;
    pt_setregs(pid, &bak);
    return ret;
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
// `trap` = adresse (dans le process cible) d'un octet 0xCC : elle est poussée
// comme adresse de retour, donc quand `fn` fait `ret` on s'arrête sur INT3
// (SIGTRAP) et on lit RAX. Sans ça, `fn` retournerait dans du code aléatoire
// du jeu (contrairement au shellcode du ploader qui contient lui-même le 0xCC).
// ─────────────────────────────────────────────────────────────────────────────
//  suspend_game : pendant l'appel distant, tous les AUTRES threads du jeu restent
//  suspendus (PT_SUSPEND) — seul le thread détourné s'exécute. Le jeu est donc
//  "en pause" pendant le chargement du PRX (pas de course avec les scripts).
// ─────────────────────────────────────────────────────────────────────────────
#ifndef PT_GETNUMLWPS
#define PT_GETNUMLWPS 14
#endif
#ifndef PT_GETLWPLIST
#define PT_GETLWPLIST 15
#endif
#ifndef PT_SUSPEND
#define PT_SUSPEND 18
#endif
#ifndef PT_RESUME
#define PT_RESUME 19
#endif

#ifndef PT_GETFPREGS
#define PT_GETFPREGS 35
#endif
#ifndef PT_SETFPREGS
#define PT_SETFPREGS 36
#endif

static bool g_suspend_others = false;

static std::vector<int> suspend_other_threads(pid_t pid)
{
    std::vector<int> done;
    int n = sys_ptrace(PT_GETNUMLWPS, pid, 0, 0);
    if (n <= 1) {
        plugin_log("[SUSPEND] PT_GETNUMLWPS → %d (rien à suspendre ou non supporté)", n);
        return done;
    }
    std::vector<int> lwps(n);
    int got = sys_ptrace(PT_GETLWPLIST, pid, (caddr_t)lwps.data(), n);
    if (got <= 1) {
        plugin_log("[SUSPEND] PT_GETLWPLIST → %d (non supporté ?)", got);
        return done;
    }
    // lwps[0] = thread principal (celui dont on modifie les registres) : on le laisse tourner
    for (int i = 1; i < got; i++)
        if (sys_ptrace(PT_SUSPEND, lwps[i], 0, 0) == 0)
            done.push_back(lwps[i]);
    plugin_log("[SUSPEND] %zu/%d thread(s) du jeu suspendus pendant le chargement",
               done.size(), got - 1);
    return done;
}

static void resume_threads(const std::vector<int> &v)
{
    for (int t : v) sys_ptrace(PT_RESUME, t, 0, 0);
    if (!v.empty()) plugin_log("[SUSPEND] %zu thread(s) relancés", v.size());
}

static long pt_call(pid_t pid, intptr_t fn, intptr_t trap,
                     uint64_t a1, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5, uint64_t a6,
                     int timeout_ms = 10000)
{
    struct reg jmp, bak;
    if (!fn || !trap) return -1;
    if (pt_getregs(pid, &bak)) return -1;

    // Sauvegarde de l'état SSE/FPU du thread détourné : le thread peut être interrompu
    // n'importe où (xmm0-15 vivants) et le chargement du PRX les écraserait.
    alignas(16) uint8_t fpbak[1024];
    memset(fpbak, 0, sizeof(fpbak));
    bool have_fp = sys_ptrace(PT_GETFPREGS, pid, (caddr_t)fpbak, 0) == 0;
    plugin_log("[PT] thread détourné: rip=0x%llx rsp=0x%llx fpregs=%s",
               (unsigned long long)bak.r_rip, (unsigned long long)bak.r_rsp,
               have_fp ? "sauvegardés" : "NON disponibles");
    auto restore_all = [&]() {
        pt_setregs(pid, &bak);
        if (have_fp) sys_ptrace(PT_SETFPREGS, pid, (caddr_t)fpbak, 0);
    };

    // Sauter la red zone (128o) puis aligner : à l'entrée d'une fonction
    // SysV, (rsp + 8) % 16 == 0, avec l'adresse de retour à [rsp].
    uint64_t sp = ((bak.r_rsp - 0x200) & ~0xFULL) - 8;
    uint64_t ra = (uint64_t)trap;
    if (pt_copyin(pid, &ra, (intptr_t)sp, sizeof(ra)) < 0) return -1;

    jmp       = bak;
    jmp.r_rsp = sp;
    jmp.r_rip = fn;
    jmp.r_rdi = a1; jmp.r_rsi = a2; jmp.r_rdx = a3;
    jmp.r_rcx = a4; jmp.r_r8  = a5; jmp.r_r9  = a6;

    if (pt_setregs(pid, &jmp)) { restore_all(); return -1; }

    std::vector<int> frozen;
    if (g_suspend_others) frozen = suspend_other_threads(pid);

    if (sys_ptrace(PT_CONTINUE, pid, (caddr_t)1, 0) < 0) {
        resume_threads(frozen);
        restore_all();
        return -1;
    }

    // pthread_create rend la main en quelques ms ; 10s est très large.
    int status = 0;
    if (pt_wait(pid, &status, timeout_ms) ||
        !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
    {
        resume_threads(frozen);
        restore_all();
        return -1;
    }
    resume_threads(frozen);

    long ret = -1;
    if (pt_getregs(pid, &jmp) == 0)
        ret = (long)jmp.r_rax;
    restore_all();
    return ret;
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
//  Snapshot / restauration des credentials du jeu (restore_sandbox)
//  Sans restauration, le jeu garde pour toujours authid SYSTEM, caps = -1 et
//  rootdir/jaildir = root vnode → comportement instable / crash selon le timing.
// ─────────────────────────────────────────────────────────────────────────────

struct CredSnap {
    uint32_t uid, ruid, svuid, ngroups, rgid, svgid;
    uint64_t authid, caps0, caps1;
    uint8_t  attr;
    intptr_t rootdir, jaildir;
};

static uint32_t ucred_attr_off() { return (g_fw_version >= 0x08000000u) ? 0x88u : 0x83u; }

static int save_creds(intptr_t ucred, CredSnap *o, pid_t pid)
{
    if (!ucred || !o || pid <= 1) return -1;
    if (kernel_copyout(ucred + UCRED_UID,     &o->uid,     4) < 0) return -1;
    if (kernel_copyout(ucred + UCRED_RUID,    &o->ruid,    4) < 0) return -1;
    if (kernel_copyout(ucred + UCRED_SVUID,   &o->svuid,   4) < 0) return -1;
    if (kernel_copyout(ucred + UCRED_NGROUPS, &o->ngroups, 4) < 0) return -1;
    if (kernel_copyout(ucred + UCRED_RGID,    &o->rgid,    4) < 0) return -1;
    if (kernel_copyout(ucred + UCRED_SVGID,   &o->svgid,   4) < 0) return -1;
    if (kernel_copyout(ucred + UCRED_AUTHID,  &o->authid,  8) < 0) return -1;
    if (kernel_copyout(ucred + UCRED_CAPS0,   &o->caps0,   8) < 0) return -1;
    if (kernel_copyout(ucred + UCRED_CAPS1,   &o->caps1,   8) < 0) return -1;
    if (kernel_copyout(ucred + ucred_attr_off(), &o->attr, 1) < 0) return -1;
    o->rootdir = kernel_get_proc_rootdir(pid);
    o->jaildir = kernel_get_proc_jaildir(pid);
    return (o->rootdir && o->jaildir) ? 0 : -1;
}

static int restore_creds(intptr_t ucred, const CredSnap *o, pid_t pid)
{
    if (!ucred || !o || pid <= 1) return -1;
    if (kernel_copyin(&o->uid,     ucred + UCRED_UID,     4) < 0) return -1;
    if (kernel_copyin(&o->ruid,    ucred + UCRED_RUID,    4) < 0) return -1;
    if (kernel_copyin(&o->svuid,   ucred + UCRED_SVUID,   4) < 0) return -1;
    if (kernel_copyin(&o->ngroups, ucred + UCRED_NGROUPS, 4) < 0) return -1;
    if (kernel_copyin(&o->rgid,    ucred + UCRED_RGID,    4) < 0) return -1;
    if (kernel_copyin(&o->svgid,   ucred + UCRED_SVGID,   4) < 0) return -1;
    if (kernel_copyin(&o->authid,  ucred + UCRED_AUTHID,  8) < 0) return -1;
    if (kernel_copyin(&o->caps0,   ucred + UCRED_CAPS0,   8) < 0) return -1;
    if (kernel_copyin(&o->caps1,   ucred + UCRED_CAPS1,   8) < 0) return -1;
    if (kernel_copyin(&o->attr,    ucred + ucred_attr_off(), 1) < 0) return -1;
    kernel_set_proc_rootdir(pid, o->rootdir);
    kernel_set_proc_jaildir(pid, o->jaildir);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  inject_prx_sync — méthode ploader : sceKernelLoadStartModule(path) est appelé
//  DIRECTEMENT dans le thread du jeu (process attaché), module_start inclus.
//  Retourne le handle (> 0) ou -1. Process toujours attaché en sortie.
// ─────────────────────────────────────────────────────────────────────────────

static const uint8_t k_sync_stub[] = {
    0x55, 0x48,0x89,0xE5, 0x48,0x83,0xE4,0xF0, 0x48,0x83,0xEC,0x28,
    0x49,0xBF, 0,0,0,0,0,0,0,0,            // mov r15, <LoadStartModule> (offset 14)
    0x31,0xF6, 0x31,0xD2, 0x31,0xC9, 0x45,0x31,0xC0, 0x45,0x31,0xC9,
    0x41,0xFF,0xD7,                         // call r15
    0x48,0x89,0xEC, 0x5D, 0xCC              // leave ; int3
};

static int inject_prx_sync(pid_t pid, const char *prx_path)
{
    if (access(prx_path, R_OK) != 0) {
        plugin_log("[INJ] Fichier inaccessible: %s (errno %d)", prx_path, errno);
        return -1;
    }
    intptr_t fn = pt_resolve(pid, NID_LOADSTARTMODULE);
    if (!fn) {
        plugin_log("[INJ] pt_resolve(LoadStartModule) échoué — libkernel pas prêt ?");
        return -1;
    }
    intptr_t page = pt_mmap(pid, 0, 0x4000, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page <= 0) {
        plugin_log("[INJ] pt_mmap échoué (%ld)", (long)page);
        return -1;
    }
    intptr_t remote_path = page;
    intptr_t remote_sc   = page + 0x1000;
    int mod = -1;

    uint8_t sc[sizeof(k_sync_stub)];
    memcpy(sc, k_sync_stub, sizeof(sc));
    memcpy(sc + 14, &fn, sizeof(fn));

    if (pt_copyin(pid, prx_path, remote_path, strlen(prx_path) + 1) >= 0 &&
        pt_copyin(pid, sc, remote_sc, sizeof(sc)) >= 0)
    {
        kernel_mprotect(pid, remote_sc, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
        // le stub se termine par son propre INT3 ; `trap` n'est que l'adresse de retour factice
        long rc = pt_call(pid, remote_sc, remote_sc + sizeof(sc) - 1,
                          (uint64_t)remote_path, 0, 0, 0, 0, 0, 30000);
        mod = (int)rc;
        plugin_log("[INJ] (sync) sceKernelLoadStartModule → %d (0x%lx)", mod, (unsigned long)rc);
        kernel_mprotect(pid, remote_sc, 0x1000, PROT_READ | PROT_WRITE);
    } else {
        plugin_log("[INJ] (sync) pt_copyin échoué");
    }
    pt_munmap(pid, page, 0x4000);
    return mod;
}

// ─────────────────────────────────────────────────────────────────────────────
//  inject_prx — injection ptrace d'un seul PRX dans le process cible
//  (méthode HYPERHEN : pthread transitoire, ne bloque pas le jeu)
//
//  Contrat inchangé : le process est attaché à l'entrée ET à la sortie
//  (l'appelant fait pt_detach). Retourne le handle du module (> 0) ou -1.
//
//  Flow:
//   1. 3 pages anonymes : contexte+path / stub / pthread_t  (pt_mmap)
//   2. Écrire ctx + path + stub, stub en RWX (kernel_mprotect)
//   3. pt_call(pthread_create) → le thread appelle sceKernelLoadStartModule
//   4. pt_detach : le jeu tourne librement pendant le chargement
//   5. Poll kernel_dynlib_handle jusqu'à ce que le module apparaisse
//   6. pt_attach, lecture de ctx->result, pt_munmap des 3 pages
// ─────────────────────────────────────────────────────────────────────────────

static int inject_prx(pid_t pid, const char *prx_path)
{
    if (access(prx_path, R_OK) != 0) {
        plugin_log("[INJ] Fichier inaccessible: %s (errno %d)", prx_path, errno);
        return -1;
    }

    const char *mod_name = strrchr(prx_path, '/');
    mod_name = mod_name ? mod_name + 1 : prx_path;

    size_t plen = strlen(prx_path) + 1;
    if (plen > INJ_PAGE_SIZE - CTX_PATH_OFFSET) {
        plugin_log("[INJ] Path trop long (%zu)", plen);
        return -1;
    }

    intptr_t load_fn = pt_resolve(pid, NID_LOADSTARTMODULE);
    intptr_t pthr_fn = pt_resolve(pid, NID_PTHREAD_CREATE);
    if (!load_fn || !pthr_fn) {
        plugin_log("[INJ] pt_resolve échoué (load=0x%lx pthread_create=0x%lx) — libkernel pas encore chargé ?",
                   (unsigned long)load_fn, (unsigned long)pthr_fn);
        return -1;
    }
    plugin_log("[INJ] LoadStartModule @ 0x%lx, pthread_create @ 0x%lx",
               (unsigned long)load_fn, (unsigned long)pthr_fn);

    intptr_t ctx_page    = pt_mmap(pid, 0, INJ_PAGE_SIZE, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    intptr_t code_page   = pt_mmap(pid, 0, INJ_PAGE_SIZE, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    intptr_t thread_page = pt_mmap(pid, 0, INJ_PAGE_SIZE, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ctx_page <= 0 || code_page <= 0 || thread_page <= 0) {
        plugin_log("[INJ] pt_mmap échoué (ctx=%ld code=%ld thread=%ld)",
                   (long)ctx_page, (long)code_page, (long)thread_page);
        if (ctx_page    > 0) pt_munmap(pid, ctx_page,    INJ_PAGE_SIZE);
        if (code_page   > 0) pt_munmap(pid, code_page,   INJ_PAGE_SIZE);
        if (thread_page > 0) pt_munmap(pid, thread_page, INJ_PAGE_SIZE);
        return -1;
    }

    auto free_pages = [&]() {
        pt_munmap(pid, ctx_page,    INJ_PAGE_SIZE);
        pt_munmap(pid, code_page,   INJ_PAGE_SIZE);
        pt_munmap(pid, thread_page, INJ_PAGE_SIZE);
    };

    RemoteCtx ctx;
    ctx.load_start_module = (uint64_t)load_fn;
    ctx.path              = (uint64_t)(ctx_page + CTX_PATH_OFFSET);
    ctx.result            = CTX_PENDING;

    if (pt_copyin(pid, &ctx,     ctx_page,            sizeof(ctx)) < 0 ||
        pt_copyin(pid, prx_path, (intptr_t)ctx.path,  plen)        < 0 ||
        pt_copyin(pid, k_thread_stub, code_page,      sizeof(k_thread_stub)) < 0)
    {
        plugin_log("[INJ] pt_copyin échoué");
        free_pages();
        return -1;
    }

    // Stub exécutable (le kernel bypasse les protections)
    kernel_mprotect(pid, code_page, INJ_PAGE_SIZE,
                    PROT_READ | PROT_WRITE | PROT_EXEC);

    // Octet INT3 servant d'adresse de retour à pt_call (après le stub, même page RWX)
    const intptr_t trap_addr = code_page + 0x800;
    const uint8_t  int3      = 0xCC;
    if (pt_copyin(pid, &int3, trap_addr, 1) < 0) {
        plugin_log("[INJ] écriture INT3 échouée");
        free_pages();
        return -1;
    }

    // pthread_create(&thread, NULL, stub, ctx)
    long trc = pt_call(pid, pthr_fn, trap_addr, (uint64_t)thread_page, 0,
                       (uint64_t)code_page, (uint64_t)ctx_page, 0, 0);
    if (trc != 0) {
        plugin_log("[INJ] pthread_create échoué (rc=%ld)", trc);
        free_pages();
        return -1;
    }
    plugin_log("[INJ] Thread de chargement lancé pour %s", mod_name);

    // Le jeu reprend : le thread charge le PRX pendant que le jeu tourne
    pt_detach(pid);

    int      handle   = -1;
    bool     loaded   = false;
    uint32_t h        = 0;
    for (int waited = 0; waited < INJ_TIMEOUT_MS; waited += INJ_POLL_MS) {
        if (!IsProcessRunning(pid))
            break;
        if (kernel_dynlib_handle(pid, mod_name, &h) == 0 && h != 0) {
            loaded = true;
            handle = (int)h;
            break;
        }
        usleep(INJ_POLL_MS * 1000);
    }

    // Ré-attacher (contrat : attaché en sortie) puis lire le résultat.
    // Le handle apparaît dès le mapping, AVANT la fin de module_start : on attend
    // que le thread ait terminé (max ~10 s) pour ne pas restaurer les creds trop tôt.
    RemoteCtx fin;
    fin.result = CTX_PENDING;
    bool read_ok = false;
    for (int i = 0; i < 20; i++) {
        if (!IsProcessRunning(pid) || pt_attach(pid) < 0) {
            plugin_log("[INJ] ré-attache impossible — pages temporaires conservées");
            return loaded ? handle : -1;
        }
        read_ok = pt_copyout(pid, ctx_page, &fin, sizeof(fin)) == 0;
        if (read_ok && fin.result != CTX_PENDING) break;
        if (i == 19) break;            // on sort attaché (contrat)
        pt_detach(pid);
        usleep(500000);
    }
    if (read_ok && fin.result != CTX_PENDING) {
        plugin_log("[INJ] sceKernelLoadStartModule → 0x%lx", (long)fin.result);
        if (!loaded && fin.result > 0 && fin.result < 0x7fffffff) {
            handle = (int)fin.result;
            loaded = true;
        }
        // Le thread a fini : on peut libérer les pages en sécurité
        free_pages();
    } else {
        // Thread encore actif (ou lecture KO) : ne JAMAIS unmap le stub
        plugin_log("[INJ] thread non terminé (timeout/lecture) — pages conservées");
    }

    if (!loaded)
        plugin_log("[INJ] %s non chargé", mod_name);
    return loaded ? handle : -1;
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

    // ── ②a Méthode PLT (v2.02) : hook scePadReadState, chargement par le thread du jeu
    //  Le process est suspendu pendant l'installation du hook, puis relancé :
    //  le PRX est chargé par le jeu lui-même au premier scePadReadState.
    {
        std::vector<const PRXConfig *> plt_list;
        for (const auto &prx : prx_list)
            if (prx.plt) plt_list.push_back(&prx);

        if (!plt_list.empty()) {
            plugin_log("[PLT] Attente initialisation process...");
            int alive = 0;
            for (int i = 0; i < 10; i++) {
                usleep(100000);
                if (IsProcessRunning(pid)) alive++;
            }
            plugin_log("[PLT] Process alive: %d/10", alive);

            UniquePtr<Hijacker> hijacker = Hijacker::getHijacker(pid);
            if (!hijacker) {
                plugin_log("[PLT] Hijacker: 1re tentative échouée, retry dans 1s...");
                sleep(1);
                hijacker = Hijacker::getHijacker(pid);
            }

            int success_count = 0;
            if (hijacker) {
                uint64_t text_base = hijacker->getEboot()->imagebase();
                plugin_log("[PLT] Hijacker OK - text_base: 0x%llx", text_base);

                sceKernelPrepareToSuspendProcess(pid);
                sceKernelSuspendProcess(pid);
                usleep(750000);

                for (size_t i = 0; i < plt_list.size(); i++) {
                    const PRXConfig &prx = *plt_list[i];
                    plugin_log("[PLT] Injection: %s", prx.path.c_str());

                    uintptr_t stuff_addr = 0;
                    if (HookGame(hijacker, text_base, prx.path.c_str(), false, 300, &stuff_addr)) {
                        plugin_log("[PLT] Hook OK: %s | stuff_addr: 0x%llx", prx.path.c_str(), stuff_addr);
                        success_count++;

                        sceKernelPrepareToResumeProcess(pid);
                        sceKernelResumeProcess(pid);
                        sleep(3);   // laisse le jeu charger le PRX

                        if (i + 1 < plt_list.size()) {
                            sceKernelPrepareToSuspendProcess(pid);
                            sceKernelSuspendProcess(pid);
                            usleep(2500000);
                        }
                    } else {
                        plugin_log("[PLT] ECHEC hook: %s", prx.path.c_str());
                    }
                }

                usleep(500000);
                sceKernelPrepareToResumeProcess(pid);
                sceKernelResumeProcess(pid);
                plugin_log("[PLT] %d/%zu PRX injectés", success_count, plt_list.size());
            } else {
                plugin_log("[PLT] ECHEC création Hijacker pour pid %d", pid);
            }
        }
    }

    // ── ② Attente + injection avec retry
    //  delay_ms (PluginLoader.toml) = délai INITIAL avant la 1re tentative,
    //  compté depuis le lancement du jeu (comme l'ancien "prx:10000" de l'INI).
    //  Si l'injection échoue (libkernel pas prêt, etc.), on réessaie toutes
    //  les RETRY_INTERVAL_MS, max 60 tentatives.
    {
        const int RETRY_INTERVAL_MS = 1000;
        const time_t t_start = time(nullptr);

        usleep(750000);

        // jb du loader (accès /data)
        jb_pid(getpid());

        for (const auto &prx : prx_list)
        {
            if (prx.plt) continue;   // déjà traité par la méthode PLT
            const char *basename = strrchr(prx.path.c_str(), '/');
            basename = basename ? basename + 1 : prx.path.c_str();
               
            // Attends que le PRX se charge (~2-3 secondes)
            sleep(3);
            
            // Fichier absent ? On ne touche surtout pas au jeu (pas de ptrace).
            if (access(prx.path.c_str(), R_OK) != 0) {
                plugin_log("[INJ] PRX introuvable: '%s' (errno %d) — injection annulée, jeu non touché",
                           prx.path.c_str(), errno);
                printf_notification("Plugin Loader: PRX introuvable!\n%s", basename);
                continue;
            }

            // Attendre que delay_ms se soit écoulé depuis le lancement du jeu,
            // SANS toucher au process (pas de ptrace pendant le boot).
            plugin_log("[PT] %s — délai initial %dms depuis le lancement", basename, prx.delay_ms);
            bool gone = false;
            if ((long)(time(nullptr) - t_start) * 1000 < (long)prx.delay_ms) {
                if (!IsProcessRunning(pid)) { gone = true; break; }
                sceKernelPrepareToSuspendProcess(pid);
                sceKernelSuspendProcess(pid);
                usleep(250000);
            }
            if (gone) {
                plugin_log("[RETRY] process %d disparu pendant le délai, abandon", pid);
                break;
            }

            // Final resume
            usleep(500000);
            sceKernelPrepareToResumeProcess(pid);
            sceKernelResumeProcess(pid);
    
            int  mod     = -1;
            int  attempt = 0;

            if (mod <= 0 && attempt < 60)
            {
                attempt++;
                plugin_log("[RETRY] %s — tentative %d/60", basename, attempt);

                if (pt_attach(pid) < 0) {
                    plugin_log("[RETRY] pt_attach échoué, attente %dms...", RETRY_INTERVAL_MS);
                    usleep(RETRY_INTERVAL_MS * 1000);
                    continue;
                }

                intptr_t ucred = kernel_get_proc_ucred(pid);
                CredSnap snap{};
                if (!ucred || save_creds(ucred, &snap, pid) != 0) {
                    plugin_log("[RETRY] snapshot credentials échoué");
                    pt_detach(pid);
                    usleep(RETRY_INTERVAL_MS * 1000);
                    continue;
                }

                if (jb_pid(pid) != 0) {
                    plugin_log("[RETRY] jb_pid échoué");
                    restore_creds(ucred, &snap, pid);
                    pt_detach(pid);
                    usleep(RETRY_INTERVAL_MS * 1000);
                    continue;
                }

                g_suspend_others = prx.suspend_game;
                mod = prx.sync_load ? inject_prx_sync(pid, prx.path.c_str())
                                    : inject_prx(pid, prx.path.c_str());

                if (prx.restore_sandbox || mod <= 0) {
                    if (restore_creds(ucred, &snap, pid) != 0)
                        plugin_log("[RETRY] restauration credentials ÉCHOUÉE");
                    else
                        plugin_log("[RETRY] credentials restaurés (restore_sandbox=%d, mod=%d)",
                                   (int)prx.restore_sandbox, mod);
                } else {
                    plugin_log("[RETRY] restore_sandbox=false → creds jailbreak conservés");
                }

                pt_detach(pid);

                if (mod > 0) {
                    plugin_log("[RETRY] OK: %s (handle %d) à la tentative %d",
                               basename, mod, attempt);
                } else {
                    plugin_log("[RETRY] handle %d — attente %dms avant retry",
                               mod, RETRY_INTERVAL_MS);
                    if (!IsProcessRunning(pid)) {
                        plugin_log("[RETRY] process %d disparu, abandon", pid);
                        break;
                    }
                    usleep(RETRY_INTERVAL_MS * 1000);
                }
            }
            
            if (mod <= 0)
                plugin_log("[RETRY] ECHEC définitif: %s après %d tentatives", basename, attempt);
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
    plugin_log("=== SHADOW PRX TROPHEE BACKPORK LOADER v3.04 ===");

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

    printf_notification("Shadow-Prx-Loader FW: %x.%02x      \nVer:3.04 By @84Ciss",
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
