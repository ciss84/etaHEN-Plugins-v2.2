// Plugin-Loader v3.00 — By @84Ciss and @NoLimit.Turno
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
#include <nid.hpp>

#include <dirent.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/event.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <machine/reg.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
#define GTAVEE_PUSH_EVENT_HOOK_COUNT 9

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
#define UCRED_ATTRS   0x80
#define UCRED_ATTR_PTRACE_INDEX 3

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

// Shared-memory counters written by tiny entry shims in the game process. The
// first 19 entries cover LSO's NP-state replacements and the final 8 cover
// the game's direct sceNpWebApi2 import slots. No URLs, tokens, request bodies,
// pointers, or return values are copied.
#define LSO_CALL_MONITOR_MAX 27

typedef struct lso_call_trace_entry {
    uint32_t call_count;
    uint32_t reserved;
    uint64_t last_result;
} lso_call_trace_entry_t;

typedef struct lso_call_trace_record {
    lso_call_trace_entry_t entries[LSO_CALL_MONITOR_MAX];
} lso_call_trace_record_t;

static_assert(sizeof(lso_call_trace_record_t) ==
                  LSO_CALL_MONITOR_MAX * 16,
              "LSO call trace entry layout changed");

// Passive, result-preserving observations of GTA E&E's nine native
// sceNpWebApi2 PushEvent imports. These calls are not redirected by LSO, and
// their exact return values are the remaining unmeasured prerequisite between
// the successful BlueSphere login and GTA's first Rockstar connection.
typedef struct gtavee_push_event_trace_entry {
    uint32_t sequence;
    uint32_t call_count;
    int32_t  last_result;
    uint32_t reserved;
    uint64_t arg0;
    uint64_t arg1;
} gtavee_push_event_trace_entry_t;

typedef struct gtavee_push_event_trace_record {
    gtavee_push_event_trace_entry_t entries[GTAVEE_PUSH_EVENT_HOOK_COUNT];
} gtavee_push_event_trace_record_t;

static_assert(sizeof(gtavee_push_event_trace_entry_t) == 32,
              "GTA PushEvent trace entry layout changed");

// Two low-frequency boundaries used to distinguish name resolution from the
// actual TCP connection. The wrappers retain every argument and return value;
// only a call count, result, hostname classification, and sockaddr are exposed
// to the loader log.
#define LSO_NET_BOUNDARY_COUNT 2

typedef struct lso_net_boundary_entry {
    uint32_t call_count;
    uint32_t reserved;
    int64_t  last_result;
    uint64_t arg0;
    uint64_t arg1;
    uint8_t  data[16];
} lso_net_boundary_entry_t;

typedef struct lso_net_boundary_record {
    lso_net_boundary_entry_t entries[LSO_NET_BOUNDARY_COUNT];
} lso_net_boundary_record_t;

static_assert(sizeof(lso_net_boundary_entry_t) == 48,
              "LSO network boundary entry layout changed");

// Three low-level libSceHttp boundaries used by GTA's Rockstar client.  The
// connection record keeps only a short URL prefix in game memory; the loader
// reports a host classification and never prints the URL or request content.
#define GTA_HTTP_BOUNDARY_COUNT 3

static constexpr intptr_t k_gta_http_import_slots[GTA_HTTP_BOUNDARY_COUNT] = {
    0x3cb1c88, // sceHttpCreateConnectionWithURL
    0x3cb1ca0, // sceHttpSendRequest
    0x3cb1ca8, // sceHttpGetStatusCode
};

typedef struct gta_http_boundary_entry {
    uint32_t call_count;
    uint32_t reserved;
    int64_t  last_result;
    uint64_t arg0;
    uint64_t arg1;
    uint8_t  data[64];
} gta_http_boundary_entry_t;

typedef struct gta_http_boundary_record {
    gta_http_boundary_entry_t entries[GTA_HTTP_BOUNDARY_COUNT];
} gta_http_boundary_record_t;

static_assert(sizeof(gta_http_boundary_entry_t) == 96,
              "GTA HTTP boundary entry layout changed");

[[maybe_unused]] static bool install_gta_http_boundary_trace(
    pid_t pid, intptr_t *trace_record_out);

[[maybe_unused]] static bool gta_http_import_targets_ready(pid_t pid)
{
    for (int i = 0; i < GTA_HTTP_BOUNDARY_COUNT; i++) {
        intptr_t target = 0;
        if (kernel_proc_copyout(pid, k_gta_http_import_slots[i], &target,
                                sizeof(target)) < 0 || target < 0x10000)
            return false;
    }
    return true;
}

// Three narrowly scoped counters for the C++ WebAPI request boundary. The
// first entry records the FW 8.60 compatibility dispatch performed directly
// after CreateRequest; the remaining entries observe the native C++ worker.
// A seqlock-style field rejects samples taken during an update.
#define LSO_CPP_BOUNDARY_COUNT 3

typedef struct lso_cpp_boundary_entry {
    uint32_t sequence;
    uint32_t call_count;
    uint64_t last_request_id;
    int32_t  last_result;
    uint32_t reserved;
} lso_cpp_boundary_entry_t;

typedef struct lso_cpp_boundary_record {
    lso_cpp_boundary_entry_t entries[LSO_CPP_BOUNDARY_COUNT];
} lso_cpp_boundary_record_t;

static_assert(sizeof(lso_cpp_boundary_record_t) == 72,
              "LSO C++ boundary trace layout changed");

// Read-only view of LSO 1.010.002's request table. These offsets were
// verified from the supplied PRX. No request URL, header, body, response data,
// token, or pointer is copied into the loader log.
#define LSO_REQUEST_SLOT_COUNT          32
#define LSO_REQUEST_NEXT_ID_OFFSET      0x28778ULL
#define LSO_REQUEST_TABLE_OFFSET        0x288f0ULL
#define LSO_REQUEST_RECORD_STRIDE       0xa200ULL
#define LSO_REQUEST_API_GROUP_OFFSET    0x8ULL
#define LSO_REQUEST_PATH_OFFSET         0x68ULL
#define LSO_REQUEST_METHOD_OFFSET       0x168ULL
#define LSO_REQUEST_BODY_SIZE_OFFSET    0x21d8ULL
#define LSO_REQUEST_RESPONSE_DATA_OFFSET 0x21e8ULL
#define LSO_REQUEST_RESPONSE_TAIL_OFFSET 0xa1e8ULL

// LSO's authenticated WebAPI proxy reads these exact globals before adding
// Authorization, X-OnlineId, and X-AccountId. Only lengths/presence are logged.
#define LSO_ACCOUNT_ID_OFFSET           0x28018ULL
#define LSO_AUTH_TOKEN_STRING_OFFSET    0x28798ULL
#define LSO_ONLINE_ID_STRING_OFFSET     0x287c0ULL
#define LSO_RELAY_TOKEN_STRING_OFFSET   0x287e8ULL
#define LSO_SEND_REQUEST_CORE_OFFSET    0x12f50ULL

typedef struct lso_request_tail {
    uint64_t response_size;
    uint64_t read_offset;
    int32_t  http_status;
    uint8_t  complete;
    uint8_t  response_ready;
    uint16_t reserved;
} lso_request_tail_t;

static_assert(sizeof(lso_request_tail_t) == 24,
              "LSO request-tail layout changed");

typedef struct lso_request_snapshot {
    uint64_t id;
    uint64_t body_size;
    lso_request_tail_t tail;
} lso_request_snapshot_t;

static void sanitize_lso_request_label(char *text, size_t capacity,
                                       bool redact_path_numbers)
{
    if (!text || capacity == 0) return;
    text[capacity - 1] = '\0';
    for (size_t i = 0; i + 1 < capacity && text[i] != '\0'; i++) {
        const unsigned char ch = (unsigned char)text[i];
        if (text[i] == '?' || text[i] == '#') {
            text[i] = '\0';
            break;
        }
        if (redact_path_numbers && text[i] >= '0' && text[i] <= '9') {
            text[i] = '#';
        } else if (ch < 0x20 || ch > 0x7e || text[i] == '"') {
            text[i] = '.';
        }
    }
}

// Retained for the unused earlier diagnostic routine below. This build does
// not install that routine's HTTP detours.
typedef struct lso_http_trace_record {
    uint32_t sequence;
    int32_t  result;
    int32_t  status;
    uint32_t stage;
    char     message[496];
} lso_http_trace_record_t;

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

// Localise l'instruction SYSCALL dans le wrapper getpid du process cible.
// Le wrapper est résolu par NID, puis lu via la primitive kernel : cela évite
// de dépendre d'un offset d'instruction propre à une version de libkernel.
static intptr_t pt_find_syscall(pid_t pid, intptr_t wrapper)
{
    uint8_t code[32] = {};
    if (kernel_proc_copyout(pid, wrapper, code, sizeof(code)) < 0)
        return 0;

    for (size_t i = 0; i + 1 < sizeof(code); i++) {
        if (code[i] == 0x0F && code[i + 1] == 0x05)
            return wrapper + (intptr_t)i;
    }
    return 0;
}

// Exécution d'un syscall dans le process cible via injection de registres.
// On redirige RIP vers l'instruction SYSCALL trouvée dans getpid().
static long pt_syscall(pid_t pid, int sysno,
                        uint64_t a1, uint64_t a2, uint64_t a3,
                        uint64_t a4, uint64_t a5, uint64_t a6)
{
    intptr_t wrapper = pt_resolve(pid, NID_GETPID);
    if (!wrapper) return -1;

    intptr_t addr = pt_find_syscall(pid, wrapper);
    if (!addr) {
        plugin_log("[PT] SYSCALL instruction not found in getpid (pid %d)", pid);
        return -1;
    }

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
//  jb_pid — jailbreak temporaire d'un process via manipulation ucred kernel
// ─────────────────────────────────────────────────────────────────────────────

struct SavedGameCredentials {
    bool      valid;
    uint32_t  uid;
    uint32_t  ruid;
    uint32_t  svuid;
    uint32_t  ngroups;
    uint32_t  rgid;
    uint32_t  svgid;
    uint64_t  authid;
    uint8_t   caps[16];
    uint8_t   attrs[32];
    intptr_t  rootdir;
    intptr_t  jaildir;
};

static int save_game_credentials(pid_t pid, SavedGameCredentials *saved)
{
    if (!saved) return -1;
    memset(saved, 0, sizeof(*saved));

    intptr_t ucred = kernel_get_proc_ucred(pid);
    if (!ucred) return -1;

    if (kernel_copyout(ucred + UCRED_UID,     &saved->uid,     4) < 0) return -1;
    if (kernel_copyout(ucred + UCRED_RUID,    &saved->ruid,    4) < 0) return -1;
    if (kernel_copyout(ucred + UCRED_SVUID,   &saved->svuid,   4) < 0) return -1;
    if (kernel_copyout(ucred + UCRED_NGROUPS, &saved->ngroups, 4) < 0) return -1;
    if (kernel_copyout(ucred + UCRED_RGID,    &saved->rgid,    4) < 0) return -1;
    if (kernel_copyout(ucred + UCRED_SVGID,   &saved->svgid,   4) < 0) return -1;
    if (kernel_copyout(ucred + UCRED_AUTHID,  &saved->authid,  8) < 0) return -1;
    if (kernel_copyout(ucred + UCRED_CAPS0,   saved->caps,    16) < 0) return -1;
    if (kernel_copyout(ucred + UCRED_ATTRS,   saved->attrs,   32) < 0) return -1;

    saved->rootdir = kernel_get_proc_rootdir(pid);
    saved->jaildir = kernel_get_proc_jaildir(pid);
    if (!saved->rootdir || !saved->jaildir) return -1;

    saved->valid = true;
    plugin_log("[JB] Saved original game identity for pid %d (authid=0x%llx)",
               pid, (unsigned long long)saved->authid);
    return 0;
}

static int restore_game_credentials(pid_t pid, const SavedGameCredentials *saved)
{
    if (!saved || !saved->valid) return -1;

    intptr_t ucred = kernel_get_proc_ucred(pid);
    if (!ucred) return -1;

    if (kernel_copyin(&saved->uid,     ucred + UCRED_UID,     4) < 0) return -1;
    if (kernel_copyin(&saved->ruid,    ucred + UCRED_RUID,    4) < 0) return -1;
    if (kernel_copyin(&saved->svuid,   ucred + UCRED_SVUID,   4) < 0) return -1;
    if (kernel_copyin(&saved->ngroups, ucred + UCRED_NGROUPS, 4) < 0) return -1;
    if (kernel_copyin(&saved->rgid,    ucred + UCRED_RGID,    4) < 0) return -1;
    if (kernel_copyin(&saved->svgid,   ucred + UCRED_SVGID,   4) < 0) return -1;
    if (kernel_copyin(&saved->authid,  ucred + UCRED_AUTHID,  8) < 0) return -1;
    if (kernel_copyin(saved->caps,     ucred + UCRED_CAPS0,  16) < 0) return -1;
    if (kernel_copyin(saved->attrs,    ucred + UCRED_ATTRS,  32) < 0) return -1;
    if (kernel_set_proc_rootdir(pid, saved->rootdir) < 0) return -1;
    if (kernel_set_proc_jaildir(pid, saved->jaildir) < 0) return -1;

    plugin_log("[JB] Restored original game identity for pid %d (authid=0x%llx)",
               pid, (unsigned long long)saved->authid);
    return 0;
}

// Make /data visible without touching uid/gid, authid, capabilities, or NP
// attributes. LoadStartModule is synchronous, so the original filesystem
// roots can be restored immediately after the PRX module_start returns.
struct SavedFilesystemRoots {
    bool valid;
    intptr_t rootdir;
    intptr_t jaildir;
    uint64_t authid;
};

static int open_game_filesystem_window(pid_t pid, SavedFilesystemRoots *saved)
{
    if (!saved) return -1;
    memset(saved, 0, sizeof(*saved));

    const intptr_t root_vnode = kernel_get_root_vnode();
    const intptr_t ucred = kernel_get_proc_ucred(pid);
    saved->rootdir = kernel_get_proc_rootdir(pid);
    saved->jaildir = kernel_get_proc_jaildir(pid);
    if (!root_vnode || !ucred || !saved->rootdir || !saved->jaildir ||
        kernel_copyout(ucred + UCRED_AUTHID, &saved->authid,
                       sizeof(saved->authid)) < 0)
    {
        plugin_log("[FS-WINDOW] Could not capture original filesystem state");
        return -1;
    }

    if (kernel_set_proc_rootdir(pid, root_vnode) < 0 ||
        kernel_set_proc_jaildir(pid, root_vnode) < 0)
    {
        kernel_set_proc_rootdir(pid, saved->rootdir);
        kernel_set_proc_jaildir(pid, saved->jaildir);
        plugin_log("[FS-WINDOW] Could not expose the root filesystem");
        return -1;
    }

    const intptr_t observed_root = kernel_get_proc_rootdir(pid);
    const intptr_t observed_jail = kernel_get_proc_jaildir(pid);
    if (observed_root != root_vnode || observed_jail != root_vnode) {
        kernel_set_proc_rootdir(pid, saved->rootdir);
        kernel_set_proc_jaildir(pid, saved->jaildir);
        plugin_log("[FS-WINDOW] Root verification failed: root=0x%llx "
                   "jail=0x%llx expected=0x%llx",
                   (unsigned long long)observed_root,
                   (unsigned long long)observed_jail,
                   (unsigned long long)root_vnode);
        return -1;
    }

    saved->valid = true;
    plugin_log("[FS-WINDOW] Opened for game-thread load only; "
               "authid remains 0x%llx",
               (unsigned long long)saved->authid);
    return 0;
}

static int close_game_filesystem_window(pid_t pid,
                                        const SavedFilesystemRoots *saved)
{
    if (!saved || !saved->valid) return -1;

    const int root_rc = kernel_set_proc_rootdir(pid, saved->rootdir);
    const int jail_rc = kernel_set_proc_jaildir(pid, saved->jaildir);
    const intptr_t observed_root = kernel_get_proc_rootdir(pid);
    const intptr_t observed_jail = kernel_get_proc_jaildir(pid);

    uint64_t observed_authid = 0;
    const intptr_t ucred = kernel_get_proc_ucred(pid);
    const int auth_rc = ucred ? kernel_copyout(
        ucred + UCRED_AUTHID, &observed_authid, sizeof(observed_authid)) : -1;

    const bool roots_restored = root_rc >= 0 && jail_rc >= 0 &&
        observed_root == saved->rootdir && observed_jail == saved->jaildir;
    const bool identity_unchanged = auth_rc >= 0 &&
        observed_authid == saved->authid;
    plugin_log("[FS-WINDOW] Closed: roots_restored=%s identity_unchanged=%s "
               "authid=0x%llx",
               roots_restored ? "yes" : "no",
               identity_unchanged ? "yes" : "no",
               (unsigned long long)observed_authid);
    return roots_restored && identity_unchanged ? 0 : -1;
}

static int jb_pid(pid_t pid)
{
    intptr_t rv    = kernel_get_root_vnode();
    intptr_t ucred = kernel_get_proc_ucred(pid);
    if (!rv || !ucred) {
        plugin_log("[JB] kernel_get_root_vnode or get_proc_ucred failed for pid %d", pid);
        return -1;
    }

    uint32_t zero   = 0;
    int64_t  caps   = -1LL;
    uint64_t authid = AUTHID_SYSTEM;
    uint8_t  attrs[32] = {};
    if (kernel_copyout(ucred + UCRED_ATTRS, attrs, sizeof(attrs)) < 0) return -1;
    attrs[UCRED_ATTR_PTRACE_INDEX] |= 0x80;

    if (kernel_copyin(&zero,   ucred + UCRED_UID,     4) < 0) return -1;
    if (kernel_copyin(&zero,   ucred + UCRED_RUID,    4) < 0) return -1;
    if (kernel_copyin(&zero,   ucred + UCRED_SVUID,   4) < 0) return -1;
    if (kernel_copyin(&zero,   ucred + UCRED_NGROUPS, 4) < 0) return -1;
    if (kernel_copyin(&zero,   ucred + UCRED_RGID,    4) < 0) return -1;
    if (kernel_copyin(&zero,   ucred + UCRED_SVGID,   4) < 0) return -1;
    if (kernel_copyin(&authid, ucred + UCRED_AUTHID,  8) < 0) return -1;
    if (kernel_copyin(&caps,   ucred + UCRED_CAPS0,   8) < 0) return -1;
    if (kernel_copyin(&caps,   ucred + UCRED_CAPS1,   8) < 0) return -1;
    if (kernel_copyin(attrs,   ucred + UCRED_ATTRS,  32) < 0) return -1;

    kernel_set_proc_rootdir(pid, rv);
    kernel_set_proc_jaildir(pid, rv);

    plugin_log("[JB] jb_pid(%d) OK - ptrace attr_off=0x83", pid);
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
        plugin_log("[INJ] File is not accessible: %s (errno %d)", prx_path, errno);
        return -1;
    }

    // Résoudre sceKernelLoadStartModule dans le process cible
    intptr_t fn = pt_resolve(pid, NID_LOADSTARTMODULE);
    if (!fn) {
        plugin_log("[INJ] pt_resolve(LOADSTARTMODULE) = 0 - is libkernel loaded?");
        return -1;
    }
    plugin_log("[INJ] Resolved sceKernelLoadStartModule @ 0x%lx", (unsigned long)fn);

    // Allouer une page 0x4000 RW anonyme dans le process cible
    // Layout: [0x0000..0x0FFF] = prx_path  |  [0x1000..0x1FFF] = shellcode
    intptr_t rw_page = pt_mmap(pid, 0, 0x4000,
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (rw_page <= 0) {
        plugin_log("[INJ] pt_mmap failed (rc=%ld)", (long)rw_page);
        return -1;
    }
    plugin_log("[INJ] Allocated RW page @ 0x%lx", (unsigned long)rw_page);

    intptr_t remote_path = rw_page;
    intptr_t remote_sc   = rw_page + 0x1000;
    int      mod         = -1;

    // Écrire le path dans la première moitié de la page
    if (pt_copyin(pid, prx_path, remote_path, strlen(prx_path) + 1) < 0) {
        plugin_log("[INJ] pt_copyin(path) failed");
        goto out;
    }

    // Préparer le shellcode : patch du pointeur de fonction à l'offset 14
    {
        uint8_t sc[sizeof(k_shellcode)];
        memcpy(sc, k_shellcode, sizeof(sc));
        memcpy(sc + SHELLCODE_FN_OFFSET, &fn, sizeof(fn)); // patch fn ptr

        if (pt_copyin(pid, sc, remote_sc, sizeof(sc)) < 0) {
            plugin_log("[INJ] pt_copyin(shellcode) failed");
            goto out;
        }
    }

    // Rendre la zone shellcode exécutable (kernel bypasse les protections)
    kernel_mprotect(pid, remote_sc, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);

    // Appeler le shellcode : sceKernelLoadStartModule(path, 0, 0, 0, 0, 0)
    // PT_CONTINUE → le process tourne librement → shellcode s'exécute
    // INT3 à la fin → SIGTRAP → ptrace récupère RAX = handle module
    mod = (int)pt_call(pid, remote_sc, (uint64_t)remote_path, 0, 0, 0, 0, 0);

    plugin_log("[INJ] sceKernelLoadStartModule -> handle %d", mod);

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
        plugin_log("[Fakelib] No fakelib in app0 (%s); skipping", sandbox_id);
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

    int res = -1;
    int mount_errno = 0;
    int attempt_count = 0;
    for (int attempt = 0; attempt < 20; attempt++) {
        attempt_count = attempt + 1;
        res = mount_unionfs(fakelib_src, mount_dst);
        if (res == 0) break;

        mount_errno = errno;
        if (mount_errno != EAGAIN) break;
        usleep(100000);
    }

    if (res != 0) {
        plugin_log("[Fakelib] mount_unionfs failed after %d attempt(s): %d "
                   "(errno %d: %s)", attempt_count, res, mount_errno,
                   strerror(mount_errno));
        // Never force-unmount the destination after a failed mount. With a
        // shadow-mounted game it may already be an essential active mount.
        free(mount_dst);
        return nullptr;
    }

    plugin_log("[Fakelib] Mounted %s -> %s after %d attempt(s)",
               fakelib_src, mount_dst, attempt_count);
    printf_notification("Fakelib mounted for %s     ", title_id);
    return mount_dst;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Attente exit jeu via kqueue (EVFILT_PROC / NOTE_EXIT)
// ─────────────────────────────────────────────────────────────────────────────

static const char *k_lso_webapi_call_names[8] = {
    "Initialize", "Terminate", "CreateUserContext", "DeleteUserContext",
    "DeleteRequest", "CreateRequest", "SendRequest", "ReadData"
};

// Exact PPSA04264 1.010.002 eboot state used by its normal NP event loop.
// The current and pending arrays contain one int32 state for each of four
// local users. The main game thread consumes pending[] and calls its regular
// transition handler, so queueing state 2 is safer than editing current[].
#define GTAVEE_EBOOT_RUNTIME_BASE         0x400000ULL
#define GTAVEE_NP_USER_IDS_ADDRESS       (GTAVEE_EBOOT_RUNTIME_BASE + 0x3F35640ULL)
#define GTAVEE_NP_CURRENT_STATE_ADDRESS  (GTAVEE_EBOOT_RUNTIME_BASE + 0x5D80D20ULL)
#define GTAVEE_NP_PENDING_STATE_ADDRESS  (GTAVEE_EBOOT_RUNTIME_BASE + 0x5D80D30ULL)

struct GtavNpStateSnapshot {
    int32_t user_ids[4];
    int32_t current[4];
    int32_t pending[4];
};

static bool read_gtav_np_state(pid_t pid, GtavNpStateSnapshot *state)
{
    if (!state) return false;
    return kernel_proc_copyout(pid, GTAVEE_NP_USER_IDS_ADDRESS,
                               state->user_ids, sizeof(state->user_ids)) == 0 &&
           kernel_proc_copyout(pid, GTAVEE_NP_CURRENT_STATE_ADDRESS,
                               state->current, sizeof(state->current)) == 0 &&
           kernel_proc_copyout(pid, GTAVEE_NP_PENDING_STATE_ADDRESS,
                               state->pending, sizeof(state->pending)) == 0;
}

static void log_gtav_np_state(pid_t pid, const char *phase)
{
    GtavNpStateSnapshot state = {};
    if (!read_gtav_np_state(pid, &state)) {
        plugin_log("[GTA-NP] %s: state arrays unreadable", phase);
        return;
    }
    plugin_log("[GTA-NP] %s: users=[%d,%d,%d,%d] current=[%d,%d,%d,%d] "
               "pending=[%d,%d,%d,%d]",
               phase,
               state.user_ids[0], state.user_ids[1], state.user_ids[2],
               state.user_ids[3], state.current[0], state.current[1],
               state.current[2], state.current[3], state.pending[0],
               state.pending[1], state.pending[2], state.pending[3]);
}

static bool np_field_present(const uint8_t *buffer, size_t buffer_size,
                             size_t offset, size_t field_size)
{
    if (!buffer || offset >= buffer_size || field_size == 0)
        return false;

    size_t available = buffer_size - offset;
    if (field_size > available)
        field_size = available;

    for (size_t i = 0; i < field_size; i++) {
        if (buffer[offset + i] != 0)
            return true;
    }
    return false;
}

// Read-only check of the persistent PS5 NP data used by current fake-sign-in
// payloads. It deliberately reports only file sizes and presence flags; account
// IDs, online IDs, e-mail addresses, tokens, and file contents are never logged.
static void audit_persistent_np_account(pid_t game_pid)
{
    GtavNpStateSnapshot state = {};
    if (!read_gtav_np_state(game_pid, &state)) {
        plugin_log("[NP-ACCOUNT] Audit skipped: GTA user state is unreadable");
        return;
    }

    int32_t user_id = -1;
    for (int i = 0; i < 4; i++) {
        if (state.user_ids[i] > 0) {
            user_id = state.user_ids[i];
            break;
        }
    }
    if (user_id <= 0) {
        plugin_log("[NP-ACCOUNT] Audit skipped: no active positive user ID");
        return;
    }

    char auth_path[PATH_MAX] = {};
    char config_path[PATH_MAX] = {};
    snprintf(auth_path, sizeof(auth_path),
             "/system_data/priv/home/%x/np/auth.dat", (uint32_t)user_id);
    snprintf(config_path, sizeof(config_path),
             "/system_data/priv/home/%x/config.dat", (uint32_t)user_id);

    struct stat auth_st = {};
    struct stat config_st = {};
    bool auth_present = stat(auth_path, &auth_st) == 0 &&
                        S_ISREG(auth_st.st_mode) && auth_st.st_size > 0;
    bool config_present = stat(config_path, &config_st) == 0 &&
                          S_ISREG(config_st.st_mode) && config_st.st_size > 0;

    plugin_log("[NP-ACCOUNT] Persistent files: auth.dat=%s size=%lld "
               "config.dat=%s size=%lld",
               auth_present ? "present" : "missing",
               auth_present ? (long long)auth_st.st_size : 0LL,
               config_present ? "present" : "missing",
               config_present ? (long long)config_st.st_size : 0LL);

    if (!config_present) {
        plugin_log("[NP-ACCOUNT] Result: incomplete persistent fake sign-in "
                   "(config.dat is unavailable)");
        return;
    }

    uint8_t config_prefix[0x1200] = {};
    int fd = open(config_path, O_RDONLY);
    if (fd < 0) {
        plugin_log("[NP-ACCOUNT] Result: config.dat exists but cannot be opened "
                   "(errno=%d)", errno);
        return;
    }

    ssize_t bytes_read = read(fd, config_prefix, sizeof(config_prefix));
    close(fd);
    if (bytes_read <= 0) {
        plugin_log("[NP-ACCOUNT] Result: config.dat could not be read");
        return;
    }

    size_t length = (size_t)bytes_read;
    bool account_id = np_field_present(config_prefix, length, 0x100, 8);
    bool email = np_field_present(config_prefix, length, 0x108, 65);
    bool np_environment = np_field_present(config_prefix, length, 0x177, 17);
    bool online_id = np_field_present(config_prefix, length, 0x1ad, 17);
    bool country = np_field_present(config_prefix, length, 0x1be, 3);
    bool language = np_field_present(config_prefix, length, 0x1c1, 6);
    bool locale = np_field_present(config_prefix, length, 0x1c7, 36);
    int32_t signin_flag = 0;
    bool signin_flag_readable = length >= 0x1fc;
    if (signin_flag_readable)
        memcpy(&signin_flag, config_prefix + 0x1f8, sizeof(signin_flag));

    plugin_log("[NP-ACCOUNT] config.dat fields: account_id=%u email=%u "
               "np_env=%u online_id=%u country=%u language=%u locale=%u "
               "signin_flag=%s%d",
               account_id, email, np_environment, online_id, country,
               language, locale, signin_flag_readable ? "" : "unreadable/",
               signin_flag_readable ? signin_flag : 0);

    bool complete = auth_present && account_id && email && np_environment &&
                    online_id && country && language && locale &&
                    signin_flag_readable && signin_flag != 0;
    plugin_log("[NP-ACCOUNT] Result: persistent fake-sign-in data is %s",
               complete ? "complete" : "incomplete");
}

static bool queue_gtav_synthetic_signed_in(pid_t pid)
{
    GtavNpStateSnapshot state = {};
    if (!read_gtav_np_state(pid, &state)) {
        plugin_log("[GTA-NP-SYNTH] State arrays unreadable; not applied");
        return false;
    }

    int active_user = -1;
    for (int i = 0; i < 4; i++) {
        if (state.current[i] >= 0) {
            active_user = i;
            break;
        }
    }
    if (active_user < 0) {
        for (int i = 0; i < 4; i++) {
            if (state.user_ids[i] >= 0) {
                active_user = i;
                break;
            }
        }
    }
    if (active_user < 0) {
        plugin_log("[GTA-NP-SYNTH] No initialized local user; not applied");
        return false;
    }

    plugin_log("[GTA-NP-SYNTH] Before: user=%d id=%d current=%d pending=%d",
               active_user, state.user_ids[active_user],
               state.current[active_user], state.pending[active_user]);

    const int32_t signed_in = 2;
    const intptr_t pending_address =
        (intptr_t)GTAVEE_NP_PENDING_STATE_ADDRESS + active_user * 4;
    if (kernel_proc_copyin(pid, &signed_in, pending_address,
                           sizeof(signed_in)) < 0) {
        plugin_log("[GTA-NP-SYNTH] Failed to queue signed-in state");
        return false;
    }

    int32_t verify = -1;
    if (kernel_proc_copyout(pid, pending_address, &verify, sizeof(verify)) < 0 ||
        verify != signed_in) {
        plugin_log("[GTA-NP-SYNTH] Verification failed (pending=%d)", verify);
        return false;
    }

    plugin_log("[GTA-NP-SYNTH] Queued signed-in state=2 for user %d", active_user);
    return true;
}

// Passive view of the game's socket table. This uses the read-only
// KERN_PROC_FILEDESC sysctl and never replaces a GTA/LSO function or touches a
// socket owned by the game. Only the service ports relevant to this diagnosis
// are retained: HTTP(S) and BlueSphere's UDP presence relay.
#define LSO_TRANSPORT_SOCKET_MAX 64

struct LsoTransportSocket {
    int32_t fd;
    uint8_t family;
    uint8_t type;
    uint16_t peer_port;
    uint8_t peer_address[16];
};

struct LsoTransportAudit {
    bool initialized;
    bool ever_read_successfully;
    bool read_warning_logged;
    bool legacy_format_logged;
    bool direct_kernel_logged;
    bool direct_kernel_warning_logged;
    bool direct_layout_validated;
    bool overflow_logged;
    bool saw_tcp_443;
    bool saw_udp_8081;
    uint32_t open_events;
    uint32_t direct_kernel_poll_ticks;
    uint32_t max_socket_files;
    uint32_t max_valid_pcbs;
    size_t previous_count;
    LsoTransportSocket previous[LSO_TRANSPORT_SOCKET_MAX];
};

static bool same_transport_socket(const LsoTransportSocket &a,
                                  const LsoTransportSocket &b)
{
    return a.fd == b.fd && a.family == b.family && a.type == b.type &&
        a.peer_port == b.peer_port &&
        memcmp(a.peer_address, b.peer_address,
               sizeof(a.peer_address)) == 0;
}

static void log_transport_socket(const char *event,
                                 const LsoTransportSocket &socket)
{
    const char *kind = socket.type == SOCK_STREAM ? "TCP" :
                       socket.type == SOCK_DGRAM ? "UDP" : "SOCKET";
    if (socket.family == AF_INET) {
        plugin_log("[GTA-SOCKET] %s fd=%d %s peer=%u.%u.%u.%u:%u",
                   event, socket.fd, kind,
                   socket.peer_address[0], socket.peer_address[1],
                   socket.peer_address[2], socket.peer_address[3],
                   socket.peer_port);
    } else {
        plugin_log("[GTA-SOCKET] %s fd=%d %s peer=IPv6:%u",
                   event, socket.fd, kind, socket.peer_port);
    }
}

static void commit_transport_snapshot(LsoTransportAudit *audit,
                                      const LsoTransportSocket *current,
                                      size_t current_count)
{
    for (size_t i = 0; i < current_count; i++) {
        bool existed = false;
        for (size_t j = 0; j < audit->previous_count; j++) {
            if (same_transport_socket(current[i], audit->previous[j])) {
                existed = true;
                break;
            }
        }
        if (!existed) {
            log_transport_socket(audit->initialized ? "OPEN" : "PRESENT",
                                 current[i]);
            audit->open_events++;
        }
        if (current[i].type == SOCK_STREAM &&
            current[i].peer_port == 443)
            audit->saw_tcp_443 = true;
        if (current[i].type == SOCK_DGRAM &&
            current[i].peer_port == 8081)
            audit->saw_udp_8081 = true;
    }

    for (size_t i = 0; audit->initialized &&
         i < audit->previous_count; i++)
    {
        bool remains = false;
        for (size_t j = 0; j < current_count; j++) {
            if (same_transport_socket(audit->previous[i], current[j])) {
                remains = true;
                break;
            }
        }
        if (!remains) log_transport_socket("CLOSED", audit->previous[i]);
    }

    memcpy(audit->previous, current,
           current_count * sizeof(LsoTransportSocket));
    audit->previous_count = current_count;
    audit->initialized = true;
}

static bool is_plausible_kernel_pointer(uintptr_t address)
{
    return (address >> 48) == 0xFFFF && address != UINTPTR_MAX;
}

// FW 8.60 hides both process-descriptor sysctls from payloads. As a final
// read-only fallback, walk the target's kernel descriptor table and copy only
// the socket/inpcb fields required to identify the remote address and port.
// These offsets match the FreeBSD-derived structures used by the PS5 SDK:
// filedescent=0x30, file.f_type=0x20, socket.so_pcb=0x10 and
// inpcb.inp_inc=0xC0. Every pointer and protocol field is validated before it
// contributes an event.
static bool read_kernel_transport_snapshot(
    pid_t pid, LsoTransportAudit *audit,
    LsoTransportSocket *current, size_t *current_count)
{
    if (!audit || !current || !current_count) return false;
    *current_count = 0;

    const uintptr_t filedesc = (uintptr_t)kernel_get_proc_filedesc(pid);
    if (!is_plausible_kernel_pointer(filedesc)) return false;

    uintptr_t table = 0;
    uint32_t slot_count = 0;
    int32_t last_file = -1;
    if (kernel_copyout((intptr_t)filedesc, &table, sizeof(table)) != 0 ||
        !is_plausible_kernel_pointer(table) ||
        kernel_copyout((intptr_t)table, &slot_count, sizeof(slot_count)) != 0 ||
        slot_count == 0 || slot_count > 4096)
        return false;

    // fd_lastfile is the highest descriptor that may be populated. Falling
    // back to the allocated size keeps the audit useful if Sony changes that
    // single field while still bounding all reads.
    kernel_copyout((intptr_t)(filedesc + 0x28), &last_file,
                   sizeof(last_file));
    uint32_t scan_count = slot_count;
    if (last_file >= 0 && (uint32_t)last_file < slot_count)
        scan_count = (uint32_t)last_file + 1;

    if (!audit->direct_kernel_logged) {
        plugin_log("[GTA-KSOCKET] FW 8.60 direct kernel descriptor audit "
                   "active (allocated=%u scanned=%u)",
                   slot_count, scan_count);
        audit->direct_kernel_logged = true;
    }

    static constexpr size_t FILEDESCENT_SIZE = 0x30;
    static constexpr size_t FILEDESCENT_TABLE_OFFSET = 0x08;
    static constexpr size_t FILE_TYPE_OFFSET = 0x20;
    static constexpr int16_t FILE_TYPE_SOCKET = 2;
    static constexpr size_t SOCKET_PREFIX_SIZE = 0x18;
    static constexpr size_t SOCKET_TYPE_OFFSET = 0x04;
    static constexpr size_t SOCKET_PCB_OFFSET = 0x10;
    static constexpr size_t INPCB_SNAPSHOT_SIZE = 0xE0;
    static constexpr size_t INPCB_PROTOCOL_OFFSET = 0x76;
    static constexpr size_t INPCB_SOCKET_BACKPTR_OFFSET = 0x58;
    static constexpr size_t INPCB_INC_FLAGS_OFFSET = 0xC0;
    static constexpr size_t INPCB_FOREIGN_PORT_OFFSET = 0xC4;
    static constexpr size_t INPCB_FOREIGN_IPV6_OFFSET = 0xC8;
    static constexpr size_t INPCB_FOREIGN_IPV4_OFFSET = 0xD4;
    static constexpr uint8_t INPCB_IS_IPV6 = 0x01;

    uint32_t socket_files = 0;
    uint32_t valid_pcbs = 0;
    for (uint32_t fd = 0; fd < scan_count; fd++) {
        const uintptr_t entry = table + FILEDESCENT_TABLE_OFFSET +
            (uintptr_t)fd * FILEDESCENT_SIZE;
        uintptr_t file = 0;
        int16_t file_type = 0;
        if (kernel_copyout((intptr_t)entry, &file, sizeof(file)) != 0 ||
            !is_plausible_kernel_pointer(file) ||
            kernel_copyout((intptr_t)(file + FILE_TYPE_OFFSET), &file_type,
                           sizeof(file_type)) != 0 ||
            file_type != FILE_TYPE_SOCKET)
            continue;
        socket_files++;

        uintptr_t socket_address = 0;
        uint8_t socket_prefix[SOCKET_PREFIX_SIZE] = {};
        if (kernel_copyout((intptr_t)file, &socket_address,
                           sizeof(socket_address)) != 0 ||
            !is_plausible_kernel_pointer(socket_address) ||
            kernel_copyout((intptr_t)socket_address, socket_prefix,
                           sizeof(socket_prefix)) != 0)
            continue;

        int16_t socket_type = 0;
        uintptr_t pcb_address = 0;
        memcpy(&socket_type, socket_prefix + SOCKET_TYPE_OFFSET,
               sizeof(socket_type));
        memcpy(&pcb_address, socket_prefix + SOCKET_PCB_OFFSET,
               sizeof(pcb_address));
        if ((socket_type != SOCK_STREAM && socket_type != SOCK_DGRAM) ||
            !is_plausible_kernel_pointer(pcb_address))
            continue;

        uint8_t pcb[INPCB_SNAPSHOT_SIZE] = {};
        if (kernel_copyout((intptr_t)pcb_address, pcb, sizeof(pcb)) != 0)
            continue;

        const uint8_t protocol = pcb[INPCB_PROTOCOL_OFFSET];
        uintptr_t socket_back_pointer = 0;
        memcpy(&socket_back_pointer, pcb + INPCB_SOCKET_BACKPTR_OFFSET,
               sizeof(socket_back_pointer));
        if (socket_back_pointer != socket_address)
            continue;
        if ((socket_type == SOCK_STREAM && protocol != IPPROTO_TCP) ||
            (socket_type == SOCK_DGRAM && protocol != IPPROTO_UDP))
            continue;
        valid_pcbs++;

        uint16_t network_port = 0;
        memcpy(&network_port, pcb + INPCB_FOREIGN_PORT_OFFSET,
               sizeof(network_port));
        const uint16_t peer_port = ntohs(network_port);
        if (peer_port != 80 && peer_port != 443 && peer_port != 8081)
            continue;

        // Reject a descriptor that changed while its backing structures were
        // sampled. This greatly narrows the race with close/reuse.
        uintptr_t confirm_file = 0;
        if (kernel_copyout((intptr_t)entry, &confirm_file,
                           sizeof(confirm_file)) != 0 ||
            confirm_file != file)
            continue;

        LsoTransportSocket item = {};
        item.fd = (int32_t)fd;
        item.type = (uint8_t)socket_type;
        item.peer_port = peer_port;
        if ((pcb[INPCB_INC_FLAGS_OFFSET] & INPCB_IS_IPV6) != 0) {
            item.family = AF_INET6;
            memcpy(item.peer_address, pcb + INPCB_FOREIGN_IPV6_OFFSET,
                   sizeof(item.peer_address));
        } else {
            item.family = AF_INET;
            memcpy(item.peer_address, pcb + INPCB_FOREIGN_IPV4_OFFSET, 4);
        }

        if (*current_count < LSO_TRANSPORT_SOCKET_MAX) {
            current[(*current_count)++] = item;
        } else if (!audit->overflow_logged) {
            plugin_log("[GTA-KSOCKET] More than %d relevant sockets; "
                       "additional entries omitted",
                       LSO_TRANSPORT_SOCKET_MAX);
            audit->overflow_logged = true;
        }
    }
    if (socket_files > audit->max_socket_files)
        audit->max_socket_files = socket_files;
    if (valid_pcbs > audit->max_valid_pcbs)
        audit->max_valid_pcbs = valid_pcbs;
    if (valid_pcbs != 0 && !audit->direct_layout_validated) {
        plugin_log("[GTA-KSOCKET] Kernel socket layout validated "
                   "(socket_files=%u valid_pcbs=%u)",
                   socket_files, valid_pcbs);
        audit->direct_layout_validated = true;
    }
    return true;
}

static void poll_game_transport_sockets(pid_t pid, LsoTransportAudit *audit)
{
    if (!audit) return;

    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_FILEDESC, pid};
    bool legacy_format = false;
    size_t required = 0;
    int size_result = sysctl(mib, 4, nullptr, &required, nullptr, 0);
    const int modern_errno = size_result == 0 ? 0 : errno;
    if (size_result != 0 || required == 0) {
        // FW 8.60 returns ENOENT for the newer FILEDESC node. Its legacy
        // OFILEDESC node exposes the same peer-address fields in kinfo_ofile.
        mib[2] = KERN_PROC_OFILEDESC;
        required = 0;
        size_result = sysctl(mib, 4, nullptr, &required, nullptr, 0);
        legacy_format = size_result == 0 && required != 0;
        if (legacy_format && !audit->legacy_format_logged) {
            plugin_log("[GTA-SOCKET] FW 8.60 legacy descriptor format active");
            audit->legacy_format_logged = true;
        }
    }
    if (size_result != 0 || required == 0) {
        // The containing monitor runs every 100 ms. Kernel descriptor reads
        // are intentionally limited to 2 Hz; relevant Online connections
        // persist much longer than one sample interval.
        if ((audit->direct_kernel_poll_ticks++ % 5) != 0) return;
        LsoTransportSocket direct[LSO_TRANSPORT_SOCKET_MAX] = {};
        size_t direct_count = 0;
        if (read_kernel_transport_snapshot(pid, audit, direct,
                                           &direct_count)) {
            audit->ever_read_successfully = true;
            commit_transport_snapshot(audit, direct, direct_count);
        } else if (!audit->direct_kernel_warning_logged) {
            plugin_log("[GTA-KSOCKET] Direct kernel descriptor audit failed "
                       "(modern_errno=%d legacy_errno=%d)",
                       modern_errno, errno);
            audit->direct_kernel_warning_logged = true;
        }
        return;
    }

    // Descriptors may be added between the sizing and copy calls.
    const size_t capacity = required + 0x4000;
    uint8_t *buffer = (uint8_t *)malloc(capacity);
    if (!buffer) {
        if (!audit->read_warning_logged) {
            plugin_log("[GTA-SOCKET] Passive socket-table allocation failed");
            audit->read_warning_logged = true;
        }
        return;
    }

    size_t copied = capacity;
    if (sysctl(mib, 4, buffer, &copied, nullptr, 0) != 0) {
        if (!audit->read_warning_logged) {
            plugin_log("[GTA-SOCKET] Passive socket-table read failed "
                       "(errno=%d)", errno);
            audit->read_warning_logged = true;
        }
        free(buffer);
        return;
    }
    audit->ever_read_successfully = true;

    LsoTransportSocket current[LSO_TRANSPORT_SOCKET_MAX] = {};
    size_t current_count = 0;

    for (size_t offset = 0; offset + sizeof(int) <= copied;) {
        const int record_size = *(const int *)(buffer + offset);
        if (record_size <= 0 || offset + (size_t)record_size > copied)
            break;
        const uint8_t *record = buffer + offset;
        offset += (size_t)record_size;

        int file_type = KF_TYPE_NONE;
        int file_fd = -1;
        int socket_type = 0;
        const struct sockaddr_storage *peer_storage = nullptr;
        if (legacy_format) {
            const size_t minimum_record =
                offsetof(struct kinfo_ofile, kf_sa_peer) +
                sizeof(struct sockaddr_storage);
            if ((size_t)record_size < minimum_record) continue;
            const struct kinfo_ofile *file =
                (const struct kinfo_ofile *)record;
            file_type = file->kf_type;
            file_fd = file->kf_fd;
            socket_type = file->kf_sock_type;
            peer_storage = &file->kf_sa_peer;
        } else {
            const size_t minimum_record =
                offsetof(struct kinfo_file, kf_sa_peer) +
                sizeof(struct sockaddr_storage);
            if ((size_t)record_size < minimum_record) continue;
            const struct kinfo_file *file =
                (const struct kinfo_file *)record;
            file_type = file->kf_type;
            file_fd = file->kf_fd;
            socket_type = file->kf_sock_type;
            peer_storage = &file->kf_sa_peer;
        }

        if (file_type != KF_TYPE_SOCKET ||
            (socket_type != SOCK_STREAM && socket_type != SOCK_DGRAM))
            continue;

        LsoTransportSocket item = {};
        item.fd = file_fd;
        item.family = peer_storage->ss_family;
        item.type = (uint8_t)socket_type;

        if (item.family == AF_INET) {
            const struct sockaddr_in *peer =
                (const struct sockaddr_in *)peer_storage;
            item.peer_port = ntohs(peer->sin_port);
            memcpy(item.peer_address, &peer->sin_addr,
                   sizeof(peer->sin_addr));
        } else if (item.family == AF_INET6) {
            const struct sockaddr_in6 *peer =
                (const struct sockaddr_in6 *)peer_storage;
            item.peer_port = ntohs(peer->sin6_port);
            memcpy(item.peer_address, &peer->sin6_addr,
                   sizeof(peer->sin6_addr));
        } else {
            continue;
        }

        const bool relevant =
            item.peer_port == 80 || item.peer_port == 443 ||
            item.peer_port == 8081;
        if (!relevant) continue;

        if (current_count < LSO_TRANSPORT_SOCKET_MAX) {
            current[current_count++] = item;
        } else if (!audit->overflow_logged) {
            plugin_log("[GTA-SOCKET] More than %d relevant sockets; "
                       "additional entries omitted",
                       LSO_TRANSPORT_SOCKET_MAX);
            audit->overflow_logged = true;
        }
    }
    free(buffer);

    commit_transport_snapshot(audit, current, current_count);
}

static void wait_for_pid_exit(pid_t pid,
                              intptr_t lso_call_trace_address = 0,
                              intptr_t lso_module_base = 0,
                              intptr_t lso_net_boundary_address = 0,
                              intptr_t gta_http_boundary_address = 0,
                              intptr_t push_event_trace_address = 0,
                              intptr_t ps5api_hit_counter_address = 0,
                              intptr_t cpp_boundary_trace_address = 0,
                              uint32_t kernel_response_route_mask = 0)
{
    int kq = kqueue();
    if (kq == -1) { sleep(3); return; }

    struct kevent kev;
    EV_SET(&kev, pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_CLEAR,
           NOTE_EXIT, 0, nullptr);

    if (kevent(kq, &kev, 1, nullptr, 0, nullptr) == -1) {
    plugin_log("[Wait] kevent registration failed for pid %d: %s",
                   pid, strerror(errno));
        close(kq);
        sleep(3);
        return;
    }

    plugin_log("[Wait] Monitoring pid %d...", pid);

    LsoTransportAudit transport_audit = {};
    if (lso_module_base) {
        plugin_log("[GTA-SOCKET] Passive audit active for TCP 80/443 and "
                   "UDP 8081; no game hooks installed");
    }

    uint32_t last_call_counts[LSO_CALL_MONITOR_MAX] = {};
    bool trace_read_warning_logged = false;
    static const char *np_call_names[19] = {
        "RegisterNpReachabilityStateCallback", "CheckNpReachability",
        "GetOnlineId", "GetAccountIdA", "GetState",
        "CommonDialogInitialize", "CheckPremium", "AuthCreateAsyncRequest",
        "AuthPollAsync", "AuthDeleteRequest", "CreateAsyncRequest",
        "PollAsync", "DeleteRequest", "AuthGetAuthorizationCodeV3",
        "GetAccountCountryA", "GetAccountAge", "RegisterStateCallbackA",
        "CheckCallback", "UserServiceGetEvent",
    };
    auto poll_lso_call_trace = [&]() {
        if (!lso_call_trace_address) return;

        lso_call_trace_record_t first = {};
        lso_call_trace_record_t second = {};
        if (kernel_proc_copyout(pid, lso_call_trace_address,
                                &first, sizeof(first)) < 0 ||
            kernel_proc_copyout(pid, lso_call_trace_address,
                                &second, sizeof(second)) < 0)
        {
            if (!trace_read_warning_logged) {
                plugin_log("[LSO-MON] Could not read the in-memory call trace");
                trace_read_warning_logged = true;
            }
            return;
        }

        for (int i = 0; i < LSO_CALL_MONITOR_MAX; i++) {
            // Two matching snapshots reject a counter update in flight.
            uint32_t count = second.entries[i].call_count;
            if (count == 0 || count == last_call_counts[i] ||
                count != first.entries[i].call_count ||
                second.entries[i].last_result != first.entries[i].last_result)
                continue;

            uint32_t delta = count - last_call_counts[i];
            if (i < 19) {
                plugin_log("[LSO-CALL] NP.%s calls=%u (+%u)",
                           np_call_names[i], count, delta);
            } else {
                int web_index = i - 19;
                plugin_log("[LSO-CALL] WebAPI.%s calls=%u (+%u)",
                           k_lso_webapi_call_names[web_index], count, delta);
            }
            last_call_counts[i] = count;
        }
    };

    uint32_t last_net_boundary_counts[LSO_NET_BOUNDARY_COUNT] = {};
    bool net_boundary_warning_logged = false;
    auto poll_lso_net_boundary = [&]() {
        if (!lso_net_boundary_address) return;

        lso_net_boundary_record_t first = {};
        lso_net_boundary_record_t second = {};
        if (kernel_proc_copyout(pid, lso_net_boundary_address,
                                &first, sizeof(first)) < 0 ||
            kernel_proc_copyout(pid, lso_net_boundary_address,
                                &second, sizeof(second)) < 0)
        {
            if (!net_boundary_warning_logged) {
                plugin_log("[LSO-NET-TRACE] Could not read boundary records");
                net_boundary_warning_logged = true;
            }
            return;
        }

        for (int i = 0; i < LSO_NET_BOUNDARY_COUNT; i++) {
            const lso_net_boundary_entry_t &a = first.entries[i];
            const lso_net_boundary_entry_t &b = second.entries[i];
            if (b.call_count == 0 ||
                b.call_count == last_net_boundary_counts[i] ||
                a.call_count != b.call_count ||
                a.last_result != b.last_result || a.arg0 != b.arg0 ||
                a.arg1 != b.arg1 ||
                memcmp(a.data, b.data, sizeof(a.data)) != 0)
                continue;

            const uint32_t delta =
                b.call_count - last_net_boundary_counts[i];
            if (i == 0) {
                const uint8_t family = b.data[1];
                const uint16_t port =
                    ((uint16_t)b.data[2] << 8) | b.data[3];
                if (family == AF_INET && b.data[0] >= 8) {
                    plugin_log("[LSO-NET-CONNECT] calls=%u (+%u) fd=%lld "
                               "result=%lld/0x%llx peer=%u.%u.%u.%u:%u",
                               b.call_count, delta, (long long)b.arg0,
                               (long long)b.last_result,
                               (unsigned long long)b.last_result,
                               b.data[4], b.data[5], b.data[6], b.data[7],
                               port);
                } else {
                    plugin_log("[LSO-NET-CONNECT] calls=%u (+%u) fd=%lld "
                               "result=%lld/0x%llx family=%u port=%u",
                               b.call_count, delta, (long long)b.arg0,
                               (long long)b.last_result,
                               (unsigned long long)b.last_result,
                               family, port);
                }
            } else {
                char hostname[64] = {};
                const char *host_class = "UNREADABLE";
                if (b.arg1 != 0 &&
                    kernel_proc_copyout(pid, (intptr_t)b.arg1, hostname,
                                        sizeof(hostname) - 1) == 0)
                {
                    hostname[sizeof(hostname) - 1] = '\0';
                    if (strcmp(hostname, "ros.rockstargames.com") == 0)
                        host_class = "ROCKSTAR_ORIGINAL";
                    else if (strcmp(hostname, "rockstargames.gtao.us") == 0)
                        host_class = "LSO_REDIRECT";
                    else
                        host_class = "OTHER";
                }
                plugin_log("[LSO-NET-RESOLVE] calls=%u (+%u) resolver=%lld "
                           "result=%lld/0x%llx host=%s address=%u.%u.%u.%u",
                           b.call_count, delta, (long long)b.arg0,
                           (long long)b.last_result,
                           (unsigned long long)b.last_result, host_class,
                           b.data[0], b.data[1], b.data[2], b.data[3]);
            }
            last_net_boundary_counts[i] = b.call_count;
        }
    };

    uint32_t last_http_boundary_counts[GTA_HTTP_BOUNDARY_COUNT] = {};
    bool http_boundary_warning_logged = false;
    auto poll_gta_http_boundary = [&]() {
        if (!gta_http_boundary_address) return;

        gta_http_boundary_record_t first = {};
        gta_http_boundary_record_t second = {};
        if (kernel_proc_copyout(pid, gta_http_boundary_address,
                                &first, sizeof(first)) < 0 ||
            kernel_proc_copyout(pid, gta_http_boundary_address,
                                &second, sizeof(second)) < 0)
        {
            if (!http_boundary_warning_logged) {
                plugin_log("[GTA-HTTP] Could not read boundary records");
                http_boundary_warning_logged = true;
            }
            return;
        }

        for (int i = 0; i < GTA_HTTP_BOUNDARY_COUNT; i++) {
            const gta_http_boundary_entry_t &a = first.entries[i];
            const gta_http_boundary_entry_t &b = second.entries[i];
            if (b.call_count == 0 ||
                b.call_count == last_http_boundary_counts[i] ||
                a.call_count != b.call_count ||
                a.last_result != b.last_result || a.arg0 != b.arg0 ||
                a.arg1 != b.arg1 ||
                memcmp(a.data, b.data, sizeof(a.data)) != 0)
                continue;

            const uint32_t delta =
                b.call_count - last_http_boundary_counts[i];
            if (i == 0) {
                char url_prefix[sizeof(b.data) + 1] = {};
                memcpy(url_prefix, b.data, sizeof(b.data));
                const char *host_class = "OTHER";
                if (strstr(url_prefix, "rockstargames.gtao.us") != nullptr)
                    host_class = "LSO_REDIRECT";
                else if (strstr(url_prefix,
                                "ros.rockstargames.com") != nullptr)
                    host_class = "ROCKSTAR_ORIGINAL";
                else if (strncmp(url_prefix, "https://", 8) == 0)
                    host_class = "OTHER_HTTPS";
                plugin_log("[GTA-HTTP-CONNECTION] calls=%u (+%u) "
                           "template=%llu result=%lld/0x%llx host=%s",
                           b.call_count, delta,
                           (unsigned long long)b.arg0,
                           (long long)b.last_result,
                           (unsigned long long)b.last_result, host_class);
            } else if (i == 1) {
                plugin_log("[GTA-HTTP-SEND] calls=%u (+%u) request=%llu "
                           "result=%lld/0x%llx bytes=%llu",
                           b.call_count, delta,
                           (unsigned long long)b.arg0,
                           (long long)b.last_result,
                           (unsigned long long)b.last_result,
                           (unsigned long long)b.arg1);
            } else {
                int32_t status = 0;
                memcpy(&status, b.data, sizeof(status));
                plugin_log("[GTA-HTTP-STATUS] calls=%u (+%u) request=%llu "
                           "result=%lld/0x%llx HTTP=%d",
                           b.call_count, delta,
                           (unsigned long long)b.arg0,
                           (long long)b.last_result,
                           (unsigned long long)b.last_result, status);
            }
            last_http_boundary_counts[i] = b.call_count;
        }
    };

    uint32_t last_cpp_boundary_counts[LSO_CPP_BOUNDARY_COUNT] = {};
    bool cpp_boundary_warning_logged = false;
    static const char *cpp_boundary_names[LSO_CPP_BOUNDARY_COUNT] = {
        "LSO.CreateRequest/eager-send", "C++.AddHttpRequestHeader",
        "C++.SendRequest",
    };
    auto poll_cpp_boundary_trace = [&]() {
        if (!cpp_boundary_trace_address) return;

        lso_cpp_boundary_record_t first = {};
        lso_cpp_boundary_record_t second = {};
        if (kernel_proc_copyout(pid, cpp_boundary_trace_address,
                                &first, sizeof(first)) < 0 ||
            kernel_proc_copyout(pid, cpp_boundary_trace_address,
                                &second, sizeof(second)) < 0)
        {
            if (!cpp_boundary_warning_logged) {
                plugin_log("[LSO-EAGER-CALL] Could not read boundary counters");
                cpp_boundary_warning_logged = true;
            }
            return;
        }

        for (int i = 0; i < LSO_CPP_BOUNDARY_COUNT; i++) {
            const auto &a = first.entries[i];
            const auto &b = second.entries[i];
            if ((b.sequence & 1) != 0 || a.sequence != b.sequence ||
                a.call_count != b.call_count ||
                a.last_request_id != b.last_request_id ||
                a.last_result != b.last_result ||
                b.call_count == last_cpp_boundary_counts[i])
                continue;

            const uint32_t delta =
                b.call_count - last_cpp_boundary_counts[i];
            plugin_log("[LSO-EAGER-CALL] %s calls=%u (+%u) request_id=0x%llx "
                       "result=0x%08x",
                       cpp_boundary_names[i], b.call_count, delta,
                       (unsigned long long)b.last_request_id,
                       (unsigned int)b.last_result);
            last_cpp_boundary_counts[i] = b.call_count;
        }
    };

    GtavNpStateSnapshot last_np_state = {};
    bool last_np_state_valid = false;
    auto poll_gtav_np_state = [&]() {
        if (!lso_module_base) return;
        GtavNpStateSnapshot state = {};
        if (!read_gtav_np_state(pid, &state)) return;
        if (!last_np_state_valid ||
            memcmp(&state, &last_np_state, sizeof(state)) != 0) {
            plugin_log("[GTA-NP] runtime: users=[%d,%d,%d,%d] "
                       "current=[%d,%d,%d,%d] pending=[%d,%d,%d,%d]",
                       state.user_ids[0], state.user_ids[1], state.user_ids[2],
                       state.user_ids[3], state.current[0], state.current[1],
                       state.current[2], state.current[3], state.pending[0],
                       state.pending[1], state.pending[2], state.pending[3]);
            last_np_state = state;
            last_np_state_valid = true;
        }
    };

    uint32_t last_push_event_counts[GTAVEE_PUSH_EVENT_HOOK_COUNT] = {};
    bool push_event_trace_warning_logged = false;
    static const char *push_event_trace_names[
        GTAVEE_PUSH_EVENT_HOOK_COUNT] = {
        "CreatePushContext", "StartPushContextCallback", "DeletePushContext",
        "CreateHandle", "CreateFilter", "DeleteHandle", "DeleteFilter",
        "RegisterCallback", "UnregisterCallback",
    };
    auto poll_push_event_trace = [&]() {
        if (!push_event_trace_address) return;

        gtavee_push_event_trace_record_t first = {};
        gtavee_push_event_trace_record_t second = {};
        if (kernel_proc_copyout(pid, push_event_trace_address, &first,
                                sizeof(first)) < 0 ||
            kernel_proc_copyout(pid, push_event_trace_address, &second,
                                sizeof(second)) < 0)
        {
            if (!push_event_trace_warning_logged) {
                plugin_log("[GTA-PUSH-TRACE] Could not read result records");
                push_event_trace_warning_logged = true;
            }
            return;
        }

        for (int i = 0; i < GTAVEE_PUSH_EVENT_HOOK_COUNT; i++) {
            const gtavee_push_event_trace_entry_t &a = first.entries[i];
            const gtavee_push_event_trace_entry_t &b = second.entries[i];
            if ((b.sequence & 1) != 0 || a.sequence != b.sequence ||
                a.call_count != b.call_count ||
                a.last_result != b.last_result || a.arg0 != b.arg0 ||
                a.arg1 != b.arg1 || b.call_count == 0 ||
                b.call_count == last_push_event_counts[i])
                continue;

            const uint32_t delta =
                b.call_count - last_push_event_counts[i];
            plugin_log("[GTA-PUSH-TRACE] %s calls=%u (+%u) "
                       "result=%d/0x%08x arg0=0x%llx",
                       push_event_trace_names[i], b.call_count, delta,
                       b.last_result, (unsigned int)b.last_result,
                       (unsigned long long)b.arg0);
            last_push_event_counts[i] = b.call_count;
        }
    };

    uint32_t last_ps5api_hit_count = 0;
    bool ps5api_counter_warning_logged = false;
    auto poll_ps5api_hit_counter = [&]() {
        if (!ps5api_hit_counter_address) return;

        uint32_t count = 0;
        if (kernel_proc_copyout(pid, ps5api_hit_counter_address, &count,
                                sizeof(count)) < 0) {
            if (!ps5api_counter_warning_logged) {
                plugin_log("[LSO-PS5API-HIT] Could not read compatibility counter");
                ps5api_counter_warning_logged = true;
            }
            return;
        }
        if (count != last_ps5api_hit_count) {
            plugin_log("[LSO-PS5API-HIT] locally completed requests=%u (+%u)",
                       count, count - last_ps5api_hit_count);
            last_ps5api_hit_count = count;
        }
    };

    lso_request_snapshot_t last_requests[LSO_REQUEST_SLOT_COUNT] = {};
    bool request_seen[LSO_REQUEST_SLOT_COUNT] = {};
    uint64_t request_metadata_id[LSO_REQUEST_SLOT_COUNT] = {};
    uint64_t request_error_text_id[LSO_REQUEST_SLOT_COUNT] = {};
    uint64_t kernel_response_completed_id[LSO_REQUEST_SLOT_COUNT] = {};
    uint64_t last_next_request_id = 0;
    bool next_request_id_seen = false;
    bool request_read_warning_logged = false;
    bool have_active_requests = false;
    bool auth_presence_logged = false;
    auto poll_lso_request_audit = [&]() {
        if (!lso_module_base) return;

        if (!auth_presence_logged) {
            uint64_t account_id = 0;
            uint64_t auth_token_length = 0;
            uint64_t online_id_length = 0;
            uint64_t relay_token_length = 0;
            const bool auth_readable =
                kernel_proc_copyout(
                    pid, lso_module_base + (intptr_t)LSO_ACCOUNT_ID_OFFSET,
                    &account_id, sizeof(account_id)) == 0 &&
                kernel_proc_copyout(
                    pid, lso_module_base +
                        (intptr_t)LSO_AUTH_TOKEN_STRING_OFFSET + 0x18,
                    &auth_token_length, sizeof(auth_token_length)) == 0 &&
                kernel_proc_copyout(
                    pid, lso_module_base +
                        (intptr_t)LSO_ONLINE_ID_STRING_OFFSET + 0x18,
                    &online_id_length, sizeof(online_id_length)) == 0 &&
                kernel_proc_copyout(
                    pid, lso_module_base +
                        (intptr_t)LSO_RELAY_TOKEN_STRING_OFFSET + 0x18,
                    &relay_token_length, sizeof(relay_token_length)) == 0;
            if (auth_readable) {
                plugin_log("[LSO-AUTH] bearer_present=%u bearer_len=%llu "
                           "online_id_present=%u online_id_len=%llu "
                           "account_id_present=%u relay_present=%u "
                           "relay_len=%llu (values not logged)",
                           auth_token_length != 0,
                           (unsigned long long)auth_token_length,
                           online_id_length != 0,
                           (unsigned long long)online_id_length,
                           account_id != 0, relay_token_length != 0,
                           (unsigned long long)relay_token_length);
                auth_presence_logged = true;
            }
        }

        const intptr_t next_id_address =
            lso_module_base + (intptr_t)LSO_REQUEST_NEXT_ID_OFFSET;
        uint64_t next_request_id = 0;
        if (kernel_proc_copyout(pid, next_id_address, &next_request_id,
                                sizeof(next_request_id)) < 0)
        {
            if (!request_read_warning_logged) {
                plugin_log("[LSO-REQ] Could not read the request counter");
                request_read_warning_logged = true;
            }
            return;
        }

        const bool counter_changed =
            next_request_id_seen && next_request_id != last_next_request_id;
        if (!next_request_id_seen || counter_changed) {
            plugin_log("[LSO-REQ] Next request id=0x%llx%s",
                       (unsigned long long)next_request_id,
                       next_request_id_seen ? " (changed)" : " (initial)");
            last_next_request_id = next_request_id;
            next_request_id_seen = true;
        }

        // With no active records, the counter is enough to detect new work.
        // Scan the table only initially, when the counter changes, or while a
        // request remains active.
        if (!counter_changed && !have_active_requests &&
            next_request_id_seen && last_next_request_id == next_request_id &&
            request_seen[0])
            return;

        bool any_active = false;
        for (int i = 0; i < LSO_REQUEST_SLOT_COUNT; i++) {
            const intptr_t record =
                lso_module_base + (intptr_t)LSO_REQUEST_TABLE_OFFSET +
                (intptr_t)(i * LSO_REQUEST_RECORD_STRIDE);
            lso_request_snapshot_t current = {};
            uint64_t id_after = 0;

            if (kernel_proc_copyout(pid, record, &current.id,
                                    sizeof(current.id)) < 0 ||
                kernel_proc_copyout(
                    pid, record + (intptr_t)LSO_REQUEST_BODY_SIZE_OFFSET,
                    &current.body_size, sizeof(current.body_size)) < 0 ||
                kernel_proc_copyout(
                    pid, record + (intptr_t)LSO_REQUEST_RESPONSE_TAIL_OFFSET,
                    &current.tail, sizeof(current.tail)) < 0 ||
                kernel_proc_copyout(pid, record, &id_after,
                                    sizeof(id_after)) < 0)
            {
                if (!request_read_warning_logged) {
                    plugin_log("[LSO-REQ] Could not read request slot %d", i);
                    request_read_warning_logged = true;
                }
                continue;
            }

            // Reject a slot that changed while the snapshots were copied.
            if (current.id != id_after) continue;

            const bool active = current.id != 0 || current.body_size != 0 ||
                current.tail.response_size != 0 ||
                current.tail.read_offset != 0 ||
                current.tail.http_status != 0 || current.tail.complete != 0 ||
                current.tail.response_ready != 0;
            any_active |= active;

            if (current.id != 0 && request_metadata_id[i] != current.id) {
                char api_group[0x61] = {};
                char path[0x101] = {};
                char method[0x11] = {};
                const bool metadata_readable =
                    kernel_proc_copyout(
                        pid, record + (intptr_t)LSO_REQUEST_API_GROUP_OFFSET,
                        api_group, sizeof(api_group) - 1) == 0 &&
                    kernel_proc_copyout(
                        pid, record + (intptr_t)LSO_REQUEST_PATH_OFFSET,
                        path, sizeof(path) - 1) == 0 &&
                    kernel_proc_copyout(
                        pid, record + (intptr_t)LSO_REQUEST_METHOD_OFFSET,
                        method, sizeof(method) - 1) == 0;
                if (metadata_readable) {
                    sanitize_lso_request_label(api_group, sizeof(api_group),
                                               false);
                    sanitize_lso_request_label(path, sizeof(path), true);
                    sanitize_lso_request_label(method, sizeof(method), false);
                    plugin_log("[LSO-REQ-META] slot=%02d id=0x%llx "
                               "group='%s' method='%s' route='%s' "
                               "(query removed; digits redacted)",
                               i, (unsigned long long)current.id,
                               api_group, method, path);
                    request_metadata_id[i] = current.id;
                }
            }

            // FW 8.60's legacy async SendRequest path can remain blocked
            // before reaching LSO's response handler. Publish the four exact
            // startup responses directly into LSO's own record instead. The
            // response bytes and numeric fields are written first; the two
            // completion bytes are written last as the publication step so
            // LSO's unchanged PollAsync/ReadData routines consume it normally.
            if (kernel_response_route_mask != 0 && current.id != 0 &&
                current.tail.complete == 0 &&
                kernel_response_completed_id[i] != current.id)
            {
                char response_group[0x61] = {};
                char response_path[0x201] = {};
                char response_method[0x11] = {};
                const bool route_readable =
                    kernel_proc_copyout(
                        pid, record + (intptr_t)LSO_REQUEST_API_GROUP_OFFSET,
                        response_group, sizeof(response_group) - 1) == 0 &&
                    kernel_proc_copyout(
                        pid, record + (intptr_t)LSO_REQUEST_PATH_OFFSET,
                        response_path, sizeof(response_path) - 1) == 0 &&
                    kernel_proc_copyout(
                        pid, record + (intptr_t)LSO_REQUEST_METHOD_OFFSET,
                        response_method, sizeof(response_method) - 1) == 0;

                const char *response = nullptr;
                const char *route_label = nullptr;
                uint32_t route_bit = 0;
                if (route_readable && strcmp(response_method, "GET") == 0) {
                    auto exact_or_query = [](const char *actual,
                                             const char *expected) {
                        const size_t length = strlen(expected);
                        return strncmp(actual, expected, length) == 0 &&
                            (actual[length] == '\0' || actual[length] == '?');
                    };

                    if (strcmp(response_group,
                               "communicationRestrictionStatus") == 0)
                    {
                        route_bit = 0x01;
                        route_label = "communicationRestrictionStatus";
                        // CommunicationRestrictionStatus2V3 models this as
                        // one required boolean named "restricted".  The old
                        // plural array was accepted as JSON but rejected by
                        // libSceNpCppWebApi's typed response parser, which
                        // made GTA retry this request indefinitely.
                        response = "{\"restricted\":false}";
                    } else if (strcmp(response_group, "userProfile") == 0 &&
                               exact_or_query(response_path,
                                              "/v1/users/me/blocks"))
                    {
                        route_bit = 0x02;
                        route_label = "blocks";
                        response = "{\"blocks\":[],\"totalItemCount\":0}";
                    } else if (strcmp(response_group, "sessionManager") == 0) {
                        static const char prefix[] = "/v1/users/";
                        static const char suffix[] =
                            "/playerSessionsInvitations";
                        const size_t prefix_length = sizeof(prefix) - 1;
                        const size_t account_id_length = 19;
                        const size_t suffix_length = sizeof(suffix) - 1;
                        const size_t suffix_offset =
                            prefix_length + account_id_length;
                        bool account_id_shape =
                            strncmp(response_path, prefix, prefix_length) == 0;
                        for (size_t digit = 0;
                             account_id_shape && digit < account_id_length;
                             ++digit)
                        {
                            const char value =
                                response_path[prefix_length + digit];
                            account_id_shape = value >= '0' && value <= '9';
                        }
                        if (account_id_shape &&
                            strncmp(response_path + suffix_offset, suffix,
                                    suffix_length) == 0 &&
                            (response_path[suffix_offset + suffix_length] ==
                                 '\0' ||
                             response_path[suffix_offset + suffix_length] ==
                                 '?'))
                        {
                            route_bit = 0x04;
                            route_label = "playerSessionsInvitations";
                            response = "{\"invitations\":[]}";
                        }
                    }

                    if (response == nullptr &&
                        strcmp(response_group, "userProfile") == 0 &&
                        exact_or_query(response_path,
                                       "/v1/users/me/friends"))
                    {
                        route_bit = 0x08;
                        route_label = "friends";
                        response = "{\"friends\":[],\"totalItemCount\":0}";
                    }
                }

                if (response != nullptr &&
                    (kernel_response_route_mask & route_bit) != 0)
                {
                    uint64_t id_before = 0;
                    const uint64_t response_size = strlen(response);
                    const uint64_t read_offset = 0;
                    const int32_t http_status = 200;
                    const uint16_t completion_flags = 0x0101;

                    bool wrote =
                        kernel_proc_copyout(pid, record, &id_before,
                                            sizeof(id_before)) == 0 &&
                        id_before == current.id &&
                        kernel_proc_copyin(
                            pid, response,
                            record +
                                (intptr_t)LSO_REQUEST_RESPONSE_DATA_OFFSET,
                            (size_t)response_size + 1) == 0 &&
                        kernel_proc_copyin(
                            pid, &response_size,
                            record +
                                (intptr_t)LSO_REQUEST_RESPONSE_TAIL_OFFSET,
                            sizeof(response_size)) == 0 &&
                        kernel_proc_copyin(
                            pid, &read_offset,
                            record +
                                (intptr_t)LSO_REQUEST_RESPONSE_TAIL_OFFSET + 8,
                            sizeof(read_offset)) == 0 &&
                        kernel_proc_copyin(
                            pid, &http_status,
                            record +
                                (intptr_t)LSO_REQUEST_RESPONSE_TAIL_OFFSET + 16,
                            sizeof(http_status)) == 0 &&
                        kernel_proc_copyin(
                            pid, &completion_flags,
                            record +
                                (intptr_t)LSO_REQUEST_RESPONSE_TAIL_OFFSET + 20,
                            sizeof(completion_flags)) == 0;

                    uint64_t id_after_response = 0;
                    lso_request_tail_t verified_tail = {};
                    wrote = wrote &&
                        kernel_proc_copyout(pid, record, &id_after_response,
                                            sizeof(id_after_response)) == 0 &&
                        kernel_proc_copyout(
                            pid,
                            record +
                                (intptr_t)LSO_REQUEST_RESPONSE_TAIL_OFFSET,
                            &verified_tail, sizeof(verified_tail)) == 0 &&
                        id_after_response == current.id &&
                        verified_tail.response_size == response_size &&
                        verified_tail.read_offset == 0 &&
                        verified_tail.http_status == 200 &&
                        verified_tail.complete == 1 &&
                        verified_tail.response_ready == 1;

                    if (wrote) {
                        kernel_response_completed_id[i] = current.id;
                        current.tail = verified_tail;
                        plugin_log("[LSO-KERNEL-RESPONSE] slot=%02d "
                                   "id=0x%llx route=%s published: "
                                   "HTTP 200 complete=1 ready=1",
                                   i, (unsigned long long)current.id,
                                   route_label);
                    } else {
                        plugin_log("[LSO-KERNEL-RESPONSE] slot=%02d "
                                   "id=0x%llx route=%s publication raced or "
                                   "failed; "
                                   "will retry while the record is active",
                                   i, (unsigned long long)current.id,
                                   route_label);
                    }
                }
            }

            // Capture a short printable preview only for failed HTTP replies.
            // Successful payloads, request bodies, headers, and credentials
            // remain excluded from the loader log.
            if (current.id != 0 && current.tail.http_status >= 400 &&
                current.tail.http_status <= 599 &&
                current.tail.complete != 0 && current.tail.response_size > 0 &&
                request_error_text_id[i] != current.id)
            {
                char error_text[193] = {};
                size_t bytes = (size_t)current.tail.response_size;
                if (bytes >= sizeof(error_text)) bytes = sizeof(error_text) - 1;
                if (kernel_proc_copyout(
                        pid,
                        record + (intptr_t)LSO_REQUEST_RESPONSE_DATA_OFFSET,
                        error_text, bytes) == 0)
                {
                    error_text[bytes] = '\0';
                    sanitize_lso_request_label(error_text, sizeof(error_text),
                                               false);
                    plugin_log("[LSO-ERR] slot=%02d id=0x%llx HTTP %d "
                               "response='%s'%s", i,
                               (unsigned long long)current.id,
                               current.tail.http_status, error_text,
                               current.tail.response_size > bytes
                                   ? " (truncated)" : "");
                    request_error_text_id[i] = current.id;
                }
            }

            const bool changed = !request_seen[i] ||
                memcmp(&current, &last_requests[i], sizeof(current)) != 0;
            if (changed && active) {
                plugin_log("[LSO-REQ] slot=%02d id=0x%llx body=%llu "
                           "response=%llu read=%llu status=%d/0x%x "
                           "complete=%u ready=%u (read-only)",
                           i, (unsigned long long)current.id,
                           (unsigned long long)current.body_size,
                           (unsigned long long)current.tail.response_size,
                           (unsigned long long)current.tail.read_offset,
                           current.tail.http_status,
                           (unsigned int)current.tail.http_status,
                           current.tail.complete,
                           current.tail.response_ready);
            } else if (changed && request_seen[i] &&
                       (last_requests[i].id != 0 ||
                        last_requests[i].tail.complete != 0 ||
                        last_requests[i].tail.response_ready != 0))
            {
                plugin_log("[LSO-REQ] slot=%02d cleared (read-only)", i);
            }

            last_requests[i] = current;
            request_seen[i] = true;
        }
        have_active_requests = any_active;
    };

    while (1) {
        poll_lso_call_trace();
        poll_lso_net_boundary();
        poll_gta_http_boundary();
        poll_cpp_boundary_trace();
        poll_lso_request_audit();
        poll_gtav_np_state();
        poll_push_event_trace();
        poll_ps5api_hit_counter();
        if (lso_module_base)
            poll_game_transport_sockets(pid, &transport_audit);

        struct kevent ev;
        struct timespec timeout = {0, 100000000}; // 100 ms while tracing
        const struct timespec *timeout_ptr =
            (lso_call_trace_address || lso_module_base) ? &timeout : nullptr;
        int nev = kevent(kq, nullptr, 0, &ev, 1, timeout_ptr);
        if (nev > 0 && (ev.fflags & NOTE_EXIT)) {
            poll_lso_call_trace();
            poll_lso_net_boundary();
            poll_gta_http_boundary();
            poll_cpp_boundary_trace();
            poll_lso_request_audit();
            poll_gtav_np_state();
            poll_push_event_trace();
            poll_ps5api_hit_counter();
            if (transport_audit.ever_read_successfully &&
                (!transport_audit.direct_kernel_logged ||
                 transport_audit.direct_layout_validated)) {
                plugin_log("[GTA-SOCKET] Summary: events=%u TCP443=%s "
                           "UDP8081=%s socket_files=%u valid_pcbs=%u",
                           transport_audit.open_events,
                           transport_audit.saw_tcp_443 ? "SEEN" : "NOT_SEEN",
                           transport_audit.saw_udp_8081 ? "SEEN" : "NOT_SEEN",
                           transport_audit.max_socket_files,
                           transport_audit.max_valid_pcbs);
            } else if (transport_audit.direct_kernel_logged) {
                plugin_log("[GTA-SOCKET] Summary: UNAVAILABLE "
                           "(kernel socket layout not validated; "
                           "socket_files=%u)",
                           transport_audit.max_socket_files);
            } else {
                plugin_log("[GTA-SOCKET] Summary: UNAVAILABLE "
                           "(no socket-table samples)");
            }
            plugin_log("[Wait] pid %d exited (event data=0x%llx)", pid,
                       (unsigned long long)ev.data);
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
    plugin_log("[Cleanup] Removing %s", sandbox_dir);
    if (cleanup_directory(sandbox_dir) == 0) {
        plugin_log("[Cleanup] Sandbox removed");
        printf_notification("Sandbox %s cleaned     ", sandbox_id);
    } else {
        plugin_log("[Cleanup] Removal failed: %s", strerror(errno));
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
        plugin_log("[Sandbox] No sandbox found for %s", title_id);
        return false;
    }
    snprintf(sandbox_id, sandbox_id_size, "%s_%03d", title_id, sandbox_num);
    plugin_log("[Sandbox] Resolved: %s", sandbox_id);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Diagnostic LSO 1.010.002 / GTAV E&E 1.10
//
//  LSO installe deux groupes de sauts absolus synchrones pendant module_start:
//    - 9 hooks réseau
//    - 19 hooks d'état NP (connexion/utilisateur/online)
//
//  Son patch.log écrit "complete" même lorsqu'un groupe ne trouve aucun motif.
//  Le loader repère donc les thunks avant LoadStartModule puis vérifie qu'ils
//  pointent bien dans LSO après le retour. Le diagnostic reste strictement
//  limité à PPSA04264 + un PRX dont le nom commence par LSO.
// ─────────────────────────────────────────────────────────────────────────────

#define LSO_NET_HOOK_COUNT 9
#define LSO_NP_HOOK_COUNT 19
#define LSO_HOOK_COUNT (LSO_NET_HOOK_COUNT + LSO_NP_HOOK_COUNT)
#define LSO_WEBAPI_HOOK_COUNT 8
#define GTAVEE_110_IMAGE_SIZE 0x5e6c000ULL
#define LSO_1010_IMAGE_SIZE_MAX 0x180000ULL
#define LSO_HTTP_STATUS_BLOCK_OFFSET 0x13379ULL
#define LSO_HTTP_SEND_BLOCK_OFFSET   0x1335FULL

// These are the fixed GTAV E&E 1.10 virtual addresses used by LSO itself,
// not offsets relative to the 0x400000 eboot mapping.
static const uint64_t k_lso_webapi_slot_addresses[LSO_WEBAPI_HOOK_COUNT] = {
    0x3cb0868ULL, // sceNpWebApi2Initialize
    0x3cb0870ULL, // sceNpWebApi2Terminate
    0x3cb08a0ULL, // sceNpWebApi2CreateUserContext
    0x3cb08a8ULL, // sceNpWebApi2DeleteUserContext
    0x3cb08f8ULL, // sceNpWebApi2DeleteRequest
    0x3cb0900ULL, // sceNpWebApi2CreateRequest
    0x3cb0908ULL, // sceNpWebApi2SendRequest
    0x3cb0910ULL, // sceNpWebApi2ReadData
};

// LSO 1.010.002 redirects the ordinary WebAPI imports above, but it leaves
// GTA E&E's adjacent PS5 PushEvent imports pointed at the native firmware
// implementation. A fake-signed-in user has no native NP push context on
// newer firmware, so those calls fail before GTA starts its Online requests.
static const uint64_t
k_gtavee_push_event_slot_addresses[GTAVEE_PUSH_EVENT_HOOK_COUNT] = {
    0x3cb08b0ULL, // sceNpWebApi2PushEventCreatePushContext
    0x3cb08b8ULL, // sceNpWebApi2PushEventStartPushContextCallback
    0x3cb08c0ULL, // sceNpWebApi2PushEventDeletePushContext
    0x3cb08c8ULL, // sceNpWebApi2PushEventCreateHandle
    0x3cb08d0ULL, // sceNpWebApi2PushEventCreateFilter
    0x3cb08d8ULL, // sceNpWebApi2PushEventDeleteHandle
    0x3cb08e0ULL, // sceNpWebApi2PushEventDeleteFilter
    0x3cb08e8ULL, // sceNpWebApi2PushEventRegisterCallback
    0x3cb08f0ULL, // sceNpWebApi2PushEventUnregisterCallback
};

// Runtime addresses of the corresponding GTA E&E 1.10 PLT entries. An
// unresolved slot normally points six bytes into its entry; that continuation
// is safe to call once and lets the platform resolver preserve normal lazy
// binding while the wrapper records the original result.
static const uint64_t
k_gtavee_push_event_plt_addresses[GTAVEE_PUSH_EVENT_HOOK_COUNT] = {
    0x3791d60ULL, 0x3791d70ULL, 0x3791d80ULL,
    0x3791d90ULL, 0x3791da0ULL, 0x3791db0ULL,
    0x3791dc0ULL, 0x3791dd0ULL, 0x3791de0ULL,
};

static const char *
k_gtavee_push_event_names[GTAVEE_PUSH_EVENT_HOOK_COUNT] = {
    "CreatePushContext", "StartPushContextCallback", "DeletePushContext",
    "CreateHandle", "CreateFilter", "DeleteHandle", "DeleteFilter",
    "RegisterCallback", "UnregisterCallback",
};

static const uint8_t k_lso_hook_signatures[LSO_HOOK_COUNT][6] = {
    // Réseau (9)
    {0xFF, 0x25, 0xDA, 0xF2, 0x91, 0x00},
    {0xFF, 0x25, 0xD2, 0xF2, 0x91, 0x00},
    {0xFF, 0x25, 0xC2, 0xF2, 0x91, 0x00},
    {0xFF, 0x25, 0xBA, 0xF2, 0x91, 0x00},
    {0xFF, 0x25, 0x4A, 0xEF, 0x91, 0x00},
    {0xFF, 0x25, 0x1A, 0xEF, 0x91, 0x00},
    {0xFF, 0x25, 0x02, 0xEF, 0x91, 0x00},
    {0xFF, 0x25, 0xFA, 0xEE, 0x91, 0x00},
    {0xFF, 0x25, 0xF2, 0xEE, 0x91, 0x00},

    // État NP (19)
    {0xFF, 0x25, 0x42, 0xEC, 0x91, 0x00},
    {0xFF, 0x25, 0x32, 0xEC, 0x91, 0x00},
    {0xFF, 0x25, 0x5A, 0xEE, 0x91, 0x00},
    {0xFF, 0x25, 0x52, 0xEE, 0x91, 0x00},
    {0xFF, 0x25, 0x62, 0xEE, 0x91, 0x00},
    {0xFF, 0x25, 0x8A, 0xED, 0x91, 0x00},
    {0xFF, 0x25, 0xDA, 0xED, 0x91, 0x00},
    {0xFF, 0x25, 0x1A, 0xEE, 0x91, 0x00},
    {0xFF, 0x25, 0x02, 0xEE, 0x91, 0x00},
    {0xFF, 0x25, 0x0A, 0xEE, 0x91, 0x00},
    {0xFF, 0x25, 0xF2, 0xED, 0x91, 0x00},
    {0xFF, 0x25, 0xD2, 0xED, 0x91, 0x00},
    {0xFF, 0x25, 0xE2, 0xED, 0x91, 0x00},
    {0xFF, 0x25, 0x12, 0xEE, 0x91, 0x00},
    {0xFF, 0x25, 0x42, 0xEE, 0x91, 0x00},
    {0xFF, 0x25, 0xEA, 0xED, 0x91, 0x00},
    {0xFF, 0x25, 0x1A, 0xDD, 0x91, 0x00},
    {0xFF, 0x25, 0x12, 0xDD, 0x91, 0x00},
    {0xFF, 0x25, 0x0A, 0xDD, 0x91, 0x00},
};

static const uint8_t k_lso_is_safe_signature[] = {
    0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56,
    0x53, 0x48, 0x83, 0xEC, 0x28, 0x4C, 0x8B, 0x35,
    0xCC, 0xB7, 0x4C, 0x02, 0x48, 0x89, 0xFB, 0x49,
    0x8B, 0x06, 0x48, 0x89, 0x45, 0xE0, 0x0F, 0xB6,
    0x05, 0xCF, 0x4B, 0xDA, 0x03,
};

// LSO also patches GTA's Rockstar service endpoint and the certificate block
// used to authenticate that endpoint.  These checks are deliberately
// read-only: they let the loader prove that both patches reached the live
// FW 8.60 game image without changing LSO's code or network behaviour.
static const char k_rockstar_original_host[] = "ros.rockstargames.com";
static const char k_lso_redirect_host[] = "rockstargames.gtao.us";
static const char k_rockstar_original_cert_prefix[] =
    "-----BEGIN CERTIFICATE-----\nMIIEKjCCAxKgAwIBAgIE";
static const char k_lso_redirect_cert_prefix[] =
    "-----BEGIN CERTIFICATE-----\nMIID+zCCAuOgAwIBAgIJ";
// Runtime virtual offset in the extracted ELF. (The SELF container file
// offset is different and must not be used against the mapped module.)
static constexpr uint64_t LSO_REDIRECT_CERT_OFFSET = 0x22847ULL;
static constexpr size_t LSO_REDIRECT_CERT_LENGTH = 0x5A0;
static constexpr size_t GTA_ORIGINAL_CERT_BLOCK_LENGTH = 0x5E1;

struct LsoDiagnostics {
    bool enabled;
    intptr_t game_base;
    intptr_t hook_addresses[LSO_HOOK_COUNT];
    uint8_t hook_original[LSO_HOOK_COUNT][16];
    intptr_t is_safe_address;
    uint8_t is_safe_before[16];
    intptr_t rockstar_host_address;
    intptr_t rockstar_cert_address;
};

static bool has_lso_candidate(const char *title_id,
                              const std::vector<PRXConfig> &prx_list)
{
    if (strcmp(title_id, "PPSA04264") != 0) return false;
    for (size_t i = 0; i < prx_list.size(); i++) {
        const char *name = strrchr(prx_list[i].path.c_str(), '/');
        name = name ? name + 1 : prx_list[i].path.c_str();
        size_t length = strlen(name);
        bool lso_prefix = length >= 3 &&
            (name[0] == 'L' || name[0] == 'l') &&
            (name[1] == 'S' || name[1] == 's') &&
            (name[2] == 'O' || name[2] == 'o');
        bool prx_suffix = length >= 4 &&
            (name[length - 4] == '.') &&
            (name[length - 3] == 'P' || name[length - 3] == 'p') &&
            (name[length - 2] == 'R' || name[length - 2] == 'r') &&
            (name[length - 1] == 'X' || name[length - 1] == 'x');
        if (lso_prefix && prx_suffix) return true;
    }
    return false;
}

static void prepare_lso_diagnostics(pid_t pid, LsoDiagnostics *diag)
{
    if (!diag || !diag->enabled) return;

    diag->game_base = kernel_dynlib_mapbase_addr(pid, 0x1);
    if (!diag->game_base) {
        // The PS5 main executable is not always returned by the SDK dynlib
        // object walker. LSO's own log identified the GTAV E&E 1.10 image as
        // 0x400000..0x626c000, so verify that address is readable and use it.
        uint8_t probe = 0;
        if (kernel_proc_copyout(pid, 0x400000, &probe, sizeof(probe)) == 0) {
            diag->game_base = 0x400000;
            plugin_log("[LSO-DIAG] SDK eboot lookup returned 0; using verified "
                       "GTAV E&E 1.10 fallback base 0x400000");
        } else {
            plugin_log("[LSO-DIAG] Eboot base not found and fallback is unreadable; "
                       "diagnostics disabled");
            diag->enabled = false;
            return;
        }
    }

    const size_t chunk_size = 0x10000;
    // 0x80 covers every signature above across a scan-chunk boundary,
    // including the longer PEM certificate prefix.
    const size_t overlap = 0x80;
    uint8_t *buffer = (uint8_t *)malloc(chunk_size + overlap);
    if (!buffer) {
        plugin_log("[LSO-DIAG] Scan-buffer allocation failed");
        diag->enabled = false;
        return;
    }

    int found_hooks = 0;
    bool found_is_safe = false;
    bool found_rockstar_host = false;
    bool found_rockstar_cert = false;

    for (uint64_t offset = 0; offset < GTAVEE_110_IMAGE_SIZE; offset += chunk_size) {
        size_t main_len = (size_t)((GTAVEE_110_IMAGE_SIZE - offset) < chunk_size
                          ? (GTAVEE_110_IMAGE_SIZE - offset) : chunk_size);
        size_t read_len = main_len;
        if (offset + main_len < GTAVEE_110_IMAGE_SIZE)
            read_len += overlap;

        if (kernel_proc_copyout(pid, diag->game_base + (intptr_t)offset,
                                buffer, read_len) < 0)
            continue;

        for (size_t i = 0; i < main_len; i++) {
            if (i + 6 <= read_len &&
                buffer[i] == 0xFF && buffer[i + 1] == 0x25) {
                for (int j = 0; j < LSO_HOOK_COUNT; j++) {
                    if (!diag->hook_addresses[j] &&
                        memcmp(buffer + i, k_lso_hook_signatures[j], 6) == 0)
                    {
                        diag->hook_addresses[j] =
                            diag->game_base + (intptr_t)offset + (intptr_t)i;
                        if (i + sizeof(diag->hook_original[j]) <= read_len)
                            memcpy(diag->hook_original[j], buffer + i,
                                   sizeof(diag->hook_original[j]));
                        found_hooks++;
                    }
                }
            }

            if (!found_is_safe && i + sizeof(k_lso_is_safe_signature) <= read_len &&
                buffer[i] == 0x55 && buffer[i + 1] == 0x48 &&
                memcmp(buffer + i, k_lso_is_safe_signature,
                       sizeof(k_lso_is_safe_signature)) == 0)
            {
                diag->is_safe_address =
                    diag->game_base + (intptr_t)offset + (intptr_t)i;
                memcpy(diag->is_safe_before, buffer + i,
                       sizeof(diag->is_safe_before));
                found_is_safe = true;
            }

            if (!found_rockstar_host &&
                i + sizeof(k_rockstar_original_host) - 1 <= read_len &&
                buffer[i] == 'r' &&
                memcmp(buffer + i, k_rockstar_original_host,
                       sizeof(k_rockstar_original_host) - 1) == 0)
            {
                diag->rockstar_host_address =
                    diag->game_base + (intptr_t)offset + (intptr_t)i;
                found_rockstar_host = true;
            }

            if (!found_rockstar_cert &&
                i + sizeof(k_rockstar_original_cert_prefix) - 1 <= read_len &&
                buffer[i] == '-' &&
                memcmp(buffer + i, k_rockstar_original_cert_prefix,
                       sizeof(k_rockstar_original_cert_prefix) - 1) == 0)
            {
                diag->rockstar_cert_address =
                    diag->game_base + (intptr_t)offset + (intptr_t)i;
                found_rockstar_cert = true;
            }
        }

        if (found_hooks == LSO_HOOK_COUNT && found_is_safe &&
            found_rockstar_host && found_rockstar_cert)
            break;
    }

    free(buffer);

    int net_found = 0;
    int np_found = 0;
    for (int i = 0; i < LSO_HOOK_COUNT; i++) {
        if (diag->hook_addresses[i]) {
            if (i < LSO_NET_HOOK_COUNT) net_found++;
            else np_found++;
        } else {
            plugin_log("[LSO-DIAG] %s signature #%02d missing before load",
                       i < LSO_NET_HOOK_COUNT ? "NET" : "NP",
                       i < LSO_NET_HOOK_COUNT ? i + 1 : i - LSO_NET_HOOK_COUNT + 1);
        }
    }

    plugin_log("[LSO-DIAG] Before LSO: base=0x%llx NET=%d/%d NP=%d/%d IsSafe=%s",
               (unsigned long long)diag->game_base,
               net_found, LSO_NET_HOOK_COUNT, np_found, LSO_NP_HOOK_COUNT,
               found_is_safe ? "FOUND" : "MISSING");
    plugin_log("[LSO-ROCKSTAR] Before LSO: host=%s certificate=%s",
               found_rockstar_host ? "FOUND" : "MISSING",
               found_rockstar_cert ? "FOUND" : "MISSING");
}

static bool lso_get_absolute_hook_destination(pid_t pid, intptr_t target,
                                               intptr_t *destination_out)
{
    uint8_t code[14] = {};
    if (destination_out) *destination_out = 0;
    if (!target ||
        kernel_proc_copyout(pid, target, code, sizeof(code)) < 0)
        return false;

    if (code[0] != 0xFF || code[1] != 0x25 || code[2] != 0 ||
        code[3] != 0 || code[4] != 0 || code[5] != 0)
        return false;

    uint64_t destination = 0;
    memcpy(&destination, code + 6, sizeof(destination));
    if (destination_out) *destination_out = (intptr_t)destination;
    return true;
}

static bool lso_absolute_hook_points_into_module(pid_t pid, intptr_t target,
                                                  intptr_t module_base)
{
    intptr_t destination = 0;
    if (!module_base ||
        !lso_get_absolute_hook_destination(pid, target, &destination))
        return false;

    return destination >= (uint64_t)module_base &&
           destination < (uint64_t)module_base + LSO_1010_IMAGE_SIZE_MAX;
}

static void verify_lso_diagnostics(pid_t pid, intptr_t module_base,
                                    const LsoDiagnostics *diag,
                                    const char *phase)
{
    if (!diag || !diag->enabled) return;

    int net_installed = 0;
    int np_installed = 0;
    for (int i = 0; i < LSO_HOOK_COUNT; i++) {
        bool installed = lso_absolute_hook_points_into_module(
            pid, diag->hook_addresses[i], module_base);
        if (installed) {
            if (i < LSO_NET_HOOK_COUNT) net_installed++;
            else np_installed++;
        } else {
            plugin_log("[LSO-DIAG] %s hook #%02d NOT installed (target=0x%llx)",
                       i < LSO_NET_HOOK_COUNT ? "NET" : "NP",
                       i < LSO_NET_HOOK_COUNT ? i + 1 : i - LSO_NET_HOOK_COUNT + 1,
                       (unsigned long long)diag->hook_addresses[i]);
        }
    }

    bool is_safe_patched = false;
    if (diag->is_safe_address) {
        uint8_t after[sizeof(diag->is_safe_before)] = {};
        if (kernel_proc_copyout(pid, diag->is_safe_address,
                                after, sizeof(after)) == 0)
            is_safe_patched =
                memcmp(after, diag->is_safe_before, sizeof(after)) != 0;
    }

    plugin_log("[LSO-DIAG] %s: NET=%d/%d NP=%d/%d IsSafe=%s",
               phase, net_installed, LSO_NET_HOOK_COUNT,
               np_installed, LSO_NP_HOOK_COUNT,
               is_safe_patched ? "PATCHED" : "NOT PATCHED");

    const char *host_state = "MISSING";
    if (diag->rockstar_host_address) {
        char host_after[sizeof(k_rockstar_original_host)] = {};
        if (kernel_proc_copyout(pid, diag->rockstar_host_address,
                                host_after, sizeof(host_after) - 1) < 0) {
            host_state = "UNREADABLE";
        } else if (memcmp(host_after, k_lso_redirect_host,
                          sizeof(k_lso_redirect_host) - 1) == 0) {
            host_state = "REDIRECTED";
        } else if (memcmp(host_after, k_rockstar_original_host,
                          sizeof(k_rockstar_original_host) - 1) == 0) {
            host_state = "ORIGINAL";
        } else {
            host_state = "UNEXPECTED";
        }
    }

    const char *cert_state = "MISSING";
    if (diag->rockstar_cert_address) {
        uint8_t cert_after[GTA_ORIGINAL_CERT_BLOCK_LENGTH] = {};
        if (kernel_proc_copyout(pid, diag->rockstar_cert_address,
                                cert_after, sizeof(cert_after)) < 0) {
            cert_state = "UNREADABLE";
        } else if (memcmp(cert_after, k_lso_redirect_cert_prefix,
                          sizeof(k_lso_redirect_cert_prefix) - 1) == 0) {
            uint8_t expected[LSO_REDIRECT_CERT_LENGTH] = {};
            bool full_match = module_base != 0 &&
                kernel_proc_copyout(
                    pid,
                    module_base + (intptr_t)LSO_REDIRECT_CERT_OFFSET,
                    expected, sizeof(expected)) == 0 &&
                memcmp(cert_after, expected, sizeof(expected)) == 0;
            bool tail_cleared = true;
            bool tail_is_pem_whitespace = true;
            for (size_t i = LSO_REDIRECT_CERT_LENGTH;
                 i < GTA_ORIGINAL_CERT_BLOCK_LENGTH; i++)
            {
                if (cert_after[i] != 0) {
                    tail_cleared = false;
                }
                if (cert_after[i] != '\n' && cert_after[i] != '\r' &&
                    cert_after[i] != ' ' && cert_after[i] != '\t')
                {
                    tail_is_pem_whitespace = false;
                }
            }
            cert_state = full_match && tail_is_pem_whitespace
                ? "REPLACED_FULL_PEM"
                : (full_match && tail_cleared
                    ? "REPLACED_FULL_NUL_GAP"
                    : "REPLACED_PREFIX_ONLY");
        } else if (memcmp(cert_after, k_rockstar_original_cert_prefix,
                          sizeof(k_rockstar_original_cert_prefix) - 1) == 0) {
            cert_state = "ORIGINAL";
        } else {
            cert_state = "UNEXPECTED";
        }
    }

    plugin_log("[LSO-ROCKSTAR] %s: host=%s certificate=%s",
               phase, host_state, cert_state);
}

// LSO 1.010.002 replaces GTA's NP state-callback registration and callback
// pump with handlers that return success but do not retain/dispatch the game
// callback. On a slower fake sign-in, the real FW event can arrive after LSO
// installs those replacements and GTA never observes the state transition.
// Restore only these two original PLT thunks after LSO reports hook state=2;
// all identity, auth, reachability, WebAPI, and network hooks remain in LSO.
static bool restore_native_np_callback_thunks(pid_t pid,
                                               const LsoDiagnostics *diag)
{
    if (!diag || !diag->enabled) return false;

    static const int indices[] = {
        LSO_NET_HOOK_COUNT + 16, // sceNpRegisterStateCallbackA (NP #17)
        LSO_NET_HOOK_COUNT + 17, // sceNpCheckCallback        (NP #18)
    };
    static const char *names[] = {
        "sceNpRegisterStateCallbackA",
        "sceNpCheckCallback",
    };

    intptr_t protected_page = 0;
    bool page_is_writable = false;
    int restored = 0;

    for (size_t item = 0; item < sizeof(indices) / sizeof(indices[0]); item++) {
        const int index = indices[item];
        const intptr_t address = diag->hook_addresses[index];
        if (!address || diag->hook_original[index][0] != 0xFF ||
            diag->hook_original[index][1] != 0x25)
        {
            plugin_log("[LSO-NP-NATIVE] %s original thunk unavailable",
                       names[item]);
            continue;
        }

        const intptr_t page = address & ~(intptr_t)0xFFF;
        if (!page_is_writable || page != protected_page) {
            if (page_is_writable)
                kernel_mprotect(pid, protected_page, 0x1000,
                                PROT_READ | PROT_EXEC);
            protected_page = page;
            page_is_writable =
                kernel_mprotect(pid, protected_page, 0x1000,
                                PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
            if (!page_is_writable) {
                plugin_log("[LSO-NP-NATIVE] Failed to make thunk page writable");
                continue;
            }
        }

        if (kernel_proc_copyin(pid, diag->hook_original[index], address,
                               sizeof(diag->hook_original[index])) < 0)
        {
            plugin_log("[LSO-NP-NATIVE] Failed to restore %s", names[item]);
            continue;
        }

        uint8_t verify[16] = {};
        if (kernel_proc_copyout(pid, address, verify, sizeof(verify)) == 0 &&
            memcmp(verify, diag->hook_original[index], sizeof(verify)) == 0)
        {
            plugin_log("[LSO-NP-NATIVE] Restored %s @ 0x%llx",
                       names[item], (unsigned long long)address);
            restored++;
        } else {
            plugin_log("[LSO-NP-NATIVE] Verification failed for %s",
                       names[item]);
        }
    }

    if (page_is_writable)
        kernel_mprotect(pid, protected_page, 0x1000, PROT_READ | PROT_EXEC);

    plugin_log("[LSO-NP-NATIVE] Native callback dispatch restored: %d/2",
               restored);
    return restored == 2;
}

// Read-only audit of the eight direct sceNpWebApi2 slots patched by LSO's
// asynchronous hook thread. This deliberately does not redirect, wrap, or
// write any game code or data.
static void verify_lso_webapi_diagnostics(pid_t pid, intptr_t module_base,
                                          const char *phase)
{
    if (!module_base) {
        plugin_log("[LSO-WEBAPI] %s: module base unavailable", phase);
        return;
    }

    int routed = 0;
    int readable = 0;
    for (int i = 0; i < LSO_WEBAPI_HOOK_COUNT; i++) {
        const intptr_t slot_address =
            (intptr_t)k_lso_webapi_slot_addresses[i];
        intptr_t target = 0;
        if (kernel_proc_copyout(pid, slot_address, &target,
                                sizeof(target)) < 0)
        {
            plugin_log("[LSO-WEBAPI] %s slot=0x%llx unreadable",
                       k_lso_webapi_call_names[i],
                       (unsigned long long)slot_address);
            continue;
        }

        readable++;
        const bool points_to_lso =
            target >= module_base &&
            target < module_base + (intptr_t)LSO_1010_IMAGE_SIZE_MAX;
        if (points_to_lso) routed++;

        plugin_log("[LSO-WEBAPI] %s slot=0x%llx target=0x%llx %s",
                   k_lso_webapi_call_names[i],
                   (unsigned long long)slot_address,
                   (unsigned long long)target,
                   points_to_lso ? "ROUTED_TO_LSO" : "NOT_ROUTED_TO_LSO");
    }

    plugin_log("[LSO-WEBAPI] %s: readable=%d/%d routed=%d/%d (read-only)",
               phase, readable, LSO_WEBAPI_HOOK_COUNT,
               routed, LSO_WEBAPI_HOOK_COUNT);
}

// LSO 1.010.002 has a second WebAPI hook pass for imports inside
// libSceNpCppWebApi. Its poll thread sets the entire C++ stage ready after any
// one import is hooked. On a firmware where some PLT slots are still lazy, the
// remaining imports are never retried. CreateRequest can consequently return
// an LSO-owned request ID, after which a native AddHttpRequestHeader rejects
// that ID and GTA never reaches SendRequest.
//
// Complete only the eight imports that the supplied LSO binary itself targets,
// using the exact proxy entry points recovered from its immutable descriptor
// table. Every proxy signature and every relocation is verified before use.
static bool repair_lso_cpp_webapi_hooks(pid_t pid, intptr_t module_base)
{
    if (!module_base) {
        plugin_log("[LSO-CPP] LSO module base unavailable; repair not applied");
        return false;
    }

    struct HookSpec {
        const char *name;
        const char *nid;
        uint32_t proxy_offset;
        uint8_t signature[16];
        uint8_t signature_size;
    };

    static const HookSpec specs[] = {
        {"CreateRequest", "3EI-OSJ65Xc", 0x138b0,
         {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,
          0x41,0x55,0x41,0x54,0x53,0x50,0x41,0xbe}, 16},
        {"DeleteRequest", "vvzWO-DvG1s", 0x13a10,
         {0x55,0x48,0x89,0xe5,0x48,0x89,0xf8,0x31,
          0xc9,0x48,0x8d,0x3d,0xd0,0x4e,0x01,0x00}, 16},
        {"AbortRequest", "zpiPsH7dbFQ", 0x13a50,
         {0x55,0x48,0x89,0xe5,0x48,0x89,0xf8,0x31,
          0xc9,0x48,0x8d,0x3d,0x90,0x4e,0x01,0x00}, 16},
        {"SendRequest", "lQOCF84lvzw", 0x13a90,
         {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,
          0x41,0x55,0x41,0x54,0x53,0x48,0x81,0xec}, 16},
        {"ReadData", "OOY9+ObfKec", 0x13b70,
         {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,
          0x41,0x55,0x41,0x54,0x53,0x48,0x81,0xec}, 16},
        {"AddHttpRequestHeader", "egOOvrnF6mI", 0x13c50,
         {0x31,0xc0,0xc3}, 3},
        {"GetHttpResponseHeaderValueLength", "HwP3aM+c85c", 0x13c60,
         {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,
          0x53,0x48,0x83,0xec,0x28,0x4c,0x8b,0x3d}, 16},
        {"GetHttpResponseHeaderValue", "hksbskNToEA", 0x13d10,
         {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,
          0x41,0x54,0x53,0x48,0x83,0xec,0x30,0x4c}, 16},
    };

    // Validate the exact supplied PRX before touching the C++ library.
    for (const auto &spec : specs) {
        uint8_t current[sizeof(spec.signature)] = {};
        const intptr_t proxy = module_base + (intptr_t)spec.proxy_offset;
        if (kernel_proc_copyout(pid, proxy, current, spec.signature_size) < 0 ||
            memcmp(current, spec.signature, spec.signature_size) != 0)
        {
            plugin_log("[LSO-CPP] %s proxy signature mismatch @ 0x%llx; "
                       "repair aborted", spec.name,
                       (unsigned long long)proxy);
            return false;
        }
    }

    UniquePtr<Hijacker> hijacker = Hijacker::getHijacker(pid);
    if (!hijacker) {
        plugin_log("[LSO-CPP] Could not create Hijacker for import repair");
        return false;
    }

    // The PS5 eboot records this dependency as libSceNpCppWebApi.prx, while
    // Hijacker's name helper unconditionally appends .sprx. Match the loaded
    // module path directly so both runtime suffixes are supported.
    UniquePtr<SharedLib> cpp_webapi;
    for (auto library : hijacker->getLibs()) {
        const char *path = library->getPath().c_str();
        if (path && strstr(path, "libSceNpCppWebApi") != nullptr) {
            plugin_log("[LSO-CPP] Found loaded module: %s", path);
            cpp_webapi = library.release();
            break;
        }
    }
    if (!cpp_webapi) {
        plugin_log("[LSO-CPP] libSceNpCppWebApi module is not loaded");
        return false;
    }

    RtldMeta *metadata = cpp_webapi->getMetaData();
    if (!metadata) {
        plugin_log("[LSO-CPP] libSceNpCppWebApi metadata unavailable");
        return false;
    }

    const uintptr_t library_base = cpp_webapi->imagebase();
    const auto &symbols = metadata->getSymbolTable();
    const auto &plt_table = metadata->getPltTable();
    int found = 0;
    int already_routed = 0;
    int repaired = 0;
    int failed = 0;

    plugin_log("[LSO-CPP] Auditing eight C++ WebAPI imports at library "
               "base=0x%llx", (unsigned long long)library_base);

    for (const auto &spec : specs) {
        const ssize_t symbol_index = symbols.getSymbolIndex(Nid{spec.nid});
        if (symbol_index < 0) {
            plugin_log("[LSO-CPP] %s NID %s not imported", spec.name,
                       spec.nid);
            failed++;
            continue;
        }

        bool slot_found = false;
        for (const auto &relocation : plt_table) {
            if ((ssize_t)ELF64_R_SYM(relocation.r_info) != symbol_index)
                continue;

            slot_found = true;
            found++;
            const intptr_t slot =
                (intptr_t)library_base + (intptr_t)relocation.r_offset;
            const intptr_t proxy =
                module_base + (intptr_t)spec.proxy_offset;
            intptr_t previous = 0;
            if (kernel_proc_copyout(pid, slot, &previous, sizeof(previous)) < 0) {
                plugin_log("[LSO-CPP] %s slot 0x%llx is unreadable",
                           spec.name, (unsigned long long)slot);
                failed++;
                continue;
            }

            if (previous == proxy) {
                plugin_log("[LSO-CPP] %s already routed to LSO @ 0x%llx",
                           spec.name, (unsigned long long)slot);
                already_routed++;
                continue;
            }

            const intptr_t page = slot & ~(intptr_t)0x3fff;
            if (kernel_mprotect(pid, page, 0x4000,
                                PROT_READ | PROT_WRITE) < 0 ||
                kernel_proc_copyin(pid, &proxy, slot, sizeof(proxy)) < 0)
            {
                kernel_mprotect(pid, page, 0x4000, PROT_READ);
                plugin_log("[LSO-CPP] %s slot repair failed @ 0x%llx "
                           "(previous=0x%llx)", spec.name,
                           (unsigned long long)slot,
                           (unsigned long long)previous);
                failed++;
                continue;
            }
            kernel_mprotect(pid, page, 0x4000, PROT_READ);

            intptr_t verify = 0;
            if (kernel_proc_copyout(pid, slot, &verify, sizeof(verify)) == 0 &&
                verify == proxy)
            {
                plugin_log("[LSO-CPP] Repaired %s @ 0x%llx "
                           "(previous=0x%llx, proxy=0x%llx)", spec.name,
                           (unsigned long long)slot,
                           (unsigned long long)previous,
                           (unsigned long long)proxy);
                repaired++;
            } else {
                plugin_log("[LSO-CPP] %s verification failed @ 0x%llx",
                           spec.name, (unsigned long long)slot);
                failed++;
            }
        }

        if (!slot_found) {
            plugin_log("[LSO-CPP] %s relocation was not found", spec.name);
            failed++;
        }
    }

    plugin_log("[LSO-CPP] Complete: found=%d routed=%d repaired=%d failed=%d",
               found, already_routed, repaired, failed);
    return failed == 0 && found >= (int)(sizeof(specs) / sizeof(specs[0])) &&
           already_routed + repaired == found;
}

// Trace only the two C++ WebAPI calls that must follow a successful
// CreateRequest. Each wrapper records a count and the numeric request ID, then
// tail-jumps to the exact LSO proxy already present in the slot. It makes no
// calls, does not touch the stack, does not inspect headers or payloads, and
// leaves all NP hooks and game state unchanged.
[[maybe_unused]] static bool install_lso_cpp_boundary_trace_v25_unused(
    pid_t pid, intptr_t module_base, intptr_t *record_out)
{
    if (record_out) *record_out = 0;
    if (!module_base) {
        plugin_log("[LSO-CPP-CALL] LSO module base unavailable");
        return false;
    }

    struct TraceSpec {
        const char *name;
        const char *nid;
        uint32_t proxy_offset;
        int record_index;
    };
    static const TraceSpec specs[2] = {
        {"AddHttpRequestHeader", "egOOvrnF6mI", 0x13c50, 0},
        {"SendRequest", "lQOCF84lvzw", 0x13a90, 1},
    };

    UniquePtr<Hijacker> hijacker = Hijacker::getHijacker(pid);
    if (!hijacker) {
        plugin_log("[LSO-CPP-CALL] Could not create Hijacker");
        return false;
    }

    UniquePtr<SharedLib> cpp_webapi;
    for (auto library : hijacker->getLibs()) {
        const char *path = library->getPath().c_str();
        if (path && strstr(path, "libSceNpCppWebApi") != nullptr) {
            cpp_webapi = library.release();
            break;
        }
    }
    if (!cpp_webapi || !cpp_webapi->getMetaData()) {
        plugin_log("[LSO-CPP-CALL] C++ WebAPI metadata unavailable");
        return false;
    }

    RtldMeta *metadata = cpp_webapi->getMetaData();
    const uintptr_t library_base = cpp_webapi->imagebase();
    const auto &symbols = metadata->getSymbolTable();
    const auto &plt_table = metadata->getPltTable();

    intptr_t slots[2] = {};
    intptr_t targets[2] = {};
    for (const auto &spec : specs) {
        const ssize_t symbol_index = symbols.getSymbolIndex(Nid{spec.nid});
        if (symbol_index < 0) {
            plugin_log("[LSO-CPP-CALL] %s import is missing", spec.name);
            return false;
        }
        for (const auto &relocation : plt_table) {
            if ((ssize_t)ELF64_R_SYM(relocation.r_info) == symbol_index) {
                slots[spec.record_index] =
                    (intptr_t)library_base + (intptr_t)relocation.r_offset;
                break;
            }
        }
        if (!slots[spec.record_index]) {
            plugin_log("[LSO-CPP-CALL] %s relocation is missing", spec.name);
            return false;
        }

        const intptr_t expected_target =
            module_base + (intptr_t)spec.proxy_offset;
        if (kernel_proc_copyout(pid, slots[spec.record_index],
                                &targets[spec.record_index],
                                sizeof(targets[spec.record_index])) < 0 ||
            targets[spec.record_index] != expected_target)
        {
            plugin_log("[LSO-CPP-CALL] %s target is not the verified LSO proxy",
                       spec.name);
            return false;
        }
    }

    const size_t page_size = 0x4000;
    const intptr_t mapping = pt_mmap(
        pid, 0, page_size * 2, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping <= 0) {
        plugin_log("[LSO-CPP-CALL] Remote trace allocation failed (rc=%lld)",
                   (long long)mapping);
        return false;
    }
    const intptr_t code_page = mapping + (intptr_t)page_size;

    auto append_bytes = [](uint8_t *code, size_t &used,
                           std::initializer_list<uint8_t> values) {
        for (uint8_t value : values) code[used++] = value;
    };
    auto append_u64 = [](uint8_t *code, size_t &used, uint64_t value) {
        memcpy(code + used, &value, sizeof(value));
        used += sizeof(value);
    };

    for (const auto &spec : specs) {
        uint8_t stub[64] = {};
        size_t used = 0;
        const intptr_t entry =
            mapping + (intptr_t)(spec.record_index *
                                 sizeof(lso_cpp_boundary_entry_t));
        append_bytes(stub, used, {0x49, 0xBB});
        append_u64(stub, used, (uint64_t)entry);             // r11=record
        append_bytes(stub, used, {0xF0,0x41,0xFF,0x03});     // seq odd
        append_bytes(stub, used, {0xF0,0x41,0xFF,0x43,0x04}); // count++
        append_bytes(stub, used, {0x49,0x89,0x7B,0x08});     // id=rdi
        append_bytes(stub, used, {0xF0,0x41,0xFF,0x03});     // seq even
        append_bytes(stub, used, {0x49,0xBB});
        append_u64(stub, used,
                   (uint64_t)targets[spec.record_index]);    // r11=LSO proxy
        append_bytes(stub, used, {0x41,0xFF,0xE3});          // jmp r11

        const intptr_t stub_address =
            code_page + (intptr_t)(spec.record_index * sizeof(stub));
        if (used > sizeof(stub) ||
            kernel_proc_copyin(pid, stub, stub_address, sizeof(stub)) < 0)
        {
            plugin_log("[LSO-CPP-CALL] Could not write %s wrapper", spec.name);
            pt_munmap(pid, mapping, page_size * 2);
            return false;
        }
    }

    if (kernel_mprotect(pid, code_page, page_size,
                        PROT_READ | PROT_EXEC) < 0)
    {
        plugin_log("[LSO-CPP-CALL] Could not activate trace wrappers");
        pt_munmap(pid, mapping, page_size * 2);
        return false;
    }

    int installed = 0;
    for (const auto &spec : specs) {
        const int index = spec.record_index;
        const intptr_t stub_address =
            code_page + (intptr_t)(index * 64);
        const intptr_t slot_page =
            slots[index] & ~(intptr_t)(page_size - 1);
        bool ok = false;
        if (kernel_mprotect(pid, slot_page, page_size,
                            PROT_READ | PROT_WRITE) >= 0)
        {
            ok = kernel_proc_copyin(pid, &stub_address, slots[index],
                                    sizeof(stub_address)) == 0;
            kernel_mprotect(pid, slot_page, page_size, PROT_READ);
        }
        if (ok) {
            installed++;
            plugin_log("[LSO-CPP-CALL] Tracing %s at slot 0x%llx",
                       spec.name, (unsigned long long)slots[index]);
        } else {
            plugin_log("[LSO-CPP-CALL] Failed to trace %s", spec.name);
        }
    }

    if (installed == 0) {
        pt_munmap(pid, mapping, page_size * 2);
        return false;
    }
    if (record_out) *record_out = mapping;
    plugin_log("[LSO-CPP-CALL] Boundary tracer installed: %d/2", installed);
    return installed == 2;
}

// FW 8.60's libSceNpCppWebApi successfully calls LSO CreateRequest for the
// PS5 communication-restriction startup route, but its asynchronous worker
// never reaches AddHttpRequestHeader or SendRequest. For that one exact API
// group, dispatch the newly-created LSO request immediately with an empty body
// and response pointer. LSO keeps the completed response in its own request
// record; the native C++ worker can subsequently issue its normal SendRequest
// and receive that cached result. All other C++ WebAPI routes remain untouched.
static bool install_lso_cpp_boundary_trace(pid_t pid, intptr_t module_base,
                                           intptr_t *record_out)
{
    if (record_out) *record_out = 0;
    if (!module_base) {
        plugin_log("[LSO-CPP-EAGER] LSO module base unavailable");
        return false;
    }

    struct TraceSpec {
        const char *name;
        const char *nid;
        uint32_t proxy_offset;
        int record_index;
    };
    static const TraceSpec specs[LSO_CPP_BOUNDARY_COUNT] = {
        {"CreateRequest/eager-dispatch", "3EI-OSJ65Xc", 0x138b0, 0},
        {"AddHttpRequestHeader", "egOOvrnF6mI", 0x13c50, 1},
        {"SendRequest", "lQOCF84lvzw", 0x13a90, 2},
    };

    UniquePtr<Hijacker> hijacker = Hijacker::getHijacker(pid);
    if (!hijacker) {
        plugin_log("[LSO-CPP-EAGER] Could not create Hijacker");
        return false;
    }

    UniquePtr<SharedLib> cpp_webapi;
    for (auto library : hijacker->getLibs()) {
        const char *path = library->getPath().c_str();
        if (path && strstr(path, "libSceNpCppWebApi") != nullptr) {
            cpp_webapi = library.release();
            break;
        }
    }
    if (!cpp_webapi || !cpp_webapi->getMetaData()) {
        plugin_log("[LSO-CPP-EAGER] C++ WebAPI metadata unavailable");
        return false;
    }

    RtldMeta *metadata = cpp_webapi->getMetaData();
    const uintptr_t library_base = cpp_webapi->imagebase();
    const auto &symbols = metadata->getSymbolTable();
    const auto &plt_table = metadata->getPltTable();
    intptr_t slots[LSO_CPP_BOUNDARY_COUNT] = {};
    intptr_t targets[LSO_CPP_BOUNDARY_COUNT] = {};

    for (const auto &spec : specs) {
        const ssize_t symbol_index = symbols.getSymbolIndex(Nid{spec.nid});
        if (symbol_index < 0) {
            plugin_log("[LSO-CPP-EAGER] %s import is missing", spec.name);
            return false;
        }
        for (const auto &relocation : plt_table) {
            if ((ssize_t)ELF64_R_SYM(relocation.r_info) == symbol_index) {
                slots[spec.record_index] =
                    (intptr_t)library_base + (intptr_t)relocation.r_offset;
                break;
            }
        }
        if (!slots[spec.record_index]) {
            plugin_log("[LSO-CPP-EAGER] %s relocation is missing", spec.name);
            return false;
        }

        const intptr_t expected =
            module_base + (intptr_t)spec.proxy_offset;
        if (kernel_proc_copyout(pid, slots[spec.record_index],
                                &targets[spec.record_index],
                                sizeof(targets[spec.record_index])) < 0 ||
            targets[spec.record_index] != expected)
        {
            plugin_log("[LSO-CPP-EAGER] %s is not routed to the verified LSO "
                       "proxy", spec.name);
            return false;
        }
    }

    constexpr size_t page_size = 0x4000;
    constexpr size_t stub_stride = 0x400;
    const intptr_t mapping = pt_mmap(
        pid, 0, page_size * 2, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping <= 0) {
        plugin_log("[LSO-CPP-EAGER] Remote allocation failed (rc=%lld)",
                   (long long)mapping);
        return false;
    }
    const intptr_t code_page = mapping + (intptr_t)page_size;

    auto append_bytes = [](uint8_t *code, size_t &used,
                           std::initializer_list<uint8_t> values) {
        for (uint8_t value : values) code[used++] = value;
    };
    auto append_u16 = [](uint8_t *code, size_t &used, uint16_t value) {
        memcpy(code + used, &value, sizeof(value));
        used += sizeof(value);
    };
    auto append_u32 = [](uint8_t *code, size_t &used, uint32_t value) {
        memcpy(code + used, &value, sizeof(value));
        used += sizeof(value);
    };
    auto append_u64 = [](uint8_t *code, size_t &used, uint64_t value) {
        memcpy(code + used, &value, sizeof(value));
        used += sizeof(value);
    };

    // Build the exact-route CreateRequest wrapper.
    uint8_t create_stub[stub_stride] = {};
    size_t create_used = 0;
    struct JumpList {
        size_t offsets[16];
        size_t count;
    };
    JumpList to_record = {};
    auto append_to_record = [&](uint8_t condition) {
        append_bytes(create_stub, create_used, {0x0F, condition});
        to_record.offsets[to_record.count++] = create_used;
        append_u32(create_stub, create_used, 0);
    };

    append_bytes(create_stub, create_used,
                 {0x55,0x48,0x89,0xE5,0x53,0x41,0x54,0x41,0x55,
                  0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x08});
    // Keep the API-group pointer separately; r9 is no longer needed after the
    // original CreateRequest call. rbx=output pointer, r15=API group.
    append_bytes(create_stub, create_used, {0x4C,0x89,0xCB}); // rbx=r9
    append_bytes(create_stub, create_used, {0x49,0x89,0xF7}); // r15=rsi
    append_bytes(create_stub, create_used, {0x49,0xBB});
    append_u64(create_stub, create_used, (uint64_t)targets[0]);
    append_bytes(create_stub, create_used, {0x41,0xFF,0xD3}); // call r11
    append_bytes(create_stub, create_used, {0x41,0x89,0xC5}); // r13d=create rc
    append_bytes(create_stub, create_used, {0x41,0x89,0xC6}); // r14d=diag rc
    append_bytes(create_stub, create_used, {0x85,0xC0});
    append_to_record(0x85);                                  // jne
    append_bytes(create_stub, create_used, {0x48,0x85,0xDB});
    append_to_record(0x84);                                  // output == null
    append_bytes(create_stub, create_used, {0x4D,0x85,0xFF});
    append_to_record(0x84);                                  // group == null

    static const char eager_group[] = "communicationRestrictionStatus";
    size_t group_index = 0;
    while (group_index + 4 <= sizeof(eager_group) - 1) {
        uint32_t word = 0;
        memcpy(&word, eager_group + group_index, sizeof(word));
        append_bytes(create_stub, create_used, {0x41,0x81,0xBF});
        append_u32(create_stub, create_used, (uint32_t)group_index);
        append_u32(create_stub, create_used, word);
        append_to_record(0x85);                              // jne
        group_index += 4;
    }
    if (group_index + 2 <= sizeof(eager_group) - 1) {
        uint16_t word = 0;
        memcpy(&word, eager_group + group_index, sizeof(word));
        append_bytes(create_stub, create_used, {0x66,0x41,0x81,0xBF});
        append_u32(create_stub, create_used, (uint32_t)group_index);
        append_u16(create_stub, create_used, word);
        append_to_record(0x85);
        group_index += 2;
    }
    if (group_index < sizeof(eager_group) - 1) {
        append_bytes(create_stub, create_used, {0x41,0x80,0xBF});
        append_u32(create_stub, create_used, (uint32_t)group_index);
        append_bytes(create_stub, create_used,
                     {(uint8_t)eager_group[group_index]});
        append_to_record(0x85);
        group_index++;
    }
    append_bytes(create_stub, create_used, {0x41,0x80,0xBF});
    append_u32(create_stub, create_used, (uint32_t)group_index);
    append_bytes(create_stub, create_used, {0x00});
    append_to_record(0x85);                                  // exact NUL

    append_bytes(create_stub, create_used, {0x48,0x8B,0x3B}); // rdi=*out
    append_bytes(create_stub, create_used, {0x48,0x85,0xFF});
    append_to_record(0x84);
    append_bytes(create_stub, create_used,
                 {0x31,0xF6,0x31,0xD2,0x31,0xC9});           // empty send
    append_bytes(create_stub, create_used, {0x49,0xBB});
    append_u64(create_stub, create_used, (uint64_t)targets[2]);
    append_bytes(create_stub, create_used, {0x41,0xFF,0xD3}); // call LSO Send
    append_bytes(create_stub, create_used, {0x41,0x89,0xC6}); // diagnostic rc

    const size_t record_label = create_used;
    for (size_t i = 0; i < to_record.count; i++) {
        const int64_t relative =
            (int64_t)record_label - (int64_t)(to_record.offsets[i] + 4);
        const int32_t relative32 = (int32_t)relative;
        memcpy(create_stub + to_record.offsets[i], &relative32,
               sizeof(relative32));
    }
    const intptr_t create_record = mapping;
    append_bytes(create_stub, create_used, {0x49,0xBC});
    append_u64(create_stub, create_used, (uint64_t)create_record);
    append_bytes(create_stub, create_used, {0xF0,0x41,0xFF,0x04,0x24});
    append_bytes(create_stub, create_used, {0xF0,0x41,0xFF,0x44,0x24,0x04});
    append_bytes(create_stub, create_used, {0x31,0xC0,0x48,0x85,0xDB,
                                            0x74,0x03,0x48,0x8B,0x03});
    append_bytes(create_stub, create_used, {0x49,0x89,0x44,0x24,0x08});
    append_bytes(create_stub, create_used, {0x45,0x89,0x74,0x24,0x10});
    append_bytes(create_stub, create_used, {0xF0,0x41,0xFF,0x04,0x24});
    append_bytes(create_stub, create_used,
                 {0x44,0x89,0xE8,0x48,0x83,0xC4,0x08,0x41,0x5F,
                  0x41,0x5E,0x41,0x5D,0x41,0x5C,0x5B,0x5D,0xC3});

    if (create_used > sizeof(create_stub) ||
        kernel_proc_copyin(pid, create_stub, code_page,
                           sizeof(create_stub)) < 0)
    {
        plugin_log("[LSO-CPP-EAGER] Could not write CreateRequest wrapper");
        pt_munmap(pid, mapping, page_size * 2);
        return false;
    }

    // Passive wrappers retain visibility into the native worker's later
    // AddHeader and SendRequest calls without changing their arguments.
    for (int index = 1; index < LSO_CPP_BOUNDARY_COUNT; index++) {
        uint8_t stub[stub_stride] = {};
        size_t used = 0;
        const intptr_t record =
            mapping + (intptr_t)(index * sizeof(lso_cpp_boundary_entry_t));
        append_bytes(stub, used, {0x49,0xBB});
        append_u64(stub, used, (uint64_t)record);
        append_bytes(stub, used, {0xF0,0x41,0xFF,0x03});
        append_bytes(stub, used, {0xF0,0x41,0xFF,0x43,0x04});
        append_bytes(stub, used, {0x49,0x89,0x7B,0x08});
        append_bytes(stub, used, {0x41,0xC7,0x43,0x10});
        append_u32(stub, used, 0x7fffffff);
        append_bytes(stub, used, {0xF0,0x41,0xFF,0x03});
        append_bytes(stub, used, {0x49,0xBB});
        append_u64(stub, used, (uint64_t)targets[index]);
        append_bytes(stub, used, {0x41,0xFF,0xE3});

        const intptr_t address =
            code_page + (intptr_t)(index * stub_stride);
        if (kernel_proc_copyin(pid, stub, address, sizeof(stub)) < 0) {
            plugin_log("[LSO-CPP-EAGER] Could not write %s tracer",
                       specs[index].name);
            pt_munmap(pid, mapping, page_size * 2);
            return false;
        }
    }

    if (kernel_mprotect(pid, code_page, page_size,
                        PROT_READ | PROT_EXEC) < 0)
    {
        plugin_log("[LSO-CPP-EAGER] Could not activate wrappers");
        pt_munmap(pid, mapping, page_size * 2);
        return false;
    }

    int installed = 0;
    for (const auto &spec : specs) {
        const int index = spec.record_index;
        const intptr_t wrapper =
            code_page + (intptr_t)(index * stub_stride);
        const intptr_t slot_page =
            slots[index] & ~(intptr_t)(page_size - 1);
        bool ok = false;
        if (kernel_mprotect(pid, slot_page, page_size,
                            PROT_READ | PROT_WRITE) >= 0)
        {
            ok = kernel_proc_copyin(pid, &wrapper, slots[index],
                                    sizeof(wrapper)) == 0;
            kernel_mprotect(pid, slot_page, page_size, PROT_READ);
        }
        if (ok) {
            installed++;
            plugin_log("[LSO-CPP-EAGER] Installed %s at slot 0x%llx",
                       spec.name, (unsigned long long)slots[index]);
        } else {
            plugin_log("[LSO-CPP-EAGER] Failed to install %s", spec.name);
        }
    }

    if (installed == 0) {
        pt_munmap(pid, mapping, page_size * 2);
        return false;
    }
    if (record_out) *record_out = mapping;
    plugin_log("[LSO-CPP-EAGER] Exact restriction-route dispatch installed: "
               "%d/%d", installed, LSO_CPP_BOUNDARY_COUNT);
    return installed == LSO_CPP_BOUNDARY_COUNT;
}

// The FW 8.60 restriction request bypasses both GTA's direct WebAPI import and
// libSceNpCppWebApi's import. Detour LSO's own exported CreateRequest entry so
// every internal and external caller crosses the same boundary. The wrapper
// replays the exact displaced prologue through a trampoline, preserves the
// original return value, and calls SendRequest only after CreateRequest has
// completely returned and only for "communicationRestrictionStatus".
static bool install_lso_internal_create_eager_send(
    pid_t pid, intptr_t module_base, intptr_t *record_out)
{
    if (record_out) *record_out = 0;
    if (!module_base) {
        plugin_log("[LSO-INTERNAL] LSO module base unavailable");
        return false;
    }

    const intptr_t create_entry = module_base + (intptr_t)0x138b0;
    const intptr_t send_target = module_base + (intptr_t)0x13a90;

    static const uint8_t expected_prologue[14] = {
        0x55,0x48,0x89,0xE5,0x41,0x57,0x41,
        0x56,0x41,0x55,0x41,0x54,0x53,0x50,
    };
    uint8_t current_prologue[sizeof(expected_prologue)] = {};
    if (kernel_proc_copyout(pid, create_entry, current_prologue,
                            sizeof(current_prologue)) < 0 ||
        memcmp(current_prologue, expected_prologue,
               sizeof(expected_prologue)) != 0)
    {
        plugin_log("[LSO-INTERNAL] Exact CreateRequest prologue mismatch; "
                   "detour not installed");
        return false;
    }

    constexpr size_t page_size = 0x4000;
    const intptr_t mapping = pt_mmap(
        pid, 0, page_size * 2, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping <= 0) {
        plugin_log("[LSO-INTERNAL] Remote allocation failed (rc=%lld)",
                   (long long)mapping);
        return false;
    }
    const intptr_t code_page = mapping + (intptr_t)page_size;
    const intptr_t trampoline_address = code_page + 0x400;

    uint8_t stub[0x400] = {};
    size_t used = 0;
    auto append_bytes = [&](std::initializer_list<uint8_t> values) {
        for (uint8_t value : values) stub[used++] = value;
    };
    auto append_u16 = [&](uint16_t value) {
        memcpy(stub + used, &value, sizeof(value));
        used += sizeof(value);
    };
    auto append_u32 = [&](uint32_t value) {
        memcpy(stub + used, &value, sizeof(value));
        used += sizeof(value);
    };
    auto append_u64 = [&](uint64_t value) {
        memcpy(stub + used, &value, sizeof(value));
        used += sizeof(value);
    };
    struct JumpList {
        size_t offsets[16];
        size_t count;
    } to_record = {};
    auto append_to_record = [&](uint8_t condition) {
        append_bytes({0x0F, condition});
        to_record.offsets[to_record.count++] = used;
        append_u32(0);
    };

    // SysV AMD64 arguments:
    // rdi=context, rsi=group, rdx=path, rcx=method, r8=params, r9=out_id.
    append_bytes({0x55,0x48,0x89,0xE5,0x53,0x41,0x54,0x41,0x55,
                  0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x08});
    append_bytes({0x4C,0x89,0xCB});             // rbx = output-id pointer
    append_bytes({0x49,0x89,0xF7});             // r15 = API-group pointer
    append_bytes({0x49,0xBB});
    append_u64((uint64_t)trampoline_address);
    append_bytes({0x41,0xFF,0xD3});             // call original via trampoline
    append_bytes({0x41,0x89,0xC5});             // r13d = original rc
    append_bytes({0x41,0xBE});
    append_u32(0x7fffffff);                     // not dispatched sentinel
    append_bytes({0x85,0xC0});
    append_to_record(0x85);                     // CreateRequest failed
    append_bytes({0x48,0x85,0xDB});
    append_to_record(0x84);                     // output pointer is null
    append_bytes({0x4D,0x85,0xFF});
    append_to_record(0x84);                     // group pointer is null

    static const char eager_group[] = "communicationRestrictionStatus";
    size_t group_index = 0;
    while (group_index + 4 <= sizeof(eager_group) - 1) {
        uint32_t word = 0;
        memcpy(&word, eager_group + group_index, sizeof(word));
        append_bytes({0x41,0x81,0xBF});
        append_u32((uint32_t)group_index);
        append_u32(word);
        append_to_record(0x85);
        group_index += 4;
    }
    if (group_index + 2 <= sizeof(eager_group) - 1) {
        uint16_t word = 0;
        memcpy(&word, eager_group + group_index, sizeof(word));
        append_bytes({0x66,0x41,0x81,0xBF});
        append_u32((uint32_t)group_index);
        append_u16(word);
        append_to_record(0x85);
        group_index += 2;
    }
    if (group_index < sizeof(eager_group) - 1) {
        append_bytes({0x41,0x80,0xBF});
        append_u32((uint32_t)group_index);
        append_bytes({(uint8_t)eager_group[group_index]});
        append_to_record(0x85);
        group_index++;
    }
    append_bytes({0x41,0x80,0xBF});
    append_u32((uint32_t)group_index);
    append_bytes({0x00});
    append_to_record(0x85);                     // require exact trailing NUL

    append_bytes({0x48,0x8B,0x3B});             // rdi = *out_id
    append_bytes({0x48,0x85,0xFF});
    append_to_record(0x84);                     // request id is zero/null
    append_bytes({0x31,0xF6,0x31,0xD2,0x31,0xC9}); // empty request body
    append_bytes({0x49,0xBB});
    append_u64((uint64_t)send_target);
    append_bytes({0x41,0xFF,0xD3});             // call LSO SendRequest
    append_bytes({0x41,0x89,0xC6});             // r14d = eager-send rc

    const size_t record_label = used;
    for (size_t i = 0; i < to_record.count; i++) {
        const int64_t relative =
            (int64_t)record_label - (int64_t)(to_record.offsets[i] + 4);
        const int32_t relative32 = (int32_t)relative;
        memcpy(stub + to_record.offsets[i], &relative32,
               sizeof(relative32));
    }

    // Entry zero uses the same seqlock record already polled by the loader.
    append_bytes({0x49,0xBC});
    append_u64((uint64_t)mapping);
    append_bytes({0xF0,0x41,0xFF,0x04,0x24});   // sequence becomes odd
    append_bytes({0xF0,0x41,0xFF,0x44,0x24,0x04}); // call_count++
    append_bytes({0x31,0xC0,0x48,0x85,0xDB,0x74,0x03,0x48,0x8B,0x03});
    append_bytes({0x49,0x89,0x44,0x24,0x08});   // last_request_id
    append_bytes({0x45,0x89,0x74,0x24,0x10});   // last_result
    append_bytes({0xF0,0x41,0xFF,0x04,0x24});   // sequence becomes even
    append_bytes({0x44,0x89,0xE8,0x48,0x83,0xC4,0x08,0x41,0x5F,
                  0x41,0x5E,0x41,0x5D,0x41,0x5C,0x5B,0x5D,0xC3});

    uint8_t trampoline[0x80] = {};
    size_t trampoline_used = 0;
    memcpy(trampoline + trampoline_used, expected_prologue,
           sizeof(expected_prologue));
    trampoline_used += sizeof(expected_prologue);
    trampoline[trampoline_used++] = 0x49;        // mov r11,imm64
    trampoline[trampoline_used++] = 0xBB;
    const uint64_t continuation =
        (uint64_t)(create_entry + (intptr_t)sizeof(expected_prologue));
    memcpy(trampoline + trampoline_used, &continuation,
           sizeof(continuation));
    trampoline_used += sizeof(continuation);
    trampoline[trampoline_used++] = 0x41;        // jmp r11
    trampoline[trampoline_used++] = 0xFF;
    trampoline[trampoline_used++] = 0xE3;

    if (used > sizeof(stub) || trampoline_used > sizeof(trampoline) ||
        kernel_proc_copyin(pid, stub, code_page, sizeof(stub)) < 0 ||
        kernel_proc_copyin(pid, trampoline, trampoline_address,
                           sizeof(trampoline)) < 0 ||
        kernel_mprotect(pid, code_page, page_size,
                        PROT_READ | PROT_EXEC) < 0)
    {
        plugin_log("[LSO-INTERNAL] Could not write/activate wrapper");
        pt_munmap(pid, mapping, page_size * 2);
        return false;
    }

    uint8_t detour[sizeof(expected_prologue)] = {};
    detour[0] = 0x49;                           // mov r11,imm64
    detour[1] = 0xBB;
    memcpy(detour + 2, &code_page, sizeof(code_page));
    detour[10] = 0x41;                          // jmp r11
    detour[11] = 0xFF;
    detour[12] = 0xE3;
    detour[13] = 0x90;

    const intptr_t entry_page =
        create_entry & ~(intptr_t)(page_size - 1);
    bool wrote = false;
    if (kernel_mprotect(pid, entry_page, page_size,
                        PROT_READ | PROT_WRITE | PROT_EXEC) >= 0)
    {
        wrote = kernel_proc_copyin(pid, detour, create_entry,
                                   sizeof(detour)) == 0;
        kernel_mprotect(pid, entry_page, page_size,
                        PROT_READ | PROT_EXEC);
    }
    uint8_t verify[sizeof(detour)] = {};
    if (!wrote ||
        kernel_proc_copyout(pid, create_entry, verify, sizeof(verify)) < 0 ||
        memcmp(verify, detour, sizeof(detour)) != 0)
    {
        plugin_log("[LSO-INTERNAL] LSO CreateRequest detour failed");
        if (kernel_mprotect(pid, entry_page, page_size,
                            PROT_READ | PROT_WRITE | PROT_EXEC) >= 0)
        {
            kernel_proc_copyin(pid, expected_prologue, create_entry,
                               sizeof(expected_prologue));
            kernel_mprotect(pid, entry_page, page_size,
                            PROT_READ | PROT_EXEC);
        }
        pt_munmap(pid, mapping, page_size * 2);
        return false;
    }

    if (record_out) *record_out = mapping;
    plugin_log("[LSO-INTERNAL] LSO CreateRequest entry detoured at 0x%llx; "
               "trampoline=0x%llx wrapper=0x%llx",
               (unsigned long long)create_entry,
               (unsigned long long)trampoline_address,
               (unsigned long long)code_page);
    return true;
}

// The separately named v31 PRX parks its ELF initializer at +0x10 with an
// exact two-byte `jmp $`. Once the early response and CreateRequest detours are
// resident, restore the original bytes so the initializer begins normally.
// Unknown bytes are never changed.
static bool release_lso_initializer_gate(pid_t pid, intptr_t module_base)
{
    if (!module_base) {
        plugin_log("[LSO-EARLY] Module base unavailable; gate not released");
        return false;
    }

    static const uint8_t expected_gate[2] = {0xEB, 0xFE};
    static const uint8_t original_entry[2] = {0x55, 0x48};
    const intptr_t entry = module_base + (intptr_t)0x10;
    uint8_t current[sizeof(expected_gate)] = {};
    if (kernel_proc_copyout(pid, entry, current, sizeof(current)) < 0 ||
        memcmp(current, expected_gate, sizeof(expected_gate)) != 0)
    {
        plugin_log("[LSO-EARLY] Initializer gate signature mismatch; "
                   "nothing restored");
        return false;
    }

    const intptr_t page = entry & ~(intptr_t)0xfff;
    const bool protection_changed =
        kernel_mprotect(pid, page, 0x1000,
                        PROT_READ | PROT_WRITE | PROT_EXEC) >= 0;
    const bool wrote =
        kernel_proc_copyin(pid, original_entry, entry,
                           sizeof(original_entry)) == 0;
    if (protection_changed)
        kernel_mprotect(pid, page, 0x1000, PROT_READ | PROT_EXEC);

    uint8_t verify[sizeof(original_entry)] = {};
    if (!wrote || kernel_proc_copyout(pid, entry, verify, sizeof(verify)) < 0 ||
        memcmp(verify, original_entry, sizeof(original_entry)) != 0)
    {
        plugin_log("[LSO-EARLY] CRITICAL: initializer gate release failed");
        return false;
    }

    plugin_log("[LSO-EARLY] Initializer gate released; original entry restored");
    return true;
}

// Wrap the native PushEvent imports without changing arguments, buffers, or
// results. Each wrapper calls the target that was present in the GOT at install
// time. A still-lazy target points to PLT+6, which safely invokes the platform
// resolver once; the resolver may then replace the GOT wrapper after that first
// recorded call. One result per API is sufficient to identify the FW 8.60
// prerequisite that fails, and avoids fighting the native loader.
[[maybe_unused]] static bool install_gtavee_push_event_result_trace(
    pid_t pid, intptr_t *trace_record_out)
{
    if (trace_record_out) *trace_record_out = 0;

    intptr_t original_targets[GTAVEE_PUSH_EVENT_HOOK_COUNT] = {};
    for (int i = 0; i < GTAVEE_PUSH_EVENT_HOOK_COUNT; i++) {
        const intptr_t slot =
            (intptr_t)k_gtavee_push_event_slot_addresses[i];
        if (kernel_proc_copyout(pid, slot, &original_targets[i],
                                sizeof(original_targets[i])) < 0 ||
            original_targets[i] < 0x10000)
        {
            plugin_log("[GTA-PUSH-TRACE] %s target unavailable; trace not "
                       "installed", k_gtavee_push_event_names[i]);
            return false;
        }

        const intptr_t plt_entry =
            (intptr_t)k_gtavee_push_event_plt_addresses[i];
        if (original_targets[i] == plt_entry) {
            plugin_log("[GTA-PUSH-TRACE] %s points to the recursive PLT entry; "
                       "trace cancelled", k_gtavee_push_event_names[i]);
            return false;
        }
    }

    constexpr size_t page_size = 0x4000;
    constexpr size_t stub_stride = 0x80;
    const intptr_t mapping = pt_mmap(
        pid, 0, page_size * 2, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping <= 0) {
        plugin_log("[GTA-PUSH-TRACE] Remote allocation failed (rc=%lld)",
                   (long long)mapping);
        return false;
    }

    const intptr_t record_address = mapping;
    const intptr_t code_address = mapping + (intptr_t)page_size;
    auto append_bytes = [](uint8_t *code, size_t &used,
                           std::initializer_list<uint8_t> values) {
        for (uint8_t value : values) code[used++] = value;
    };
    auto append_imm64 = [](uint8_t *code, size_t &used, uint64_t value) {
        memcpy(code + used, &value, sizeof(value));
        used += sizeof(value);
    };

    for (int i = 0; i < GTAVEE_PUSH_EVENT_HOOK_COUNT; i++) {
        uint8_t stub[stub_stride] = {};
        size_t used = 0;
        const intptr_t entry = record_address +
            (intptr_t)i * (intptr_t)sizeof(gtavee_push_event_trace_entry_t);
        const intptr_t stub_address =
            code_address + (intptr_t)i * (intptr_t)stub_stride;

        // Entry RSP is 8 mod 16. Saving r12 aligns the stack for the native
        // call and gives the wrapper a callee-saved record pointer.
        append_bytes(stub, used, {0x41, 0x54});             // push r12
        append_bytes(stub, used, {0x49, 0xBC});             // mov r12,entry
        append_imm64(stub, used, (uint64_t)entry);
        append_bytes(stub, used,
                     {0xF0, 0x41, 0xFF, 0x04, 0x24});       // sequence odd
        append_bytes(stub, used,
                     {0x49, 0x89, 0x7C, 0x24, 0x10});       // arg0=rdi
        append_bytes(stub, used,
                     {0x49, 0x89, 0x74, 0x24, 0x18});       // arg1=rsi
        append_bytes(stub, used, {0x49, 0xBB});             // mov r11,target
        append_imm64(stub, used, (uint64_t)original_targets[i]);
        append_bytes(stub, used, {0x41, 0xFF, 0xD3});       // call r11
        append_bytes(stub, used,
                     {0x41, 0x89, 0x44, 0x24, 0x08});       // result=eax
        append_bytes(stub, used,
                     {0xF0, 0x41, 0xFF, 0x44, 0x24, 0x04}); // call_count++
        append_bytes(stub, used,
                     {0xF0, 0x41, 0xFF, 0x04, 0x24});       // sequence even
        append_bytes(stub, used,
                     {0x41, 0x8B, 0x44, 0x24, 0x08});       // restore eax
        append_bytes(stub, used, {0x41, 0x5C, 0xC3});       // pop r12; ret

        if (used > sizeof(stub) ||
            kernel_proc_copyin(pid, stub, stub_address, sizeof(stub)) < 0)
        {
            plugin_log("[GTA-PUSH-TRACE] Could not write %s wrapper",
                       k_gtavee_push_event_names[i]);
            pt_munmap(pid, mapping, page_size * 2);
            return false;
        }
    }

    if (kernel_mprotect(pid, code_address, page_size,
                        PROT_READ | PROT_EXEC) < 0)
    {
        plugin_log("[GTA-PUSH-TRACE] Could not activate passive wrappers");
        pt_munmap(pid, mapping, page_size * 2);
        return false;
    }

    const intptr_t slot_page =
        (intptr_t)k_gtavee_push_event_slot_addresses[0] &
        ~(intptr_t)(page_size - 1);
    bool installed = kernel_mprotect(pid, slot_page, page_size,
                                     PROT_READ | PROT_WRITE) >= 0;
    for (int i = 0; installed && i < GTAVEE_PUSH_EVENT_HOOK_COUNT; i++) {
        const intptr_t slot =
            (intptr_t)k_gtavee_push_event_slot_addresses[i];
        const intptr_t wrapper =
            code_address + (intptr_t)i * (intptr_t)stub_stride;
        installed = kernel_proc_copyin(pid, &wrapper, slot,
                                       sizeof(wrapper)) == 0;
    }
    kernel_mprotect(pid, slot_page, page_size, PROT_READ);

    bool verified = installed;
    for (int i = 0; verified && i < GTAVEE_PUSH_EVENT_HOOK_COUNT; i++) {
        const intptr_t slot =
            (intptr_t)k_gtavee_push_event_slot_addresses[i];
        const intptr_t expected =
            code_address + (intptr_t)i * (intptr_t)stub_stride;
        intptr_t observed = 0;
        verified = kernel_proc_copyout(pid, slot, &observed,
                                       sizeof(observed)) == 0 &&
                   observed == expected;
    }

    if (!verified) {
        if (kernel_mprotect(pid, slot_page, page_size,
                            PROT_READ | PROT_WRITE) >= 0)
        {
            for (int i = 0; i < GTAVEE_PUSH_EVENT_HOOK_COUNT; i++) {
                const intptr_t slot =
                    (intptr_t)k_gtavee_push_event_slot_addresses[i];
                kernel_proc_copyin(pid, &original_targets[i], slot,
                                   sizeof(original_targets[i]));
            }
            kernel_mprotect(pid, slot_page, page_size, PROT_READ);
        }
        pt_munmap(pid, mapping, page_size * 2);
        plugin_log("[GTA-PUSH-TRACE] Installation failed; native targets "
                   "restored");
        return false;
    }

    for (int i = 0; i < GTAVEE_PUSH_EVENT_HOOK_COUNT; i++) {
        const intptr_t lazy_target =
            (intptr_t)k_gtavee_push_event_plt_addresses[i] + 6;
        plugin_log("[GTA-PUSH-TRACE] %s native target=0x%llx binding=%s",
                   k_gtavee_push_event_names[i],
                   (unsigned long long)original_targets[i],
                   original_targets[i] == lazy_target ? "LAZY" : "BOUND");
    }
    if (trace_record_out) *trace_record_out = record_address;
    plugin_log("[GTA-PUSH-TRACE] Passive native result trace installed (9/9); "
               "arguments and return values remain unchanged");
    return true;
}

// GTA E&E treats PushEvent context setup as a prerequisite for its Online
// state machine. LSO supplies the player/session data itself and does not use
// the native PushEvent service, so fake-sign-in mode only needs stable local
// handles and successful no-op lifecycle calls. This patch changes the nine
// PushEvent GOT slots only; ordinary WebAPI remains routed through LSO.
[[maybe_unused]] static bool install_gtavee_push_event_compat(
    pid_t pid, intptr_t *counter_address_out)
{
    if (counter_address_out) *counter_address_out = 0;

    intptr_t original_targets[GTAVEE_PUSH_EVENT_HOOK_COUNT] = {};
    for (int i = 0; i < GTAVEE_PUSH_EVENT_HOOK_COUNT; i++) {
        const intptr_t slot =
            (intptr_t)k_gtavee_push_event_slot_addresses[i];
        if (kernel_proc_copyout(pid, slot, &original_targets[i],
                                sizeof(original_targets[i])) < 0 ||
            original_targets[i] == 0)
        {
            plugin_log("[GTA-PUSH] %s slot=0x%llx is unreadable; shim not installed",
                       k_gtavee_push_event_names[i],
                       (unsigned long long)slot);
            return false;
        }
    }

    const intptr_t mapping = pt_mmap(pid, 0, 0x4000,
                                     PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping <= 0) {
        plugin_log("[GTA-PUSH] Remote shim allocation failed (rc=%lld)",
                   (long long)mapping);
        return false;
    }

    // Each 0x20-byte stub atomically increments its own counter on the second
    // page, then returns either success (0) or a stable synthetic handle (1).
    // The counter page remains writable while only the code page becomes RX.
    constexpr intptr_t stub_stride = 0x20;
    constexpr intptr_t counter_offset = 0x1000;
    uint8_t code[0x1000] = {};
    static const bool returns_handle[GTAVEE_PUSH_EVENT_HOOK_COUNT] = {
        false, false, false, true, true, false, false, true, false,
    };
    for (int i = 0; i < GTAVEE_PUSH_EVENT_HOOK_COUNT; i++) {
        const intptr_t stub_offset = (intptr_t)i * stub_stride;
        uint8_t *stub = code + stub_offset;
        stub[0] = 0xF0; // lock inc dword ptr [rip+disp32]
        stub[1] = 0xFF;
        stub[2] = 0x05;
        const intptr_t instruction_end = mapping + stub_offset + 7;
        const intptr_t counter = mapping + counter_offset +
                                 (intptr_t)i * sizeof(uint32_t);
        const int32_t displacement = (int32_t)(counter - instruction_end);
        memcpy(stub + 3, &displacement, sizeof(displacement));
        if (returns_handle[i]) {
            stub[7] = 0xB8; // mov eax,1
            stub[8] = 0x01;
            stub[9] = 0x00;
            stub[10] = 0x00;
            stub[11] = 0x00;
            stub[12] = 0xC3; // ret
        } else {
            stub[7] = 0x31; // xor eax,eax
            stub[8] = 0xC0;
            stub[9] = 0xC3; // ret
        }
    }

    if (pt_copyin(pid, code, mapping, sizeof(code)) < 0 ||
        kernel_mprotect(pid, mapping, 0x1000,
                        PROT_READ | PROT_EXEC) < 0)
    {
        plugin_log("[GTA-PUSH] Could not write/activate remote shim");
        pt_munmap(pid, mapping, 0x4000);
        return false;
    }

    const intptr_t slot_page =
        (intptr_t)k_gtavee_push_event_slot_addresses[0] & ~(intptr_t)0xfff;
    if (kernel_mprotect(pid, slot_page, 0x1000,
                        PROT_READ | PROT_WRITE) < 0)
    {
        plugin_log("[GTA-PUSH] Could not make PushEvent slot page writable");
        pt_munmap(pid, mapping, 0x4000);
        return false;
    }

    int installed = 0;
    for (int i = 0; i < GTAVEE_PUSH_EVENT_HOOK_COUNT; i++) {
        const intptr_t slot =
            (intptr_t)k_gtavee_push_event_slot_addresses[i];
        const intptr_t target = mapping + (intptr_t)i * stub_stride;
        if (kernel_proc_copyin(pid, &target, slot, sizeof(target)) == 0)
            installed++;
    }
    kernel_mprotect(pid, slot_page, 0x1000, PROT_READ);

    int verified = 0;
    for (int i = 0; i < GTAVEE_PUSH_EVENT_HOOK_COUNT; i++) {
        const intptr_t slot =
            (intptr_t)k_gtavee_push_event_slot_addresses[i];
        const intptr_t expected = mapping + (intptr_t)i * stub_stride;
        intptr_t actual = 0;
        if (kernel_proc_copyout(pid, slot, &actual, sizeof(actual)) == 0 &&
            actual == expected)
        {
            verified++;
            plugin_log("[GTA-PUSH] %s redirected (native=0x%llx)",
                       k_gtavee_push_event_names[i],
                       (unsigned long long)original_targets[i]);
        } else {
            plugin_log("[GTA-PUSH] %s redirect verification failed",
                       k_gtavee_push_event_names[i]);
        }
    }

    if (installed != GTAVEE_PUSH_EVENT_HOOK_COUNT ||
        verified != GTAVEE_PUSH_EVENT_HOOK_COUNT)
    {
        plugin_log("[GTA-PUSH] Incomplete installation: wrote=%d/%d verified=%d/%d",
                   installed, GTAVEE_PUSH_EVENT_HOOK_COUNT,
                   verified, GTAVEE_PUSH_EVENT_HOOK_COUNT);
        if (kernel_mprotect(pid, slot_page, 0x1000,
                            PROT_READ | PROT_WRITE) == 0) {
            for (int i = 0; i < GTAVEE_PUSH_EVENT_HOOK_COUNT; i++) {
                const intptr_t slot =
                    (intptr_t)k_gtavee_push_event_slot_addresses[i];
                kernel_proc_copyin(pid, &original_targets[i], slot,
                                   sizeof(original_targets[i]));
            }
            kernel_mprotect(pid, slot_page, 0x1000, PROT_READ);
        }
        pt_munmap(pid, mapping, 0x4000);
        return false;
    }

    if (counter_address_out)
        *counter_address_out = mapping + counter_offset;
    plugin_log("[GTA-PUSH] PS5 fake-sign-in PushEvent shim installed: 9/9 "
               "(call tracing enabled)");
    return true;
}

// One-run diagnostic for the exact supplied LSO 1.010.002 binary. GTA calls
// DeleteRequest soon after consuming a WebAPI result, and LSO immediately
// clears the entire 0xa200-byte request record. The loader polls every 100 ms,
// so a completed response can otherwise disappear between samples. Replacing
// only DeleteRequest with a successful no-op preserves up to 32 records for
// the existing numeric audit. The exact 16-byte function signature prevents
// this patch from being applied to a different LSO build.
static bool preserve_lso_request_records(pid_t pid, intptr_t module_base)
{
    if (!module_base) {
        plugin_log("[LSO-REQ-KEEP] Module base unavailable; not applied");
        return false;
    }

    static const uint8_t expected[16] = {
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0xf8, 0x31,
        0xc9, 0x48, 0x8d, 0x3d, 0xd0, 0x4e, 0x01, 0x00,
    };
    static const uint8_t replacement[3] = {
        0x31, 0xc0, // xor eax, eax
        0xc3,       // ret
    };

    const intptr_t address = module_base + (intptr_t)0x13a10;
    uint8_t current[sizeof(expected)] = {};
    if (kernel_proc_copyout(pid, address, current, sizeof(current)) < 0) {
        plugin_log("[LSO-REQ-KEEP] Could not read DeleteRequest @ 0x%llx",
                   (unsigned long long)address);
        return false;
    }
    if (memcmp(current, expected, sizeof(expected)) != 0) {
        plugin_log("[LSO-REQ-KEEP] Exact DeleteRequest signature mismatch; "
                   "not applied");
        return false;
    }

    const intptr_t page = address & ~(intptr_t)0xfff;
    if (kernel_mprotect(pid, page, 0x1000,
                        PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    {
        plugin_log("[LSO-REQ-KEEP] Could not make DeleteRequest page writable");
        return false;
    }

    const int write_result = kernel_proc_copyin(
        pid, replacement, address, sizeof(replacement));
    kernel_mprotect(pid, page, 0x1000, PROT_READ | PROT_EXEC);

    uint8_t verify[sizeof(replacement)] = {};
    if (write_result < 0 ||
        kernel_proc_copyout(pid, address, verify, sizeof(verify)) < 0 ||
        memcmp(verify, replacement, sizeof(replacement)) != 0)
    {
        plugin_log("[LSO-REQ-KEEP] DeleteRequest no-op verification failed");
        return false;
    }

    plugin_log("[LSO-REQ-KEEP] DeleteRequest disabled for this run; "
               "numeric request results will be retained (32-slot limit)");
    return true;
}

// Verify the six narrow code edits in the separately named FW 8.60 PRX. Some
// transfer/mount paths can select the requested filename while still exposing
// stale executable pages. If every region is either the exact original bytes
// or the exact patched bytes, complete the same patch in memory and verify it
// before GTA resumes. Unknown bytes are never overwritten.
static bool ensure_lso_eager_prx_patch(pid_t pid, intptr_t module_base)
{
    if (!module_base) {
        plugin_log("[LSO-PRX-PATCH] Module base unavailable");
        return false;
    }

    static const uint8_t patch_a[] = {
        0x4C,0x89,0xF7,0x51,0x31,0xC9,0xE9,0xF6,0x00,0x00,0x00
    };
    static const uint8_t patch_b[] = {
        0x31,0xF6,0xEB,0x09,0x59,0x45,0x31,0xF6,0xC3,0xCC
    };
    static const uint8_t patch_c[] = {
        0x48,0xB8,0x63,0x6F,0x6D,0x6D,0x75,0x6E,0x69,0x63,0xEB,0x07,0xCC
    };
    static const uint8_t patch_d[] = {
        0x49,0x39,0x44,0x1D,0x08,0x75,0xDD,0xEB,0x04,0xCC
    };
    static const uint8_t patch_e[] = {
        0x45,0x31,0xF6,0x31,0xD2,0xE8,0xE3,0x01,0x00,0x00,0x59,0xC3,0xCC
    };
    static const uint8_t patch_entry[] = {
        0xE8,0xB5,0xFD,0xFF,0xFF,0xE3,0x3B,0x90
    };
    static const uint8_t original_entry[] = {
        0x45,0x31,0xF6,0x48,0x85,0xC9,0x74,0x3A
    };

    struct PatchSpan {
        uint32_t offset;
        const uint8_t *patched;
        const uint8_t *original;
        size_t size;
    };
    static const PatchSpan spans[] = {
        {0x13775, patch_a, nullptr, sizeof(patch_a)},
        {0x13876, patch_b, nullptr, sizeof(patch_b)},
        {0x13883, patch_c, nullptr, sizeof(patch_c)},
        {0x13896, patch_d, nullptr, sizeof(patch_d)},
        {0x138A3, patch_e, nullptr, sizeof(patch_e)},
        {0x139BB, patch_entry, original_entry, sizeof(patch_entry)},
    };

    int already_patched = 0;
    for (const auto &span : spans) {
        uint8_t current[sizeof(patch_c)] = {};
        if (span.size > sizeof(current) ||
            kernel_proc_copyout(pid, module_base + span.offset,
                                current, span.size) < 0)
        {
            plugin_log("[LSO-PRX-PATCH] Could not read region +0x%x",
                       span.offset);
            return false;
        }
        if (memcmp(current, span.patched, span.size) == 0) {
            already_patched++;
            continue;
        }

        bool original_matches = false;
        if (span.original) {
            original_matches =
                memcmp(current, span.original, span.size) == 0;
        } else {
            original_matches = true;
            for (size_t i = 0; i < span.size; i++) {
                if (current[i] != 0xCC) {
                    original_matches = false;
                    break;
                }
            }
        }
        if (!original_matches) {
            plugin_log("[LSO-PRX-PATCH] Unknown bytes at +0x%x; refusing "
                       "to modify the module", span.offset);
            return false;
        }
    }

    if (already_patched == (int)(sizeof(spans) / sizeof(spans[0]))) {
        plugin_log("[LSO-PRX-PATCH] Resident eager-send patch verified: %d/%zu",
                   already_patched, sizeof(spans) / sizeof(spans[0]));
        return true;
    }

    const intptr_t code_page =
        (module_base + (intptr_t)spans[0].offset) & ~(intptr_t)0xFFF;
    if (kernel_mprotect(pid, code_page, 0x1000,
                        PROT_READ | PROT_WRITE | PROT_EXEC) < 0)
    {
        plugin_log("[LSO-PRX-PATCH] Could not make the code page writable");
        return false;
    }

    bool write_ok = true;
    for (const auto &span : spans) {
        if (kernel_proc_copyin(pid, span.patched,
                               module_base + span.offset,
                               span.size) < 0)
        {
            write_ok = false;
            break;
        }
    }
    kernel_mprotect(pid, code_page, 0x1000, PROT_READ | PROT_EXEC);
    if (!write_ok) {
        plugin_log("[LSO-PRX-PATCH] In-memory patch write failed");
        return false;
    }

    for (const auto &span : spans) {
        uint8_t verify[sizeof(patch_c)] = {};
        if (kernel_proc_copyout(pid, module_base + span.offset,
                                verify, span.size) < 0 ||
            memcmp(verify, span.patched, span.size) != 0)
        {
            plugin_log("[LSO-PRX-PATCH] Verification failed at +0x%x",
                       span.offset);
            return false;
        }
    }
    plugin_log("[LSO-PRX-PATCH] Completed stale/partial resident patch: "
               "%d/%zu regions were already present",
               already_patched, sizeof(spans) / sizeof(spans[0]));
    return true;
}

// BlueSphere currently rejects or does not implement four PS5-only startup
// routes even though the LSO bearer token, Online ID, and account ID are all
// present. This exact-version compatibility shim preloads a completed response
// into LSO's own request record, then continues through LSO's original
// SendRequest routine. LSO therefore performs the normal response-info and
// return-value handling instead of returning directly from injected code.
//
// The shim is installed in the already-loaded LSO module, never in eboot.bin.
// It verifies the supplied LSO 1.010.002 entry bytes before modifying anything.
static bool install_lso_ps5_webapi_compat(pid_t pid, intptr_t module_base,
                                          uint32_t route_mask,
                                          intptr_t *hit_counter_out)
{
    if (hit_counter_out) *hit_counter_out = 0;
    route_mask &= 0x0f;
    if (route_mask == 0) {
        plugin_log("[LSO-PS5API] Route mask is zero; shim not installed");
        return false;
    }

    if (!module_base) {
        plugin_log("[LSO-PS5API] Module base unavailable; shim not installed");
        return false;
    }

    static const uint8_t expected[] = {
        0x55,                         // push rbp
        0x48, 0x89, 0xE5,             // mov rbp,rsp
        0x41, 0x57,                   // push r15
        0x41, 0x56,                   // push r14
        0x41, 0x55,                   // push r13
        0x41, 0x54,                   // push r12
        0x53,                         // push rbx
        0x48, 0x81, 0xEC, 0x38, 0x04, 0x00, 0x00 // sub rsp,0x438
    };
    const intptr_t entry =
        module_base + (intptr_t)LSO_SEND_REQUEST_CORE_OFFSET;
    uint8_t current[sizeof(expected)] = {};
    if (kernel_proc_copyout(pid, entry, current, sizeof(current)) < 0 ||
        memcmp(current, expected, sizeof(expected)) != 0)
    {
        plugin_log("[LSO-PS5API] LSO 1.010.002 SendRequest signature "
                   "mismatch; shim not installed");
        return false;
    }

    const intptr_t mapping = pt_mmap(pid, 0, 0x4000,
                                     PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping <= 0) {
        plugin_log("[LSO-PS5API] Remote shim allocation failed (rc=%lld)",
                   (long long)mapping);
        return false;
    }
    // Keep diagnostics on the final RW page. The generated code and static
    // response data occupy the first three pages, which become RX below.
    const intptr_t hit_counter_address = mapping + 0x3000;

    uint8_t stub[2048] = {};
    size_t used = 0;

    struct JumpList {
        size_t offsets[96];
        size_t count;
    };
    struct DataReference {
        size_t immediate_offset;
        int data_index;
    };
    JumpList null_to_passthrough = {};
    JumpList synthesized_to_passthrough = {};
    DataReference data_references[4] = {};
    size_t data_reference_count = 0;
    size_t synth_jumps[4] = {};
    size_t synth_jump_count = 0;

    auto append_bytes = [&](std::initializer_list<uint8_t> values) {
        for (uint8_t value : values) stub[used++] = value;
    };
    auto append_u16 = [&](uint16_t value) {
        memcpy(stub + used, &value, sizeof(value));
        used += sizeof(value);
    };
    auto append_u32 = [&](uint32_t value) {
        memcpy(stub + used, &value, sizeof(value));
        used += sizeof(value);
    };
    auto append_u64 = [&](uint64_t value) {
        memcpy(stub + used, &value, sizeof(value));
        used += sizeof(value);
    };
    auto append_conditional_jump = [&](uint8_t condition, JumpList &list) {
        append_bytes({0x0F, condition});
        list.offsets[list.count++] = used;
        append_u32(0);
    };
    auto patch_jumps = [&](const JumpList &list, size_t target) {
        for (size_t i = 0; i < list.count; i++) {
            const int64_t relative =
                (int64_t)target - (int64_t)(list.offsets[i] + 4);
            const int32_t relative32 = (int32_t)relative;
            memcpy(stub + list.offsets[i], &relative32, sizeof(relative32));
        }
    };
    auto emit_string_compare = [&](uint32_t displacement, const char *value,
                                   bool require_null, JumpList &mismatches) {
        const size_t length = strlen(value);
        size_t index = 0;
        while (index + 4 <= length) {
            uint32_t word = 0;
            memcpy(&word, value + index, sizeof(word));
            append_bytes({0x81, 0xBF}); // cmp dword [rdi+disp32],imm32
            append_u32(displacement + (uint32_t)index);
            append_u32(word);
            append_conditional_jump(0x85, mismatches); // jne
            index += 4;
        }
        if (index + 2 <= length) {
            uint16_t word = 0;
            memcpy(&word, value + index, sizeof(word));
            append_bytes({0x66, 0x81, 0xBF});
            append_u32(displacement + (uint32_t)index);
            append_u16(word);
            append_conditional_jump(0x85, mismatches);
            index += 2;
        }
        if (index < length) {
            append_bytes({0x80, 0xBF}); // cmp byte [rdi+disp32],imm8
            append_u32(displacement + (uint32_t)index);
            append_bytes({(uint8_t)value[index]});
            append_conditional_jump(0x85, mismatches);
        }
        if (require_null) {
            append_bytes({0x80, 0xBF});
            append_u32(displacement + (uint32_t)length);
            append_bytes({0x00});
            append_conditional_jump(0x85, mismatches);
        }
    };
    auto emit_response_selection = [&](int data_index, uint32_t length) {
        append_bytes({0x48, 0xBE}); // mov rsi,response_address
        data_references[data_reference_count++] = {used, data_index};
        append_u64(0);
        append_bytes({0xB8});       // mov eax,response_length
        append_u32(length);
        append_bytes({0xE9});       // jmp synthesize
        synth_jumps[synth_jump_count++] = used;
        append_u32(0);
    };

    // Preserve the four public arguments in caller-saved registers. The
    // response writer temporarily uses rdi/rsi/rdx/rcx, then restores them
    // before entering LSO's untouched prologue.
    append_bytes({0x49, 0x89, 0xF8}); // mov r8,rdi
    append_bytes({0x49, 0x89, 0xF1}); // mov r9,rsi
    append_bytes({0x49, 0x89, 0xD2}); // mov r10,rdx
    append_bytes({0x49, 0x89, 0xCB}); // mov r11,rcx
    append_bytes({0x48, 0x85, 0xFF}); // test rdi,rdi
    append_conditional_jump(0x84, null_to_passthrough); // jz

    static constexpr uint32_t ROUTE_RESTRICTION = 0x01;
    static constexpr uint32_t ROUTE_BLOCKS = 0x02;
    static constexpr uint32_t ROUTE_INVITATIONS = 0x04;
    static constexpr uint32_t ROUTE_FRIENDS = 0x08;

    // 1) PS5 Communication Restriction Status V3.
    JumpList restriction_to_user_profile = {};
    if ((route_mask & ROUTE_RESTRICTION) != 0) {
        emit_string_compare(LSO_REQUEST_API_GROUP_OFFSET,
                            "communicationRestrictionStatus", true,
                            restriction_to_user_profile);
        emit_response_selection(0, 20);
    }

    // 2) PS5 User Profile V1 block/friend list routes. Query strings are
    // permitted after the matched route prefix.
    const size_t user_profile_check = used;
    patch_jumps(restriction_to_user_profile, user_profile_check);
    JumpList user_profile_to_session_manager = {};
    JumpList blocks_to_next = {};
    JumpList friends_to_session_manager = {};
    if ((route_mask & (ROUTE_BLOCKS | ROUTE_FRIENDS)) != 0) {
        emit_string_compare(LSO_REQUEST_API_GROUP_OFFSET, "userProfile", true,
                            user_profile_to_session_manager);
        if ((route_mask & ROUTE_BLOCKS) != 0) {
            emit_string_compare(LSO_REQUEST_PATH_OFFSET,
                                "/v1/users/me/blocks", false,
                                blocks_to_next);
            emit_response_selection(1, 32);
            if ((route_mask & ROUTE_FRIENDS) != 0)
                patch_jumps(blocks_to_next, used);
        }
        if ((route_mask & ROUTE_FRIENDS) != 0) {
            emit_string_compare(LSO_REQUEST_PATH_OFFSET,
                                "/v1/users/me/friends", false,
                                friends_to_session_manager);
            emit_response_selection(2, 33);
        }
    }

    // 3) PS5 Session Manager V1 invitations. The account ID occupies the 19
    // bytes between "/v1/users/" and the matched route suffix.
    const size_t session_manager_check = used;
    patch_jumps(user_profile_to_session_manager, session_manager_check);
    patch_jumps(friends_to_session_manager, session_manager_check);
    if ((route_mask & ROUTE_FRIENDS) == 0)
        patch_jumps(blocks_to_next, session_manager_check);
    JumpList session_manager_to_passthrough = {};
    if ((route_mask & ROUTE_INVITATIONS) != 0) {
        emit_string_compare(LSO_REQUEST_API_GROUP_OFFSET, "sessionManager", true,
                            session_manager_to_passthrough);
        emit_string_compare(LSO_REQUEST_PATH_OFFSET, "/v1/users/", false,
                            session_manager_to_passthrough);
        emit_string_compare(LSO_REQUEST_PATH_OFFSET + 10 + 19,
                            "/playerSessionsInvitations", false,
                            session_manager_to_passthrough);
        emit_response_selection(3, 18);
    }

    // A route excluded by the mask must enter the original SendRequest path.
    // Keep an explicit jump here because some masks omit the final matcher;
    // without it, a nonmatch could fall into the synthetic response writer.
    append_bytes({0xE9});
    const size_t unmatched_to_passthrough = used;
    append_u32(0);

    // Common response preloader. rsi points at immutable JSON and eax contains
    // its length. The hit counter gives the loader an explicit confirmation
    // that a request matched, even if GTA deletes the record before polling.
    const size_t synthesize = used;
    for (size_t i = 0; i < synth_jump_count; i++) {
        const int64_t relative =
            (int64_t)synthesize - (int64_t)(synth_jumps[i] + 4);
        const int32_t relative32 = (int32_t)relative;
        memcpy(stub + synth_jumps[i], &relative32, sizeof(relative32));
    }
    append_bytes({0x48, 0xBA});             // mov rdx,hit_counter_address
    append_u64((uint64_t)hit_counter_address);
    append_bytes({0xF0, 0xFF, 0x02});       // lock inc dword ptr [rdx]
    append_bytes({0x48, 0x89, 0xC1});       // mov rcx,rax
    append_bytes({0x4C, 0x89, 0xC7});       // mov rdi,r8
    append_bytes({0x48, 0x81, 0xC7, 0xE8, 0x21, 0x00, 0x00});
    append_bytes({0xF3, 0xA4});             // rep movsb
    append_bytes({0xC6, 0x07, 0x00});       // trailing NUL
    append_bytes({0x49, 0x89, 0x80, 0xE8, 0xA1, 0x00, 0x00});
    append_bytes({0x31, 0xD2});             // xor edx,edx
    append_bytes({0x49, 0x89, 0x90, 0xF0, 0xA1, 0x00, 0x00});
    append_bytes({0x41, 0xC7, 0x80, 0xF8, 0xA1, 0x00, 0x00});
    append_u32(200);
    append_bytes({0x66, 0x41, 0xC7, 0x80, 0xFC, 0xA1, 0x00, 0x00});
    append_u16(0x0101);
    append_bytes({0x4C, 0x89, 0xC7});       // mov rdi,r8
    append_bytes({0x4C, 0x89, 0xCE});       // mov rsi,r9
    append_bytes({0x4C, 0x89, 0xD2});       // mov rdx,r10
    append_bytes({0x4C, 0x89, 0xD9});       // mov rcx,r11
    append_bytes({0xE9});                   // jmp passthrough
    synthesized_to_passthrough.offsets[
        synthesized_to_passthrough.count++] = used;
    append_u32(0);

    // Every nonmatching request resumes the unmodified LSO routine.
    const size_t passthrough = used;
    patch_jumps(null_to_passthrough, passthrough);
    patch_jumps(session_manager_to_passthrough, passthrough);
    patch_jumps(synthesized_to_passthrough, passthrough);
    {
        const int64_t relative =
            (int64_t)passthrough - (int64_t)(unmatched_to_passthrough + 4);
        const int32_t relative32 = (int32_t)relative;
        memcpy(stub + unmatched_to_passthrough, &relative32,
               sizeof(relative32));
    }

    // Replay the untouched prologue, then continue immediately after it.
    memcpy(stub + used, expected, sizeof(expected));
    used += sizeof(expected);
    append_bytes({0x49, 0xBB});
    append_u64((uint64_t)(entry + (intptr_t)sizeof(expected)));
    append_bytes({0x41, 0xFF, 0xE3});       // jmp r11

    static const char *responses[4] = {
        "{\"restricted\":false}",
        "{\"blocks\":[],\"totalItemCount\":0}",
        "{\"friends\":[],\"totalItemCount\":0}",
        "{\"invitations\":[]}"
    };
    size_t data_offsets[4] = {};
    for (size_t i = 0; i < 4; i++) {
        data_offsets[i] = used;
        const size_t length = strlen(responses[i]);
        memcpy(stub + used, responses[i], length + 1);
        used += length + 1;
    }
    for (size_t i = 0; i < data_reference_count; i++) {
        const uint64_t address =
            (uint64_t)mapping + data_offsets[data_references[i].data_index];
        memcpy(stub + data_references[i].immediate_offset, &address,
               sizeof(address));
    }

    if (used > sizeof(stub) ||
        pt_copyin(pid, stub, mapping, used) < 0 ||
        kernel_mprotect(pid, mapping, 0x3000, PROT_READ | PROT_EXEC) < 0)
    {
        plugin_log("[LSO-PS5API] Could not write/activate remote shim");
        pt_munmap(pid, mapping, 0x4000);
        return false;
    }

    uint8_t detour[sizeof(expected)];
    memset(detour, 0x90, sizeof(detour));
    detour[0] = 0xFF;
    detour[1] = 0x25;
    memset(detour + 2, 0, 4);
    memcpy(detour + 6, &mapping, sizeof(mapping));

    const intptr_t code_page = entry & ~(intptr_t)0xFFF;
    if (kernel_mprotect(pid, code_page, 0x1000,
                        PROT_READ | PROT_WRITE | PROT_EXEC) < 0 ||
        kernel_proc_copyin(pid, detour, entry, sizeof(detour)) < 0)
    {
        plugin_log("[LSO-PS5API] Could not install SendRequest detour");
        kernel_proc_copyin(pid, expected, entry, sizeof(expected));
        kernel_mprotect(pid, code_page, 0x1000, PROT_READ | PROT_EXEC);
        pt_munmap(pid, mapping, 0x4000);
        return false;
    }
    kernel_mprotect(pid, code_page, 0x1000, PROT_READ | PROT_EXEC);

    uint8_t verify[sizeof(detour)] = {};
    if (kernel_proc_copyout(pid, entry, verify, sizeof(verify)) < 0 ||
        memcmp(verify, detour, sizeof(detour)) != 0)
    {
        plugin_log("[LSO-PS5API] SendRequest detour verification failed");
        if (kernel_mprotect(pid, code_page, 0x1000,
                            PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
            kernel_proc_copyin(pid, expected, entry, sizeof(expected));
            kernel_mprotect(pid, code_page, 0x1000, PROT_READ | PROT_EXEC);
        }
        pt_munmap(pid, mapping, 0x4000);
        return false;
    }

    if (hit_counter_out) *hit_counter_out = hit_counter_address;
    plugin_log("[LSO-PS5API] v4 lifecycle-safe preloader installed: route mask=0x%x "
               "(restriction=1 blocks=2 invitations=4 friends=8)", route_mask);
    return true;
}

// LSO 1.010.002 normally does not expose ordinary HTTP response codes in its
// log. This diagnostic records only the numeric result and status in a private
// page in
// the game process. The loader polls that page with kernel_proc_copyout and
// writes the completed records to PluginLoader.log. It does not depend on the
// game's restored filesystem credentials and never reads or writes patch.log.
// No URL, authorization header, BlueSphere token, or response data is captured.
[[maybe_unused]] static bool install_lso_http_trace(
    pid_t pid, intptr_t module_base, intptr_t *trace_record_out)
{
    if (trace_record_out) *trace_record_out = 0;

    if (!module_base) {
        plugin_log("[LSO-HTTP] Module base unavailable; trace not installed");
        return false;
    }

    static const uint8_t send_expected[] = {
        0x85, 0xC0,                         // test eax,eax
        0x0F, 0x88, 0x80, 0x00, 0x00, 0x00, // js send_failure
        0x49, 0x8D, 0x9D, 0xF8, 0xA1, 0x00, 0x00 // lea rbx,[r13+0xa1f8]
    };
    static const uint8_t status_expected[] = {
        0x85, 0xC0,                         // test eax,eax
        0x79, 0x1D,                         // jns success
        0x89, 0xC6,                         // mov esi,eax
        0x48, 0x8D, 0x3D, 0x3B, 0xDE, 0x00, 0x00,
        0x48, 0x8D, 0x95, 0xD0, 0xFD, 0xFF, 0xFF,
        0x31, 0xC0,
        0xE8, 0xDC, 0xA2, 0xFF, 0xFF,
        0xC7, 0x03, 0x00, 0x00, 0x00, 0x00
    };

    const intptr_t send_patch_address =
        module_base + (intptr_t)LSO_HTTP_SEND_BLOCK_OFFSET;
    const intptr_t status_patch_address =
        module_base + (intptr_t)LSO_HTTP_STATUS_BLOCK_OFFSET;
    uint8_t send_current[sizeof(send_expected)] = {};
    uint8_t status_current[sizeof(status_expected)] = {};
    if (kernel_proc_copyout(pid, send_patch_address, send_current,
                            sizeof(send_current)) < 0 ||
        memcmp(send_current, send_expected, sizeof(send_expected)) != 0)
    {
        plugin_log("[LSO-HTTP] LSO 1.010.002 send block mismatch at 0x%llx; "
                   "trace not installed",
                   (unsigned long long)send_patch_address);
        return false;
    }
    if (kernel_proc_copyout(pid, status_patch_address, status_current,
                            sizeof(status_current)) < 0 ||
        memcmp(status_current, status_expected, sizeof(status_expected)) != 0)
    {
        plugin_log("[LSO-HTTP] LSO 1.010.002 status block mismatch at 0x%llx; "
                   "trace not installed",
                   (unsigned long long)status_patch_address);
        return false;
    }

    // Keep the data page writable and make only the second page executable.
    const intptr_t trace_mapping = pt_mmap(pid, 0, 0x2000,
                                           PROT_READ | PROT_WRITE,
                                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (trace_mapping <= 0) {
        plugin_log("[LSO-HTTP] Remote trace allocation failed (rc=%lld)",
                   (long long)trace_mapping);
        return false;
    }

    const intptr_t record_address = trace_mapping;
    const intptr_t send_stub_address = trace_mapping + 0x1000;
    const intptr_t status_stub_address = trace_mapping + 0x1200;
    const intptr_t send_success_continuation =
        send_patch_address + (intptr_t)sizeof(send_expected);
    const intptr_t send_failure_target = module_base + 0x133E7;
    const intptr_t status_continuation =
        status_patch_address + (intptr_t)sizeof(status_expected);

    auto append_bytes = [](uint8_t *code, size_t &used,
                           std::initializer_list<uint8_t> values) {
        for (uint8_t value : values) code[used++] = value;
    };
    auto append_imm64 = [](uint8_t *code, size_t &used, uint64_t value) {
        memcpy(code + used, &value, sizeof(value));
        used += sizeof(value);
    };

    // Emit a minimal numeric mailbox writer. It does not dereference or copy
    // strings from the game's stack, and it does not call any function.
    auto append_record_writer = [&](uint8_t *code, size_t &used,
                                    uint32_t stage, bool capture_status) {
        append_bytes(code, used, {0x41, 0x89, 0xC2});       // r10d=result
        append_bytes(code, used, {0x49, 0xBB});
        append_imm64(code, used, (uint64_t)record_address);
        append_bytes(code, used, {0xF0, 0x41, 0xFF, 0x03}); // sequence odd
        append_bytes(code, used, {0x45, 0x89, 0x53, 0x04}); // record.result
        if (capture_status) {
            append_bytes(code, used, {0x8B, 0x03});         // eax=*status
            append_bytes(code, used, {0x41, 0x89, 0x43, 0x08});
        } else {
            append_bytes(code, used,
                         {0x41, 0xC7, 0x43, 0x08,
                          0x00, 0x00, 0x00, 0x00});         // status=0
        }
        append_bytes(code, used, {0x41, 0xC7, 0x43, 0x0C}); // record.stage
        memcpy(code + used, &stage, sizeof(stage));
        used += sizeof(stage);
        append_bytes(code, used, {0xF0, 0x41, 0xFF, 0x03}); // commit even
        append_bytes(code, used, {0x44, 0x89, 0xD0});       // restore eax
    };

    uint8_t send_stub[192] = {};
    size_t send_n = 0;
    append_record_writer(send_stub, send_n, 1, false);
    append_bytes(send_stub, send_n, {0x85, 0xC0});           // test result
    const size_t send_success_jump = send_n;
    append_bytes(send_stub, send_n, {0x79, 0x00});           // jns success
    append_bytes(send_stub, send_n, {0x49, 0xBB});
    append_imm64(send_stub, send_n, (uint64_t)send_failure_target);
    append_bytes(send_stub, send_n, {0x41, 0xFF, 0xE3});     // jump failure
    const size_t send_success = send_n;
    send_stub[send_success_jump + 1] =
        (uint8_t)(send_success - (send_success_jump + 2));
    append_bytes(send_stub, send_n,
                 {0x49, 0x8D, 0x9D, 0xF8, 0xA1, 0x00, 0x00}); // original lea
    append_bytes(send_stub, send_n, {0x49, 0xBB});
    append_imm64(send_stub, send_n, (uint64_t)send_success_continuation);
    append_bytes(send_stub, send_n, {0x41, 0xFF, 0xE3});

    uint8_t status_stub[192] = {};
    size_t status_n = 0;
    append_record_writer(status_stub, status_n, 2, true);
    append_bytes(status_stub, status_n, {0x85, 0xC0});
    append_bytes(status_stub, status_n, {0x79, 0x06});       // success
    append_bytes(status_stub, status_n,
                 {0xC7, 0x03, 0x00, 0x00, 0x00, 0x00});     // status=0
    append_bytes(status_stub, status_n, {0x49, 0xBB});
    append_imm64(status_stub, status_n, (uint64_t)status_continuation);
    append_bytes(status_stub, status_n, {0x41, 0xFF, 0xE3});

    if (send_n > sizeof(send_stub) || status_n > sizeof(status_stub) ||
        pt_copyin(pid, send_stub, send_stub_address, send_n) < 0 ||
        pt_copyin(pid, status_stub, status_stub_address, status_n) < 0)
    {
        plugin_log("[LSO-HTTP] Failed to write the remote transport stubs");
        pt_munmap(pid, trace_mapping, 0x2000);
        return false;
    }

    if (kernel_mprotect(pid, send_stub_address, 0x1000,
                        PROT_READ | PROT_EXEC) < 0)
    {
        plugin_log("[LSO-HTTP] Failed to make the remote trace stub executable");
        pt_munmap(pid, trace_mapping, 0x2000);
        return false;
    }

    uint8_t send_detour[sizeof(send_expected)];
    uint8_t status_detour[sizeof(status_expected)];
    auto make_detour = [](uint8_t *detour, size_t length, intptr_t target) {
        memset(detour, 0x90, length);
        detour[0] = 0xFF;
        detour[1] = 0x25;
        memset(detour + 2, 0, 4);
        memcpy(detour + 6, &target, sizeof(target));
    };
    make_detour(send_detour, sizeof(send_detour), send_stub_address);
    make_detour(status_detour, sizeof(status_detour), status_stub_address);

    const intptr_t code_page = status_patch_address & ~(intptr_t)0xFFF;
    if (kernel_mprotect(pid, code_page, 0x1000,
                        PROT_READ | PROT_WRITE | PROT_EXEC) < 0 ||
        kernel_proc_copyin(pid, send_detour, send_patch_address,
                           sizeof(send_detour)) < 0 ||
        kernel_proc_copyin(pid, status_detour, status_patch_address,
                           sizeof(status_detour)) < 0)
    {
        plugin_log("[LSO-HTTP] Failed to install the transport trace detours");
        kernel_proc_copyin(pid, send_expected, send_patch_address,
                           sizeof(send_expected));
        kernel_proc_copyin(pid, status_expected, status_patch_address,
                           sizeof(status_expected));
        kernel_mprotect(pid, code_page, 0x1000, PROT_READ | PROT_EXEC);
        pt_munmap(pid, trace_mapping, 0x2000);
        return false;
    }
    kernel_mprotect(pid, code_page, 0x1000, PROT_READ | PROT_EXEC);

    if (trace_record_out) *trace_record_out = record_address;
    plugin_log("[LSO-MON] Numeric send/status monitor installed at 0x%llx; "
               "results will appear only in PluginLoader.log",
               (unsigned long long)record_address);
    return true;
}

// Observe the calls immediately before Online succeeds or the process exits.
// Each game thunk/import slot is redirected through a tiny entry shim that
// increments a counter and tail-jumps to the already-installed LSO target.
// The original stack, arguments, and return path are therefore unchanged.
static bool install_lso_call_monitor(
    pid_t pid, intptr_t module_base, const LsoDiagnostics *diag,
    intptr_t *trace_record_out, bool include_np_hooks,
    bool include_webapi_hooks)
{
    if (trace_record_out) *trace_record_out = 0;
    if (!diag || !diag->enabled || !diag->game_base || !module_base) {
        plugin_log("[LSO-MON] Required module addresses unavailable");
        return false;
    }

    static_assert(LSO_NP_HOOK_COUNT + LSO_WEBAPI_HOOK_COUNT ==
                      LSO_CALL_MONITOR_MAX,
                  "Call-monitor entry count mismatch");

    struct MonitorPoint {
        intptr_t patch_address;
        intptr_t original_target;
        int       record_index;
        bool      absolute_jump;
    };

    MonitorPoint points[LSO_CALL_MONITOR_MAX] = {};
    int point_count = 0;

    if (include_np_hooks) {
        for (int i = 0; i < LSO_NP_HOOK_COUNT; i++) {
            intptr_t patch_address =
                diag->hook_addresses[LSO_NET_HOOK_COUNT + i];
            intptr_t original_target = 0;
            if (!lso_get_absolute_hook_destination(pid, patch_address,
                                                    &original_target) ||
                original_target < module_base ||
                original_target >= module_base +
                                       (intptr_t)LSO_1010_IMAGE_SIZE_MAX)
            {
                plugin_log("[LSO-MON] NP#%02d target unavailable; skipping",
                           i + 1);
                continue;
            }
            points[point_count++] =
                {patch_address, original_target, i, true};
        }
    }

    if (include_webapi_hooks) {
        for (int i = 0; i < LSO_WEBAPI_HOOK_COUNT; i++) {
            intptr_t slot_address =
                (intptr_t)k_lso_webapi_slot_addresses[i];
            intptr_t original_target = 0;
            if (kernel_proc_copyout(pid, slot_address, &original_target,
                                    sizeof(original_target)) < 0 ||
                original_target < module_base ||
                original_target >= module_base +
                                       (intptr_t)LSO_1010_IMAGE_SIZE_MAX)
            {
                plugin_log("[LSO-MON] WebAPI.%s slot 0x%llx target 0x%llx is "
                           "not routed to LSO; skipping",
                           k_lso_webapi_call_names[i],
                           (unsigned long long)slot_address,
                           (unsigned long long)original_target);
                continue;
            }
            points[point_count++] =
                {slot_address, original_target, LSO_NP_HOOK_COUNT + i, false};
        }
    }

    if (point_count == 0) {
        plugin_log("[LSO-MON] No NP/WebAPI call sites were eligible");
        return false;
    }

    const size_t remote_page_size = 0x4000;
    const intptr_t trace_mapping = pt_mmap(
        pid, 0, remote_page_size * 2, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (trace_mapping <= 0) {
        plugin_log("[LSO-MON] Remote call-trace allocation failed (rc=%lld)",
                   (long long)trace_mapping);
        return false;
    }

    const intptr_t record_address = trace_mapping;
    const intptr_t code_address = trace_mapping + (intptr_t)remote_page_size;
    const size_t stub_stride = 64;

    auto append_bytes = [](uint8_t *code, size_t &used,
                           std::initializer_list<uint8_t> values) {
        for (uint8_t value : values) code[used++] = value;
    };
    auto append_imm64 = [](uint8_t *code, size_t &used, uint64_t value) {
        memcpy(code + used, &value, sizeof(value));
        used += sizeof(value);
    };

    for (int i = 0; i < point_count; i++) {
        const MonitorPoint &point = points[i];
        const intptr_t stub_address =
            code_address + (intptr_t)(point.record_index * stub_stride);
        const intptr_t entry_address =
            record_address +
            (intptr_t)(point.record_index * sizeof(lso_call_trace_entry_t));

        uint8_t stub[stub_stride] = {};
        size_t used = 0;
        append_bytes(stub, used, {0x49, 0xBB});             // mov r11,entry
        append_imm64(stub, used, (uint64_t)entry_address);
        append_bytes(stub, used,
                     {0xF0, 0x41, 0xFF, 0x03});             // lock inc count
        append_bytes(stub, used, {0x49, 0xBB});             // mov r11,target
        append_imm64(stub, used, (uint64_t)point.original_target);
        append_bytes(stub, used, {0x41, 0xFF, 0xE3});       // jmp r11

        if (used > sizeof(stub) ||
            kernel_proc_copyin(pid, stub, stub_address, sizeof(stub)) < 0)
        {
            plugin_log("[LSO-MON] Failed to write wrapper for entry %d",
                       point.record_index);
            pt_munmap(pid, trace_mapping, remote_page_size * 2);
            return false;
        }
    }

    if (kernel_mprotect(pid, code_address, remote_page_size,
                        PROT_READ | PROT_EXEC) < 0)
    {
        plugin_log("[LSO-MON] Failed to make call wrappers executable");
        pt_munmap(pid, trace_mapping, remote_page_size * 2);
        return false;
    }

    int installed = 0;
    for (int i = 0; i < point_count; i++) {
        const MonitorPoint &point = points[i];
        const intptr_t stub_address =
            code_address + (intptr_t)(point.record_index * stub_stride);
        bool ok = false;

        if (point.absolute_jump) {
            uint8_t detour[14] = {0xFF, 0x25, 0, 0, 0, 0};
            memcpy(detour + 6, &stub_address, sizeof(stub_address));
            const intptr_t target_page =
                point.patch_address & ~(intptr_t)(remote_page_size - 1);
            if (kernel_mprotect(pid, target_page, remote_page_size,
                                PROT_READ | PROT_WRITE | PROT_EXEC) >= 0)
            {
                ok = kernel_proc_copyin(pid, detour, point.patch_address,
                                        sizeof(detour)) == 0;
                kernel_mprotect(pid, target_page, remote_page_size,
                                PROT_READ | PROT_EXEC);
            }
        } else {
            const intptr_t slot_page =
                point.patch_address & ~(intptr_t)(remote_page_size - 1);
            if (kernel_mprotect(pid, slot_page, remote_page_size,
                                PROT_READ | PROT_WRITE) >= 0)
            {
                ok = kernel_proc_copyin(pid, &stub_address,
                                        point.patch_address,
                                        sizeof(stub_address)) == 0;
                kernel_mprotect(pid, slot_page, remote_page_size, PROT_READ);
            }
        }

        if (ok) {
            installed++;
        } else if (point.record_index < LSO_NP_HOOK_COUNT) {
            plugin_log("[LSO-MON] Failed to wrap NP#%02d",
                       point.record_index + 1);
        } else {
            plugin_log("[LSO-MON] Failed to wrap WebAPI.%s",
                       k_lso_webapi_call_names[
                           point.record_index - LSO_NP_HOOK_COUNT]);
        }
    }

    if (installed == 0) {
        pt_munmap(pid, trace_mapping, remote_page_size * 2);
        plugin_log("[LSO-MON] No call wrappers could be installed");
        return false;
    }

    if (trace_record_out) *trace_record_out = record_address;
    plugin_log("[LSO-MON] Safe entry-call monitor installed: %d/%d selected "
               "sites; counts go only to PluginLoader.log",
               installed, point_count);
    return true;
}

// Wrap only sceNetConnect (NET #6) and sceNetResolverStartNtoa (NET #8).
// These calls are infrequent and directly bracket the unresolved FW 8.60
// failure. The shims call the exact LSO destinations, preserve nonvolatile
// registers and ABI stack alignment, publish the original return value, then
// return normally to GTA.
[[maybe_unused]] static bool install_lso_net_boundary_trace(
    pid_t pid, intptr_t module_base, const LsoDiagnostics *diag,
    intptr_t *trace_record_out)
{
    if (trace_record_out) *trace_record_out = 0;
    if (!diag || !diag->enabled || !module_base) {
        plugin_log("[LSO-NET-TRACE] Required module addresses unavailable");
        return false;
    }

    static const int hook_indexes[LSO_NET_BOUNDARY_COUNT] = {
        5, // NET #6: sceNetConnect
        7, // NET #8: sceNetResolverStartNtoa
    };
    intptr_t original_targets[LSO_NET_BOUNDARY_COUNT] = {};
    for (int i = 0; i < LSO_NET_BOUNDARY_COUNT; i++) {
        const intptr_t patch_address =
            diag->hook_addresses[hook_indexes[i]];
        if (!lso_get_absolute_hook_destination(
                pid, patch_address, &original_targets[i]) ||
            original_targets[i] < module_base ||
            original_targets[i] >=
                module_base + (intptr_t)LSO_1010_IMAGE_SIZE_MAX)
        {
            plugin_log("[LSO-NET-TRACE] NET #%d target unavailable",
                       hook_indexes[i] + 1);
            return false;
        }
    }

    const size_t remote_page_size = 0x4000;
    const size_t stub_stride = 128;
    const intptr_t trace_mapping = pt_mmap(
        pid, 0, remote_page_size * 2, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (trace_mapping <= 0) {
        plugin_log("[LSO-NET-TRACE] Remote allocation failed (rc=%lld)",
                   (long long)trace_mapping);
        return false;
    }

    const intptr_t record_address = trace_mapping;
    const intptr_t code_address = trace_mapping + (intptr_t)remote_page_size;
    auto append_bytes = [](uint8_t *code, size_t &used,
                           std::initializer_list<uint8_t> values) {
        for (uint8_t value : values) code[used++] = value;
    };
    auto append_imm64 = [](uint8_t *code, size_t &used, uint64_t value) {
        memcpy(code + used, &value, sizeof(value));
        used += sizeof(value);
    };

    // sceNetConnect(fd, sockaddr, length)
    {
        uint8_t stub[stub_stride] = {};
        size_t used = 0;
        const intptr_t entry = record_address;
        append_bytes(stub, used, {0x41, 0x54});             // push r12
        append_bytes(stub, used, {0x49, 0xBC});             // mov r12,entry
        append_imm64(stub, used, (uint64_t)entry);
        append_bytes(stub, used,
                     {0x49, 0x89, 0x7C, 0x24, 0x10});       // arg0=fd
        append_bytes(stub, used, {0x48, 0x85, 0xF6});       // test rsi,rsi
        const size_t null_jump = used;
        append_bytes(stub, used, {0x74, 0x00});             // jz no-copy
        append_bytes(stub, used,
                     {0x48, 0x83, 0xFA, 0x10});             // cmp rdx,16
        const size_t length_jump = used;
        append_bytes(stub, used, {0x72, 0x00});             // jb no-copy
        append_bytes(stub, used, {0x48, 0x8B, 0x06});       // mov rax,[rsi]
        append_bytes(stub, used,
                     {0x49, 0x89, 0x44, 0x24, 0x20});       // data[0..7]
        append_bytes(stub, used,
                     {0x48, 0x8B, 0x46, 0x08});             // mov rax,[rsi+8]
        append_bytes(stub, used,
                     {0x49, 0x89, 0x44, 0x24, 0x28});       // data[8..15]
        const size_t no_copy = used;
        stub[null_jump + 1] =
            (uint8_t)(no_copy - (null_jump + 2));
        stub[length_jump + 1] =
            (uint8_t)(no_copy - (length_jump + 2));
        append_bytes(stub, used, {0x49, 0xBB});             // mov r11,target
        append_imm64(stub, used, (uint64_t)original_targets[0]);
        append_bytes(stub, used, {0x41, 0xFF, 0xD3});       // call r11
        append_bytes(stub, used,
                     {0x49, 0x89, 0x44, 0x24, 0x08});       // last_result=rax
        append_bytes(stub, used,
                     {0xF0, 0x41, 0xFF, 0x04, 0x24});       // lock inc count
        append_bytes(stub, used, {0x41, 0x5C, 0xC3});       // pop r12; ret
        if (used > sizeof(stub) ||
            kernel_proc_copyin(pid, stub, code_address,
                               sizeof(stub)) < 0)
        {
            plugin_log("[LSO-NET-TRACE] Could not write connect wrapper");
            pt_munmap(pid, trace_mapping, remote_page_size * 2);
            return false;
        }
    }

    // sceNetResolverStartNtoa(resolver, hostname, address, ...)
    {
        uint8_t stub[stub_stride] = {};
        size_t used = 0;
        const intptr_t entry = record_address +
            (intptr_t)sizeof(lso_net_boundary_entry_t);
        const intptr_t stub_address = code_address + (intptr_t)stub_stride;
        append_bytes(stub, used,
                     {0x41, 0x54, 0x41, 0x55});             // push r12,r13
        append_bytes(stub, used,
                     {0x48, 0x83, 0xEC, 0x08});             // ABI alignment
        append_bytes(stub, used, {0x49, 0xBC});             // mov r12,entry
        append_imm64(stub, used, (uint64_t)entry);
        append_bytes(stub, used,
                     {0x49, 0x89, 0x7C, 0x24, 0x10});       // arg0=resolver
        append_bytes(stub, used,
                     {0x49, 0x89, 0x74, 0x24, 0x18});       // arg1=hostname
        append_bytes(stub, used, {0x49, 0x89, 0xD5});       // r13=address out
        append_bytes(stub, used, {0x49, 0xBB});             // mov r11,target
        append_imm64(stub, used, (uint64_t)original_targets[1]);
        append_bytes(stub, used, {0x41, 0xFF, 0xD3});       // call r11
        append_bytes(stub, used,
                     {0x49, 0x89, 0x44, 0x24, 0x08});       // last_result=rax
        append_bytes(stub, used, {0x4D, 0x85, 0xED});       // test r13,r13
        const size_t no_address_jump = used;
        append_bytes(stub, used, {0x74, 0x00});             // jz publish
        append_bytes(stub, used,
                     {0x41, 0x8B, 0x45, 0x00});             // eax=[r13]
        append_bytes(stub, used,
                     {0x41, 0x89, 0x44, 0x24, 0x20});       // data[0..3]
        const size_t publish = used;
        stub[no_address_jump + 1] =
            (uint8_t)(publish - (no_address_jump + 2));
        append_bytes(stub, used,
                     {0xF0, 0x41, 0xFF, 0x04, 0x24});       // lock inc count
        append_bytes(stub, used,
                     {0x49, 0x8B, 0x44, 0x24, 0x08});       // restore result
        append_bytes(stub, used,
                     {0x48, 0x83, 0xC4, 0x08});             // undo alignment
        append_bytes(stub, used,
                     {0x41, 0x5D, 0x41, 0x5C, 0xC3});       // pop; pop; ret
        if (used > sizeof(stub) ||
            kernel_proc_copyin(pid, stub, stub_address,
                               sizeof(stub)) < 0)
        {
            plugin_log("[LSO-NET-TRACE] Could not write resolver wrapper");
            pt_munmap(pid, trace_mapping, remote_page_size * 2);
            return false;
        }
    }

    if (kernel_mprotect(pid, code_address, remote_page_size,
                        PROT_READ | PROT_EXEC) < 0)
    {
        plugin_log("[LSO-NET-TRACE] Could not make wrappers executable");
        pt_munmap(pid, trace_mapping, remote_page_size * 2);
        return false;
    }

    int installed = 0;
    for (int i = 0; i < LSO_NET_BOUNDARY_COUNT; i++) {
        const intptr_t patch_address =
            diag->hook_addresses[hook_indexes[i]];
        const intptr_t stub_address =
            code_address + (intptr_t)i * (intptr_t)stub_stride;
        uint8_t detour[14] = {0xFF, 0x25, 0, 0, 0, 0};
        memcpy(detour + 6, &stub_address, sizeof(stub_address));
        const intptr_t page =
            patch_address & ~(intptr_t)(remote_page_size - 1);
        bool ok = false;
        if (kernel_mprotect(pid, page, remote_page_size,
                            PROT_READ | PROT_WRITE | PROT_EXEC) >= 0)
        {
            ok = kernel_proc_copyin(pid, detour, patch_address,
                                    sizeof(detour)) == 0;
            kernel_mprotect(pid, page, remote_page_size,
                            PROT_READ | PROT_EXEC);
        }
        if (ok) installed++;
        else plugin_log("[LSO-NET-TRACE] Failed to wrap NET #%d",
                        hook_indexes[i] + 1);
    }

    if (installed != LSO_NET_BOUNDARY_COUNT) {
        plugin_log("[LSO-NET-TRACE] Incomplete installation: %d/%d",
                   installed, LSO_NET_BOUNDARY_COUNT);
        return false;
    }
    if (trace_record_out) *trace_record_out = record_address;
    plugin_log("[LSO-NET-TRACE] Resolver/connect result trace installed "
               "(%d/%d)", installed, LSO_NET_BOUNDARY_COUNT);
    return true;
}

// Observe the libSceHttp path that GTA's Rockstar client actually uses. v38
// established that the title's direct resolver/connect imports are not part
// of this flow. These three result-preserving GOT shims expose only host
// classification, request identifiers, return codes, and HTTP status.
[[maybe_unused]] static bool install_gta_http_boundary_trace(
    pid_t pid, intptr_t *trace_record_out)
{
    if (trace_record_out) *trace_record_out = 0;

    const intptr_t *slots = k_gta_http_import_slots;
    intptr_t original_targets[GTA_HTTP_BOUNDARY_COUNT] = {};
    for (int i = 0; i < GTA_HTTP_BOUNDARY_COUNT; i++) {
        if (kernel_proc_copyout(pid, slots[i], &original_targets[i],
                                sizeof(original_targets[i])) < 0 ||
            original_targets[i] < 0x10000)
        {
            plugin_log("[GTA-HTTP-TRACE] Import %d target unavailable", i + 1);
            return false;
        }
    }

    const size_t remote_page_size = 0x4000;
    const size_t stub_stride = 160;
    const intptr_t trace_mapping = pt_mmap(
        pid, 0, remote_page_size * 2, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (trace_mapping <= 0) {
        plugin_log("[GTA-HTTP-TRACE] Remote allocation failed (rc=%lld)",
                   (long long)trace_mapping);
        return false;
    }

    const intptr_t record_address = trace_mapping;
    const intptr_t code_address = trace_mapping + (intptr_t)remote_page_size;
    auto append_bytes = [](uint8_t *code, size_t &used,
                           std::initializer_list<uint8_t> values) {
        for (uint8_t value : values) code[used++] = value;
    };
    auto append_imm64 = [](uint8_t *code, size_t &used, uint64_t value) {
        memcpy(code + used, &value, sizeof(value));
        used += sizeof(value);
    };

    // sceHttpCreateConnectionWithURL(template, url, keep_alive)
    {
        uint8_t stub[stub_stride] = {};
        size_t used = 0;
        const intptr_t entry = record_address;
        append_bytes(stub, used, {0x41, 0x54});             // push r12
        append_bytes(stub, used, {0x49, 0xBC});             // mov r12,entry
        append_imm64(stub, used, (uint64_t)entry);
        append_bytes(stub, used,
                     {0x49, 0x89, 0x7C, 0x24, 0x10});       // arg0=template
        append_bytes(stub, used,
                     {0x49, 0x89, 0x74, 0x24, 0x18});       // arg1=url ptr
        append_bytes(stub, used, {0x31, 0xC0});             // xor eax,eax
        for (uint8_t offset = 0; offset < 64; offset += 8) {
            append_bytes(stub, used,
                         {0x49, 0x89, 0x44, 0x24,
                          (uint8_t)(0x20 + offset)});         // clear prefix
        }
        append_bytes(stub, used, {0x48, 0x85, 0xF6});       // test rsi,rsi
        const size_t null_jump = used;
        append_bytes(stub, used, {0x74, 0x00});             // jz call
        for (uint8_t offset = 0; offset < 32; offset += 8) {
            if (offset == 0)
                append_bytes(stub, used, {0x48, 0x8B, 0x06});
            else
                append_bytes(stub, used,
                             {0x48, 0x8B, 0x46, offset});
            append_bytes(stub, used,
                         {0x49, 0x89, 0x44, 0x24,
                          (uint8_t)(0x20 + offset)});
        }
        const size_t call_target = used;
        stub[null_jump + 1] =
            (uint8_t)(call_target - (null_jump + 2));
        append_bytes(stub, used, {0x49, 0xBB});             // mov r11,target
        append_imm64(stub, used, (uint64_t)original_targets[0]);
        append_bytes(stub, used, {0x41, 0xFF, 0xD3});       // call r11
        append_bytes(stub, used,
                     {0x49, 0x89, 0x44, 0x24, 0x08});       // result
        append_bytes(stub, used,
                     {0xF0, 0x41, 0xFF, 0x04, 0x24});       // lock inc count
        append_bytes(stub, used, {0x41, 0x5C, 0xC3});       // pop r12; ret
        if (used > sizeof(stub) ||
            kernel_proc_copyin(pid, stub, code_address,
                               sizeof(stub)) < 0)
        {
            plugin_log("[GTA-HTTP-TRACE] Could not write connection wrapper");
            pt_munmap(pid, trace_mapping, remote_page_size * 2);
            return false;
        }
    }

    // sceHttpSendRequest(request, body, length)
    {
        uint8_t stub[stub_stride] = {};
        size_t used = 0;
        const intptr_t entry = record_address +
            (intptr_t)sizeof(gta_http_boundary_entry_t);
        const intptr_t stub_address = code_address + (intptr_t)stub_stride;
        append_bytes(stub, used, {0x41, 0x54});             // push r12
        append_bytes(stub, used, {0x49, 0xBC});             // mov r12,entry
        append_imm64(stub, used, (uint64_t)entry);
        append_bytes(stub, used,
                     {0x49, 0x89, 0x7C, 0x24, 0x10});       // arg0=request
        append_bytes(stub, used,
                     {0x49, 0x89, 0x54, 0x24, 0x18});       // arg1=length
        append_bytes(stub, used, {0x49, 0xBB});             // mov r11,target
        append_imm64(stub, used, (uint64_t)original_targets[1]);
        append_bytes(stub, used, {0x41, 0xFF, 0xD3});       // call r11
        append_bytes(stub, used,
                     {0x49, 0x89, 0x44, 0x24, 0x08});       // result
        append_bytes(stub, used,
                     {0xF0, 0x41, 0xFF, 0x04, 0x24});       // lock inc count
        append_bytes(stub, used, {0x41, 0x5C, 0xC3});       // pop r12; ret
        if (used > sizeof(stub) ||
            kernel_proc_copyin(pid, stub, stub_address,
                               sizeof(stub)) < 0)
        {
            plugin_log("[GTA-HTTP-TRACE] Could not write send wrapper");
            pt_munmap(pid, trace_mapping, remote_page_size * 2);
            return false;
        }
    }

    // sceHttpGetStatusCode(request, status_out)
    {
        uint8_t stub[stub_stride] = {};
        size_t used = 0;
        const intptr_t entry = record_address +
            (intptr_t)(2 * sizeof(gta_http_boundary_entry_t));
        const intptr_t stub_address = code_address +
            (intptr_t)(2 * stub_stride);
        append_bytes(stub, used,
                     {0x41, 0x54, 0x41, 0x55});             // push r12,r13
        append_bytes(stub, used,
                     {0x48, 0x83, 0xEC, 0x08});             // ABI alignment
        append_bytes(stub, used, {0x49, 0xBC});             // mov r12,entry
        append_imm64(stub, used, (uint64_t)entry);
        append_bytes(stub, used,
                     {0x49, 0x89, 0x7C, 0x24, 0x10});       // arg0=request
        append_bytes(stub, used,
                     {0x49, 0x89, 0x74, 0x24, 0x18});       // arg1=status ptr
        append_bytes(stub, used, {0x49, 0x89, 0xF5});       // r13=status ptr
        append_bytes(stub, used, {0x49, 0xBB});             // mov r11,target
        append_imm64(stub, used, (uint64_t)original_targets[2]);
        append_bytes(stub, used, {0x41, 0xFF, 0xD3});       // call r11
        append_bytes(stub, used,
                     {0x49, 0x89, 0x44, 0x24, 0x08});       // result
        append_bytes(stub, used, {0x4D, 0x85, 0xED});       // test r13,r13
        const size_t null_jump = used;
        append_bytes(stub, used, {0x74, 0x00});             // jz publish
        append_bytes(stub, used,
                     {0x41, 0x8B, 0x45, 0x00});             // eax=[r13]
        append_bytes(stub, used,
                     {0x41, 0x89, 0x44, 0x24, 0x20});       // data=status
        const size_t publish = used;
        stub[null_jump + 1] =
            (uint8_t)(publish - (null_jump + 2));
        append_bytes(stub, used,
                     {0xF0, 0x41, 0xFF, 0x04, 0x24});       // lock inc count
        append_bytes(stub, used,
                     {0x49, 0x8B, 0x44, 0x24, 0x08});       // restore result
        append_bytes(stub, used,
                     {0x48, 0x83, 0xC4, 0x08});             // undo alignment
        append_bytes(stub, used,
                     {0x41, 0x5D, 0x41, 0x5C, 0xC3});       // pop; pop; ret
        if (used > sizeof(stub) ||
            kernel_proc_copyin(pid, stub, stub_address,
                               sizeof(stub)) < 0)
        {
            plugin_log("[GTA-HTTP-TRACE] Could not write status wrapper");
            pt_munmap(pid, trace_mapping, remote_page_size * 2);
            return false;
        }
    }

    if (kernel_mprotect(pid, code_address, remote_page_size,
                        PROT_READ | PROT_EXEC) < 0)
    {
        plugin_log("[GTA-HTTP-TRACE] Could not make wrappers executable");
        pt_munmap(pid, trace_mapping, remote_page_size * 2);
        return false;
    }

    const intptr_t slot_page = slots[0] & ~(intptr_t)(remote_page_size - 1);
    bool installed = kernel_mprotect(pid, slot_page, remote_page_size,
                                     PROT_READ | PROT_WRITE) >= 0;
    for (int i = 0; installed && i < GTA_HTTP_BOUNDARY_COUNT; i++) {
        const intptr_t stub_address =
            code_address + (intptr_t)i * (intptr_t)stub_stride;
        installed = kernel_proc_copyin(pid, &stub_address, slots[i],
                                       sizeof(stub_address)) == 0;
    }
    kernel_mprotect(pid, slot_page, remote_page_size, PROT_READ);

    if (!installed) {
        if (kernel_mprotect(pid, slot_page, remote_page_size,
                            PROT_READ | PROT_WRITE) >= 0)
        {
            for (int i = 0; i < GTA_HTTP_BOUNDARY_COUNT; i++)
                kernel_proc_copyin(pid, &original_targets[i], slots[i],
                                   sizeof(original_targets[i]));
            kernel_mprotect(pid, slot_page, remote_page_size, PROT_READ);
        }
        pt_munmap(pid, trace_mapping, remote_page_size * 2);
        plugin_log("[GTA-HTTP-TRACE] Import wrapping failed; originals restored");
        return false;
    }

    bool verified = true;
    for (int i = 0; i < GTA_HTTP_BOUNDARY_COUNT; i++) {
        intptr_t observed = 0;
        const intptr_t expected =
            code_address + (intptr_t)i * (intptr_t)stub_stride;
        verified = verified &&
            kernel_proc_copyout(pid, slots[i], &observed,
                                sizeof(observed)) == 0 &&
            observed == expected;
    }
    if (!verified) {
        plugin_log("[GTA-HTTP-TRACE] Import verification failed");
        return false;
    }

    if (trace_record_out) *trace_record_out = record_address;
    plugin_log("[GTA-HTTP-TRACE] Rockstar HTTP result trace installed (3/3)");
    return true;
}

// The original PS5 LSO GitHub loader does not change the title's credentials.
// It redirects the game's scePadReadState import to a small one-shot stub so
// sceKernelLoadStartModule runs naturally on a game thread. This FW 8.60
// variant keeps that useful property while removing its controller-layout and
// return-value checks, which are not stable across firmware revisions.
struct GameThreadLoadContext {
    uintptr_t scePadReadState;          // +0x00
    uintptr_t reserved_debugout;        // +0x08
    uintptr_t sceKernelLoadStartModule; // +0x10
    uintptr_t reserved_dlsym;           // +0x18
    uint64_t image_base;                // +0x20
    char prx_path[256];                 // +0x28
    int32_t load_result;                // +0x128 (0 pending, >0 handle, <0 error)
    uint32_t reserved;                  // +0x12c
};

static_assert(offsetof(GameThreadLoadContext, prx_path) == 0x28,
              "game-thread loader path offset changed");
static_assert(offsetof(GameThreadLoadContext, load_result) == 0x128,
              "game-thread loader result offset changed");
static_assert(sizeof(GameThreadLoadContext) == 0x130,
              "game-thread loader context size changed");

struct GameThreadLoadInstall {
    uintptr_t context_address;
    uintptr_t hook_address;
    uintptr_t stub_address;
    uintptr_t original_target;
};

static bool install_game_thread_loader(pid_t pid, const char *prx_path,
                                       GameThreadLoadInstall *result)
{
    if (result) *result = {};

    UniquePtr<Hijacker> hijacker = Hijacker::getHijacker(pid);
    if (!hijacker) {
        plugin_log("[GAME-THREAD] Could not create Hijacker for pid %d", pid);
        return false;
    }

    GameThreadLoadContext context = {};
    UniquePtr<SharedLib> pad_library = hijacker->getLib("libScePad.sprx");
    if (!pad_library) {
        plugin_log("[GAME-THREAD] libScePad.sprx was not found");
        return false;
    }

    context.scePadReadState =
        hijacker->getFunctionAddress(pad_library.get(), nid::scePadReadState);
    context.sceKernelLoadStartModule =
        hijacker->getLibKernelAddress(nid::sceKernelLoadStartModule);
    context.image_base = hijacker->getEboot()->imagebase();
    strncpy(context.prx_path, prx_path, sizeof(context.prx_path) - 1);
    context.prx_path[sizeof(context.prx_path) - 1] = '\0';

    if (!context.scePadReadState || !context.sceKernelLoadStartModule) {
        plugin_log("[GAME-THREAD] Required functions unavailable: "
                   "scePadReadState=0x%llx LoadStartModule=0x%llx",
                   (unsigned long long)context.scePadReadState,
                   (unsigned long long)context.sceKernelLoadStartModule);
        return false;
    }

    auto metadata = hijacker->getEboot()->getMetaData();
    if (!metadata) {
        plugin_log("[GAME-THREAD] Eboot metadata unavailable");
        return false;
    }

    const auto &plt_table = metadata->getPltTable();
    const auto symbol_index =
        metadata->getSymbolTable().getSymbolIndex(nid::scePadReadState);

    uintptr_t hook_address = 0;
    for (const auto &plt : plt_table) {
        if (ELF64_R_SYM(plt.r_info) == symbol_index) {
            hook_address = context.image_base + plt.r_offset;
            break;
        }
    }
    if (!hook_address) {
        plugin_log("[GAME-THREAD] scePadReadState PLT entry was not found");
        return false;
    }

    // rdx=context; call original scePadReadState; once only, call
    // sceKernelLoadStartModule(path,0,0,0,0,0); retain its exact result; return
    // the original scePadReadState value. No pad-data fields are inspected.
    static const uint8_t template_stub[] = {
        0x48, 0xBA, 0,0,0,0,0,0,0,0,             // mov rdx,context
        0x55, 0x41, 0x57, 0x41, 0x56, 0x53,       // save nonvolatile regs
        0x48, 0x83, 0xEC, 0x18,                   // align stack
        0x48, 0x89, 0xD3,                         // mov rbx,rdx
        0x49, 0x89, 0xF6,                         // mov r14,rsi
        0x41, 0x89, 0xFF,                         // mov r15d,edi
        0xFF, 0x12,                               // call [rdx]
        0x89, 0xC5,                               // mov ebp,eax
        0x83, 0xBB, 0x28,0x01,0,0, 0,            // cmp [rbx+0x128],0
        0x75, 0x19,                               // jne epilogue
        0x48, 0x8D, 0x7B, 0x28,                   // lea rdi,[rbx+0x28]
        0x31, 0xF6, 0x31, 0xD2, 0x31, 0xC9,       // args 2-4 = 0
        0x45, 0x31, 0xC0, 0x45, 0x31, 0xC9,       // args 5-6 = 0
        0xFF, 0x53, 0x10,                         // call [rbx+0x10]
        0x89, 0x83, 0x28,0x01,0,0,                // store exact result
        0x89, 0xE8,                               // epilogue: mov eax,ebp
        0x48, 0x83, 0xC4, 0x18,
        0x5B, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3
    };

    uint8_t stub[sizeof(template_stub)] = {};
    memcpy(stub, template_stub, sizeof(stub));

    const uintptr_t stub_address =
        hijacker->getTextAllocator().allocate(sizeof(stub));
    const uintptr_t context_address =
        hijacker->getDataAllocator().allocate(sizeof(context));
    if (!stub_address || !context_address) {
        plugin_log("[GAME-THREAD] Remote allocator failed: stub=0x%llx "
                   "context=0x%llx",
                   (unsigned long long)stub_address,
                   (unsigned long long)context_address);
        return false;
    }
    memcpy(stub + 2, &context_address, sizeof(context_address));

    uintptr_t original_target = 0;
    if (kernel_proc_copyout(pid, hook_address, &original_target,
                            sizeof(original_target)) < 0)
    {
        plugin_log("[GAME-THREAD] Could not read the original PLT target");
        return false;
    }
    if (original_target != context.scePadReadState) {
        plugin_log("[GAME-THREAD] Refusing unresolved/changed pad import: "
                   "PLT=0x%llx target=0x%llx expected=0x%llx",
                   (unsigned long long)hook_address,
                   (unsigned long long)original_target,
                   (unsigned long long)context.scePadReadState);
        return false;
    }

    // FW 8.60 can reject mdbg WRITE_CMD writes to the eboot PLT/GOT page.
    // Use the kernel process-copy primitive for the stub, context, and hook so
    // all three writes follow the same firmware-independent path. Unlike the
    // old Hijacker::write calls, every result is checked before resuming GTA.
    const int stub_write_rc = kernel_proc_copyin(
        pid, stub, stub_address, sizeof(stub));
    const int context_write_rc = kernel_proc_copyin(
        pid, &context, context_address, sizeof(context));
    const int hook_write_rc = kernel_proc_copyin(
        pid, &stub_address, hook_address, sizeof(stub_address));

    uintptr_t installed_target = 0;
    const int verify_read_rc = kernel_proc_copyout(
        pid, hook_address, &installed_target, sizeof(installed_target));
    if (stub_write_rc < 0 || context_write_rc < 0 || hook_write_rc < 0 ||
        verify_read_rc < 0 ||
        installed_target != stub_address)
    {
        const int restore_rc = kernel_proc_copyin(
            pid, &original_target, hook_address, sizeof(original_target));
        plugin_log("[GAME-THREAD] Kernel write/verify failed: "
                   "stub_rc=%d context_rc=%d hook_rc=%d read_rc=%d "
                   "PLT=0x%llx expected=0x%llx observed=0x%llx "
                   "restore_rc=%d",
                   stub_write_rc, context_write_rc, hook_write_rc,
                   verify_read_rc,
                   (unsigned long long)hook_address,
                   (unsigned long long)stub_address,
                   (unsigned long long)installed_target,
                   restore_rc);
        return false;
    }

    if (result) {
        result->context_address = context_address;
        result->hook_address = hook_address;
        result->stub_address = stub_address;
        result->original_target = original_target;
    }
    plugin_log("[GAME-THREAD] Kernel-written one-shot loader verified: PLT=0x%llx "
               "stub=0x%llx context=0x%llx (identity unchanged)",
               (unsigned long long)hook_address,
               (unsigned long long)stub_address,
               (unsigned long long)context_address);
    return true;
}

// Wait until GTA's dynamic loader has resolved the scePadReadState import to
// the final libScePad address. Installing a hook while the slot still contains
// a lazy-binding target lets the dynamic loader overwrite it before the first
// controller read. The timeout is a ceiling, not a forced injection delay.
static bool wait_for_resolved_pad_import(pid_t pid, int timeout_ms)
{
    constexpr int poll_interval_ms = 100;
    constexpr int required_stable_samples = 2;
    uintptr_t last_target = 0;
    uintptr_t last_hook = 0;
    uintptr_t last_resolved = 0;
    int stable_samples = 0;

    for (int elapsed_ms = 0; elapsed_ms <= timeout_ms;
         elapsed_ms += poll_interval_ms)
    {
        if (!IsProcessRunning(pid)) break;

        UniquePtr<Hijacker> hijacker = Hijacker::getHijacker(pid);
        if (hijacker) {
            UniquePtr<SharedLib> pad_library =
                hijacker->getLib("libScePad.sprx");
            auto metadata = hijacker->getEboot()->getMetaData();
            if (pad_library && metadata) {
                const uintptr_t resolved = hijacker->getFunctionAddress(
                    pad_library.get(), nid::scePadReadState);
                const auto symbol_index = metadata->getSymbolTable()
                    .getSymbolIndex(nid::scePadReadState);

                uintptr_t hook_address = 0;
                for (const auto &plt : metadata->getPltTable()) {
                    if (ELF64_R_SYM(plt.r_info) == symbol_index) {
                        hook_address = hijacker->getEboot()->imagebase() +
                            plt.r_offset;
                        break;
                    }
                }

                uintptr_t target = 0;
                if (resolved && hook_address &&
                    kernel_proc_copyout(pid, hook_address, &target,
                                        sizeof(target)) == 0)
                {
                    last_hook = hook_address;
                    last_resolved = resolved;
                    if (target == resolved && target == last_target) {
                        stable_samples++;
                    } else if (target == resolved) {
                        stable_samples = 1;
                    } else {
                        stable_samples = 0;
                    }
                    last_target = target;

                    if (stable_samples >= required_stable_samples) {
                        plugin_log("[PAD-READY] Resolved import stable after "
                                   "%dms: PLT=0x%llx target=0x%llx",
                                   elapsed_ms,
                                   (unsigned long long)hook_address,
                                   (unsigned long long)target);
                        return true;
                    }
                }
            }
        }

        usleep(poll_interval_ms * 1000);
    }

    plugin_log("[PAD-READY] Timed out: PLT=0x%llx observed=0x%llx "
               "resolved=0x%llx",
               (unsigned long long)last_hook,
               (unsigned long long)last_target,
               (unsigned long long)last_resolved);
    return false;
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
    plugin_log("Injecting into %s (pid %d) - %zu PRX", title_id, pid, prx_list.size());
    plugin_log("========================================");

    // ── ① FAKELIB (jeux PS5 natifs PPSA uniquement) ───────────────────────
    char  sandbox_id[32] = {};
    char *fakelib_mount  = nullptr;
    SavedGameCredentials original_credentials = {};
    LsoDiagnostics lso_diag = {};
    intptr_t lso_module_base = 0;
    intptr_t lso_call_trace_address = 0;
    intptr_t lso_net_boundary_address = 0;
    intptr_t gta_http_boundary_address = 0;
    intptr_t push_event_trace_address = 0;
    intptr_t ps5api_hit_counter_address = 0;
    intptr_t cpp_boundary_trace_address = 0;
    bool early_ps5api_installed = false;
    bool early_create_detour_installed = false;
    lso_diag.enabled = has_lso_candidate(title_id, prx_list);

    auto restore_cfg = config.restore_credentials.find(std::string(title_id));
    bool restore_wanted = (restore_cfg != config.restore_credentials.end() &&
                           restore_cfg->second);

    auto game_thread_cfg =
        config.game_thread_loader.find(std::string(title_id));
    bool game_thread_loader_wanted =
        game_thread_cfg != config.game_thread_loader.end() &&
        game_thread_cfg->second;

    auto native_np_cfg = config.native_np_callbacks.find(std::string(title_id));
    bool native_np_callbacks_wanted =
        native_np_cfg != config.native_np_callbacks.end() &&
        native_np_cfg->second;

    auto cpp_webapi_repair_cfg =
        config.repair_cpp_webapi_hooks.find(std::string(title_id));
    bool repair_cpp_webapi_hooks_wanted =
        cpp_webapi_repair_cfg != config.repair_cpp_webapi_hooks.end() &&
        cpp_webapi_repair_cfg->second;

    auto synthetic_np_cfg =
        config.synthetic_np_signed_in.find(std::string(title_id));
    bool synthetic_np_signed_in_wanted =
        synthetic_np_cfg != config.synthetic_np_signed_in.end() &&
        synthetic_np_cfg->second;

    if (synthetic_np_signed_in_wanted) {
        plugin_log("[GTA-NP-SYNTH] Requested synthetic state is disabled in "
                   "this isolation build; relying on LSO/native NP state");
        synthetic_np_signed_in_wanted = false;
    }

    auto preserve_requests_cfg =
        config.preserve_lso_requests.find(std::string(title_id));
    bool preserve_lso_requests_wanted =
        preserve_requests_cfg != config.preserve_lso_requests.end() &&
        preserve_requests_cfg->second;

    auto ps5_api_compat_cfg =
        config.emulate_lso_missing_ps5_routes.find(std::string(title_id));
    bool ps5_api_compat_wanted =
        ps5_api_compat_cfg != config.emulate_lso_missing_ps5_routes.end() &&
        ps5_api_compat_cfg->second;

    auto ps5_api_route_mask_cfg =
        config.emulate_lso_route_mask.find(std::string(title_id));
    uint32_t ps5_api_route_mask =
        ps5_api_route_mask_cfg != config.emulate_lso_route_mask.end()
            ? (ps5_api_route_mask_cfg->second & 0x0f)
            : 0x0f;

    auto push_event_cfg =
        config.emulate_np_push_events.find(std::string(title_id));
    const bool push_event_compat_requested =
        push_event_cfg != config.emulate_np_push_events.end() &&
        push_event_cfg->second;
    if (push_event_compat_requested) {
        plugin_log("[GTA-PUSH] PushEvent modification is disabled in this "
                   "BlueSphere-only build");
    }

    auto webapi_trace_cfg =
        config.trace_lso_webapi_calls.find(std::string(title_id));
    bool webapi_trace_wanted =
        webapi_trace_cfg != config.trace_lso_webapi_calls.end() &&
        webapi_trace_cfg->second;

    auto np_trace_cfg =
        config.trace_lso_np_calls.find(std::string(title_id));
    bool np_trace_wanted =
        np_trace_cfg != config.trace_lso_np_calls.end() &&
        np_trace_cfg->second;

    if (np_trace_wanted || webapi_trace_wanted) {
        plugin_log("[LSO-MON] Requested call tracing is disabled in this "
                   "recovery build because it causes an 8.60 process exit");
        np_trace_wanted = false;
        webapi_trace_wanted = false;
    }

    auto watch_cfg = config.restore_watch_offset.find(std::string(title_id));
    uint64_t restore_watch_offset =
        (watch_cfg != config.restore_watch_offset.end()) ? watch_cfg->second : 0;

    auto timeout_cfg = config.restore_timeout_ms.find(std::string(title_id));
    int restore_timeout_ms =
        (timeout_cfg != config.restore_timeout_ms.end()) ? timeout_cfg->second : 15000;

    auto fakelib_cfg    = config.fakelib_enabled.find(std::string(title_id));
    bool fakelib_wanted = (strncmp(title_id, "PPSA", 4) == 0) &&
                          (fakelib_cfg == config.fakelib_enabled.end() ||
                           fakelib_cfg->second);

    bool sandbox_resolved = false;
    if (fakelib_wanted)
        sandbox_resolved =
            resolve_sandbox_id(title_id, sandbox_id, sizeof(sandbox_id));

    if (fakelib_wanted && sandbox_resolved)
    {
        char fakelib_check[PATH_MAX];
        snprintf(fakelib_check, sizeof(fakelib_check),
                 "/mnt/sandbox/%s/app0/fakelib", sandbox_id);

        struct stat st;
        for (int t = 0; t < 30 && stat(fakelib_check, &st) != 0; t++)
            usleep(50000);

        if (stat(fakelib_check, &st) == 0) {
            plugin_log("[Fakelib] Found app0/fakelib; mounting...");
            fakelib_mount = try_mount_fakelib(title_id, sandbox_id);
            if (!fakelib_mount)
                plugin_log("[Fakelib] Mount failed");
        } else {
            plugin_log("[Fakelib] No app0/fakelib for %s", title_id);
        }
    }

    // For the game-thread loader, delay=X is a maximum readiness timeout. The
    // hook is installed as soon as the final pad import is resolved and stable.
    // Other injection modes retain the traditional fixed delay.
    bool game_thread_import_ready = true;
    {
        auto it_delay = config.inject_delay_ms.find(std::string(title_id));
        int delay_ms  = (it_delay != config.inject_delay_ms.end())
                        ? it_delay->second
                        : 15000;

        if (game_thread_loader_wanted) {
            plugin_log("[PAD-READY] Waiting up to %dms for GTA's resolved "
                       "scePadReadState import", delay_ms);
            game_thread_import_ready =
                wait_for_resolved_pad_import(pid, delay_ms);
        } else {
            plugin_log("[PT] Waiting %dms before injection "
                       "(set with delay= in the INI)", delay_ms);

            int steps = delay_ms / 100;
            int alive = 0;
            for (int i = 0; i < steps; i++) {
                usleep(100000);
                if (IsProcessRunning(pid)) alive++;
            }
            plugin_log("[PT] Process alive: %d/%d checks", alive, steps);
        }
    }

    // ── ③ jb_pid loader (accès /data depuis le loader lui-même) ──────────
    {
        pid_t mypid = getpid();
        if (jb_pid(mypid) == 0)
            plugin_log("[PT] jb_pid(loader=%d) OK", mypid);
        else
            plugin_log("[PT] jb_pid(loader) already applied or skipped");
    }

    // Reference-loader mode: schedule LoadStartModule on GTA's ordinary pad
    // thread and never change the game process identity. FW 8.60 does not
    // reliably expose /data to this process, so only its filesystem roots are
    // temporarily changed while synchronous module_start is running.
    if (game_thread_loader_wanted) {
        plugin_log("[GAME-THREAD] Identity-preserving loader mode selected; "
                   "jb_pid(game) and credential restoration are disabled");

        if (!game_thread_import_ready) {
            plugin_log("[GAME-THREAD] PRX not scheduled because the pad import "
                       "never reached a stable resolved state");
            printf_notification("BlueSphere loader readiness timed out for %s     ",
                                title_id);
            goto wait_and_cleanup;
        }

        if (prx_list.size() != 1) {
            plugin_log("[GAME-THREAD] This isolated test requires exactly one PRX");
            printf_notification("Game-thread loader requires exactly one PRX for %s     ",
                                title_id);
            goto wait_and_cleanup;
        }

        const auto &prx = prx_list[0];
        const char *basename = strrchr(prx.path.c_str(), '/');
        basename = basename ? basename + 1 : prx.path.c_str();
        const bool initializer_gated =
            strstr(basename, "FW8.60-gated") != nullptr;

        prepare_lso_diagnostics(pid, &lso_diag);
        if (lso_diag.enabled) {
            log_gtav_np_state(pid, "Before game-thread load");
            audit_persistent_np_account(pid);
        }

        printf_notification("Scheduling %s on the original game thread...     ",
                            basename);

        int prepare_rc = sceKernelPrepareToSuspendProcess(pid);
        int suspend_rc = sceKernelSuspendProcess(pid);
        plugin_log("[GAME-THREAD] Suspend: prepare=%d suspend=%d",
                   prepare_rc, suspend_rc);

        SavedFilesystemRoots filesystem_roots = {};
        bool filesystem_window_open = suspend_rc >= 0 &&
            open_game_filesystem_window(pid, &filesystem_roots) == 0;

        GameThreadLoadInstall load_install = {};
        bool loader_installed = filesystem_window_open &&
            install_game_thread_loader(pid, prx.path.c_str(), &load_install);

        if (!loader_installed && filesystem_window_open) {
            close_game_filesystem_window(pid, &filesystem_roots);
            filesystem_window_open = false;
        }

        int resume_prepare_rc = sceKernelPrepareToResumeProcess(pid);
        int resume_rc = sceKernelResumeProcess(pid);
        plugin_log("[GAME-THREAD] Resume: prepare=%d resume=%d",
                   resume_prepare_rc, resume_rc);

        if (!loader_installed) {
            plugin_log("[GAME-THREAD] One-shot loader installation failed");
            printf_notification("Game-thread loader failed for %s     ", title_id);
            goto wait_and_cleanup;
        }

        int32_t load_result = 0;
        uint32_t module_handle = 0;
        int load_elapsed_ms = 0;
        bool module_seen_while_starting = false;
        constexpr int load_poll_interval_ms = 10;
        for (; load_elapsed_ms < restore_timeout_ms;
             load_elapsed_ms += load_poll_interval_ms)
        {
            if (!IsProcessRunning(pid)) break;
            load_result = (int32_t)kernel_proc_getint(
                pid, (intptr_t)load_install.context_address + 0x128);
            if (load_result != 0) break;

            // A module enters the dynlib list before its synchronous
            // module_start has returned. Treating that handle as completion
            // closed the FW 8.60 filesystem window too early in v18, leaving
            // LSO mapped but with none of its NET/NP hooks installed.
            uint32_t observed_handle = 0;
            if (!module_seen_while_starting &&
                kernel_dynlib_handle(pid, basename, &observed_handle) == 0 &&
                observed_handle != 0)
            {
                module_seen_while_starting = true;
                module_handle = observed_handle;
                plugin_log("[GAME-THREAD] PRX mapped as handle=%u; "
                           "module_start still running, keeping filesystem "
                           "window open",
                           observed_handle);

                if (initializer_gated) {
                    const intptr_t early_module_base =
                        kernel_dynlib_mapbase_addr(pid, observed_handle);
                    plugin_log("[LSO-EARLY] Gated module observed at 0x%llx; "
                               "installing compatibility before initializer",
                               (unsigned long long)early_module_base);

                    bool attached = false;
                    bool gate_released = false;
                    if (early_module_base && pt_attach(pid) == 0) {
                        attached = true;
                        plugin_log("[LSO-EARLY] Attached while initializer is "
                                   "parked");
                        if (ps5_api_compat_wanted) {
                            early_ps5api_installed =
                                install_lso_ps5_webapi_compat(
                                    pid, early_module_base,
                                    ps5_api_route_mask,
                                    &ps5api_hit_counter_address);
                            if (early_ps5api_installed) {
                                early_create_detour_installed =
                                    install_lso_internal_create_eager_send(
                                        pid, early_module_base,
                                        &cpp_boundary_trace_address);
                            }
                        }
                        gate_released =
                            release_lso_initializer_gate(pid,
                                                        early_module_base);
                        pt_detach(pid);
                    } else if (early_module_base) {
                        plugin_log("[LSO-EARLY] Could not ptrace-attach; "
                                   "attempting emergency gate release");
                        gate_released =
                            release_lso_initializer_gate(pid,
                                                        early_module_base);
                    }

                    plugin_log("[LSO-EARLY] Pre-start result: attached=%s "
                               "response=%s create_detour=%s gate_released=%s",
                               attached ? "yes" : "no",
                               early_ps5api_installed ? "yes" : "no",
                               early_create_detour_installed ? "yes" : "no",
                               gate_released ? "yes" : "no");
                }
            }
            usleep(load_poll_interval_ms * 1000);
        }

        if (load_result == 0) {
            plugin_log("[GAME-THREAD] Timed out waiting for the exact "
                       "LoadStartModule return after %dms (mapped=%s "
                       "handle=%u)",
                       load_elapsed_ms,
                       module_seen_while_starting ? "yes" : "no",
                       module_handle);
        }

        // The one-shot has finished (success or error), so remove the pad hook
        // and leave the game's original import table in place.
        bool hook_restored =
            kernel_proc_copyin(pid, &load_install.original_target,
                               load_install.hook_address,
                               sizeof(load_install.original_target)) == 0;
        bool filesystem_window_closed = filesystem_window_open &&
            close_game_filesystem_window(pid, &filesystem_roots) == 0;
        plugin_log("[GAME-THREAD] Load result=%d (0x%08x) after %dms; "
                   "pad hook restored=%s filesystem restored=%s",
                   load_result, (unsigned int)load_result, load_elapsed_ms,
                   hook_restored ? "yes" : "no",
                   filesystem_window_closed ? "yes" : "no");

        if (load_result <= 0) {
            plugin_log("[GAME-THREAD] PRX did not load from GTA's game thread");
            printf_notification("Game-thread PRX load failed for %s (rc=%d)     ",
                                title_id, load_result);
            goto wait_and_cleanup;
        }

        if (!hook_restored || !filesystem_window_closed) {
            plugin_log("[GAME-THREAD] Post-load restoration failed; "
                       "compatibility setup is cancelled");
            printf_notification("Game-thread restoration failed for %s     ",
                                title_id);
            goto wait_and_cleanup;
        }

        module_handle = (uint32_t)load_result;
        lso_module_base =
            kernel_dynlib_mapbase_addr(pid, module_handle);
        if (!lso_module_base &&
            kernel_dynlib_handle(pid, basename, &module_handle) == 0)
        {
            lso_module_base =
                kernel_dynlib_mapbase_addr(pid, module_handle);
        }
        plugin_log("[GAME-THREAD] PRX loaded: handle=%u module=0x%llx",
                   module_handle, (unsigned long long)lso_module_base);

        uint32_t hook_state = 0xffffffffu;
        int hook_elapsed_ms = 0;
        if (lso_module_base && restore_watch_offset != 0) {
            const intptr_t hook_state_address =
                lso_module_base + (intptr_t)restore_watch_offset;
            for (; hook_elapsed_ms < restore_timeout_ms;
                 hook_elapsed_ms += 100)
            {
                if (!IsProcessRunning(pid)) break;
                hook_state = kernel_proc_getint(pid, hook_state_address);
                if (hook_state == 2) break;
                usleep(100000);
            }
        }
        plugin_log("[GAME-THREAD] LSO hook state=%u after %dms",
                   hook_state, hook_elapsed_ms);

        if (IsProcessRunning(pid) && lso_module_base &&
            pt_attach(pid) == 0)
        {
            plugin_log("[GAME-THREAD] Attached for post-load compatibility "
                       "setup; game identity remains unchanged");
            verify_lso_diagnostics(pid, lso_module_base, &lso_diag,
                                   "After original-identity load");
            verify_lso_webapi_diagnostics(
                pid, lso_module_base, "After original-identity load");

            // v43 proved that LSO intentionally replaces GTA's complete
            // certificate block with its verified live server certificate.
            // No certificate bytes are modified in this build.
            plugin_log("[LSO-TLS] LSO certificate replacement left "
                       "unchanged (verified intentional behavior)");

            plugin_log("[GTA-PUSH-TRACE] Not installed; v46 keeps native "
                       "PushEvent imports untouched");

            plugin_log("[LSO-PS5API] Communication restriction response "
                       "schema: {restricted:false}");

            if (hook_state == 2 &&
                strstr(prx.path.c_str(), "FW8.60-eager") != nullptr) {
                ensure_lso_eager_prx_patch(pid, lso_module_base);
            }

            if (repair_cpp_webapi_hooks_wanted) {
                if (hook_state == 2) {
                    repair_lso_cpp_webapi_hooks(pid, lso_module_base);
                    install_lso_cpp_boundary_trace(
                        pid, lso_module_base, &cpp_boundary_trace_address);
                } else {
                    plugin_log("[LSO-CPP] Not applied because LSO hook state "
                               "did not reach 2");
                }
            }

            if (ps5_api_compat_wanted) {
                if (hook_state == 2) {
                    plugin_log("[LSO-KERNEL-RESPONSE] Armed direct request-table "
                               "completion: route mask=0x%x",
                               ps5_api_route_mask);
                } else {
                    plugin_log("[LSO-PS5API] Not installed because LSO hook "
                               "state did not reach 2");
                }
            }

            if (native_np_callbacks_wanted) {
                if (hook_state == 2) {
                    restore_native_np_callback_thunks(pid, &lso_diag);
                } else {
                    plugin_log("[LSO-NP-NATIVE] Not applied because LSO hook "
                               "state did not reach 2");
                }
            }
            pt_detach(pid);
            plugin_log("[GAME-THREAD] Post-load setup complete; game resumed");
        } else {
            plugin_log("[GAME-THREAD] Could not attach for post-load setup");
        }

        printf_notification("1/1 PRX loaded into %s with original identity     ",
                            title_id);
        goto wait_and_cleanup;
    }

    // ── ④ PT_ATTACH sur le process jeu ────────────────────────────────────
    if (pt_attach(pid) < 0) {
        plugin_log("[PT] pt_attach(%d) FAILED: %s", pid, strerror(errno));
        printf_notification("PT attach failed for %s     ", title_id);
        goto wait_and_cleanup;
    }
    plugin_log("[PT] pt_attach OK");

    if (restore_wanted && save_game_credentials(pid, &original_credentials) != 0) {
        plugin_log("[JB] FAILED to save original game identity - injection cancelled");
        pt_detach(pid);
        printf_notification("Failed to save game identity for %s     ", title_id);
        goto wait_and_cleanup;
    }

    // ── ⑤ jb_pid game (le jeu peut maintenant voir /data pour LoadStartModule) ──
    if (jb_pid(pid) != 0) {
        plugin_log("[PT] jb_pid(game=%d) FAILED", pid);
        pt_detach(pid);
        printf_notification("jb_pid failed for %s     ", title_id);
        goto wait_and_cleanup;
    }
    plugin_log("[PT] jb_pid(game=%d) OK", pid);

    // Le jeu est arrêté et toujours attaché: mémoriser les cibles LSO avant
    // que module_start ne remplace leurs thunks.
    prepare_lso_diagnostics(pid, &lso_diag);
    if (lso_diag.enabled) {
        log_gtav_np_state(pid, "Before LSO");
        audit_persistent_np_account(pid);
    }

    // ── ⑥ Injection multi-PRX (synchrone) ─────────────────────────────────
    {
        int success_count = 0;
        intptr_t restore_watch_addr = 0;
        printf_notification("Injecting %s...     \n%zu PRX in progress",
                            title_id, prx_list.size());

        for (size_t i = 0; i < prx_list.size(); i++) {
            const auto &prx = prx_list[i];
            const char *basename = strrchr(prx.path.c_str(), '/');
            basename = basename ? basename + 1 : prx.path.c_str();

            plugin_log("[PT] [%zu/%zu] -> %s", i + 1, prx_list.size(),
                       prx.path.c_str());

            int rc = inject_prx(pid, prx.path.c_str());

            if (rc > 0) {
                plugin_log("[PT] OK: %s (handle %d)", basename, rc);
                success_count++;

                if (restore_wanted && restore_watch_offset != 0 &&
                    restore_watch_addr == 0)
                {
                    intptr_t module_base =
                        kernel_dynlib_mapbase_addr(pid, (uint32_t)rc);
                    if (module_base) {
                        restore_watch_addr =
                            module_base + (intptr_t)restore_watch_offset;
                        plugin_log("[JB] Restore watch: module=0x%llx "
                                   "state_addr=0x%llx target=2 timeout=%dms",
                                   (unsigned long long)module_base,
                                   (unsigned long long)restore_watch_addr,
                                   restore_timeout_ms);
                    } else {
                        plugin_log("[JB] Module base not found for handle %d - "
                                   "restoring immediately", rc);
                    }
                }

                size_t basename_length = strlen(basename);
                bool is_lso_name = basename_length >= 3 &&
                    (basename[0] == 'L' || basename[0] == 'l') &&
                    (basename[1] == 'S' || basename[1] == 's') &&
                    (basename[2] == 'O' || basename[2] == 'o');
                if (lso_diag.enabled && is_lso_name) {
                    intptr_t module_base =
                        kernel_dynlib_mapbase_addr(pid, (uint32_t)rc);
                    lso_module_base = module_base;
                    verify_lso_diagnostics(pid, module_base, &lso_diag,
                                           "After LSO load");
                }
            } else {
                plugin_log("[PT] FAIL: %s (rc=%d)", basename, rc);
            }
        }

        bool deferred_restore = restore_wanted && restore_watch_addr != 0;

        if (restore_wanted && !deferred_restore) {
            if (restore_game_credentials(pid, &original_credentials) != 0) {
                plugin_log("[JB] FAILED to restore original game identity");
                printf_notification("Failed to restore game identity for %s     ", title_id);
            } else {
                plugin_log("[JB] Temporary privilege mode ended before game resume");
                verify_lso_diagnostics(pid, lso_module_base, &lso_diag,
                                       "After credential restore");
            }
        }

        if (!deferred_restore && lso_module_base)
            verify_lso_webapi_diagnostics(pid, lso_module_base,
                                          "Before first resume");

        if (!deferred_restore && ps5_api_compat_wanted && lso_module_base)
            install_lso_ps5_webapi_compat(pid, lso_module_base,
                                          ps5_api_route_mask,
                                          &ps5api_hit_counter_address);

        if (!deferred_restore &&
            (np_trace_wanted || webapi_trace_wanted) && lso_module_base)
            install_lso_call_monitor(pid, lso_module_base, &lso_diag,
                                     &lso_call_trace_address,
                                     np_trace_wanted, webapi_trace_wanted);

        // ── ⑦ Détacher → le jeu reprend son exécution normale ─────────────
        pt_detach(pid);
        plugin_log("[PT] pt_detach - game resumed (%d/%zu PRX loaded)",
                   success_count, prx_list.size());

        if (deferred_restore) {
            plugin_log("[JB] Game resumed with temporary privileges; "
                       "waiting for hook state=2 (maximum %dms)", restore_timeout_ms);

            uint32_t hook_state = 0xffffffffu;
            int elapsed_ms = 0;
            for (; elapsed_ms < restore_timeout_ms; elapsed_ms += 250) {
                if (!IsProcessRunning(pid)) break;
                hook_state = kernel_proc_getint(pid, restore_watch_addr);
                if (hook_state == 2) break;
                usleep(250000);
            }

            plugin_log("[JB] Hook watch finished: state=%u after %dms",
                       hook_state, elapsed_ms);

            if (IsProcessRunning(pid) && pt_attach(pid) == 0) {
                plugin_log("[JB] Reattached for final credential restore");
                if (restore_game_credentials(pid, &original_credentials) != 0) {
                    plugin_log("[JB] FAILED delayed game-identity restore");
                    printf_notification("Delayed credential restore failed for %s     ",
                                        title_id);
                } else {
                    plugin_log("[JB] Delayed credential restore completed (hook state=%u)",
                               hook_state);
                    verify_lso_diagnostics(pid, lso_module_base, &lso_diag,
                                           "After credential restore");
                }

                if (lso_module_base)
                    verify_lso_webapi_diagnostics(pid, lso_module_base,
                                                  "After hook-state wait");
                if (repair_cpp_webapi_hooks_wanted) {
                    if (hook_state == 2) {
                        repair_lso_cpp_webapi_hooks(pid, lso_module_base);
                    } else {
                        plugin_log("[LSO-CPP] Not applied because LSO hook "
                                   "state did not reach 2");
                    }
                }
                if (ps5_api_compat_wanted) {
                    if (hook_state == 2) {
                        install_lso_ps5_webapi_compat(pid, lso_module_base,
                                                      ps5_api_route_mask,
                                                      &ps5api_hit_counter_address);
                    } else {
                        plugin_log("[LSO-PS5API] Not installed because LSO "
                                   "hook state did not reach 2");
                    }
                }
                if (np_trace_wanted || webapi_trace_wanted) {
                    if (hook_state == 2) {
                        install_lso_call_monitor(
                            pid, lso_module_base, &lso_diag,
                            &lso_call_trace_address,
                            np_trace_wanted, webapi_trace_wanted);
                    } else {
                        plugin_log("[LSO-MON] Call trace not installed because "
                                   "LSO hook state did not reach 2");
                    }
                }
                if (preserve_lso_requests_wanted) {
                    if (hook_state == 2) {
                        preserve_lso_request_records(pid, lso_module_base);
                    } else {
                        plugin_log("[LSO-REQ-KEEP] Not applied because LSO hook "
                                   "state did not reach 2");
                    }
                }
                if (native_np_callbacks_wanted) {
                    if (synthetic_np_signed_in_wanted) {
                        plugin_log("[LSO-NP-NATIVE] Skipped because synthetic "
                                   "NP signed-in mode is enabled");
                    } else if (hook_state == 2) {
                        restore_native_np_callback_thunks(pid, &lso_diag);
                    } else {
                        plugin_log("[LSO-NP-NATIVE] Not applied because LSO hook "
                                   "state did not reach 2");
                    }
                }
                if (synthetic_np_signed_in_wanted) {
                    if (hook_state == 2) {
                        queue_gtav_synthetic_signed_in(pid);
                    } else {
                        plugin_log("[GTA-NP-SYNTH] Not applied because LSO hook "
                                   "state did not reach 2");
                    }
                }
                pt_detach(pid);
                plugin_log("[PT] Final pt_detach - game resumed with original identity");
            } else {
                plugin_log("[JB] FAILED to reattach for delayed credential restore");
                printf_notification("Credential-restore reattach failed for %s     ",
                                    title_id);
            }
        }

        if (fakelib_wanted) {
            printf_notification("%d/%zu PRX -> %s     \nFakelib: %s",
                                success_count, prx_list.size(), title_id,
                                fakelib_mount ? "OK" : "absent");
        } else {
            printf_notification("%d/%zu PRX -> %s     ",
                                success_count, prx_list.size(), title_id);
        }
    }

wait_and_cleanup:
    // ── ⑧ Attendre fermeture du jeu, puis cleanup fakelib ─────────────────
    plugin_log("[Wait] Waiting for game to exit (pid %d)...", pid);
    wait_for_pid_exit(pid, lso_call_trace_address, lso_module_base,
                      lso_net_boundary_address,
                      gta_http_boundary_address,
                      push_event_trace_address,
                      ps5api_hit_counter_address,
                      cpp_boundary_trace_address,
                      ps5_api_compat_wanted ? ps5_api_route_mask : 0);

    if (fakelib_mount)
        cleanup_after_game(pid, sandbox_id, fakelib_mount);

    plugin_log("Game %s closed - ready for the next launch", title_id);
}

// ─────────────────────────────────────────────────────────────────────────────
//  main — détection kqueue sur SceSysCore + boucle événements
// ─────────────────────────────────────────────────────────────────────────────

int main()
{
    plugin_log("=== BLUESPHERE PRX LOADER v46 ===");
    plugin_log("By @84Ciss and @NoLimit.Turno");
    plugin_log("Build: FW 8.60 / LSO 1.010.002 resolved-import v46");

    // Initialisation kernel
    payload_args_t *args = payload_get_args();
    kernel_base   = args->kdata_base_addr;
    g_fw_version  = kernel_get_fw_version();

    uint32_t fw_major = (g_fw_version >> 24) & 0xFF;
    uint32_t fw_minor = (g_fw_version >> 16) & 0xFF;
    plugin_log("Kernel base: 0x%llx", (unsigned long long)kernel_base);
    plugin_log("Detected FW: 0x%08x (%x.%02x)", g_fw_version, fw_major, fw_minor);
    plugin_log("UCRED ptrace attr offset: 0x83 (SDK layout)");

    // patch_shellcore (sauf si etaHEN a déjà tout fait)
    {
        struct stat eta_st{};
        bool eta_present = (stat("/download0/etahen_jailbreak", &eta_st) == 0);
        if (eta_present) {
            plugin_log("[SC_PATCH] etaHEN detected - skipping ShellCore patch");
        } else {
            if (!patch_shellcore_for_data())
                plugin_log("[SC_PATCH] SceShellCore patch failed - /data will remain sandboxed");
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
        plugin_log("ERROR: SceSysCore.elf not found");
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

    printf_notification("BlueSphere PRX Loader v46 | FW %x.%02x      \nBy @84Ciss and @NoLimit.Turno",
                        fw_major, fw_minor);
    plugin_log("Monitoring SceSysCore.elf (pid %d)...", syscore_pid);

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
                plugin_log("sceKernelGetAppInfo failed for pid %d", child_pid);
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

            plugin_log("Detected game: %s (pid %d)", title_id, child_pid);

            GameInjectorConfig config = parse_injector_config();
            auto it = config.games.find(std::string(title_id));

            if (it == config.games.end()) {
                // Pas de PRX configuré pour ce titre → fakelib only (PPSA)
                plugin_log("No PRX configured for %s - fakelib only", title_id);

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
