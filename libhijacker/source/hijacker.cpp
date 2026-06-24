#include "hijacker.hpp"
#include "offsets.hpp"
#include "util.hpp"

extern "C" {
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ps5/payload.h>
#include <ps5/kernel.h>
#include <notify.hpp>

int klog_printf(const char *fmt, ...);
int sceNotificationSend(int userId, bool isLogged, const char *payload);
}

#define LOG(fmt, ...) klog_printf("[lapy_jb] " fmt "\n", ##__VA_ARGS__)
#define SANDBOX_BASE     "/mnt/sandbox"
#define JB_FILE_RELPATH  "/download0/etahen_jailbreak"
#define POLL_INTERVAL_US (250 * 1000)

UniquePtr<Hijacker> Hijacker::getHijacker(const StringView &processName) {
	UniquePtr<SharedObject> obj = nullptr;
	for (dbg::ProcessInfo info : dbg::getProcesses()) {
		if (info.name() == processName) {
			auto p = ::getProc(info.pid());
			obj = p->getSharedObject();
		}
	}
	return obj ? new Hijacker(obj.release()) : nullptr;
}


int Hijacker::getMainThreadId() const {
	if (mainThreadId == -1) {
		for (dbg::ThreadInfo info : dbg::getThreads(obj->pid)) {
			StringView name = info.name();
			if (name.contains("Main") || name.contains(".")) {
				// this works for most of them
				mainThreadId = info.tid();
				break;
			}
		}
		if (mainThreadId == -1) [[unlikely]] {
			puts("main thread id not found");
		}
	}
	return mainThreadId;
}

UniquePtr<TrapFrame> Hijacker::getTrapFrame() const {
	// do not cache this
	int tid = getMainThreadId();
	if (tid == -1) [[unlikely]] {
		return nullptr;
	}
	auto p = ::getProc(obj->pid);
	if (p == nullptr) {
		return nullptr;
	}

	auto td = p->getThread(tid);
	if (td == nullptr) {
		return nullptr;
	}
	return td->getFrame();
}

/*void Hijacker::jailbreak(bool escapeSandbox) const {
    auto proc = getProc();
    if (!proc) return;

    uintptr_t ucred = proc->p_ucred();
    if (!ucred) return;

    // Root uid/gid
    static constexpr uint32_t ROOT = 0;
    kernel_copyin(&ROOT, ucred + 0x04, sizeof(ROOT)); // uid
    kernel_copyin(&ROOT, ucred + 0x08, sizeof(ROOT)); // ruid
    kernel_copyin(&ROOT, ucred + 0x0c, sizeof(ROOT)); // svuid
    kernel_copyin(&ROOT, ucred + 0x10, sizeof(ROOT)); // gid
    kernel_copyin(&ROOT, ucred + 0x14, sizeof(ROOT)); // rgid
    kernel_copyin(&ROOT, ucred + 0x18, sizeof(ROOT)); // svgid

    // Sony auth / capability flags
    size_t sceattr_off = offsets::ucred_sceattr();
    static constexpr uint64_t SCEATTRVAL = 0x4800000000000003ULL;
    kernel_copyin(&SCEATTRVAL, ucred + sceattr_off, sizeof(SCEATTRVAL));

    // Escape sandbox via root vnode
    if (escapeSandbox) {
        uintptr_t fd = proc->p_fd();
        if (fd) {
            uintptr_t root_vn = 0;
            kernel_copyout(
                (uintptr_t)kernel_base + offsets::root_vnode(),
                &root_vn, sizeof(root_vn)
            );
            if (root_vn) {
                kernel_copyin(&root_vn, fd + 0x10, sizeof(root_vn)); // fd_jdir
                kernel_copyin(&root_vn, fd + 0x18, sizeof(root_vn)); // fd_rdir
            }
        }
    }
}*/

void Hijacker::jailbreak(bool escapeSandbox) const {
    auto proc = getProc();
    if (!proc) return;

    uintptr_t ucred = proc->p_ucred();
    if (!ucred) return;
    
	  int uid = -1;
	  kernel_copyout(ucred + 0x04, &uid, 0x4);
	  if(uid == 0 && !escapeSandbox){
		  puts("already jailbroken");
		  return;
	  }
    // Root uid/gid
    static constexpr uint32_t ROOT = 0;
    kernel_copyin(&ROOT, ucred + 0x04, sizeof(ROOT)); // uid
    kernel_copyin(&ROOT, ucred + 0x08, sizeof(ROOT)); // ruid
    kernel_copyin(&ROOT, ucred + 0x0c, sizeof(ROOT)); // svuid
    kernel_copyin(&ROOT, ucred + 0x10, sizeof(ROOT)); // gid
    kernel_copyin(&ROOT, ucred + 0x14, sizeof(ROOT)); // rgid

    // Sony auth / capability flags
    size_t sceattr_off = offsets::ucred_sceattr();
    static constexpr uint64_t SCEATTRVAL = 0x4801000000000013l;
    int64_t caps_store = -1;
	  uint8_t attr_store[] = {0x80, 0, 0, 0, 0, 0, 0, 0};
    kernel_copyin(&SCEATTRVAL, ucred + sceattr_off, sizeof(SCEATTRVAL));
	  kernel_copyin(&caps_store, ucred + 0x60, 0x8);		 // cr_sceCaps[0]
	  kernel_copyin(&caps_store, ucred + 0x68, 0x8);		 // cr_sceCaps[1]	  
	  kernel_copyin(&attr_store, ucred + 0x83, 0x1);		 // cr_sceAttr[0]	
	  
    // Escape sandbox via root vnode
    if (escapeSandbox) {
        uintptr_t fd = proc->p_fd();
        if (fd) {
            uintptr_t root_vn = 0;
            kernel_copyout(
                (uintptr_t)kernel_base + offsets::root_vnode(),
                &root_vn, sizeof(root_vn)
            );
            if (root_vn) {
                kernel_copyin(&root_vn, fd + 0x10, sizeof(root_vn)); // fd_jdir
                kernel_copyin(&root_vn, fd + 0x18, sizeof(root_vn)); // fd_rdir
            }
        }
    }
}

// NOLINTBEGIN
//
static void notif(const char *fmt, ...) {
    OrbisNotificationRequest req{};
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(req.message, sizeof(req.message), fmt, ap);
    va_end(ap);
    if (len > 0 && req.message[len-1] == '\n')
        req.message[len-1] = '\0';
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

static ssize_t slurp_file(const char *path, char *buf, size_t buf_size) {
	int fd = open(path, O_RDONLY);
	if (fd < 0) return -1;
	ssize_t n = read(fd, buf, buf_size - 1);
	close(fd);
	if (n < 0) return -1;
	buf[n] = '\0';
	return n;
}

static pid_t parse_pid_from_json(const char *json) {
	const char *p = strstr(json, "\"PID\"");
	if (!p) return -1;
	p = strchr(p, ':');
	if (!p) return -1;
	p++;
	while (*p && (*p == ' ' || *p == '\t' || *p == '"')) p++;
	if (!*p) return -1;
	pid_t pid = (pid_t)atoi(p);
	return pid > 0 ? pid : -1;
}

static int do_jailbreak(pid_t target_pid) {
	LOG("jailbreak attempt : pid=%d", target_pid);
	auto hj = Hijacker::getHijacker(target_pid);
	if (!hj) {
		LOG("getHijacker(%d) FAIL — process likely exited", target_pid);
		return -1;
	}
	hj->jailbreak(/*escapeSandbox=*/ true);
	LOG("jailbreak OK pid=%d", target_pid);
	return 0;
}

int daemon_main(payload_args_t *args) {
	kernel_base = args->kdata_base_addr;
	LOG("kernel_base = 0x%lx", (uintptr_t)kernel_base);
	notif("Lapy JB Daemon active — launch your app");

	char buf[512];
	char path[512];
	while (true) {
		DIR *d = opendir(SANDBOX_BASE);
		if (!d) { usleep(POLL_INTERVAL_US); continue; }
		struct dirent *de;
		while ((de = readdir(d)) != NULL) {
			if (de->d_name[0] == '.') continue;
			int n = snprintf(path, sizeof(path), "%s/%s%s",
			                 SANDBOX_BASE, de->d_name, JB_FILE_RELPATH);
			if (n <= 0 || (size_t)n >= sizeof(path)) continue;
			struct stat st;
			if (stat(path, &st) != 0 || st.st_size == 0) continue;
			ssize_t got = slurp_file(path, buf, sizeof(buf));
			if (got > 0) {
				pid_t pid = parse_pid_from_json(buf);
				if (pid > 0) {
					LOG("request from %s : pid=%d", de->d_name, pid);
					if (do_jailbreak(pid) == 0)
						notif("%s pid=%d unsandboxed", de->d_name, (int)pid);
					else
						notif("Jailbreak FAIL pid=%d", (int)pid);
				} else {
					LOG("could not parse PID from '%s' (%s)", buf, path);
				}
			}
			unlink(path);
		}
		closedir(d);
		usleep(POLL_INTERVAL_US);
	}
	return 0;
}

uintptr_t Hijacker::getFunctionAddress(const SharedLib *lib, const Nid &fname) const noexcept {
	RtldMeta *meta = lib->getMetaData();
	rtld::ElfSymbol sym = meta->getSymbolTable()[fname];
	#ifdef DEBUG
	if (!sym) [[unlikely]] {
		fatalf("failed to get symbol for %s %s\n", lib->getPath().c_str(), fname.str);
	}
	#endif
	return sym ? sym.vaddr() : 0;
}
// NOLINTEND