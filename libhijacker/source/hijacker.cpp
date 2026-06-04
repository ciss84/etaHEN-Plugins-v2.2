#include "hijacker.hpp"
#include "offsets.hpp"
#include "util.hpp"
#include <ps5/kernel.h>

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
int klog_printf(const char *fmt, ...);
int sceNotificationSend(int userId, bool isLogged, const char *payload);
}

extern "C" uint64_t kernel_base = 0;

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

// NOLINTBEGIN
//
static void notif(const char *fmt, ...) {
	char text[256];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(text, sizeof(text), fmt, ap);
	va_end(ap);
	char json[1024];
	snprintf(json, sizeof(json),
		"{\"rawData\":{"
		"\"viewTemplateType\":\"InteractiveToastTemplateB\","
		"\"channelType\":\"Downloads\","
		"\"useCaseId\":\"IDC\","
		"\"toastOverwriteType\":\"Yes\","
		"\"isImmediate\":true,"
		"\"priority\":100,"
		"\"viewData\":{"
		"\"icon\":{\"type\":\"Predefined\",\"parameters\":{\"icon\":\"download\"}},"
		"\"message\":{\"body\":\"%s\"},"
		"\"subMessage\":{\"body\":\"Lapy JB Daemon\"}"
		"},"
		"\"platformViews\":{"
		"\"previewDisabled\":{"
		"\"viewData\":{"
		"\"icon\":{\"type\":\"Predefined\",\"parameters\":{\"icon\":\"download\"}},"
		"\"message\":{\"body\":\"%s\"}"
		"}"
		"}"
		"}"
		"},"
		"\"localNotificationId\":\"LAPY_JB\""
		"}",
		text, text);
	sceNotificationSend(0xFE, true, json);
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