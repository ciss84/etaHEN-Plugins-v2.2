#include "hijacker.hpp"
#include "offsets.hpp"
#include "util.hpp"
#include <ps5/kernel.h>

extern "C" {
#include <stdint.h>
#include <stdio.h>
}

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

void Hijacker::do_jailbreak(pid_t target_pid) const {
    auto hj = Hijacker::getHijacker(target_pid);
    if (!hj) {
        //LOG("getHijacker(%d) FAIL — process likely exited", target_pid);
        return -1;
    }
    hj->jailbreak(/*escapeSandbox=*/ true);
    //LOG("jailbreak OK pid=%d", target_pid);
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