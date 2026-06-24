// Multi-fw libhijacker offsets override.
//
// libhijacker's vanilla offsets.cpp hardcodes fw 9.40 kernel-symbol offsets.
// This file replaces it with a multi-fw resolution path : ps5-payload-sdk
// already exposes the absolute kernel virtual addresses at runtime via the
// KERNEL_ADDRESS_* extern globals (auto-populated per-fw from kern.sdk_version,
// see ps5/kernel.h), so the only job here is converting absolute VA -> offset
// from kdata_base — which is what libhijacker's offsets:: namespace expects.
//
// Compile this .o BEFORE -lhijacker on the link line so the linker resolves
// the offsets:: symbols from here and skips the vanilla offsets.cpp.o that
// would otherwise be pulled from libhijacker.a.
//
// Covers every fw the SDK knows about (3.00 -> 12.00 via kstuff). On an
// unknown fw the SDK returns 0 and libhijacker fails cleanly with NULL
// attach — same graceful failure as the old 9.40-hardcoded path on wrong fw.


extern "C" {
#include <stddef.h>
#include <ps5/kernel.h>
}

namespace offsets {

static inline size_t rel(intptr_t va) {
    return (size_t)(va - KERNEL_ADDRESS_DATA_BASE);
}

size_t allproc()        { return rel(KERNEL_ADDRESS_ALLPROC); }
size_t security_flags() { return rel(KERNEL_ADDRESS_SECURITY_FLAGS); }
size_t qa_flags()       { return rel(KERNEL_ADDRESS_QA_FLAGS); }
size_t utoken_flags()   { return rel(KERNEL_ADDRESS_UTOKEN_FLAGS); }
size_t root_vnode()     { return rel(KERNEL_ADDRESS_ROOTVNODE); }
size_t ucred_sceattr()  { return (size_t)KERNEL_OFFSET_UCRED_CR_SCEATTRS; }
}
