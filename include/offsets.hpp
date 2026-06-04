
extern "C" {
	#include <stddef.h>
}

namespace offsets {

size_t allproc();
size_t security_flags();
size_t qa_flags();
size_t utoken_flags();
size_t root_vnode();

// ucred struct field offsets — fw-dependent
size_t ucred_sceattr();   // cr_sceAttr[0] : 0x83 on <8.00, 0x88 on 8.00+

} // offsets
