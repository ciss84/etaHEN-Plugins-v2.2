#pragma once

// ─────────────────────────────────────────────────────────────────────────────
//  patch_shellcore.hpp — active /data en sandbox sans etaHEN
//  Porté depuis etaHEN (cpp_service.cpp / util daemon)
//  A inclure/appeler UNE SEULE FOIS au démarrage de Plugin-Loader
//  NOTE: ne pas inclure utils.hpp ici (pas de include guard dessus)
//        On utilise directement les headers système + hijacker
// ─────────────────────────────────────────────────────────────────────────────

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include "hijacker/hijacker.hpp"
#include "dbg/dbg.hpp"

// plugin_log est défini dans utils.cpp, déclaration externe
extern void plugin_log(const char* fmt, ...);

// kernel_get_fw_version depuis ps5/kernel.h (déjà inclus dans main.cpp avant nous)
extern "C" uint32_t kernel_get_fw_version();

// ── Firmware version constants ────────────────────────────────────────────────
static constexpr uint32_t SC_VERSION_MASK = 0xffff0000;
static constexpr uint32_t SC_V200  = 0x2000000;
static constexpr uint32_t SC_V220  = 0x2200000;
static constexpr uint32_t SC_V225  = 0x2250000;
static constexpr uint32_t SC_V226  = 0x2260000;
static constexpr uint32_t SC_V230  = 0x2300000;
static constexpr uint32_t SC_V250  = 0x2500000;
static constexpr uint32_t SC_V270  = 0x2700000;
static constexpr uint32_t SC_V300  = 0x3000000;
static constexpr uint32_t SC_V310  = 0x3100000;
static constexpr uint32_t SC_V320  = 0x3200000;
static constexpr uint32_t SC_V321  = 0x3210000;
static constexpr uint32_t SC_V400  = 0x4000000;
static constexpr uint32_t SC_V402  = 0x4020000;
static constexpr uint32_t SC_V403  = 0x4030000;
static constexpr uint32_t SC_V450  = 0x4500000;
static constexpr uint32_t SC_V451  = 0x4510000;
static constexpr uint32_t SC_V500  = 0x5000000;
static constexpr uint32_t SC_V502  = 0x5020000;
static constexpr uint32_t SC_V510  = 0x5100000;
static constexpr uint32_t SC_V550  = 0x5500000;
static constexpr uint32_t SC_V600  = 0x6000000;
static constexpr uint32_t SC_V602  = 0x6020000;
static constexpr uint32_t SC_V650  = 0x6500000;
static constexpr uint32_t SC_V700  = 0x7000000;
static constexpr uint32_t SC_V701  = 0x7010000;
static constexpr uint32_t SC_V720  = 0x7200000;
static constexpr uint32_t SC_V740  = 0x7400000;
static constexpr uint32_t SC_V760  = 0x7600000;
static constexpr uint32_t SC_V761  = 0x7610000;
static constexpr uint32_t SC_V800  = 0x8000000;
static constexpr uint32_t SC_V820  = 0x8200000;
