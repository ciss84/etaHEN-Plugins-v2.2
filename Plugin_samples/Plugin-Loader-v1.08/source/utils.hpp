#include <stddef.h>
#include <stdio.h>
#include <sys/_pthreadtypes.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include "dbg.hpp"
#include "dbg/dbg.hpp"
#include "elf/elf.hpp"
#include "hijacker/hijacker.hpp"
#include "notify.hpp"
#include "backtrace.hpp"

#define ORBIS_PAD_PORT_TYPE_STANDARD 0
#define ORBIS_PAD_PORT_TYPE_SPECIAL 2

#define ORBIS_PAD_DEVICE_CLASS_PAD 0
#define ORBIS_PAD_DEVICE_CLASS_GUITAR 1
#define ORBIS_PAD_DEVICE_CLASS_DRUMS 2

#define ORBIS_PAD_CONNECTION_TYPE_STANDARD 0
#define ORBIS_PAD_CONNECTION_TYPE_REMOTE 2

	enum OrbisPadButton
	{
		ORBIS_PAD_BUTTON_L3 = 0x0002,
		ORBIS_PAD_BUTTON_R3 = 0x0004,
		ORBIS_PAD_BUTTON_OPTIONS = 0x0008,
		ORBIS_PAD_BUTTON_UP = 0x0010,
		ORBIS_PAD_BUTTON_RIGHT = 0x0020,
		ORBIS_PAD_BUTTON_DOWN = 0x0040,
		ORBIS_PAD_BUTTON_LEFT = 0x0080,

		ORBIS_PAD_BUTTON_L2 = 0x0100,
		ORBIS_PAD_BUTTON_R2 = 0x0200,
		ORBIS_PAD_BUTTON_L1 = 0x0400,
		ORBIS_PAD_BUTTON_R1 = 0x0800,

		ORBIS_PAD_BUTTON_TRIANGLE = 0x1000,
		ORBIS_PAD_BUTTON_CIRCLE = 0x2000,
		ORBIS_PAD_BUTTON_CROSS = 0x4000,
		ORBIS_PAD_BUTTON_SQUARE = 0x8000,

		ORBIS_PAD_BUTTON_TOUCH_PAD = 0x100000
	};

#define ORBIS_PAD_MAX_TOUCH_NUM 2
#define ORBIS_PAD_MAX_DATA_NUM 0x40

	typedef struct vec_float3
	{
		float x;
		float y;
		float z;
	} vec_float3;

	typedef struct vec_float4
	{
		float x;
		float y;
		float z;
		float w;
	} vec_float4;

	typedef struct stick
	{
		uint8_t x;
		uint8_t y;
	} stick;

	typedef struct analog
	{
		uint8_t l2;
		uint8_t r2;
	} analog;

	typedef struct OrbisPadTouch
	{
		uint16_t x, y;
		uint8_t finger;
		uint8_t pad[3];
	} OrbisPadTouch;

	typedef struct OrbisPadTouchData
	{
		uint8_t fingers;
		uint8_t pad1[3];
		uint32_t pad2;
		OrbisPadTouch touch[ORBIS_PAD_MAX_TOUCH_NUM];
	} OrbisPadTouchData;

	// The ScePadData Structure contains data polled from the DS4 controller. This includes button states, analogue
	// positional data, and touchpad related data.
	typedef struct OrbisPadData
	{
		uint32_t buttons;
		stick leftStick;
		stick rightStick;
		analog analogButtons;
		uint16_t padding;
		vec_float4 quat;
		vec_float3 vel;
		vec_float3 acell;
		OrbisPadTouchData touch;
		uint8_t connected;
		uint64_t timestamp;
		uint8_t ext[16];
		uint8_t count;
		uint8_t unknown[15];
	} OrbisPadData;

	// The PadColor structure contains RGBA for the DS4 controller lightbar.
	typedef struct OrbisPadColor
	{
		uint8_t r;
		uint8_t g;
		uint8_t b;
		uint8_t a;
	} OrbisPadColor;

	typedef struct OrbisPadVibeParam
	{
		uint8_t lgMotor;
		uint8_t smMotor;
	} OrbisPadVibeParam;

	// Vendor information about which controller to open for scePadOpenExt
	typedef struct _OrbisPadExtParam
	{
		uint16_t vendorId;
		uint16_t productId;
		uint16_t productId_2; // this is in here twice?
		uint8_t unknown[10];
	} OrbisPadExtParam;

	typedef struct _OrbisPadInformation
	{
		float touchpadDensity;
		uint16_t touchResolutionX;
		uint16_t touchResolutionY;
		uint8_t stickDeadzoneL;
		uint8_t stickDeadzoneR;
		uint8_t connectionType;
		uint8_t count;
		int32_t connected;
		int32_t deviceClass;
		uint8_t unknown[8];
	} OrbisPadInformation;

struct GameStuff {
  uintptr_t scePadReadState;        // +0x00
  uintptr_t debugout;                // +0x08
  uintptr_t sceKernelLoadStartModule; // +0x10
  uintptr_t sceKernelDlsym;          // +0x18
  uint64_t ASLR_Base = 0;            // +0x20
  char prx_path[256];                 // +0x28
  int loaded = 0;                     // +0x128
  uint64_t game_hash = 0;            // +0x12C (padding fait que c'est a +0x130)
  int frame_delay = 300;             // +0x138
  int frame_counter = 0;             // +0x13C

  GameStuff(Hijacker &hijacker) noexcept
      : debugout(hijacker.getLibKernelAddress(nid::sceKernelDebugOutText)), 
        sceKernelLoadStartModule(hijacker.getLibKernelAddress(nid::sceKernelLoadStartModule)),
        sceKernelDlsym(hijacker.getLibKernelAddress(nid::sceKernelDlsym)) {}
};

struct GameBuilder {
  static constexpr size_t SHELLCODE_SIZE = 137;
  static constexpr size_t SHELLCODE_SIZE_AUTO = 210; // Shellcode avec hash check pour multi-PRX
  static constexpr size_t EXTRA_STUFF_ADDR_OFFSET = 2;

  uint8_t shellcode[256]; // Buffer agrandi pour le nouveau shellcode

  void setExtraStuffAddr(uintptr_t addr) noexcept {
    *reinterpret_cast<uintptr_t *>(shellcode + EXTRA_STUFF_ADDR_OFFSET) = addr;
  }
};

// Standard shellcode (waits for controller input)
static constexpr GameBuilder BUILDER_TEMPLATE {
    0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RDX, [GameStuff addr]
    0x55, 0x41, 0x57, 0x41, 0x56, 0x53, 0x48, 0x83, 0xec, 0x18, 0x48, 0xb8, 0x48, 0x65, 0x6c, 0x6c,
    0x6f, 0x20, 0x66, 0x72, 0x48, 0x89, 0xd3, 0x49, 0x89, 0xf6, 0x41, 0x89, 0xff, 0x48, 0x89, 0x04,
    0x24, 0x48, 0xb8, 0x6f, 0x6d, 0x20, 0x42, 0x4f, 0x36, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x08,
    0xff, 0x12, 0x89, 0xc5, 0x45, 0x85, 0xff, 0x7e, 0x39, 0x85, 0xed, 0x75, 0x35, 0x41, 0x80, 0x7e,
    0x4c, 0x00, 0x74, 0x2e, 0x83, 0xbb, 0x28, 0x01, 0x00, 0x00, 0x00, 0x75, 0x25, 0x48, 0x8d, 0x7b,
    0x28, 0x31, 0xf6, 0x31, 0xd2, 0x31, 0xc9, 0x45, 0x31, 0xc0, 0x45, 0x31, 0xc9, 0xff, 0x53, 0x10,
    0x48, 0x89, 0xe6, 0x31, 0xff, 0xff, 0x53, 0x08, 0xc7, 0x83, 0x28, 0x01, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x89, 0xe8, 0x48, 0x83, 0xc4, 0x18, 0x5b, 0x41, 0x5e, 0x41, 0x5f, 0x5d, 0xc3
};

// Auto-load shellcode AVEC HASH CHECK (210 bytes)
// Correspond au code C dans Shellcode.c
// Permet de charger PLUSIEURS PRX differents (LSO153 + BeachOffline)
static constexpr GameBuilder BUILDER_TEMPLATE_AUTO {
    0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x55, 0x41, 0x57, 0x41, 0x56, 0x41, 0x54, 0x53, 0x48, 0x83,
    0xec, 0x18, 0x48, 0x89, 0xd3, 0x49, 0x89, 0xf6, 0x41, 0x89,
    0xff, 0xff, 0x13, 0x89, 0xc5, 0x48, 0x8d, 0x7b, 0x28, 0x48,
    0x31, 0xc0, 0x31, 0xc9, 0x81, 0xf9, 0x00, 0x01, 0x00, 0x00,
    0x7d, 0x13, 0x0f, 0xb6, 0x14, 0x0f, 0x84, 0xd2, 0x74, 0x0c,
    0x48, 0x6b, 0xc0, 0x1f, 0x48, 0x01, 0xd0, 0xff, 0xc1, 0xeb,
    0xe9, 0x49, 0x89, 0xc4, 0x83, 0xbb, 0x28, 0x01, 0x00, 0x00,
    0x00, 0x74, 0x0a, 0x4c, 0x3b, 0xa3, 0x30, 0x01, 0x00, 0x00,
    0x0f, 0x84, 0x4c, 0x00, 0x00, 0x00, 0x8b, 0x83, 0x3c, 0x01,
    0x00, 0x00, 0xff, 0xc0, 0x89, 0x83, 0x3c, 0x01, 0x00, 0x00,
    0x3b, 0x83, 0x38, 0x01, 0x00, 0x00, 0x0f, 0x8c, 0x38, 0x00,
    0x00, 0x00, 0x48, 0x8d, 0x7b, 0x28, 0x31, 0xf6, 0x31, 0xd2,
    0x31, 0xc9, 0x45, 0x31, 0xc0, 0x45, 0x31, 0xc9, 0xff, 0x53,
    0x10, 0x85, 0xc0, 0x78, 0x17, 0xc7, 0x83, 0x28, 0x01, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x4c, 0x89, 0xa3, 0x30, 0x01,
    0x00, 0x00, 0xc7, 0x83, 0x3c, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xeb, 0x0f, 0x8b, 0x83, 0x38, 0x01, 0x00, 0x00,
    0x83, 0xe8, 0xb4, 0x78, 0x02, 0xeb, 0x02, 0x31, 0xc0, 0x89,
    0x83, 0x3c, 0x01, 0x00, 0x00, 0x89, 0xe8, 0x48, 0x83, 0xc4,
    0x18, 0x5b, 0x41, 0x5c, 0x41, 0x5e, 0x41, 0x5f, 0x5d, 0xc3
};


extern "C" int sceSystemServiceKillApp(int, int, int, int);
extern "C" int sceSystemServiceGetAppId(const char *);
extern "C" int _sceApplicationGetAppId(int pid, int *appId);

#include <map>
#include <string>
#include <vector>

// Config structures for injector
struct PRXConfig {
	std::string path;
	int frame_delay;
};

struct GameInjectorConfig {
	std::map<std::string, std::vector<PRXConfig>> games;
};

void plugin_log(const char* fmt, ...);
bool Is_Game_Running(int &BigAppid, const char* title_id);
bool HookGame(UniquePtr<Hijacker> &hijacker, uint64_t alsr_b, const char* prx_path, bool auto_load, int frame_delay = 300);
GameInjectorConfig parse_injector_config();