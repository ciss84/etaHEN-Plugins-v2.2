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

	typedef struct _OrbisPadExtParam
	{
		uint16_t vendorId;
		uint16_t productId;
		uint16_t productId_2;
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
  uintptr_t scePadReadState;          // +0x00
  uintptr_t debugout;                  // +0x08
  uintptr_t sceKernelLoadStartModule;  // +0x10
  uintptr_t sceKernelDlsym;           // +0x18
  uint64_t ASLR_Base = 0;             // +0x20
  char prx_path[256];                  // +0x28
  int loaded = 0;                      // +0x128
  uint32_t _pad = 0;                   // +0x12C (explicit padding)
  uint64_t game_hash = 0;             // +0x130
  int frame_delay = 300;              // +0x138
  int frame_counter = 0;              // +0x13C

  GameStuff(Hijacker &hijacker) noexcept
      : debugout(hijacker.getLibKernelAddress(nid::sceKernelDebugOutText)),
        sceKernelLoadStartModule(hijacker.getLibKernelAddress(nid::sceKernelLoadStartModule)),
        sceKernelDlsym(hijacker.getLibKernelAddress(nid::sceKernelDlsym)) {}
};

// Verify offsets at compile time
static_assert(offsetof(GameStuff, prx_path)               == 0x28,  "GameStuff::prx_path offset wrong");
static_assert(offsetof(GameStuff, loaded)                  == 0x128, "GameStuff::loaded offset wrong");
static_assert(offsetof(GameStuff, game_hash)               == 0x130, "GameStuff::game_hash offset wrong");
static_assert(offsetof(GameStuff, frame_delay)             == 0x138, "GameStuff::frame_delay offset wrong");
static_assert(offsetof(GameStuff, frame_counter)           == 0x13C, "GameStuff::frame_counter offset wrong");

struct GameBuilder {
  static constexpr size_t SHELLCODE_SIZE      = 137;
  static constexpr size_t SHELLCODE_SIZE_AUTO = 210;
  static constexpr size_t EXTRA_STUFF_ADDR_OFFSET = 2;

  uint8_t shellcode[256];

  void setExtraStuffAddr(uintptr_t addr) noexcept {
    *reinterpret_cast<uintptr_t *>(shellcode + EXTRA_STUFF_ADDR_OFFSET) = addr;
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  Standard shellcode — connected check REMOVED (NOPed bytes [71-77])
//  Raison: sur FW 10.00 le check connected=0x4C peut etre faux si Sony a
//  change la structure OrbisPadData, ce qui bloque module_start pour toujours.
//
//  Ancien code (bytes 71-77):
//    41 80 7e 4c 00  = CMP BYTE PTR [R14+0x4C], 0  ; connected check
//    74 2e           = JE skip_load                 ; skip si non connecte
//  Nouveau code:
//    90 90 90 90 90  = NOP x5
//    90 90           = NOP x2
// ─────────────────────────────────────────────────────────────────────────────
static constexpr GameBuilder BUILDER_TEMPLATE {
    // [0-9]   MOV RDX, stuffAddr (patché par setExtraStuffAddr)
    0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // [10-19] prologue
    0x55, 0x41, 0x57, 0x41, 0x56, 0x53, 0x48, 0x83, 0xec, 0x18,
    // [20-29] MOV RAX, "Hello fr"
    0x48, 0xb8, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x66, 0x72,
    // [30-32] MOV RBX, RDX
    0x48, 0x89, 0xd3,
    // [33-35] MOV R14, RSI  (data ptr)
    0x49, 0x89, 0xf6,
    // [36-38] MOV R15D, EDI (handle)
    0x41, 0x89, 0xff,
    // [39-42] MOV [RSP], RAX
    0x48, 0x89, 0x04, 0x24,
    // [43-52] MOV RAX, "om BO6\0\0"
    0x48, 0xb8, 0x6f, 0x6d, 0x20, 0x42, 0x4f, 0x36, 0x00, 0x00,
    // [53-57] MOV [RSP+8], RAX
    0x48, 0x89, 0x44, 0x24, 0x08,
    // [58-59] CALL [RDX] = scePadReadState (original)
    0xff, 0x12,
    // [60-61] MOV EBP, EAX (save return value)
    0x89, 0xc5,
    // [62-70] NOP x9 — bypass handle + retval checks (test FW7.6x+)
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    // [71-77] FIX FW10: connected check supprime (7x NOP)
    // Ancien: CMP BYTE PTR [R14+0x4C],0 / JE skip
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    // [78-84] CMP DWORD PTR [RBX+0x128], 0  (loaded ?)
    0x83, 0xbb, 0x28, 0x01, 0x00, 0x00, 0x00,
    // [85-86] JNZ epilogue (deja charge)
    0x75, 0x25,
    // [87-90] LEA RDI, [RBX+0x28]  (prx_path)
    0x48, 0x8d, 0x7b, 0x28,
    // [91-92] XOR ESI, ESI  (args = 0)
    0x31, 0xf6,
    // [93-94] XOR EDX, EDX  (argp = NULL)
    0x31, 0xd2,
    // [95-96] XOR ECX, ECX  (flags = 0)
    0x31, 0xc9,
    // [97-99] XOR R8D, R8D  (pOpt = NULL)
    0x45, 0x31, 0xc0,
    // [100-104] LEA R9, [RSP+0x4]  (pRes = pointeur stack valide)
    0x4c, 0x8d, 0x4c, 0x24, 0x04,    
    // [103-105] CALL [RBX+0x10]  = sceKernelLoadStartModule
    0xff, 0x53, 0x10,
    // [106-108] MOV RSI, RSP
    0x48, 0x89, 0xe6,
    // [109-110] XOR EDI, EDI
    0x31, 0xff,
    // [111-113] CALL [RBX+0x08]  = debugout
    0xff, 0x53, 0x08,
    // [114-123] MOV DWORD PTR [RBX+0x128], 1  (loaded = 1)
    0xc7, 0x83, 0x28, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    // [124-125] MOV EAX, EBP  (restore scePadReadState retval)
    0x89, 0xe8,
    // [126-129] ADD RSP, 24
    0x48, 0x83, 0xc4, 0x18,
    // [130]     POP RBX
    0x5b,
    // [131-132] POP R14
    0x41, 0x5e,
    // [133-134] POP R15
    0x41, 0x5f,
    // [135]     POP RBP
    0x5d,
    // [136]     RET
    0xc3
};

// Auto-load shellcode avec hash check pour multi-PRX (210 bytes) — inchangé
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

struct PRXConfig {
	std::string path;
	int frame_delay;
};

struct GameInjectorConfig {
	std::map<std::string, std::vector<PRXConfig>> games;
	std::map<std::string, bool> fakelib_enabled;
};

void plugin_log(const char* fmt, ...);
bool Is_Game_Running(int &BigAppid, const char* title_id);

// out_stuff_addr (optionnel) : recoit l'adresse du GameStuff alloue dans le
// process cible, pour lire le flag 'loaded' depuis l'exterieur apres injection.
bool HookGame(UniquePtr<Hijacker> &hijacker, uint64_t alsr_b, const char* prx_path,
              bool auto_load, int frame_delay = 300, uintptr_t* out_stuff_addr = nullptr);

GameInjectorConfig parse_injector_config();
