#include <stdint.h>

#define ORBIS_PAD_PORT_TYPE_STANDARD 0
#define ORBIS_PAD_PORT_TYPE_SPECIAL 2

#define ORBIS_PAD_DEVICE_CLASS_PAD 0
#define ORBIS_PAD_DEVICE_CLASS_GUITAR 1
#define ORBIS_PAD_DEVICE_CLASS_DRUMS 2

#define ORBIS_PAD_CONNECTION_TYPE_STANDARD 0
#define ORBIS_PAD_CONNECTION_TYPE_REMOTE 2

enum OrbisPadButton {
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

typedef struct vec_float3 {
  float x;
  float y;
  float z;
}
vec_float3;

typedef struct vec_float4 {
  float x;
  float y;
  float z;
  float w;
}
vec_float4;

typedef struct stick {
  uint8_t x;
  uint8_t y;
}
stick;

typedef struct analog {
  uint8_t l2;
  uint8_t r2;
}
analog;

typedef struct OrbisPadTouch {
  uint16_t x, y;
  uint8_t finger;
  uint8_t pad[3];
}
OrbisPadTouch;

typedef struct OrbisPadTouchData {
  uint8_t fingers;
  uint8_t pad1[3];
  uint32_t pad2;
  OrbisPadTouch touch[ORBIS_PAD_MAX_TOUCH_NUM];
}
OrbisPadTouchData;

typedef struct OrbisPadData {
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

// Structure EXACTEMENT comme GameStuff dans utils.hpp
typedef struct {
  int (*scePadReadState)(int handle, OrbisPadData *pData);
  int (*sceKernelDebugOutText)(int channel, const char *txt);
  int (*sceKernelLoadStartModule)(const char *moduleFileName, int args, const void *argp, int flags, void *opt, int *pRes);
  int (*sceKernelDlsym)(int handle, const char *symbol, void **addrp);
  uint64_t ASLR_Base;
  char prx_path[256];
  int loaded;
  uint64_t game_hash;
  int frame_delay;
  int frame_counter;
} GameExtraStuff;


static uint64_t __attribute__((used)) simple_hash(const char *str) {
    uint64_t hash = 0;
    for (int i = 0; str[i] != '\0' && i < 256; i++) {
        hash = hash * 31 + str[i];
    }
    return hash;
}

// Messages statiques - créés 1 fois (optimisation)
static const char msg_success[] = "PRX loaded ok";
static const char msg_error[] = "Lib err lib load";

static int __attribute__((used)) scePadReadState_Hook(int handle, OrbisPadData *pData, GameExtraStuff *restrict stuff){

    // Appeler scePadReadState original
    int ret = stuff->scePadReadState(handle, pData);
    
    // OPTIMISATION 1: Early return si déjà chargé
    uint64_t current_hash = simple_hash(stuff->prx_path);
    if (stuff->loaded && stuff->game_hash == current_hash) {
        return ret; // Gain ~90% CPU
    }
    
    // OPTIMISATION 2: Compteur de frames
    if (stuff->frame_counter < stuff->frame_delay) {
        stuff->frame_counter++;
        return ret;
    }
    
    // Chargement du PRX
    int res = stuff->sceKernelLoadStartModule(stuff->prx_path, 0, 0, 0, 0, 0);
    
    if (res >= 0) {
        // Succès
        stuff->sceKernelDebugOutText(0, msg_success);
        stuff->loaded = 1;
        stuff->game_hash = current_hash;
        stuff->frame_counter = 0;
    } else {
        // Erreur - retry dans 3 sec
        stuff->sceKernelDebugOutText(0, msg_error);
        stuff->frame_counter = stuff->frame_delay - 180;
        if (stuff->frame_counter < 0) {
            stuff->frame_counter = 0;
        }
    }
    
    return ret;
}
