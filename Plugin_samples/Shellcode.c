#include <stdint.h>

#define ORBIS_PAD_PORT_TYPE_STANDARD 0
#define ORBIS_PAD_PORT_TYPE_SPECIAL 2

#define ORBIS_PAD_DEVICE_CLASS_PAD 0
#define ORBIS_PAD_DEVICE_CLASS_GUITAR 1
#define ORBIS_PAD_DEVICE_CLASS_DRUMS 2

#define ORBIS_PAD_CONNECTION_TYPE_STANDARD 0
#define ORBIS_PAD_CONNECTION_TYPE_REMOTE 2

#define MAX_PRX_COUNT 4

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
} vec_float3;

typedef struct vec_float4 {
    float x;
    float y;
    float z;
    float w;
} vec_float4;

typedef struct stick {
    uint8_t x;
    uint8_t y;
} stick;

typedef struct analog {
    uint8_t l2;
    uint8_t r2;
} analog;

typedef struct OrbisPadTouch {
    uint16_t x, y;
    uint8_t finger;
    uint8_t pad[3];
} OrbisPadTouch;

typedef struct OrbisPadTouchData {
    uint8_t fingers;
    uint8_t pad1[3];
    uint32_t pad2;
    OrbisPadTouch touch[ORBIS_PAD_MAX_TOUCH_NUM];
} OrbisPadTouchData;

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

// Structure pour un seul PRX
typedef struct {
    char prx_path[256];
    int loaded;
    uint64_t game_hash;
    int frame_delay;
    int frame_counter;
} PRXSlot;

// Structure MULTI-PRX
typedef struct {
    int (*scePadReadState)(int handle, OrbisPadData *pData);
    int (*sceKernelDebugOutText)(int channel, const char *txt);
    int (*sceKernelLoadStartModule)(const char *moduleFileName, int args, const void *argp, int flags, void *opt, int *pRes);
    int (*sceKernelDlsym)(int handle, const char *symbol, void **addrp);
    uint64_t ASLR_Base;
    
    int prx_count;                  // Nombre de PRX à charger (1-4)
    PRXSlot prx_slots[MAX_PRX_COUNT]; // Tableau de PRX
} GameExtraStuff;

static uint64_t __attribute__((used)) simple_hash(const char *str) {
    uint64_t hash = 0;
    for (int i = 0; str[i] != '\0' && i < 256; i++) {
        hash = hash * 31 + str[i];
    }
    return hash;
}

// Messages statiques
static const char msg_prx1_ok[] = "[1/X] PRX loaded";
static const char msg_prx2_ok[] = "[2/X] PRX loaded";
static const char msg_prx3_ok[] = "[3/X] PRX loaded";
static const char msg_prx4_ok[] = "[4/X] PRX loaded";
static const char msg_error[] = "PRX load error";

static int __attribute__((used)) scePadReadState_Hook(int handle, OrbisPadData *pData, GameExtraStuff *restrict stuff) {
    // Appeler scePadReadState original
    int ret = stuff->scePadReadState(handle, pData);
    
    // Traiter chaque PRX dans l'ordre
    for (int i = 0; i < stuff->prx_count && i < MAX_PRX_COUNT; i++) {
        PRXSlot *slot = &stuff->prx_slots[i];
        
        // Skip si path vide
        if (slot->prx_path[0] == '\0') {
            continue;
        }
        
        // Early return si déjà chargé avec le bon hash
        uint64_t current_hash = simple_hash(slot->prx_path);
        if (slot->loaded && slot->game_hash == current_hash) {
            continue;
        }
        
        // Compteur de frames
        if (slot->frame_counter < slot->frame_delay) {
            slot->frame_counter++;
            continue;
        }
        
        // Charger le PRX
        int res = stuff->sceKernelLoadStartModule(slot->prx_path, 0, 0, 0, 0, 0);
        
        if (res >= 0) {
            // Succès - message basé sur l'index
            const char *msg = msg_prx1_ok;
            if (i == 1) msg = msg_prx2_ok;
            else if (i == 2) msg = msg_prx3_ok;
            else if (i == 3) msg = msg_prx4_ok;
            
            stuff->sceKernelDebugOutText(0, msg);
            slot->loaded = 1;
            slot->game_hash = current_hash;
            slot->frame_counter = 0;
        } else {
            // Erreur - retry dans 3 sec (180 frames @ 60fps)
            stuff->sceKernelDebugOutText(0, msg_error);
            slot->frame_counter = slot->frame_delay - 180;
            if (slot->frame_counter < 0) {
                slot->frame_counter = 0;
            }
        }
    }
    
    return ret;
}
