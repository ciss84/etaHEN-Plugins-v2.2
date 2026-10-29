extern "C"
{
#include <stdint.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <stdio.h>
}

static constexpr uint32_t VERSION_MASK = 0xffff0000;

// Existing and new firmware version constants
static constexpr uint32_t V100 = 0x1000000;
static constexpr uint32_t V101 = 0x1010000;
static constexpr uint32_t V102 = 0x1020000;
static constexpr uint32_t V105 = 0x1050000;
static constexpr uint32_t V110 = 0x1100000;
static constexpr uint32_t V111 = 0x1110000;
static constexpr uint32_t V112 = 0x1120000;
static constexpr uint32_t V113 = 0x1130000;
static constexpr uint32_t V114 = 0x1140000;
static constexpr uint32_t V200 = 0x2000000;
static constexpr uint32_t V220 = 0x2200000;
static constexpr uint32_t V225 = 0x2250000;
static constexpr uint32_t V226 = 0x2260000;
static constexpr uint32_t V230 = 0x2300000;
static constexpr uint32_t V250 = 0x2500000;
static constexpr uint32_t V270 = 0x2700000;
static constexpr uint32_t V300 = 0x3000000;
static constexpr uint32_t V310 = 0x3100000;
static constexpr uint32_t V320 = 0x3200000;
static constexpr uint32_t V321 = 0x3210000;
static constexpr uint32_t V400 = 0x4000000;
static constexpr uint32_t V402 = 0x4020000;
static constexpr uint32_t V403 = 0x4030000;
static constexpr uint32_t V450 = 0x4500000;
static constexpr uint32_t V451 = 0x4510000;
static constexpr uint32_t V500 = 0x5000000;
static constexpr uint32_t V502 = 0x5020000;
static constexpr uint32_t V510 = 0x5100000;
static constexpr uint32_t V550 = 0x5500000;
static constexpr uint32_t V600 = 0x6000000;
static constexpr uint32_t V602 = 0x6020000;
static constexpr uint32_t V650 = 0x6500000;
static constexpr uint32_t V700 = 0x7000000;
static constexpr uint32_t V701 = 0x7010000;
static constexpr uint32_t V720 = 0x7200000;
static constexpr uint32_t V740 = 0x7400000;
static constexpr uint32_t V760 = 0x7600000;
static constexpr uint32_t V761 = 0x7610000;
// New firmware versions
static constexpr uint32_t V800 = 0x8000000;
static constexpr uint32_t V820 = 0x8200000;
static constexpr uint32_t V840 = 0x8400000;
static constexpr uint32_t V860 = 0x8600000;
static constexpr uint32_t V900 = 0x9000000;
static constexpr uint32_t V905 = 0x9050000;
static constexpr uint32_t V920 = 0x9200000;
static constexpr uint32_t V940 = 0x9400000;
static constexpr uint32_t V960 = 0x9600000;
static constexpr uint32_t V1000 = 0x10000000;
static constexpr uint32_t V1001 = 0x10010000;
static constexpr uint32_t V1020 = 0x10200000;
static constexpr uint32_t V1040 = 0x10400000;
static constexpr uint32_t V1060 = 0x10600000;
// 11.xx -> 13.xx : valeurs publiques (portage etaHEN, firmware-profiles.json).
// NON VERIFIEES sur console par l'auteur de cet ajout : seule la source indique
// "community-confirmed" pour 11.20, 12.40, 13.40 et 13.60.
// 11.40 : table KERNEL_ADDRESS_* fournie par l'utilisateur (meme bucket noyau
// que 11.00/11.20/11.60 pour allproc/security_flags/root_vnode) -> ajoute ci-dessous.
static constexpr uint32_t V1100 = 0x11000000;
static constexpr uint32_t V1120 = 0x11200000;
static constexpr uint32_t V1140 = 0x11400000;
static constexpr uint32_t V1160 = 0x11600000;
static constexpr uint32_t V1200 = 0x12000000;
static constexpr uint32_t V1202 = 0x12020000;
static constexpr uint32_t V1220 = 0x12200000;
static constexpr uint32_t V1240 = 0x12400000;
static constexpr uint32_t V1260 = 0x12600000;
static constexpr uint32_t V1270 = 0x12700000;
static constexpr uint32_t V1300 = 0x13000000;
static constexpr uint32_t V1320 = 0x13200000;
static constexpr uint32_t V1340 = 0x13400000;
static constexpr uint32_t V1342 = 0x13420000;
static constexpr uint32_t V1360 = 0x13600000;
// 14.xx : table KERNEL_ADDRESS_* fournie par l'utilisateur. NON VERIFIE sur
// console par l'auteur de cet ajout.
static constexpr uint32_t V1400 = 0x14000000;
static constexpr uint32_t V1410 = 0x14100000;




uint32_t getSystemSwVersion() {
    static uint32_t version;
    if (version != 0) [[likely]] {
        return version;
    }
    size_t size = 4;
    sysctlbyname("kern.sdk_version", &version, &size, nullptr, 0);
    return version;
}
namespace offsets {
    size_t allproc() {
        static size_t allprocOffset;
        if (allprocOffset != 0) [[likely]] {
            return allprocOffset;
        }
        switch (getSystemSwVersion() & VERSION_MASK) {
            case V100: case V101: case V102: case V105:
            case V110: case V111: case V112: case V113:
            case V114:
                allprocOffset = 0x26D1C18;
                break;
            case V200: case V220: case V225: case V226:
            case V230: case V250: case V270:
                allprocOffset = 0x2701C28;
                break;
            case V300: case V310: case V320: case V321:
                allprocOffset = 0x276DC58;
                break;
            case V400: case V402: case V403: case V450: case V451:
                allprocOffset = 0x27EDCB8;
                break;
            case V500: case V502: case V510: case V550:
                allprocOffset = 0x291DD00;
                break;
            case V600: case V602: case V650:
                allprocOffset = 0x2869D20;
                break;
            case V700: case V701: case V720: case V740: case V760: case V761:
                allprocOffset = 0x2859D50;
                break;
            case V800: case V820: case V840: case V860:
                allprocOffset = 0x2875D50;
                break;
            case V900:
                allprocOffset = 0x2755D50;
                break;
            case V905: case V920: case V940: case V960:
                allprocOffset = 0x2755D50;
                break;
            case V1000: case V1001: case V1020: case V1040: case V1060:
                allprocOffset = 0x2765D70;
                break;
            // -- 11.xx -> 13.xx (valeurs publiques, NON VERIFIEES) --
            // 11.00 / 11.20 / 11.40 / 11.60
            case V1100: case V1120: case V1140: case V1160:
                allprocOffset = 0x2875D70;
                break;
            // 12.00 / 12.02 / 12.20 / 12.40 / 12.60 / 12.70
            case V1200: case V1202: case V1220: case V1240: case V1260: case V1270:
                allprocOffset = 0x2885E00;
                break;
            // 13.00 / 13.20
            case V1300: case V1320:
                allprocOffset = 0x28C5E00;
                break;
            // 13.40 / 13.42
            case V1340: case V1342:
                allprocOffset = 0x28C9E80;
                break;
            // 13.60
            case V1360:
                allprocOffset = 0x28C9E80;
                break;
            // 14.00 / 14.10
            case V1400: case V1410:
                allprocOffset = 0x28D9EA0;
                break;
            default:
                printf("Unsupported firmware version: 0x%x\n", getSystemSwVersion() & VERSION_MASK);
                allprocOffset = -1;
                break;
        }
        return allprocOffset;
    }

    size_t security_flags() {
        switch (getSystemSwVersion() & VERSION_MASK) {
            case V100: case V101: case V102: case V105:
            case V110: case V111: case V112: case V113:
            case V114:
                return 0x6241074;
            case V200: case V220: case V225: case V226:
            case V230: case V250: case V270:
                return 0x63E1274;
            case V300: case V310: case V320: case V321:
                return 0x6466474;
            case V400: case V402: case V403: case V450: case V451:
                return 0x6506474;
            case V500: case V502: case V510: case V550:
                return 0x66466EC; // SECURITY_FLAGS
            case V600: case V602: case V650:
                return 0x65968EC;
            case V700: case V701: case V720: case V740: case V760: case V761:
                return 0x0AC8064;
            case V800: case V820: case V840: case V860:
                return 0x0AC3064;
            case V900:
                return 0x0D72064;
            case V905: case V920: case V940: case V960:
                return 0x0D73064;
            case V1000: case V1001: case V1020: case V1040: case V1060:
                return 0x0D79064;
            // -- 11.xx -> 13.xx (valeurs publiques, NON VERIFIEES) --
            // 11.00 / 11.20 / 11.40 / 11.60
            case V1100: case V1120: case V1140: case V1160:
                return 0xD8C064;
            // 12.00 / 12.02 / 12.20 / 12.40 / 12.60 / 12.70
            case V1200: case V1202: case V1220: case V1240: case V1260: case V1270:
                return 0xD83064;
            // 13.00 / 13.20 / 13.40 / 13.42 -- CONFIRME independamment par
            // ps5debug-NG (projet "Fully Verified" sur materiel reel) : son
            // kpatch syscall-filter pour 13.0x-13.4x cible kbase + 0xD99088 =
            // security_flags() + 0x24 (= qa_flags()), donc 0xD99064 est
            // valide, pas juste porte d'une table.
            case V1300: case V1320:
                return 0xD99064;
            case V1340: case V1342:
                return 0xD99064;
            // 13.60 -- idem, confirme par ps5debug-NG : kpatch cible
            // kbase + 0xD9C088 = security_flags() + 0x24 (= qa_flags()),
            // donc 0xD9C064 est valide.
            case V1360:
                return 0xD9C064;
            // 14.00 / 14.10
            case V1400: case V1410:
                return 0xDA4064;
            default:
                printf("Unsupported firmware version: 0x%x\n", getSystemSwVersion() & VERSION_MASK);
                return -1;
        }
    }

    size_t qa_flags() {
        switch (getSystemSwVersion() & VERSION_MASK) {
            case V100: case V101: case V102: case V105:
            case V110: case V111: case V112: case V113:
            case V114:
            case V200: case V220: case V225: case V226:
            case V230: case V250: case V270:
            case V300: case V310: case V320: case V321:
            case V400: case V402: case V403: case V450: case V451:
                return 0x6506498;
            case V500: case V502: case V510: case V550:
                return 0x6241098;
            case V600: case V602: case V650:
                return 0x65968EC + 0x24;
            case V700: case V701: case V720: case V740: case V760: case V761:
                return 0x0AC8064 + 0x24;
            case V800: case V820: case V840: case V860:
                return 0x0AC3088; //0x0AC3064 + 0x24
            case V900:
                return 0x0D72088; //0x0D72064 + 0x24
            case V905: case V920: case V940: case V960:
                return 0x0D73088; //0x0D73064 + 0x24
            case V1000: case V1001: case V1020: case V1040: case V1060:
                return 0x0D79088; //0x0D79064 + 0x24
            // -- 11.xx -> 13.xx (valeurs publiques, NON VERIFIEES) --
            // 11.00 / 11.20 / 11.40 / 11.60
            case V1100: case V1120: case V1140: case V1160:
                return 0xD8C064 + 0x24;
            // 12.00 / 12.02 / 12.20 / 12.40 / 12.60 / 12.70
            case V1200: case V1202: case V1220: case V1240: case V1260: case V1270:
                return 0xD83064 + 0x24;
            // 13.00 / 13.20
            case V1300: case V1320:
                return 0xD99064 + 0x24;
            // 13.40 / 13.42
            case V1340: case V1342:
                return 0xD99064 + 0x24;
            // 13.60
            case V1360:
                return 0xD9C064 + 0x24;
            // 14.00 / 14.10
            case V1400: case V1410:
                return 0xDA4064 + 0x24;
            default:
                printf("Unsupported firmware version: 0x%x\n", getSystemSwVersion() & VERSION_MASK);
                return -1;
        }
    }

    size_t utoken_flags() {
        switch (getSystemSwVersion() & VERSION_MASK) {
            case V100: case V101: case V102: case V105:
            case V110: case V111: case V112: case V113:
            case V114:
            case V200: case V220: case V225: case V226:
            case V230: case V250: case V270:
            case V300: case V310: case V320: case V321:
            case V400: case V402: case V403: case V450: case V451:
                return 0x6506500;
            case V500: case V502: case V510: case V550: 
                return 0x6646710; //qa flags offset
            case V600: case V602: case V650:
                return 0x65968EC + 0x8C;
            case V700: case V701: case V720: case V740: case V760: case V761:
                return 0x0AC8064 + 0x8C;
            case V800: case V820: case V840: case V860:
                return 0x0AC30F0; //0x0AC3064 + 0x8C
            case V900:
                return 0x0D720F0; //0x0D72064 + 0x8C
            case V905: case V920: case V940: case V960:
                return 0x0D730F0; //0x0D73064 + 0x8C
            case V1000: case V1001: case V1020: case V1040: case V1060:
                return 0x0D790F0; //0x0D79064 + 0x8C
            // -- 11.xx -> 13.xx (valeurs publiques, NON VERIFIEES) --
            // 11.00 / 11.20 / 11.40 / 11.60
            case V1100: case V1120: case V1140: case V1160:
                return 0xD8C064 + 0x8C;
            // 12.00 / 12.02 / 12.20 / 12.40 / 12.60 / 12.70
            case V1200: case V1202: case V1220: case V1240: case V1260: case V1270:
                return 0xD83064 + 0x8C;
            // 13.00 / 13.20
            case V1300: case V1320:
                return 0xD99064 + 0x8C;
            // 13.40 / 13.42
            case V1340: case V1342:
                return 0xD99064 + 0x8C;
            // 13.60
            case V1360:
                return 0xD9C064 + 0x8C;
            // 14.00 / 14.10
            case V1400: case V1410:
                return 0xDA4064 + 0x8C;
            default:
                printf("Unsupported firmware version: 0x%x\n", getSystemSwVersion() & VERSION_MASK);
                return -1;
        }
    }

    size_t root_vnode() {
        switch (getSystemSwVersion() & VERSION_MASK) {
            case V100: case V101: case V102: case V105:
            case V110: case V111: case V112: case V113:
            case V114:
                return 0x6565540;
            case V200: case V220: case V225: case V226:
            case V230: case V250: case V270:
                return 0x67134C0;
            case V300: case V310: case V320: case V321:
                return 0x67AB4C0;
            case V400: case V402: case V403: case V450: case V451:
                return 0x66E74C0;
            case V500: case V502: case V510: case V550:
                return 0x6853510;
            case V600: case V602: case V650:
                return 0x679F510;
            case V700: case V701: case V720: case V740: case V760: case V761:
                return 0x30C7510;
            case V800: case V820: case V840: case V860:
                return 0x30FB510;
            case V900:
                return 0x2FDB510;
            case V905: case V920: case V940: case V960:
                return 0x2FDB510;
            case V1000: case V1001: case V1020: case V1040: case V1060:
                return 0x2FA3510;
            // -- 11.xx -> 13.xx (valeurs publiques, NON VERIFIEES) --
            // 11.00 / 11.20 / 11.40 / 11.60
            case V1100: case V1120: case V1140: case V1160:
                return 0x30B7510;
            // 12.00 / 12.02 / 12.20 / 12.40 / 12.60 / 12.70
            case V1200: case V1202: case V1220: case V1240: case V1260: case V1270:
                return 0x30D7510;
            // 13.00 / 13.20
            case V1300: case V1320:
                return 0x3133510;
            // 13.40 / 13.42
            case V1340: case V1342:
                return 0x3137510;
            // 13.60
            case V1360:
                return 0x314B510;
            // 14.00 / 14.10
            case V1400: case V1410:
                return 0x315B510;
            default:
                printf("Unsupported firmware version: 0x%x\n", getSystemSwVersion() & VERSION_MASK);
                return -1;
        }
    }

    // ── Ajouts : champs KERNEL_ADDRESS_TEXT_BASE / BUS_DATA_DEVICES et
    // KERNEL_OFFSET_VMSPACE_P_ROOT / VM_PMAP fournis par l'utilisateur.
    // NON UTILISES ailleurs dans le code actuel (aucun appelant existant) et
    // NON VERIFIES sur console : ajoutes tels quels depuis la table fournie.
    // text_base_delta() est SIGNE : l'adresse reelle est
    //   kernel_data_base + text_base_delta()   (le delta est negatif ici).

    int64_t text_base_delta() {
        switch (getSystemSwVersion() & VERSION_MASK) {
            case V100: case V101: case V102:
            case V105: case V110: case V111: case V112: case V113: case V114:
                return -0x1B40000;
            case V200: case V220: case V225: case V226:
            case V230: case V250: case V270:
                return -0x1B80000;
            case V300: case V310: case V320: case V321:
                return -0x0BD0000;
            case V400: case V402: case V403: case V450: case V451:
                return -0x0C00000;
            case V500: case V502: case V510: case V550:
                return -0x0C40000;
            case V600: case V602: case V650:
                return -0x0C60000;
            case V700: case V701: case V720: case V740: case V760: case V761:
                return -0x0C50000;
            case V800: case V820: case V840: case V860:
                return -0x0C70000;
            case V900: case V905: case V920: case V940: case V960:
                return -0x0CA0000;
            case V1000: case V1001: case V1020: case V1040: case V1060:
                return -0x0CC0000;
            case V1100: case V1120: case V1140: case V1160:
                return -0x0D30000;
            case V1200: case V1202: case V1220: case V1240: case V1260: case V1270:
                return -0x0D50000;
            case V1300: case V1320:
                return -0x0CB0000;
            case V1340: case V1342:
                return -0x0CB0000;
            case V1360:
                return -0x0CC0000;
            case V1400: case V1410:
                return -0x0CE0000;
            default:
                printf("Unsupported firmware version: 0x%x\n", getSystemSwVersion() & VERSION_MASK);
                return 0;
        }
    }

    size_t bus_data_devices() {
        switch (getSystemSwVersion() & VERSION_MASK) {
            case V100: case V101: case V102:
                return 0x1D6D478;
            case V105: case V110: case V111: case V112: case V113: case V114:
                return 0x1D6D487;
            case V200: case V220: case V225: case V226:
            case V230: case V250: case V270:
                return 0x1D91478;
            case V300: case V310: case V320: case V321:
                return 0x1DF1678;
            case V400: case V402: case V403: case V450: case V451:
                return 0x1E69678;
            case V500: case V502: case V510: case V550:
                return 0x1F996C8;
            case V600: case V602: case V650:
                return 0x1FB96C8;
            case V700: case V701: case V720: case V740: case V760: case V761:
                return 0x1FA5718;
            case V800: case V820: case V840: case V860:
                return 0x1FA5718;
            case V900: case V905: case V920: case V940: case V960:
                return 0x1F65718;
            case V1000: case V1001: case V1020: case V1040: case V1060:
                return 0x1F65718;
            case V1100: case V1120: case V1140: case V1160:
                return 0x2075718;
            case V1200: case V1202: case V1220: case V1240: case V1260: case V1270:
                return 0x20757E8;
            case V1300: case V1320:
                return 0x20981E8;
            case V1340: case V1342:
                return 0x20981E8;
            case V1360:
                return 0x2098228;
            case V1400: case V1410:
                return 0x20A8878;
            default:
                printf("Unsupported firmware version: 0x%x\n", getSystemSwVersion() & VERSION_MASK);
                return -1;
        }
    }

    // Offsets de champs DANS la structure vmspace (pas relatifs a
    // KERNEL_ADDRESS_DATA_BASE, contrairement aux fonctions ci-dessus).
    size_t vmspace_p_root() {
        switch (getSystemSwVersion() & VERSION_MASK) {
            case V100: case V101: case V102:
                return 0x1c0;
            case V105: case V110: case V111: case V112: case V113: case V114:
            case V200: case V220: case V225: case V226:
            case V230: case V250: case V270:
            case V300: case V310: case V320: case V321:
            case V400: case V402: case V403: case V450: case V451:
            case V500: case V502: case V510: case V550:
                return 0x1c8;
            case V600: case V602: case V650:
            case V700: case V701: case V720: case V740: case V760: case V761:
            case V800: case V820: case V840: case V860:
            case V900: case V905: case V920: case V940: case V960:
            case V1000: case V1001: case V1020: case V1040: case V1060:
            case V1100: case V1120: case V1140: case V1160:
            case V1200: case V1202: case V1220: case V1240: case V1260: case V1270:
            case V1300: case V1320: case V1340: case V1342: case V1360:
            case V1400: case V1410:
                return 0x1d0;
            default:
                printf("Unsupported firmware version: 0x%x\n", getSystemSwVersion() & VERSION_MASK);
                return -1;
        }
    }

    size_t vmspace_vm_pmap() {
        switch (getSystemSwVersion() & VERSION_MASK) {
            case V100: case V101: case V102:
                return 0x2c0;
            case V105: case V110: case V111: case V112: case V113: case V114:
            case V200: case V220: case V225: case V226:
            case V230: case V250: case V270:
            case V300: case V310: case V320: case V321:
            case V400: case V402: case V403: case V450: case V451:
            case V500: case V502: case V510: case V550:
                return 0x2e0;
            case V600: case V602: case V650:
            case V700: case V701: case V720: case V740: case V760: case V761:
            case V800: case V820: case V840: case V860:
            case V900: case V905: case V920: case V940: case V960:
            case V1000: case V1001: case V1020: case V1040: case V1060:
            case V1100: case V1120: case V1140: case V1160:
            case V1200: case V1202: case V1220: case V1240: case V1260: case V1270:
            case V1300: case V1320: case V1340: case V1342: case V1360:
            case V1400: case V1410:
                return 0x2e8;
            default:
                printf("Unsupported firmware version: 0x%x\n", getSystemSwVersion() & VERSION_MASK);
                return -1;
        }
    }
}