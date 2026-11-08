#ifndef SM_PATHS_H
#define SM_PATHS_H

#define IMAGE_MOUNT_BASE "/mnt/shadowmod"
#define PFSC_IMAGE_MOUNT_BASE "/mnt/shadowmod/pfsc"

#define DEFAULT_BACKPORTS_DIR_NAME "backports"
#define DEFAULT_GLOBAL_FAKELIB_PATH "/data/PluginLoader/fakelib"
#define LOG_DIR "/data/PluginLoader"
#define LOG_FILE "/data/PluginLoader/debug.log"
#define LOG_FILE_PREV "/data/PluginLoader/debug.log.1"
#define CONFIG_FILE "/data/PluginLoader/config.ini"
#define AUTOTUNE_FILE "/data/PluginLoader/autotune.ini"
#define MANUAL_LIST_FILE "/data/PluginLoader/manual.lst"
#define MANUAL_STATUS_FILE "/data/PluginLoader/manual.status"
#define IMAGE_INDEX_FILE_PATH "/data/PluginLoader/image_index.bin"
#define APPMETA_BASE "/user/appmeta"
#define APP_BASE "/user/app"
#define KSTUFF_NOAUTOMOUNT_FILE "/data/.kstuff_noautomount"
#define KILL_FILE "/data/PluginLoader/STOP"
#define TOAST_FILE "/data/PluginLoader/notify.txt"
#define NOTIFY_ICON_DIR "/user/data/PluginLoader"
#define NOTIFY_ICON_FILE "/user/data/PluginLoader/smp_icon.png"
#define APP_DB_PATH "/system_data/priv/mms/app.db"

/* Compile-time default scan roots (used when config has no scanpath entries). */
#define SM_DEFAULT_SCAN_PATHS_INITIALIZER                                      \
  {                                                                            \
    /* Internal */                                                             \
    "/data/homebrew", "/data/etaHEN/games",                                   \
    /* Extended Storage */                                                     \
    "/mnt/ext0/homebrew", "/mnt/ext0/etaHEN/games",                           \
    /* M.2 Drive */                                                            \
    "/mnt/ext1/homebrew", "/mnt/ext1/etaHEN/games",                           \
    /* USB Subfolders */                                                       \
    "/mnt/usb0/homebrew", "/mnt/usb1/homebrew", "/mnt/usb2/homebrew",         \
        "/mnt/usb3/homebrew", "/mnt/usb4/homebrew", "/mnt/usb5/homebrew",     \
        "/mnt/usb6/homebrew", "/mnt/usb7/homebrew",                           \
        "/mnt/usb0/etaHEN/games", "/mnt/usb1/etaHEN/games",                   \
        "/mnt/usb2/etaHEN/games", "/mnt/usb3/etaHEN/games",                   \
        "/mnt/usb4/etaHEN/games", "/mnt/usb5/etaHEN/games",                   \
        "/mnt/usb6/etaHEN/games", "/mnt/usb7/etaHEN/games",                   \
    /* USB Root Paths */                                                       \
    "/mnt/usb0", "/mnt/usb1", "/mnt/usb2", "/mnt/usb3", "/mnt/usb4",          \
        "/mnt/usb5", "/mnt/usb6", "/mnt/usb7", "/mnt/ext0", "/mnt/ext1", NULL \
  }

#endif
