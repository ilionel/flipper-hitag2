#pragma once

// Internal header shared by the Hitag app core (hitag_app.c) and the menu module
// (hitag_menu.c). It holds the app state struct, the view/menu enums, the layout
// constants, and the declarations of the handlers the menu dispatches to (and of
// the menu builder/navigation the app registers). Not a public interface.

#include <furi.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_input.h>
#include <gui/modules/byte_input.h>
#include <gui/modules/variable_item_list.h>
#include <storage/storage.h>
#include <dialogs/dialogs.h>
#include <flipper_format/flipper_format.h>
#include <notification/notification_messages.h>
#include <furi_hal_rfid.h>
#include <furi_hal_rtc.h>
#include "hitag_worker.h"
#include "hitag_frames.h"

#define HITAG_DIR EXT_PATH("apps_data/hitag")
#define HITAG_EXT ".hitag"
#define HITAG_CONF EXT_PATH("apps_data/hitag/settings.conf") // persisted keys + tuning + debug
#define HITAG_NAME_LEN 32

#define HITAG_LINE_LEN 24
#define HITAG_LINES_MAX 12
#define HITAG_VISIBLE 4 // content lines shown between title and footer

// Emu autotune: sweep T_wresp x leadbit at the proven preamble 4 (5/6/7 never complete a
// read on PM3, and against a strict reader every preamble stalled at AUTH). T_wresp is the one Hitag2
// lever never tested against a strict reader: poll+DMA-start latency can push our reply past the
// 204..212 Tc spec window, so a strict reader (reader) rejects it where the tolerant PM3
// accepts. Sweep around AND below 1664us to land the reply back in-window.
// Bench-proven: preamble 4 is best (6 and 8 scored 0 PWD/READ). So the autotune fixes
// preamble 4 and sweeps only a FINE in-window T_wresp {1664,1648,1680}, with lock-on-success.
#define HITAG_AT_NPRE 1 // preamble fixed at 4 (proven best)
#define HITAG_AT_NWRESP 3 // T_wresp fine, in-window: {1664,1648,1680}
#define HITAG_AT_NCOMBO (HITAG_AT_NPRE * HITAG_AT_NWRESP) // 3
#define HITAG_AT_DWELL 24 // ~6s per combo

typedef enum {
    HitagViewSubmenu,
    HitagViewScan, // live read/sniff/emulate animation
    HitagViewContent, // scrollable tag content (UID / password / pages)
    HitagViewTextInput,
    HitagViewByteInput,
    HitagViewTuning, // emulate reply tuning (preamble / T_wresp)
} HitagView;

typedef enum {
    // leaf actions
    HitagMenuDetect,
    HitagMenuReadHt2,
    HitagMenuReadHt1,
    HitagMenuReadHtS,
    HitagMenuSniffHt2,
    HitagMenuSniffHt2Nonce, // Hitag2 crypto: capture nR/aR nonce pairs (for the PC cracker)
    HitagMenuSniffHtS82xx, // Hitag S: capture the 8268/8310 password write
    HitagMenuEmulate,
    HitagMenuEmulateHt1,
    HitagMenuEmulateHtS,
    HitagMenuEmuSettings,
    HitagMenuPassword,
    HitagMenuHtsKey,
    HitagMenuHts82xx,
    HitagMenuResetDefaults, // Settings -> reset all settings to factory defaults
    HitagMenuDebugTraces, // toggle in the Debug submenu
    HitagMenuLeanLogs, // toggle in the Debug submenu
    // card actions (shown on the card menu after a Read / Saved), NFC-style
    HitagCardInfo,
    HitagCardEmulate,
    HitagCardSave,
    HitagCardRename,
    HitagCardDelete,
    // group items (open a sub-level) — keep after the leaves
    HitagGroupRead,
    HitagGroupSniff,
    HitagGroupEmulate,
    HitagMenuSaved, // "Saved" opens the dump browser directly (NFC-style), then the card menu
    HitagGroupSettings,
    HitagGroupDebug,
} HitagMenuItem;

// tag family of the current dump — used only to name a Save (hitag1_/hitag2_/hitags_)
typedef enum {
    HitagTypeHt1,
    HitagTypeHt2,
    HitagTypeHtS,
} HitagTagType;

// nested-menu level (NFC-style: a few top groups, Back walks up one level)
typedef enum {
    MLTop,
    MLRead,
    MLSniff,
    MLEmulate,
    MLCard, // per-dump action menu (after a Read / Saved)
    MLSettings,
    MLDebug,
} HitagMenuLevel;

typedef struct {
    Gui* gui;
    Storage* storage;
    DialogsApp* dialogs;
    ViewDispatcher* view_dispatcher;
    Submenu* submenu; // main menu (nested: repopulated per level)
    HitagMenuLevel menu_level; // current submenu level (Back walks up)
    char debug_label[24]; // persistent label for the Debug "Traces: on/off" item
    char lean_label[24]; // persistent label for the Debug "Lean logs: on/off" item
    HitagTagType tag_type; // family of the current dump (set on Read/Detect/Load) -> Save name
    View* scan_view; // read/sniff/emulate animation
    View* content_view; // scrollable tag content
    VariableItemList* tuning; // emulate reply tuning list
    TextInput* text_input;
    ByteInput* byte_input;
    NotificationApp* notifications;
    HitagWorker* worker;
    FuriMutex* worker_mutex; // sérialise free(worker) [GUI] vs accès worker [thread timer]
    FuriTimer* timer;
    bool emulating;
    bool detect_mode; // alternate Hitag2<->Hitag1 to find the tag type
    bool detect_locked; // a type was detected; stop alternating
    HitagWorkerSetting detect_setting;
    uint8_t detect_ticks; // ticks on the current detect attempt before switching
    bool found; // success feedback latched
    bool has_data; // last_pages holds a valid dump (read or loaded)
    bool scan_is_sniff; // the running scan is a sniff (password / nonces / 82xx)
    HitagWorkerSetting scan_setting; // the setting driving the current scan (sniff target)
    bool from_sniff; // current dump came from a sniff (password only, no UID)
    bool from_saved; // current dump was loaded from a file (enables Rename/Delete on the card)
    char card_header[24]; // "<type> <UID>" header for the card menu
    char loaded_path[192]; // path of the loaded .hitag (for card Rename/Delete)
    bool renaming; // the text-input commit renames the loaded file instead of saving a new one
    uint8_t password[4]; // current Hitag2 password (default MIKR)
    uint8_t hts_key[6]; // Hitag S crypto key (default ONMIKR) — matches the reader's -k bytes
    uint8_t hts_82xx[4]; // Hitag S 8268/8310 password (default BB DD 33 99)
    uint8_t last_pages[32]; // last read/loaded pages (for Save / Emulate / content)
    char scan_title[24]; // title carried from scan to content view
    char save_name[HITAG_NAME_LEN];
    uint8_t emu_preamble; // emulate reply preamble length (default 5)
    uint32_t emu_wresp_us; // emulate reply T_wresp in us (default 1664)
    uint8_t emu_leadbit; // emulate reply: prepend a '0' data bit (default 0)
    uint8_t emu_lean; // emulate: skip live command log (min reply jitter, default 0)
    uint8_t emu_fast; // emulate: answer config on any 32-bit frame (Tolerant mode, default 0)
    uint8_t emu_auto; // emulate: Auto timing -> run the T_wresp autotune sweep (default 0)
    uint8_t debug_traces; // record diagnostic files (emulog/autotune/snifflog) — default OFF
    // autotune sweep state
    bool autotune;
    uint8_t at_combo; // current combo index
    uint8_t at_dwell; // timer ticks elapsed on the current combo
    uint16_t at_base_a, at_base_p, at_base_r; // cumulative-count snapshot at combo start
    uint16_t at_aa[HITAG_AT_NCOMBO]; // accumulated AUTH per combo
    uint16_t at_pp[HITAG_AT_NCOMBO]; // accumulated PWD per combo
    uint16_t at_rr[HITAG_AT_NCOMBO]; // accumulated READ per combo
    bool at_locked; // autotune: locked onto a winning combo (stop sweeping after a hit)
    uint16_t emu_prev_pwd, emu_prev_read; // last seen counts (haptic feedback on increment)
} HitagApp;

// --- app handlers the menu dispatches to (defined in hitag_app.c) ---
void hitag_build_content(HitagApp* app, const char* title);
void hitag_handle_load(HitagApp* app);
void hitag_handle_save(HitagApp* app);
void hitag_handle_rename(HitagApp* app);
void hitag_card_delete(HitagApp* app);
void hitag_start_detect(HitagApp* app);
void hitag_start_read(HitagApp* app, HitagWorkerSetting setting, const char* title);
void hitag_handle_emulate(HitagApp* app);
void hitag_emulate_by_type(HitagApp* app);
void hitag_emulate_hitag1(HitagApp* app);
void hitag_emulate_hitagS(HitagApp* app);
void hitag_emulate_ht2_crypto(HitagApp* app);
void hitag_handle_emu_settings(HitagApp* app);
void hitag_byte_input_cb(void* ctx); // byte-input commit (password / Hitag S key / 82xx)
void hitag_config_reset(HitagApp* app); // Settings -> reset all settings to factory defaults

// --- menu builder + navigation (defined in hitag_menu.c, registered by the app) ---
void hitag_build_menu(HitagApp* app, HitagMenuLevel level);
bool hitag_nav_cb(void* ctx);
uint32_t hitag_prev_menu(void* ctx);
