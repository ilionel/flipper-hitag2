// Nested Submenu UI for the Hitag app.
//
// One Submenu view is repopulated per level (hitag_build_menu): a few top-level
// groups (Read / Saved / Emulate / Sniff / Settings / Debug), each opening a focused
// list, plus the per-card action menu shown after a Read/Sniff or a Saved dump.
// hitag_submenu_cb dispatches a tapped item -- descending into a sub-level or calling
// the matching app handler -- and hitag_nav_cb / hitag_prev_menu implement Back
// (walk one level up, exit at the top). All app state + handlers come from
// hitag_app_i.h; this file owns no logic beyond menu layout and dispatch.

#include "hitag_app_i.h"

#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/byte_input.h>

static void hitag_submenu_cb(void* ctx, uint32_t index);

// (Re)populate the single Submenu view for a given level. NFC-style nesting: a handful of
// top-level groups, each opening a focused list; Back (hitag_nav_cb) walks one level up.
void hitag_build_menu(HitagApp* app, HitagMenuLevel level) {
    Submenu* sm = app->submenu;
    submenu_reset(sm);
    app->menu_level = level;
    switch(level) {
    case MLTop:
        submenu_set_header(sm, "Hitag");
        submenu_add_item(sm, "Read", HitagGroupRead, hitag_submenu_cb, app);
        submenu_add_item(sm, "Saved", HitagMenuSaved, hitag_submenu_cb, app);
        submenu_add_item(sm, "Emulate", HitagGroupEmulate, hitag_submenu_cb, app);
        submenu_add_item(sm, "Sniff", HitagGroupSniff, hitag_submenu_cb, app);
        submenu_add_item(sm, "Settings", HitagGroupSettings, hitag_submenu_cb, app);
        submenu_add_item(sm, "Debug", HitagGroupDebug, hitag_submenu_cb, app);
        break;
    case MLRead:
        submenu_set_header(sm, "Read");
        // protocols in NXP release order: Hitag1 -> Hitag2 -> Hitag S
        submenu_add_item(sm, "Detect (auto)", HitagMenuDetect, hitag_submenu_cb, app);
        submenu_add_item(sm, "Hitag1", HitagMenuReadHt1, hitag_submenu_cb, app);
        submenu_add_item(sm, "Hitag2", HitagMenuReadHt2, hitag_submenu_cb, app);
        submenu_add_item(sm, "Hitag S", HitagMenuReadHtS, hitag_submenu_cb, app);
        break;
    case MLSniff:
        submenu_set_header(sm, "Sniff");
        submenu_add_item(sm, "Hitag2 password", HitagMenuSniffHt2, hitag_submenu_cb, app);
        submenu_add_item(sm, "Hitag2 crypto", HitagMenuSniffHt2Nonce, hitag_submenu_cb, app);
        submenu_add_item(sm, "Hitag S 82xx", HitagMenuSniffHtS82xx, hitag_submenu_cb, app);
        break;
    case MLEmulate:
        submenu_set_header(sm, "Emulate");
        // same protocol choice as Read, NXP release order. Hitag2 auto-picks password vs
        // crypto from the dump's config page (0x06 = password, 0x0E = crypto).
        submenu_add_item(sm, "Hitag1", HitagMenuEmulateHt1, hitag_submenu_cb, app);
        submenu_add_item(sm, "Hitag2", HitagMenuEmulate, hitag_submenu_cb, app);
        submenu_add_item(sm, "Hitag S", HitagMenuEmulateHtS, hitag_submenu_cb, app);
        break;
    case MLCard: // per-dump actions (after a Read or Saved), NFC-style
        submenu_set_header(sm, app->card_header);
        submenu_add_item(sm, "Info", HitagCardInfo, hitag_submenu_cb, app);
        submenu_add_item(sm, "Emulate", HitagCardEmulate, hitag_submenu_cb, app);
        submenu_add_item(sm, "Save", HitagCardSave, hitag_submenu_cb, app);
        if(app->from_saved) {
            submenu_add_item(sm, "Rename", HitagCardRename, hitag_submenu_cb, app);
            submenu_add_item(sm, "Delete", HitagCardDelete, hitag_submenu_cb, app);
        }
        break;
    case MLSettings:
        submenu_set_header(sm, "Settings");
        submenu_add_item(sm, "Emulation tuning", HitagMenuEmuSettings, hitag_submenu_cb, app);
        submenu_add_item(sm, "Hitag2 password", HitagMenuPassword, hitag_submenu_cb, app);
        submenu_add_item(sm, "Hitag S key", HitagMenuHtsKey, hitag_submenu_cb, app);
        submenu_add_item(sm, "Hitag S 82xx pwd", HitagMenuHts82xx, hitag_submenu_cb, app);
        submenu_add_item(sm, "Reset to defaults", HitagMenuResetDefaults, hitag_submenu_cb, app);
        break;
    case MLDebug:
        submenu_set_header(sm, "Debug");
        snprintf(
            app->debug_label, sizeof(app->debug_label), "Traces: %s",
            app->debug_traces ? "on" : "off");
        submenu_add_item(sm, app->debug_label, HitagMenuDebugTraces, hitag_submenu_cb, app);
        snprintf(
            app->lean_label, sizeof(app->lean_label), "Lean logs: %s",
            app->emu_lean ? "on" : "off");
        submenu_add_item(sm, app->lean_label, HitagMenuLeanLogs, hitag_submenu_cb, app);
        break;
    }
}

static void hitag_submenu_cb(void* ctx, uint32_t index) {
    HitagApp* app = ctx;
    switch(index) {
    // group items -> descend into the sub-level
    case HitagGroupRead:
        hitag_build_menu(app, MLRead);
        return;
    case HitagGroupSniff:
        hitag_build_menu(app, MLSniff);
        return;
    case HitagGroupEmulate:
        hitag_build_menu(app, MLEmulate);
        return;
    case HitagMenuSaved: // open the dump browser directly (NFC-style) -> card menu on success
        hitag_handle_load(app);
        return;
    // card actions (after a Read / Saved)
    case HitagCardInfo:
        hitag_build_content(app, app->card_header);
        view_dispatcher_switch_to_view(app->view_dispatcher, HitagViewContent);
        return;
    case HitagCardEmulate:
        hitag_emulate_by_type(app);
        return;
    case HitagCardSave:
        hitag_handle_save(app);
        return;
    case HitagCardRename:
        hitag_handle_rename(app);
        return;
    case HitagCardDelete:
        hitag_card_delete(app);
        return;
    case HitagGroupSettings:
        hitag_build_menu(app, MLSettings);
        return;
    case HitagGroupDebug:
        hitag_build_menu(app, MLDebug);
        return;
    case HitagMenuDebugTraces: // toggle + rebuild to refresh the label, keep the cursor on it
        app->debug_traces = !app->debug_traces;
        hitag_build_menu(app, MLDebug);
        submenu_set_selected_item(app->submenu, 0);
        return;
    case HitagMenuLeanLogs:
        app->emu_lean = !app->emu_lean;
        hitag_build_menu(app, MLDebug);
        submenu_set_selected_item(app->submenu, 1);
        return;
    case HitagMenuDetect:
        hitag_start_detect(app);
        break;
    case HitagMenuReadHt2:
        hitag_start_read(app, HitagWorkerSettingReadHitag2, "Read Hitag2");
        break;
    case HitagMenuReadHtS:
        hitag_start_read(app, HitagWorkerSettingReadHitagS, "Read Hitag S");
        break;
    case HitagMenuReadHt1:
        hitag_start_read(app, HitagWorkerSettingRead, "Read Hitag1");
        break;
    case HitagMenuSniffHt2:
        hitag_start_read(app, HitagWorkerSettingSniffHitag2, "Sniff Hitag2");
        break;
    case HitagMenuSniffHt2Nonce:
        hitag_start_read(app, HitagWorkerSettingSniffHitag2Nonce, "Sniff HT2 crypto");
        break;
    case HitagMenuSniffHtS82xx:
        hitag_start_read(app, HitagWorkerSettingSniffHitagS82xx, "Sniff HtS 82xx");
        break;
    case HitagMenuEmulate:
        hitag_handle_emulate(app);
        break;
    case HitagMenuEmulateHt1:
        hitag_emulate_hitag1(app);
        break;
    case HitagMenuEmulateHtS:
        hitag_emulate_hitagS(app);
        break;
    case HitagMenuEmuSettings:
        hitag_handle_emu_settings(app);
        break;
    case HitagMenuPassword:
        byte_input_set_result_callback(
            app->byte_input, hitag_byte_input_cb, NULL, app, app->password, 4);
        byte_input_set_header_text(app->byte_input, "Hitag2 password (RWD)");
        view_dispatcher_switch_to_view(app->view_dispatcher, HitagViewByteInput);
        break;
    case HitagMenuHtsKey:
        byte_input_set_result_callback(
            app->byte_input, hitag_byte_input_cb, NULL, app, app->hts_key, 6);
        byte_input_set_header_text(app->byte_input, "Hitag S crypto key (6B)");
        view_dispatcher_switch_to_view(app->view_dispatcher, HitagViewByteInput);
        break;
    case HitagMenuHts82xx:
        byte_input_set_result_callback(
            app->byte_input, hitag_byte_input_cb, NULL, app, app->hts_82xx, 4);
        byte_input_set_header_text(app->byte_input, "Hitag S 82xx pwd (4B)");
        view_dispatcher_switch_to_view(app->view_dispatcher, HitagViewByteInput);
        break;
    case HitagMenuResetDefaults:
        hitag_config_reset(app);
        break;
    default:
        break;
    }
}

// sub-views return to the main menu on Back
uint32_t hitag_prev_menu(void* ctx) {
    UNUSED(ctx);
    return HitagViewSubmenu;
}

// fires on Back from the submenu (no previous-callback). In a sub-level -> walk up to Top;
// at Top -> exit the app.
bool hitag_nav_cb(void* ctx) {
    HitagApp* app = ctx;
    if(app->menu_level != MLTop) {
        hitag_build_menu(app, MLTop);
        submenu_set_selected_item(app->submenu, 0);
        return true; // stay in the app, now at the top menu
    }
    view_dispatcher_stop(app->view_dispatcher);
    return true;
}
