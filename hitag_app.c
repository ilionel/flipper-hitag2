// Standalone Hitag app for the Flipper Zero:
// Read / Sniff / Detect -> scrollable content view (UID, password, pages) -> Load / Save
// / Emulate, plus a Password editor. Drives the FAP-side Hitag worker over the firmware
// RTF HAL.

#include "hitag_app_i.h"

typedef struct {
    char title[24];
    uint8_t pages_known;
    uint8_t signal; // read coupling gauge: best frame bit-count in the last poll (37 = full)
    bool emulating;
    bool detecting;
    bool sniffing;
    uint16_t sniff_cmds; // reader commands captured so far (sniff)
    uint8_t sniff_kind; // 0 = password, 1 = crypto nonces, 2 = Hitag S 82xx
    uint16_t sniff_found; // nonces captured (kind 1) / 82xx captured 0-1 (kind 2)
    uint16_t emu_auth; // live emulate readout (coupling quality)
    uint16_t emu_pwd;
    uint16_t emu_read;
    // autotune live display
    bool autotune;
    uint16_t at_wresp; // current combo T_wresp (us)
    uint8_t at_lead; // current combo leadbit
    uint8_t at_pre; // current combo preamble
    bool at_locked; // locked onto a winning combo
    uint16_t at_cur_p, at_cur_r; // current combo accumulated PWD/READ
    int8_t at_best; // best combo index (-1 = none)
    uint16_t at_best_wresp;
    uint8_t at_best_lead;
    uint8_t at_best_pre;
    uint16_t at_best_p, at_best_r;
    uint8_t anim; // animation frame counter
} HitagScanModel;

typedef struct {
    char title[24];
    char lines[HITAG_LINES_MAX][HITAG_LINE_LEN];
    uint8_t nlines;
    int8_t scroll;
    int8_t max_scroll;
    bool can_emulate; // OK acts as Emulate (false for message screens)
} HitagContentModel;

static void hitag_emulate_current(HitagApp* app);
static void hitag_start_autotune(HitagApp* app);
static void hitag_finish_sniff(HitagApp* app);
static HitagTagType hitag_type_from_setting(HitagWorkerSetting s);
static inline uint8_t hitag_sniff_kind(HitagWorkerSetting s);
static const char* hitag_type_prefix(HitagTagType t);
static void hitag_show_card(HitagApp* app); // emulate_by_type / handle_rename / card_delete /
    // build_menu are declared in hitag_app_i.h (shared with the menu module)
static void hitag_save_emulate_log(HitagApp* app);
static void hitag_save_autotune_log(HitagApp* app);

// autotune sweep grid: preamble x T_wresp (leadbit fixed OFF — the norm-correct framing that
// makes the reader read all 32 bits faithfully). combo i -> pre[i/NWRESP], wresp[i%NWRESP]. T_wresp is
// a FINE grid centred on 1664us(=208 Tc) and kept INSIDE the 204..212 Tc (1632..1696us) window
// (the old coarse grid mostly sampled OUTSIDE it). Index 0 = the known-good (pre 4, 1664us)
// where plain Emulate already scored a PWD, so the sweep starts there then explores outward.
static const uint8_t hitag_at_pre[HITAG_AT_NPRE] = {4};
static const uint16_t hitag_at_wresp[HITAG_AT_NWRESP] = {1664, 1648, 1680};
static inline uint8_t hitag_at_pre_of(uint8_t i) {
    return hitag_at_pre[i / HITAG_AT_NWRESP];
}
static inline uint32_t hitag_at_wresp_of(uint8_t i) {
    return hitag_at_wresp[i % HITAG_AT_NWRESP];
}
static inline uint8_t hitag_at_lead_of(uint8_t i) {
    UNUSED(i);
    return 0; // norm-correct framing: no leadbit (preamble=tag_sof gives faithful 32-bit replies)
}
// rank combos by depth: READ dominates, then PWD. Returns best index or -1.
static int8_t hitag_at_best(HitagApp* app) {
    int8_t best = -1;
    uint32_t bestscore = 0;
    for(uint8_t i = 0; i < HITAG_AT_NCOMBO; i++) {
        uint32_t sc = (uint32_t)app->at_rr[i] * 1000u + app->at_pp[i];
        if(sc > bestscore) {
            bestscore = sc;
            best = (int8_t)i;
        }
    }
    return best;
}

/* ---------------------------------- worker control -------------------------------- */

static void hitag_worker_teardown(HitagApp* app) {
    // Mutex récursif : le callback timer (thread du service timer) accède à
    // app->worker ; furi_timer_stop ne draine PAS un callback en cours → sans ce
    // verrou, le free ci-dessous pourrait survenir pendant hitag_timer_cb (UAF).
    // Récursif car hitag_finish_to_content() (appelé DEPUIS le callback timer, qui
    // tient déjà le verrou) ré-entre par ici.
    furi_mutex_acquire(app->worker_mutex, FuriWaitForever);
    if(app->timer) furi_timer_stop(app->timer);
    if(app->worker) {
        hitag_worker_stop(app->worker);
        hitag_worker_free(app->worker);
        app->worker = NULL;
    }
    furi_mutex_release(app->worker_mutex);
}

/* ---------------------------------- content view ---------------------------------- */

static inline bool hitag_printable(uint8_t c) {
    return c >= 0x20 && c < 0x7f;
}

// Build the scrollable content from app->last_pages: UID (page 0), password (page 1,
// with ASCII if printable), then the 8 raw pages.
void hitag_build_content(HitagApp* app, const char* title) {
    with_view_model(
        app->content_view,
        HitagContentModel * m,
        {
            strncpy(m->title, title, sizeof(m->title) - 1);
            m->title[sizeof(m->title) - 1] = 0;
            m->can_emulate = true;
            m->nlines = 0;
            const uint8_t* pg = app->last_pages;

            snprintf(
                m->lines[m->nlines++],
                HITAG_LINE_LEN,
                "UID: %02X%02X%02X%02X",
                pg[0],
                pg[1],
                pg[2],
                pg[3]);

            bool pr = true;
            char asc[5] = {0};
            for(uint8_t i = 0; i < 4; i++) {
                if(!hitag_printable(pg[4 + i])) {
                    pr = false;
                    break;
                }
                asc[i] = (char)pg[4 + i];
            }
            if(pr) {
                snprintf(
                    m->lines[m->nlines++],
                    HITAG_LINE_LEN,
                    "Pwd: %02X%02X%02X%02X %s",
                    pg[4],
                    pg[5],
                    pg[6],
                    pg[7],
                    asc);
            } else {
                snprintf(
                    m->lines[m->nlines++],
                    HITAG_LINE_LEN,
                    "Pwd: %02X%02X%02X%02X",
                    pg[4],
                    pg[5],
                    pg[6],
                    pg[7]);
            }

            snprintf(m->lines[m->nlines++], HITAG_LINE_LEN, "-- pages --");
            for(uint8_t p = 0; p < 8; p++) {
                snprintf(
                    m->lines[m->nlines++],
                    HITAG_LINE_LEN,
                    "%u: %02X%02X%02X%02X",
                    p,
                    pg[p * 4 + 0],
                    pg[p * 4 + 1],
                    pg[p * 4 + 2],
                    pg[p * 4 + 3]);
            }

            m->scroll = 0;
            m->max_scroll = (int8_t)m->nlines - HITAG_VISIBLE;
            if(m->max_scroll < 0) m->max_scroll = 0;
        },
        true);
}

// One-line informational screen (no emulate action), reuses the content view.
static void hitag_show_message(HitagApp* app, const char* title, const char* msg) {
    with_view_model(
        app->content_view,
        HitagContentModel * m,
        {
            strncpy(m->title, title, sizeof(m->title) - 1);
            m->title[sizeof(m->title) - 1] = 0;
            m->nlines = 0;
            m->can_emulate = false;
            snprintf(m->lines[0], HITAG_LINE_LEN, "%s", msg);
            m->nlines = 1;
            m->scroll = 0;
            m->max_scroll = 0;
        },
        true);
    view_dispatcher_switch_to_view(app->view_dispatcher, HitagViewContent);
}

static void hitag_content_draw(Canvas* canvas, void* model) {
    HitagContentModel* m = model;
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 10, m->title);
    canvas_set_font(canvas, FontSecondary);

    for(int i = 0; i < HITAG_VISIBLE && (m->scroll + i) < m->nlines; i++) {
        canvas_draw_str(canvas, 2, 22 + i * 9, m->lines[m->scroll + i]);
    }
    if(m->scroll > 0) canvas_draw_str(canvas, 122, 22, "^");
    if(m->scroll < m->max_scroll) canvas_draw_str(canvas, 122, 49, "v");

    if(m->can_emulate) canvas_draw_str(canvas, 2, 63, "OK:Emulate");
    canvas_draw_str(canvas, 100, 63, "Back");
}

static bool hitag_content_input(InputEvent* event, void* ctx) {
    HitagApp* app = ctx;
    if(event->type != InputTypeShort && event->type != InputTypeRepeat) return false;

    if(event->key == InputKeyUp || event->key == InputKeyDown) {
        with_view_model(
            app->content_view,
            HitagContentModel * m,
            {
                if(event->key == InputKeyUp && m->scroll > 0) m->scroll--;
                if(event->key == InputKeyDown && m->scroll < m->max_scroll) m->scroll++;
            },
            true);
        return true;
    }
    if(event->key == InputKeyOk && event->type == InputTypeShort) {
        if(app->has_data) hitag_emulate_by_type(app); // OK on the Info screen = emulate this card
        return true;
    }
    return false; // Back -> previous-callback (card menu)
}

/* ---------------------------------- scan view ------------------------------------- */

// a small spinning indicator (no icon assets needed)
static void hitag_draw_spinner(Canvas* canvas, uint8_t x, uint8_t y, uint8_t frame) {
    static const char* f[] = {"|", "/", "-", "\\"};
    canvas_draw_str(canvas, x, y, f[frame & 3]);
}

static void hitag_scan_draw(Canvas* canvas, void* model) {
    HitagScanModel* m = model;
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 12, m->title);
    canvas_set_font(canvas, FontSecondary);

    if(m->emulating) {
        char l[40];
        hitag_draw_spinner(canvas, 116, 30, m->anim);
        // depth reached so far: READ > PWD > AUTH > none
        const char* depth = (m->emu_read > 0) ? "READ" :
                            (m->emu_pwd > 0)  ? "PWD" :
                            (m->emu_auth > 0) ? "AUTH" :
                                                "-";
        if(m->autotune) {
            snprintf(l, sizeof(l), "%s pre%u W%u", m->at_locked ? "LOCK" : "Try", m->at_pre, m->at_wresp);
            canvas_draw_str(canvas, 2, 30, l);
            snprintf(l, sizeof(l), "this  P:%u R:%u", m->at_cur_p, m->at_cur_r);
            canvas_draw_str(canvas, 2, 42, l);
            if(m->at_best >= 0)
                snprintf(
                    l, sizeof(l), "best pre%u W%u R%u P%u",
                    m->at_best_pre, m->at_best_wresp, m->at_best_r, m->at_best_p);
            else
                snprintf(l, sizeof(l), "depth: %s", depth);
            canvas_draw_str(canvas, 2, 53, l);
        } else {
            canvas_draw_str(canvas, 2, 30, "Emulating to a reader");
            // AUTH rising = reader polls us; PWD/READ = it accepted our UID reply
            snprintf(l, sizeof(l), "AUTH:%u PWD:%u RD:%u", m->emu_auth, m->emu_pwd, m->emu_read);
            canvas_draw_str(canvas, 2, 44, l);
            // Coupling is the wall: if AUTH stays 0 the reader field isn't reaching our coil.
            // Prompt the user to hunt a position (LF coupling peaks at a small ~5mm gap, not
            // contact); once AUTH climbs, show how deep the handshake got instead.
            if(m->emu_auth == 0)
                canvas_draw_str(canvas, 2, 54, "Move to find coupling");
            else {
                snprintf(l, sizeof(l), "depth: %s", depth);
                canvas_draw_str(canvas, 2, 54, l);
            }
        }
        canvas_draw_str(canvas, 2, 63, "Back: stop & save");
        return;
    }

    if(m->sniffing) {
        const char* what = m->sniff_kind == 1 ? "Sniffing crypto..." :
                           m->sniff_kind == 2 ? "Sniffing Hitag S..." :
                                                "Sniffing reader...";
        canvas_draw_str(canvas, 2, 30, what);
        hitag_draw_spinner(canvas, 116, 30, m->anim);
        char l[24];
        snprintf(l, sizeof(l), "Cmds captured: %u", m->sniff_cmds);
        canvas_draw_str(canvas, 2, 43, l);
        // Passive, but still coupling-dependent: nudge the coil into the reader's field.
        // Then show the target-specific tally (nonces / 82xx) so the user knows when to stop.
        if(m->sniff_cmds == 0)
            canvas_draw_str(canvas, 2, 53, "Move into reader field");
        else if(m->sniff_kind == 1) {
            snprintf(l, sizeof(l), "Nonces: %u (>=2)", m->sniff_found);
            canvas_draw_str(canvas, 2, 53, l);
        } else if(m->sniff_kind == 2)
            canvas_draw_str(
                canvas, 2, 53, m->sniff_found ? "82xx pwd: captured!" : "82xx pwd: waiting...");
        canvas_draw_str(canvas, 2, 62, "Back: stop & save");
        return;
    }

    canvas_draw_str(canvas, 2, 30, m->detecting ? "Detecting tag..." : "Scanning...");
    hitag_draw_spinner(canvas, 116, 30, m->anim);
    char line[24];
    snprintf(line, sizeof(line), "Pages %u/8", m->pages_known);
    canvas_draw_str(canvas, 2, 44, line);
    // The Sig bar below IS the coupling gauge: reposition until it fills (a full frame = 37).
    // live coupling gauge: text + bar (37 = a full clean reply frame). Position the badge
    // until it fills up -> the read then completes in seconds instead of moving blindly.
    snprintf(line, sizeof(line), "Sig %u/37", m->signal);
    canvas_draw_str(canvas, 2, 54, line);
    canvas_draw_frame(canvas, 60, 47, 62, 7);
    uint8_t w = m->signal >= 37 ? 60 : (uint8_t)((uint16_t)m->signal * 60 / 37);
    if(w) canvas_draw_box(canvas, 61, 48, w, 5);
    canvas_draw_str(canvas, 2, 63, "OK:keep  Back:cancel");
}

static void hitag_restart_worker(HitagApp* app, HitagWorkerSetting setting) {
    if(app->worker) {
        hitag_worker_stop(app->worker);
        hitag_worker_free(app->worker);
    }
    app->worker = hitag_worker_alloc();
    hitag_worker_set_password(app->worker, app->password);
    hitag_worker_start(app->worker, setting);
}

// snapshot the worker pages, mark data present, tear down, and show the content view
static void hitag_finish_to_content(HitagApp* app, const char* title) {
    uint8_t known[8];
    hitag_worker_get_pages(app->worker, app->last_pages, known);
    app->has_data = true;
    app->from_sniff = app->scan_is_sniff;
    app->from_saved = false; // a fresh read, not a loaded file
    // a sniff captures the reader password (page 1) -> apply it so a later Read works
    if(app->from_sniff) memcpy(app->password, &app->last_pages[4], 4);
    hitag_worker_teardown(app);
    notification_message(app->notifications, &sequence_success);
    hitag_build_content(app, title); // prepared for the card's "Info" action
    hitag_show_card(app); // NFC-style: land on the card menu (Info / Emulate / Save)
}

// Audible + haptic cue when the reader ACCEPTS our UID (PWD): a short beep the user can HEAR
// against a strict reader (READ uses the louder sequence_success). Sound restored per user request.
static const NotificationSequence seq_hitag_pwd = {
    &message_vibro_on,
    &message_note_c5,
    &message_delay_50,
    &message_sound_off,
    &message_vibro_off,
    NULL,
};

static void hitag_timer_cb(void* ctx) {
    HitagApp* app = ctx;
    // Verrouille pour empêcher un free(worker) concurrent (thread GUI) pendant qu'on
    // déréférence app->worker ici. Chaque sortie relâche le verrou.
    furi_mutex_acquire(app->worker_mutex, FuriWaitForever);
    if(!app->worker) {
        furi_mutex_release(app->worker_mutex);
        return;
    }

    // emulate: live coupling readout (commands received by type), never auto-finish
    if(app->emulating) {
        uint16_t a = 0, p = 0, r = 0;
        hitag_worker_get_emu_counts(app->worker, &a, &p, &r);

        // haptic: buzz when the reader ACCEPTS our UID (PWD++) and a stronger success on a
        // page READ (READ++). Lets the user FEEL a good-coupling instant against a strict reader and
        // HOLD the position (can't watch the screen while positioning the Flipper).
        if(p > app->emu_prev_pwd) notification_message(app->notifications, &seq_hitag_pwd);
        if(r > app->emu_prev_read) notification_message(app->notifications, &sequence_success);
        app->emu_prev_pwd = p;
        app->emu_prev_read = r;

        if(app->autotune) {
            // deltas since this combo started
            uint16_t da = a - app->at_base_a, dp = p - app->at_base_p, dr = r - app->at_base_r;
            // LOCK-ON-SUCCESS: the moment a combo scores a PWD/READ, stop sweeping and STAY on
            // it (retry/exploit the winning timing) instead of the old blind advance that
            // dropped a rare hit before it could complete the handshake.
            if(!app->at_locked && (dp > 0 || dr > 0)) app->at_locked = true;
            if(!app->at_locked && ++app->at_dwell >= HITAG_AT_DWELL) {
                // bank this combo's result and advance to the next (live, no worker restart)
                app->at_aa[app->at_combo] += da;
                app->at_pp[app->at_combo] += dp;
                app->at_rr[app->at_combo] += dr;
                app->at_combo = (app->at_combo + 1) % HITAG_AT_NCOMBO;
                hitag_worker_set_emu_tuning(
                    app->worker,
                    hitag_at_pre_of(app->at_combo),
                    hitag_at_wresp_of(app->at_combo),
                    hitag_at_lead_of(app->at_combo));
                app->at_base_a = a;
                app->at_base_p = p;
                app->at_base_r = r;
                app->at_dwell = 0;
                da = dp = dr = 0;
            }
            uint8_t cc = app->at_combo;
            // when locked, the winner IS the current combo; else pick the best-scoring one
            int8_t best = app->at_locked ? (int8_t)cc : hitag_at_best(app);
            with_view_model(
                app->scan_view,
                HitagScanModel * m,
                {
                    m->autotune = true;
                    m->at_locked = app->at_locked;
                    m->at_pre = hitag_at_pre_of(cc);
                    m->at_wresp = hitag_at_wresp_of(cc);
                    m->at_lead = hitag_at_lead_of(cc);
                    m->at_cur_p = app->at_pp[cc] + dp;
                    m->at_cur_r = app->at_rr[cc] + dr;
                    m->at_best = best;
                    if(best >= 0) {
                        uint8_t bi = (uint8_t)best;
                        m->at_best_pre = hitag_at_pre_of(bi);
                        m->at_best_wresp = hitag_at_wresp_of(bi);
                        m->at_best_lead = hitag_at_lead_of(bi);
                        m->at_best_p = app->at_pp[bi] + (bi == cc ? dp : 0);
                        m->at_best_r = app->at_rr[bi] + (bi == cc ? dr : 0);
                    }
                    m->emu_auth = a;
                    m->emu_pwd = p;
                    m->emu_read = r;
                    m->anim++;
                },
                true);
            furi_mutex_release(app->worker_mutex);
            return;
        }

        with_view_model(
            app->scan_view,
            HitagScanModel * m,
            {
                m->autotune = false;
                m->emu_auth = a;
                m->emu_pwd = p;
                m->emu_read = r;
                m->anim++;
            },
            true);
        furi_mutex_release(app->worker_mutex);
        return;
    }

    // sniff: never auto-finish; keep capturing the whole reader transaction and just
    // refresh the captured-command count until the user presses Back.
    if(app->scan_is_sniff) {
        uint16_t n = hitag_worker_get_sniff_count(app->worker);
        uint8_t kind = hitag_sniff_kind(app->scan_setting);
        uint16_t found = 0;
        if(kind == 1) { // crypto nonces captured so far
            static uint32_t nr[HITAG_SNIFF_NONCE_MAX];
            static uint32_t ar[HITAG_SNIFF_NONCE_MAX];
            found = hitag_worker_get_nonces(app->worker, nr, ar);
        } else if(kind == 2) { // 82xx password captured yet?
            uint8_t pwd[4];
            found = hitag_worker_get_sniff_82xx(app->worker, pwd) ? 1 : 0;
        }
        notification_message(app->notifications, &sequence_blink_blue_10);
        with_view_model(
            app->scan_view,
            HitagScanModel * m,
            {
                m->sniff_cmds = n;
                m->sniff_kind = kind;
                m->sniff_found = found;
                m->anim++;
            },
            true);
        furi_mutex_release(app->worker_mutex);
        return;
    }

    uint8_t pages[32];
    uint8_t known[8];
    hitag_worker_get_pages(app->worker, pages, known);
    uint8_t sig = hitag_worker_get_read_best_bits(app->worker); // live coupling gauge
    uint8_t cnt = 0;
    for(uint8_t p = 0; p < 8; p++) cnt += known[p] ? 1 : 0;
    HitagStatus st = hitag_worker_get_status(app->worker);
    bool detected = (cnt > 0) || (st == HitagStatusDetected) || (st == HitagStatusRead);
    bool done = (cnt >= 8) || (st == HitagStatusRead);

    // detect mode: rotate Hitag2 -> Hitag1 -> Hitag S until something answers, then lock
    if(app->detect_mode && !app->detect_locked) {
        if(detected) {
            app->detect_locked = true;
            app->tag_type = hitag_type_from_setting(app->detect_setting); // record the found family
        } else {
            app->detect_ticks++;
            if(app->detect_ticks >= 16) { // ~4s per protocol
                app->detect_ticks = 0;
                app->detect_setting =
                    (app->detect_setting == HitagWorkerSettingReadHitag2) ?
                        HitagWorkerSettingRead :
                    (app->detect_setting == HitagWorkerSettingRead) ?
                        HitagWorkerSettingReadHitagS :
                        HitagWorkerSettingReadHitag2;
                hitag_restart_worker(app, app->detect_setting);
            }
        }
    }

    if(done) {
        const char* title = app->scan_title;
        if(app->detect_mode) {
            title = (app->detect_setting == HitagWorkerSettingReadHitag2) ? "Hitag2" :
                    (app->detect_setting == HitagWorkerSettingRead)      ? "Hitag1" :
                                                                                 "Hitag S";
        }
        hitag_finish_to_content(app, title); // ré-entre teardown (mutex récursif)
        furi_mutex_release(app->worker_mutex);
        return;
    }

    notification_message(app->notifications, &sequence_blink_blue_10);

    with_view_model(
        app->scan_view,
        HitagScanModel * m,
        {
            m->pages_known = cnt;
            m->signal = sig;
            m->anim++;
        },
        true);
    furi_mutex_release(app->worker_mutex);
}

static bool hitag_scan_input(InputEvent* event, void* ctx) {
    HitagApp* app = ctx;
    if(event->type != InputTypeShort) return false;
    // sniff: Back or OK stops, saves the transaction log, and shows the result
    if(app->scan_is_sniff && app->worker &&
       (event->key == InputKeyBack || event->key == InputKeyOk)) {
        hitag_finish_sniff(app);
        return true;
    }
    if(event->key == InputKeyBack) {
        // emulation: dump what we got before tearing down (autotune -> sweep results).
        // Only when Debug traces is on (Emulation settings) — off = clean, no files written.
        if(app->emulating && app->worker && app->debug_traces) {
            if(app->autotune)
                hitag_save_autotune_log(app);
            else
                hitag_save_emulate_log(app);
        }
        hitag_worker_teardown(app);
        view_dispatcher_switch_to_view(app->view_dispatcher, HitagViewSubmenu);
        return true;
    }
    // OK while reading -> keep whatever pages we have so far and show them
    if(event->key == InputKeyOk && !app->emulating && app->worker) {
        uint8_t known[8];
        uint8_t tmp[32];
        hitag_worker_get_pages(app->worker, tmp, known);
        uint8_t cnt = 0;
        for(uint8_t p = 0; p < 8; p++) cnt += known[p] ? 1 : 0;
        if(cnt == 0) return true;
        hitag_finish_to_content(app, app->scan_title);
        return true;
    }
    return false;
}

static void hitag_show_scan(HitagApp* app, const char* title, bool emulating, bool detecting) {
    app->emulating = emulating;
    app->found = false;
    app->emu_prev_pwd = 0; // reset haptic edge-detect for a fresh emulate/autotune session
    app->emu_prev_read = 0;
    strncpy(app->scan_title, title, sizeof(app->scan_title) - 1);
    app->scan_title[sizeof(app->scan_title) - 1] = 0;
    with_view_model(
        app->scan_view,
        HitagScanModel * m,
        {
            strncpy(m->title, title, sizeof(m->title) - 1);
            m->title[sizeof(m->title) - 1] = 0;
            m->pages_known = 0;
            m->emulating = emulating;
            m->detecting = detecting;
            m->sniffing = app->scan_is_sniff;
            m->sniff_cmds = 0;
            m->sniff_kind = hitag_sniff_kind(app->scan_setting);
            m->sniff_found = 0;
            m->emu_auth = 0;
            m->emu_pwd = 0;
            m->emu_read = 0;
            m->autotune = app->autotune;
            m->at_best = -1;
            m->at_cur_p = 0;
            m->at_cur_r = 0;
            m->at_pre = hitag_at_pre_of(0);
            m->at_wresp = hitag_at_wresp_of(0);
            m->at_lead = hitag_at_lead_of(0);
            m->at_locked = false;
            m->anim = 0;
        },
        true);
    view_dispatcher_switch_to_view(app->view_dispatcher, HitagViewScan);
    // run the timer in all live modes now (emulate uses it for the coupling readout)
    furi_timer_start(app->timer, furi_ms_to_ticks(250));
}

/* ---------------------------------- command log ----------------------------------- */

// MMDD_HHMMSS timestamp so each capture is uniquely named (nothing overwritten across
// runs in the one reader session) and the file tells you when it was taken.
static void hitag_timestamp(char* out, size_t n) {
    DateTime dt;
    furi_hal_rtc_get_datetime(&dt);
    snprintf(out, n, "%02u%02u_%02u%02u%02u", dt.month, dt.day, dt.hour, dt.minute, dt.second);
}

// Decode the captured reader commands into a human-readable .txt on SD. Used by both
// sniff (reader<->real badge) and emulate (reader<->Flipper, to see how far the handshake
// gets). label = the header line; path = full destination.
static void hitag_write_cmd_log(HitagApp* app, const char* label, const char* path) {
    // static (1.25KB) to keep the stack bounded: this is nested inside hitag_save_sniff_log
    // and only ever runs on the GUI thread (sequential, not re-entrant).
    static uint8_t lens[HITAG_SNIFF_LOG_MAX];
    static uint32_t vals[HITAG_SNIFF_LOG_MAX];
    uint16_t n = hitag_worker_get_sniff_log(app->worker, lens, vals);

    FuriString* body = furi_string_alloc();
    furi_string_printf(body, "%s\nReader commands: %u\n\n", label, n);
    for(uint16_t i = 0; i < n; i++) {
        uint8_t l = lens[i];
        uint32_t v = vals[i];
        uint8_t page = 0;
        switch(hitag_classify_frame(l, v, &page)) {
        case HitagFrameStartAuth:
            furi_string_cat_printf(body, "%2u: START_AUTH\n", i);
            break;
        case HitagFrameRead:
            furi_string_cat_printf(body, "%2u: READ page %u\n", i, (unsigned)page);
            break;
        case HitagFramePassword:
            furi_string_cat_printf(body, "%2u: PASSWORD %08lX\n", i, (unsigned long)v);
            break;
        default:
            furi_string_cat_printf(body, "%2u: ? (%ub) %08lX\n", i, l, (unsigned long)v);
            break;
        }
    }

    File* f = storage_file_alloc(app->storage);
    if(storage_file_open(f, path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        storage_file_write(f, furi_string_get_cstr(body), furi_string_size(body));
    }
    storage_file_close(f);
    storage_file_free(f);
    furi_string_free(body);
}

static void hitag_save_sniff_log(HitagApp* app) {
    static uint8_t lens[HITAG_SNIFF_LOG_MAX];
    static uint32_t vals[HITAG_SNIFF_LOG_MAX];
    uint16_t n = hitag_worker_get_sniff_log(app->worker, lens, vals);
    storage_simply_mkdir(app->storage, HITAG_DIR);
    uint32_t pw = 0;
    for(uint16_t i = 0; i < n; i++)
        if(lens[i] >= 31 && lens[i] <= 34) {
            pw = vals[i];
            break;
        }
    char ts[24];
    hitag_timestamp(ts, sizeof(ts));
    FuriString* path =
        pw ? furi_string_alloc_printf("%s/snifflog_%08lX_%s.txt", HITAG_DIR, (unsigned long)pw, ts) :
             furi_string_alloc_printf("%s/snifflog_%s.txt", HITAG_DIR, ts);
    hitag_write_cmd_log(app, "Hitag2 sniff log", furi_string_get_cstr(path));
    furi_string_free(path);

    // also dump the real tag's reply waveform (ground truth vs our emulate self-scope)
    uint16_t cells[HITAG_SNIFF_SCOPE_MAX];
    uint8_t cn = hitag_worker_get_sniff_scope(app->worker, cells);
    if(cn > 0) {
        FuriString* sbody = furi_string_alloc();
        furi_string_printf(
            sbody, "Hitag2 real-tag reply (after START_AUTH)\nCells: %u (us each)\n\n", cn);
        for(uint8_t i = 0; i < cn; i++) furi_string_cat_printf(sbody, "%u ", cells[i]);
        furi_string_cat_str(sbody, "\n");
        FuriString* spath = furi_string_alloc_printf("%s/realscope_%s.txt", HITAG_DIR, ts);
        File* f = storage_file_alloc(app->storage);
        if(storage_file_open(f, furi_string_get_cstr(spath), FSAM_WRITE, FSOM_CREATE_ALWAYS))
            storage_file_write(f, furi_string_get_cstr(sbody), furi_string_size(sbody));
        storage_file_close(f);
        storage_file_free(f);
        furi_string_free(sbody);
        furi_string_free(spath);
    }
}

// self-scope: dump the realized per-cell timing (us) of our LAST emulate reply, so the
// preamble/data0 boundary (the framing-shift suspect) is inspectable at the bench.
static void hitag_save_scope(HitagApp* app, const char* ts) {
    uint16_t cells[FURI_HAL_RFID_RTF_REPLY_CAP_MAX];
    size_t n = furi_hal_rfid_rtf_reply_cap(cells, FURI_HAL_RFID_RTF_REPLY_CAP_MAX);
    if(n == 0) return;
    storage_simply_mkdir(app->storage, HITAG_DIR);
    FuriString* body = furi_string_alloc();
    furi_string_printf(body, "Hitag2 self-scope (last reply)\nCells: %u (us each)\n\n", (unsigned)n);
    for(size_t i = 0; i < n; i++) furi_string_cat_printf(body, "%u ", cells[i]);
    furi_string_cat_str(body, "\n");
    FuriString* path = furi_string_alloc_printf("%s/emuscope_%s.txt", HITAG_DIR, ts);
    File* f = storage_file_alloc(app->storage);
    if(storage_file_open(f, furi_string_get_cstr(path), FSAM_WRITE, FSOM_CREATE_ALWAYS))
        storage_file_write(f, furi_string_get_cstr(body), furi_string_size(body));
    storage_file_close(f);
    storage_file_free(f);
    furi_string_free(body);
    furi_string_free(path);
}

// emulate diagnostic: dump the reader commands our emulation received this session
static void hitag_save_emulate_log(HitagApp* app) {
    // worker_mutex : exclut le callback timer (thread service timer) qui lit aussi
    // app->worker pendant qu'on l'arrête et qu'on lit ses buffers.
    furi_mutex_acquire(app->worker_mutex, FuriWaitForever);
    if(!app->worker) {
        furi_mutex_release(app->worker_mutex);
        return;
    }
    // stop the worker thread first so the log/scope buffers are not written while we read
    hitag_worker_stop(app->worker);
    storage_simply_mkdir(app->storage, HITAG_DIR);
    char ts[24];
    hitag_timestamp(ts, sizeof(ts));
    FuriString* path = furi_string_alloc_printf("%s/emulog_%s.txt", HITAG_DIR, ts);
    hitag_write_cmd_log(app, "Hitag2 emulate log (reader handshake)", furi_string_get_cstr(path));
    furi_string_free(path);
    hitag_save_scope(app, ts); // same timestamp -> emuscope pairs with this emulog
    furi_mutex_release(app->worker_mutex);
}

// stop the sniff: pull the captured password into the dump + app password, save the log
// Write the captured Hitag2 crypto nR/aR pairs to a text file for the PC-side cracker. The
// Flipper only collects the nonces (on-device key recovery is not feasible — see REFERENCE);
// the file is ready to feed to the hitag2crack tools. Returns the number of pairs written.
static uint8_t hitag_save_nonces(HitagApp* app) {
    static uint32_t nr[HITAG_SNIFF_NONCE_MAX];
    static uint32_t ar[HITAG_SNIFF_NONCE_MAX];
    uint8_t n = hitag_worker_get_nonces(app->worker, nr, ar);
    if(n == 0) return 0;
    storage_simply_mkdir(app->storage, HITAG_DIR);
    char ts[24];
    hitag_timestamp(ts, sizeof(ts));
    FuriString* body = furi_string_alloc();
    furi_string_printf(
        body,
        "# Hitag2 crypto nonces (Flipper Hitag sniff)\n"
        "# UID: %02X%02X%02X%02X (page 0 of the current dump — verify vs the sniffed tag)\n"
        "# Format: <nR> <aR>  hex, MSB-first as transmitted\n"
        "# Crack on a PC, e.g.: ht2crack5 <UID> <nR0> <aR0> <nR1> <aR1>\n"
        "# (or feed the pairs to ht2crack2 / ht2crack4 per their docs)\n",
        app->last_pages[0],
        app->last_pages[1],
        app->last_pages[2],
        app->last_pages[3]);
    for(uint8_t i = 0; i < n; i++)
        furi_string_cat_printf(
            body, "%08lX %08lX\n", (unsigned long)nr[i], (unsigned long)ar[i]);
    FuriString* path = furi_string_alloc_printf(
        "%s/nonces_%02X%02X%02X%02X_%s.txt",
        HITAG_DIR,
        app->last_pages[0],
        app->last_pages[1],
        app->last_pages[2],
        app->last_pages[3],
        ts);
    File* f = storage_file_alloc(app->storage);
    if(storage_file_open(f, furi_string_get_cstr(path), FSAM_WRITE, FSOM_CREATE_ALWAYS))
        storage_file_write(f, furi_string_get_cstr(body), furi_string_size(body));
    storage_file_close(f);
    storage_file_free(f);
    furi_string_free(path);
    furi_string_free(body);
    return n;
}

static void hitag_finish_sniff(HitagApp* app) {
    // stop the timer + worker thread before reading their buffers (no concurrent writes).
    // worker_mutex : exclut le callback timer le temps de l'arrêt + lecture + teardown
    // (teardown ré-entre via le mutex récursif). build_content reste hors du verrou.
    furi_mutex_acquire(app->worker_mutex, FuriWaitForever);
    if(app->timer) furi_timer_stop(app->timer);
    hitag_worker_stop(app->worker);

    // Hitag2 crypto nonce sniff: export the nR/aR pairs for the PC cracker, then a summary.
    if(app->scan_setting == HitagWorkerSettingSniffHitag2Nonce) {
        uint8_t n = hitag_save_nonces(app);
        hitag_worker_teardown(app);
        furi_mutex_release(app->worker_mutex);
        notification_message(app->notifications, n ? &sequence_success : &sequence_error);
        char msg[48];
        if(n)
            snprintf(msg, sizeof(msg), "%u pair(s) -> nonces_*.txt", n);
        else
            snprintf(msg, sizeof(msg), "No nonce captured");
        hitag_show_message(app, "HT2 crypto sniff", msg);
        return;
    }
    // Hitag S 82xx sniff: apply the captured password to the 82xx setting, then a summary.
    if(app->scan_setting == HitagWorkerSettingSniffHitagS82xx) {
        uint8_t pwd[4];
        bool got = hitag_worker_get_sniff_82xx(app->worker, pwd);
        if(got) memcpy(app->hts_82xx, pwd, 4);
        hitag_worker_teardown(app);
        furi_mutex_release(app->worker_mutex);
        notification_message(app->notifications, got ? &sequence_success : &sequence_error);
        char msg[48];
        if(got)
            snprintf(
                msg, sizeof(msg), "%02X %02X %02X %02X -> settings", pwd[0], pwd[1], pwd[2],
                pwd[3]);
        else
            snprintf(msg, sizeof(msg), "No 82xx write seen");
        hitag_show_message(app, "Hitag S 82xx sniff", msg);
        return;
    }

    // Hitag2 password sniff (default): recover the reader password into the current dump.
    uint8_t known[8];
    hitag_worker_get_pages(app->worker, app->last_pages, known);
    // The captured password is always applied below; the transaction-log FILE is written only
    // with Debug traces on (Emulation settings) — off = clean, no file.
    if(app->debug_traces) hitag_save_sniff_log(app);
    app->has_data = true;
    app->from_sniff = true;
    app->from_saved = false;
    memcpy(app->password, &app->last_pages[4], 4); // apply captured password
    hitag_worker_teardown(app);
    furi_mutex_release(app->worker_mutex);
    notification_message(app->notifications, &sequence_success);
    hitag_build_content(app, app->debug_traces ? "Sniff saved" : "Sniff done");
    hitag_show_card(app);
}

/* ---------------------------------- save / load ----------------------------------- */

static bool hitag_save_file(HitagApp* app, const char* name) {
    storage_simply_mkdir(app->storage, HITAG_DIR);
    FuriString* path = furi_string_alloc_printf("%s/%s%s", HITAG_DIR, name, HITAG_EXT);
    FlipperFormat* ff = flipper_format_file_alloc(app->storage);
    bool ok = false;
    do {
        if(!flipper_format_file_open_always(ff, furi_string_get_cstr(path))) break;
        if(!flipper_format_write_header_cstr(ff, "Flipper Hitag dump", 1)) break;
        if(!flipper_format_write_hex(ff, "Pages", app->last_pages, 32)) break;
        ok = true;
    } while(false);
    flipper_format_free(ff);
    furi_string_free(path);
    return ok;
}

static bool hitag_load_path(HitagApp* app, const char* path) {
    FlipperFormat* ff = flipper_format_file_alloc(app->storage);
    bool ok = false;
    do {
        if(!flipper_format_file_open_existing(ff, path)) break;
        FuriString* hdr = furi_string_alloc();
        uint32_t ver = 0;
        // Vérifier le type de fichier (cf. hitag_save_file) avant de lire les pages,
        // pour rejeter proprement un .hitag d'un autre format au lieu de charger du bruit.
        bool hdr_ok = flipper_format_read_header(ff, hdr, &ver) &&
                      furi_string_equal_str(hdr, "Flipper Hitag dump");
        furi_string_free(hdr);
        if(!hdr_ok) break;
        if(!flipper_format_read_hex(ff, "Pages", app->last_pages, 32)) break;
        // Recover the tag family from the filename prefix (hitag1_/hitag2_/hitags_) so a later
        // Save keeps it; default Hitag2 for anything else.
        const char* fn = strrchr(path, '/');
        fn = fn ? fn + 1 : path;
        app->tag_type = (strncmp(fn, "hitags", 6) == 0) ? HitagTypeHtS :
                        (strncmp(fn, "hitag1", 6) == 0) ? HitagTypeHt1 :
                                                          HitagTypeHt2;
        ok = true;
    } while(false);
    flipper_format_free(ff);
    return ok;
}

static void hitag_text_input_cb(void* ctx) {
    HitagApp* app = ctx;
    bool ok;
    FuriString* np = furi_string_alloc_printf("%s/%s%s", HITAG_DIR, app->save_name, HITAG_EXT);
    if(app->renaming) {
        ok = storage_common_rename(
                 app->storage, app->loaded_path, furi_string_get_cstr(np)) == FSE_OK;
        app->renaming = false;
    } else {
        ok = hitag_save_file(app, app->save_name);
    }
    if(ok) {
        // the dump now exists on disk -> it's a Saved dump (card shows Rename/Delete)
        strncpy(app->loaded_path, furi_string_get_cstr(np), sizeof(app->loaded_path) - 1);
        app->loaded_path[sizeof(app->loaded_path) - 1] = 0;
        app->from_saved = true;
    }
    furi_string_free(np);
    notification_message(app->notifications, ok ? &sequence_success : &sequence_error);
    hitag_show_card(app); // back to the card menu
}

// Native-style file browser: pick a .hitag dump.
static bool hitag_pick_file(HitagApp* app) {
    storage_simply_mkdir(app->storage, HITAG_DIR);
    FuriString* path = furi_string_alloc_set_str(HITAG_DIR);
    DialogsFileBrowserOptions opts;
    dialog_file_browser_set_basic_options(&opts, HITAG_EXT, NULL);
    opts.base_path = HITAG_DIR;
    bool ok = dialog_file_browser_show(app->dialogs, path, path, &opts) &&
              hitag_load_path(app, furi_string_get_cstr(path));
    if(ok) {
        // remember the file so the card's Rename/Delete act on it
        strncpy(app->loaded_path, furi_string_get_cstr(path), sizeof(app->loaded_path) - 1);
        app->loaded_path[sizeof(app->loaded_path) - 1] = 0;
    }
    furi_string_free(path);
    return ok;
}

void hitag_handle_load(HitagApp* app) {
    if(hitag_pick_file(app)) {
        app->has_data = true;
        app->from_sniff = false;
        app->from_saved = true; // a loaded dump -> card offers Rename / Delete
        hitag_build_content(app, "Loaded"); // prepared for the card's "Info" action
        hitag_show_card(app);
    }
}

void hitag_handle_save(HitagApp* app) {
    if(!app->has_data) {
        notification_message(app->notifications, &sequence_error);
        hitag_show_message(app, "Save", "Read or Load first");
        return;
    }
    // default name carries the tag family: <hitag1|hitag2|hitags>_<UID>; a sniff (password
    // only, always Hitag2) -> hitag2_pw_<pwd>.
    if(app->from_sniff) {
        snprintf(
            app->save_name,
            HITAG_NAME_LEN,
            "hitag2_pw_%02X%02X%02X%02X",
            app->last_pages[4],
            app->last_pages[5],
            app->last_pages[6],
            app->last_pages[7]);
    } else {
        snprintf(
            app->save_name,
            HITAG_NAME_LEN,
            "%s_%02X%02X%02X%02X",
            hitag_type_prefix(app->tag_type),
            app->last_pages[0],
            app->last_pages[1],
            app->last_pages[2],
            app->last_pages[3]);
    }
    text_input_set_header_text(app->text_input, "Name the dump");
    view_dispatcher_switch_to_view(app->view_dispatcher, HitagViewTextInput);
}

/* ---------------------------------- emulate --------------------------------------- */

static void hitag_emulate_current(HitagApp* app) {
    if(!app->has_data) return;
    app->detect_mode = false;
    app->autotune = false;
    app->worker = hitag_worker_alloc();
    hitag_worker_set_password(app->worker, app->password);
    hitag_worker_set_emu_tuning(
        app->worker, app->emu_preamble, app->emu_wresp_us, app->emu_leadbit);
    hitag_worker_set_emu_lean(app->worker, app->emu_lean);
    hitag_worker_set_emu_fast(app->worker, app->emu_fast);
    hitag_worker_set_pages(app->worker, app->last_pages);
    hitag_worker_start(app->worker, HitagWorkerSettingEmulateHitag2);
    hitag_show_scan(app, app->emu_fast ? "Emulate (tolerant)" : "Emulate", true, false);
}

// Emulate the current dump as a Hitag S (plain mode): Manchester replies to
// UID_REQ -> SELECT -> READ. Separate from the proven Hitag2 Emulate above so the
// reader-badge path is never affected; validated with the PM3 as reader (lf hitag hts reader).
void hitag_emulate_hitagS(HitagApp* app) {
    if(!app->has_data) {
        if(!hitag_pick_file(app)) return;
        app->has_data = true;
    }
    app->detect_mode = false;
    app->autotune = false;
    app->worker = hitag_worker_alloc();
    hitag_worker_set_pages(app->worker, app->last_pages);
    hitag_worker_set_hts_key(app->worker, app->hts_key);
    hitag_worker_set_hts_82xx(app->worker, app->hts_82xx);
    hitag_worker_start(app->worker, HitagWorkerSettingEmulateHitagS);
    hitag_show_scan(app, "Emulate Hitag S", true, false);
}

// Emulate the current dump as a Hitag1 tag (from the RTF base). Untested — no Hitag1 tag was
// available during development — but wired for completeness alongside Read Hitag1.
void hitag_emulate_hitag1(HitagApp* app) {
    if(!app->has_data) {
        if(!hitag_pick_file(app)) return;
        app->has_data = true;
    }
    app->detect_mode = false;
    app->autotune = false;
    app->worker = hitag_worker_alloc();
    hitag_worker_set_pages(app->worker, app->last_pages);
    hitag_worker_start(app->worker, HitagWorkerSettingEmulate);
    hitag_show_scan(app, "Emulate Hitag1", true, false);
}

// Emulate the current dump as a Hitag2 tag in CRYPTO mode (nRaR mutual auth + 48-bit cipher),
// separate from the proven password-mode Emulate. The reader authenticates with the "Hitag S
// key" (shared ONMIKR-family crypto key); validated with the PM3 as reader (read --ht2 --crypto).
void hitag_emulate_ht2_crypto(HitagApp* app) {
    if(!app->has_data) {
        if(!hitag_pick_file(app)) return;
        app->has_data = true;
    }
    app->detect_mode = false;
    app->autotune = false;
    app->worker = hitag_worker_alloc();
    hitag_worker_set_pages(app->worker, app->last_pages);
    hitag_worker_set_hts_key(app->worker, app->hts_key);
    hitag_worker_start(app->worker, HitagWorkerSettingEmulateHitag2Crypto);
    hitag_show_scan(app, "Emulate HT2 crypto", true, false);
}

// Launch emulation using the current Emulation settings:
//   Mode   Normal / Tolerant  -> emu_fast
//   Timing Fixed / Auto       -> Auto runs the T_wresp autotune sweep (respects Mode)
void hitag_handle_emulate(HitagApp* app) {
    if(!app->has_data) {
        if(!hitag_pick_file(app)) return;
        app->has_data = true;
    }
    // The dump's config (page 3, byte 0) carries the Hitag2 mode: 0x06 = password, 0x0E =
    // crypto (bit 0x08). So the user picks "Hitag2" and the dump decides password vs crypto.
    if(app->last_pages[3 * 4 + 0] & 0x08) {
        hitag_emulate_ht2_crypto(app);
        return;
    }
    if(app->emu_auto)
        hitag_start_autotune(app);
    else
        hitag_emulate_current(app);
}

// Autotune: emulate while sweeping T_wresp, banking per-combo AUTH/PWD/READ.
static void hitag_start_autotune(HitagApp* app) {
    if(!app->has_data) {
        if(!hitag_pick_file(app)) return;
        app->has_data = true;
    }
    app->detect_mode = false;
    app->autotune = true;
    app->at_combo = 0;
    app->at_dwell = 0;
    app->at_locked = false;
    app->at_base_a = app->at_base_p = app->at_base_r = 0;
    memset(app->at_aa, 0, sizeof(app->at_aa));
    memset(app->at_pp, 0, sizeof(app->at_pp));
    memset(app->at_rr, 0, sizeof(app->at_rr));
    app->worker = hitag_worker_alloc();
    hitag_worker_set_password(app->worker, app->password);
    hitag_worker_set_emu_tuning(
        app->worker, hitag_at_pre_of(0), hitag_at_wresp_of(0), hitag_at_lead_of(0));
    hitag_worker_set_emu_lean(app->worker, app->emu_lean);
    hitag_worker_set_emu_fast(app->worker, app->emu_fast); // Auto respects Mode
    hitag_worker_set_pages(app->worker, app->last_pages);
    hitag_worker_start(app->worker, HitagWorkerSettingEmulateHitag2);
    hitag_show_scan(app, app->emu_fast ? "Autotune (tol)" : "Autotune", true, false);
}

// Write the per-combo sweep results (and the best) to autotune_<ts>.txt.
static void hitag_save_autotune_log(HitagApp* app) {
    furi_mutex_acquire(app->worker_mutex, FuriWaitForever);
    if(app->worker) hitag_worker_stop(app->worker);
    // bank the in-progress combo so its tally isn't lost
    if(app->worker) {
        uint16_t a = 0, p = 0, r = 0;
        hitag_worker_get_emu_counts(app->worker, &a, &p, &r);
        app->at_aa[app->at_combo] += (uint16_t)(a - app->at_base_a);
        app->at_pp[app->at_combo] += (uint16_t)(p - app->at_base_p);
        app->at_rr[app->at_combo] += (uint16_t)(r - app->at_base_r);
    }
    storage_simply_mkdir(app->storage, HITAG_DIR);
    char ts[24];
    hitag_timestamp(ts, sizeof(ts));
    FuriString* body = furi_string_alloc();
    furi_string_cat_printf(
        body, "Hitag2 autotune (preamble x T_wresp, leadbit=on)%s\n\n",
        app->at_locked ? " [LOCKED on a hit]" : "");
    for(uint8_t i = 0; i < HITAG_AT_NCOMBO; i++) {
        furi_string_cat_printf(
            body,
            "pre%u W%lu: AUTH=%u PWD=%u READ=%u\n",
            hitag_at_pre_of(i),
            (unsigned long)hitag_at_wresp_of(i),
            app->at_aa[i],
            app->at_pp[i],
            app->at_rr[i]);
    }
    int8_t best = hitag_at_best(app);
    if(best >= 0)
        furi_string_cat_printf(
            body,
            "\nBEST: pre%u W%lu (READ=%u PWD=%u)\n",
            hitag_at_pre_of((uint8_t)best),
            (unsigned long)hitag_at_wresp_of((uint8_t)best),
            app->at_rr[best],
            app->at_pp[best]);
    else
        furi_string_cat_str(body, "\nBEST: none (no PWD/READ reached)\n");
    FuriString* path = furi_string_alloc_printf("%s/autotune_%s.txt", HITAG_DIR, ts);
    File* f = storage_file_alloc(app->storage);
    if(storage_file_open(f, furi_string_get_cstr(path), FSAM_WRITE, FSOM_CREATE_ALWAYS))
        storage_file_write(f, furi_string_get_cstr(body), furi_string_size(body));
    storage_file_close(f);
    storage_file_free(f);
    furi_string_free(body);
    furi_string_free(path);
    furi_mutex_release(app->worker_mutex);
}

/* ---------------------------------- emulate tuning -------------------------------- */

#define HITAG_PRE_MIN 3u
#define HITAG_WRESP_MIN 1536u // 192 carrier periods
#define HITAG_WRESP_STEP 64u // 8 carrier periods per step

// Mode: Normal (validate password) vs Tolerant (answer config on any 32-bit frame,
// for marginal coupling — see the worker Ht2CmdPwd case).
static void hitag_setting_mode_cb(VariableItem* item) {
    HitagApp* app = variable_item_get_context(item);
    app->emu_fast = variable_item_get_current_value_index(item) ? 1 : 0;
    variable_item_set_current_value_text(item, app->emu_fast ? "Tolerant" : "Normal");
}

// Timing: Fixed (use T_wresp below) vs Auto (autotune sweeps T_wresp and locks on a hit).
static void hitag_setting_timing_cb(VariableItem* item) {
    HitagApp* app = variable_item_get_context(item);
    app->emu_auto = variable_item_get_current_value_index(item) ? 1 : 0;
    variable_item_set_current_value_text(item, app->emu_auto ? "Auto" : "Fixed");
}

static void hitag_tuning_wresp_cb(VariableItem* item) {
    HitagApp* app = variable_item_get_context(item);
    uint32_t v = HITAG_WRESP_MIN + (uint32_t)variable_item_get_current_value_index(item) * HITAG_WRESP_STEP;
    app->emu_wresp_us = v;
    char b[12];
    snprintf(b, sizeof(b), "%lu", (unsigned long)v);
    variable_item_set_current_value_text(item, b);
}



// Emulation tuning: Mode (Normal/Tolerant) + Timing (Fixed/Auto) + T_wresp. The logging
// toggles (Lean logs, Debug traces) live in the Debug menu. Preamble/leadbit are NOT exposed:
// the norm-correct framing is preamble 4 (= reader tag_sof) with NO leadbit, so any other value
// would only distort a faithful emulation.
void hitag_handle_emu_settings(HitagApp* app) {
    variable_item_list_reset(app->tuning);
    char b[12];

    VariableItem* it = variable_item_list_add(app->tuning, "Mode", 2, hitag_setting_mode_cb, app);
    variable_item_set_current_value_index(it, app->emu_fast ? 1 : 0);
    variable_item_set_current_value_text(it, app->emu_fast ? "Tolerant" : "Normal");

    it = variable_item_list_add(app->tuning, "Timing", 2, hitag_setting_timing_cb, app);
    variable_item_set_current_value_index(it, app->emu_auto ? 1 : 0);
    variable_item_set_current_value_text(it, app->emu_auto ? "Auto" : "Fixed");

    it = variable_item_list_add(app->tuning, "T_wresp us", 9, hitag_tuning_wresp_cb, app); // 1536..2048
    uint32_t widx = (app->emu_wresp_us > HITAG_WRESP_MIN) ?
                        (app->emu_wresp_us - HITAG_WRESP_MIN) / HITAG_WRESP_STEP :
                        0;
    if(widx > 8) widx = 8;
    variable_item_set_current_value_index(it, widx);
    snprintf(b, sizeof(b), "%lu", (unsigned long)app->emu_wresp_us);
    variable_item_set_current_value_text(it, b);

    view_dispatcher_switch_to_view(app->view_dispatcher, HitagViewTuning);
}

/* ------------------------------- card action menu --------------------------------- */

// Show the per-dump card menu (Info / Emulate / Save / [Rename / Delete]) after a Read/Saved,
// NFC-style: you act on the tag you just read or loaded.
static void hitag_show_card(HitagApp* app) {
    const char* tn = app->tag_type == HitagTypeHt1 ? "Hitag1" :
                     app->tag_type == HitagTypeHtS ? "Hitag S" :
                                                     "Hitag2";
    if(app->from_sniff)
        snprintf(app->card_header, sizeof(app->card_header), "%s pwd", tn);
    else
        snprintf(
            app->card_header,
            sizeof(app->card_header),
            "%s %02X%02X%02X%02X",
            tn,
            app->last_pages[0],
            app->last_pages[1],
            app->last_pages[2],
            app->last_pages[3]);
    hitag_build_menu(app, MLCard);
    submenu_set_selected_item(app->submenu, 0);
    view_dispatcher_switch_to_view(app->view_dispatcher, HitagViewSubmenu);
}

// Emulate the current dump in its own family (the card's tracked type).
void hitag_emulate_by_type(HitagApp* app) {
    if(app->tag_type == HitagTypeHt1)
        hitag_emulate_hitag1(app);
    else if(app->tag_type == HitagTypeHtS)
        hitag_emulate_hitagS(app);
    else
        hitag_handle_emulate(app); // Hitag2: password/crypto auto-selected from the config
}

// Delete the loaded .hitag file (card action, Saved dumps only) -> back to the main menu.
void hitag_card_delete(HitagApp* app) {
    if(app->loaded_path[0]) {
        bool ok = storage_simply_remove(app->storage, app->loaded_path);
        notification_message(app->notifications, ok ? &sequence_success : &sequence_error);
        app->loaded_path[0] = 0;
        app->from_saved = false;
    }
    hitag_build_menu(app, MLTop);
    submenu_set_selected_item(app->submenu, 0);
    view_dispatcher_switch_to_view(app->view_dispatcher, HitagViewSubmenu);
}

// Rename the loaded .hitag file: prefill the text input with the current name (renaming=true so
// the commit renames instead of saving a new dump).
void hitag_handle_rename(HitagApp* app) {
    if(!app->from_saved || !app->loaded_path[0]) return;
    const char* base = strrchr(app->loaded_path, '/');
    base = base ? base + 1 : app->loaded_path;
    strncpy(app->save_name, base, HITAG_NAME_LEN - 1);
    app->save_name[HITAG_NAME_LEN - 1] = 0;
    char* dot = strstr(app->save_name, HITAG_EXT); // strip .hitag
    if(dot) *dot = 0;
    app->renaming = true;
    text_input_set_header_text(app->text_input, "Rename the dump");
    view_dispatcher_switch_to_view(app->view_dispatcher, HitagViewTextInput);
}

/* ---------------------------------- password -------------------------------------- */

void hitag_byte_input_cb(void* ctx) {
    HitagApp* app = ctx;
    view_dispatcher_switch_to_view(app->view_dispatcher, HitagViewSubmenu);
}

/* ---------------------------------- main menu ------------------------------------- */

static HitagTagType hitag_type_from_setting(HitagWorkerSetting s) {
    return (s == HitagWorkerSettingRead)          ? HitagTypeHt1 :
           (s == HitagWorkerSettingReadHitagS)    ? HitagTypeHtS :
           (s == HitagWorkerSettingSniffHitagS82xx) ? HitagTypeHtS :
                                                          HitagTypeHt2; // ReadHitag2 / SniffHitag2[Nonce]
}

// true if the setting is one of the passive sniff modes (password / nonces / 82xx)
static inline bool hitag_setting_is_sniff(HitagWorkerSetting s) {
    return s == HitagWorkerSettingSniffHitag2 ||
           s == HitagWorkerSettingSniffHitag2Nonce ||
           s == HitagWorkerSettingSniffHitagS82xx;
}
// live-display kind for a sniff setting: 0 = password, 1 = crypto nonces, 2 = Hitag S 82xx
static inline uint8_t hitag_sniff_kind(HitagWorkerSetting s) {
    return s == HitagWorkerSettingSniffHitag2Nonce ? 1 :
           s == HitagWorkerSettingSniffHitagS82xx  ? 2 :
                                                           0;
}
static const char* hitag_type_prefix(HitagTagType t) {
    return t == HitagTypeHt1 ? "hitag1" : t == HitagTypeHtS ? "hitags" : "hitag2";
}

void hitag_start_read(HitagApp* app, HitagWorkerSetting setting, const char* title) {
    app->tag_type = hitag_type_from_setting(setting);
    app->detect_mode = false;
    app->scan_is_sniff = hitag_setting_is_sniff(setting);
    app->scan_setting = setting;
    app->worker = hitag_worker_alloc();
    hitag_worker_set_password(app->worker, app->password);
    hitag_worker_start(app->worker, setting);
    hitag_show_scan(app, title, false, false);
}

void hitag_start_detect(HitagApp* app) {
    app->detect_mode = true;
    app->detect_locked = false;
    app->scan_is_sniff = false;
    app->detect_setting = HitagWorkerSettingReadHitag2;
    app->detect_ticks = 0;
    app->worker = hitag_worker_alloc();
    hitag_worker_set_password(app->worker, app->password);
    hitag_worker_start(app->worker, app->detect_setting);
    hitag_show_scan(app, "Detecting tag", false, true);
}


/* ------------------------------- settings persistence ----------------------------- */

// Factory-default settings: the keys/passwords, the emulate reply tuning and the debug
// toggles. NOT the preloaded demo dump. Norm-correct framing is fixed here — preamble = the
// reader's 4-bit SOF with NO leadbit, so the reader reads all 32 reply bits faithfully.
static void hitag_config_defaults(HitagApp* app) {
    memcpy(app->password, (const uint8_t[]){0x4D, 0x49, 0x4B, 0x52}, 4); // MIKR
    memcpy(app->hts_key, (const uint8_t[]){0x4F, 0x4E, 0x4D, 0x49, 0x4B, 0x52}, 6); // ONMIKR
    memcpy(app->hts_82xx, (const uint8_t[]){0xBB, 0xDD, 0x33, 0x99}, 4); // Proxmark3 default
    app->emu_preamble = 4; // fixed: the reader's SOF length
    app->emu_wresp_us = 1664; // T_wresp, centre of the 204..212 Tc reply window
    app->emu_leadbit = 0; // fixed: faithful 32-bit framing
    app->emu_lean = 0; // Debug -> Lean logs
    app->debug_traces = 0; // Debug -> Traces (diagnostic files off by default)
    app->emu_fast = 0; // Emulation tuning -> Mode: Normal
    app->emu_auto = 0; // Emulation tuning -> Timing: Fixed
}

// Persist the user-editable settings to settings.conf so they survive a reboot.
static void hitag_config_save(HitagApp* app) {
    storage_simply_mkdir(app->storage, HITAG_DIR);
    FlipperFormat* ff = flipper_format_file_alloc(app->storage);
    do {
        if(!flipper_format_file_open_always(ff, HITAG_CONF)) break;
        if(!flipper_format_write_header_cstr(ff, "Flipper Hitag settings", 1)) break;
        flipper_format_write_hex(ff, "Password", app->password, 4);
        flipper_format_write_hex(ff, "HtsKey", app->hts_key, 6);
        flipper_format_write_hex(ff, "Hts82xx", app->hts_82xx, 4);
        uint32_t v;
        v = app->emu_fast;
        flipper_format_write_uint32(ff, "EmuMode", &v, 1);
        v = app->emu_auto;
        flipper_format_write_uint32(ff, "EmuTiming", &v, 1);
        v = app->emu_wresp_us;
        flipper_format_write_uint32(ff, "EmuWresp", &v, 1);
        v = app->emu_lean;
        flipper_format_write_uint32(ff, "EmuLean", &v, 1);
        v = app->debug_traces;
        flipper_format_write_uint32(ff, "DebugTraces", &v, 1);
    } while(false);
    flipper_format_free(ff);
}

// Load settings.conf over the current (default) settings. Best-effort: a missing file or a
// missing key just leaves that setting at its default.
static void hitag_config_load(HitagApp* app) {
    FlipperFormat* ff = flipper_format_file_alloc(app->storage);
    do {
        if(!flipper_format_file_open_existing(ff, HITAG_CONF)) break;
        FuriString* hdr = furi_string_alloc();
        uint32_t ver = 0;
        bool ok = flipper_format_read_header(ff, hdr, &ver) &&
                  furi_string_equal_str(hdr, "Flipper Hitag settings");
        furi_string_free(hdr);
        if(!ok) break;
        flipper_format_read_hex(ff, "Password", app->password, 4);
        flipper_format_read_hex(ff, "HtsKey", app->hts_key, 6);
        flipper_format_read_hex(ff, "Hts82xx", app->hts_82xx, 4);
        uint32_t v;
        if(flipper_format_read_uint32(ff, "EmuMode", &v, 1)) app->emu_fast = v;
        if(flipper_format_read_uint32(ff, "EmuTiming", &v, 1)) app->emu_auto = v;
        if(flipper_format_read_uint32(ff, "EmuWresp", &v, 1)) app->emu_wresp_us = v;
        if(flipper_format_read_uint32(ff, "EmuLean", &v, 1)) app->emu_lean = v;
        if(flipper_format_read_uint32(ff, "DebugTraces", &v, 1)) app->debug_traces = v;
    } while(false);
    flipper_format_free(ff);
}

// Settings -> "Reset to defaults": restore factory settings and persist immediately.
void hitag_config_reset(HitagApp* app) {
    hitag_config_defaults(app);
    hitag_config_save(app);
    notification_message(app->notifications, &sequence_success);
    hitag_show_message(app, "Settings", "Reset to factory defaults");
}

int32_t hitag_app(void* p) {
    UNUSED(p);
    HitagApp* app = malloc(sizeof(HitagApp));
    furi_check(app);
    memset(app, 0, sizeof(HitagApp));
    // factory-default settings (keys + tuning + debug); the saved settings.conf, if any, is
    // loaded over these once storage is open, below.
    hitag_config_defaults(app);
    // preload a DEMO dump so Emulate/Autotune run out of the box (no file browser).
    // p0=UID 12345678, p1=pwd MIKR (password mode), p4="DEMO"; p5-7 = test patterns.
    {
        static const uint8_t badge[32] = {
            0x12, 0x34, 0x56, 0x78, 0x4D, 0x49, 0x4B, 0x52, 0x00, 0x00, 0x00,
            0x00, 0x06, 0xAA, 0x48, 0x54, 0x44, 0x45, 0x4D, 0x4F, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
        memcpy(app->last_pages, badge, 32);
        app->has_data = true;
        app->tag_type = HitagTypeHt2; // the preloaded demo is a Hitag2 password-mode dump
    }

    app->worker_mutex = furi_mutex_alloc(FuriMutexTypeRecursive);
    app->gui = furi_record_open(RECORD_GUI);
    app->storage = furi_record_open(RECORD_STORAGE);
    app->dialogs = furi_record_open(RECORD_DIALOGS);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);
    hitag_config_load(app); // restore persisted settings over the defaults
    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);

    app->submenu = submenu_alloc();
    hitag_build_menu(app, MLTop);
    view_dispatcher_add_view(app->view_dispatcher, HitagViewSubmenu, submenu_get_view(app->submenu));

    app->scan_view = view_alloc();
    view_allocate_model(app->scan_view, ViewModelTypeLocking, sizeof(HitagScanModel));
    view_set_context(app->scan_view, app);
    view_set_draw_callback(app->scan_view, hitag_scan_draw);
    view_set_input_callback(app->scan_view, hitag_scan_input);
    view_dispatcher_add_view(app->view_dispatcher, HitagViewScan, app->scan_view);

    app->content_view = view_alloc();
    view_allocate_model(app->content_view, ViewModelTypeLocking, sizeof(HitagContentModel));
    view_set_context(app->content_view, app);
    view_set_draw_callback(app->content_view, hitag_content_draw);
    view_set_input_callback(app->content_view, hitag_content_input);
    view_set_previous_callback(app->content_view, hitag_prev_menu);
    view_dispatcher_add_view(app->view_dispatcher, HitagViewContent, app->content_view);

    app->text_input = text_input_alloc();
    text_input_set_result_callback(
        app->text_input, hitag_text_input_cb, app, app->save_name, HITAG_NAME_LEN, true);
    text_input_set_header_text(app->text_input, "Name the dump");
    view_set_previous_callback(text_input_get_view(app->text_input), hitag_prev_menu);
    view_dispatcher_add_view(
        app->view_dispatcher, HitagViewTextInput, text_input_get_view(app->text_input));

    app->byte_input = byte_input_alloc();
    view_set_previous_callback(byte_input_get_view(app->byte_input), hitag_prev_menu);
    view_dispatcher_add_view(
        app->view_dispatcher, HitagViewByteInput, byte_input_get_view(app->byte_input));

    app->tuning = variable_item_list_alloc();
    view_set_previous_callback(variable_item_list_get_view(app->tuning), hitag_prev_menu);
    view_dispatcher_add_view(
        app->view_dispatcher, HitagViewTuning, variable_item_list_get_view(app->tuning));

    app->timer = furi_timer_alloc(hitag_timer_cb, FuriTimerTypePeriodic, app);

    view_dispatcher_set_navigation_event_callback(app->view_dispatcher, hitag_nav_cb);
    view_dispatcher_switch_to_view(app->view_dispatcher, HitagViewSubmenu);
    view_dispatcher_run(app->view_dispatcher);

    // cleanup
    hitag_config_save(app); // persist settings on exit (keys / tuning / debug)
    hitag_worker_teardown(app);
    furi_timer_free(app->timer);
    furi_mutex_free(app->worker_mutex);
    view_dispatcher_remove_view(app->view_dispatcher, HitagViewSubmenu);
    view_dispatcher_remove_view(app->view_dispatcher, HitagViewScan);
    view_dispatcher_remove_view(app->view_dispatcher, HitagViewContent);
    view_dispatcher_remove_view(app->view_dispatcher, HitagViewTextInput);
    view_dispatcher_remove_view(app->view_dispatcher, HitagViewByteInput);
    view_dispatcher_remove_view(app->view_dispatcher, HitagViewTuning);
    submenu_free(app->submenu);
    view_free(app->scan_view);
    view_free(app->content_view);
    variable_item_list_free(app->tuning);
    text_input_free(app->text_input);
    byte_input_free(app->byte_input);
    view_dispatcher_free(app->view_dispatcher);
    furi_record_close(RECORD_NOTIFICATION);
    furi_record_close(RECORD_DIALOGS);
    furi_record_close(RECORD_STORAGE);
    furi_record_close(RECORD_GUI);
    free(app);
    return 0;
}
