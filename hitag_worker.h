#pragma once
#include <furi.h>
#include <furi_hal.h>
#include <furi_hal_rfid.h>
#include <furi_hal_ibutton.h>
#include <furi_hal_interrupt.h>
#include <furi_hal_resources.h>
#include <furi_hal_bus.h>
#include <flipper_format/flipper_format.h>

#include <toolbox/stream/file_stream.h>
#include "buffer_stream.h"
#include <toolbox/varint.h>
#include "varint_pair.h"

#include <inttypes.h>

#include <stm32wbxx_ll_tim.h>
#include <stm32wbxx_ll_comp.h>
#include <stm32wbxx_ll_dma.h>

#include <dolphin/dolphin.h>

#define HITAG_BLOCKS 16
#define HITAG_BLOCKPAGES 4
#define HITAG_PAGES 64
#define HITAG_PAGEBYTES 4

// max reader commands captured per sniff/emulate session (for the full-transaction log)
#define HITAG_SNIFF_LOG_MAX 256
// max carrier-in cells captured of the real tag reply after a START_AUTH (sniff scope)
#define HITAG_SNIFF_SCOPE_MAX 160
// max Hitag2 crypto nR/aR nonce pairs captured per sniff (fed to the PC cracker)
#define HITAG_SNIFF_NONCE_MAX 32

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HitagWorkerSettingRead, // Hitag1 read (RTF anticollision)
    HitagWorkerSettingReadHitag2, // Hitag2 password-mode read
    HitagWorkerSettingSniffHitag2, // Hitag2 passive sniff (capture reader password)
    HitagWorkerSettingEmulate, // Hitag1 emulate
    HitagWorkerSettingEmulateHitag2, // Hitag2 password-mode emulate
    HitagWorkerSettingReadHitagS, // Hitag S plain-mode read (UID_REQ -> SELECT -> READ)
    HitagWorkerSettingEmulateHitagS, // Hitag S plain-mode emulate (Manchester replies)
    HitagWorkerSettingEmulateHitag2Crypto, // Hitag2 crypto-mode emulate (nRaR + cipher)
    HitagWorkerSettingSniffHitag2Nonce, // Hitag2 crypto sniff: capture nR/aR nonce pairs
    HitagWorkerSettingSniffHitagS82xx, // Hitag S sniff: capture the 8268/8310 password write
} HitagWorkerSetting;

typedef enum {
    HitagStatusScanning,
    HitagStatusDetected,
    HitagStatusRead,
} HitagStatus;

typedef struct HitagWorker HitagWorker;

/**
 * @brief Get the tag read status
 *
 * @return tag read status
 */
HitagStatus hitag_worker_get_status(HitagWorker* worker);

/**
 * @brief Allocate a new HitagWorker instance
 * 
 * @return HitagWorker* 
 */
HitagWorker* hitag_worker_alloc(void);

/**
 * @brief Copy out the 8 Hitag pages (32 bytes) and their known flags after a read/sniff.
 */
void hitag_worker_get_pages(HitagWorker* worker, uint8_t pages[32], uint8_t known[8]);

/**
 * @brief Load the 8 Hitag pages (32 bytes) to emulate (all marked known).
 */
void hitag_worker_set_pages(HitagWorker* worker, const uint8_t pages[32]);

/**
 * @brief Copy out the captured sniff transaction log (reader commands).
 *
 * @param lens out: per-command bit length (size of each frame)
 * @param vals out: per-command value (bits[0], MSB-aligned)
 * @return number of commands captured (<= HITAG_SNIFF_LOG_MAX)
 */
uint16_t hitag_worker_get_sniff_log(
    HitagWorker* worker,
    uint8_t lens[HITAG_SNIFF_LOG_MAX],
    uint32_t vals[HITAG_SNIFF_LOG_MAX]);

/** Lightweight count of captured reader commands (no buffer copy; safe to poll often). */
uint16_t hitag_worker_get_sniff_count(HitagWorker* worker);

/**
 * @brief Copy out the captured real-tag reply waveform (carrier-in cells, us) recorded
 *        after the first START_AUTH during a sniff. Ground truth to compare vs our emulate.
 *
 * @param cells out: per-cell durations in us
 * @return number of cells captured (<= HITAG_SNIFF_SCOPE_MAX)
 */
uint8_t hitag_worker_get_sniff_scope(
    HitagWorker* worker,
    uint16_t cells[HITAG_SNIFF_SCOPE_MAX]);

/**
 * @brief Copy out the Hitag2 crypto nR/aR nonce pairs captured during a nonce sniff.
 *        Each pair is one 64-bit reader auth frame (nR = high 32, aR = low 32). Feed these
 *        (with the UID) to the PC-side hitag2crack tools; the Flipper only collects them.
 *
 * @param nr out: per-pair nR (32-bit, MSB-aligned as transmitted)
 * @param ar out: per-pair aR (32-bit)
 * @return number of pairs captured (<= HITAG_SNIFF_NONCE_MAX)
 */
uint8_t hitag_worker_get_nonces(
    HitagWorker* worker,
    uint32_t nr[HITAG_SNIFF_NONCE_MAX],
    uint32_t ar[HITAG_SNIFF_NONCE_MAX]);

/**
 * @brief Get the Hitag S 8268/8310 password captured during an 82xx sniff (the value the
 *        reader wrote to virtual page 64). Returns true if one was captured; pwd[] gets the
 *        4 bytes MSB-first.
 */
bool hitag_worker_get_sniff_82xx(HitagWorker* worker, uint8_t pwd[4]);

/**
 * @brief Tune the Hitag2 emulate reply: preamble length (default 4), T_wresp in us
 *        (default 1664), and leadbit (1 = prepend a '0' data bit for a clean
 *        preamble/data boundary). For bench A/B of the framing shift, no reflash.
 */
void hitag_worker_set_emu_tuning(
    HitagWorker* worker,
    uint8_t preamble,
    uint32_t wresp_us,
    uint8_t leadbit);

/**
 * @brief Lean run: 1 = skip the per-command diagnostic log write during emulate, to
 *        minimise latency/jitter on the command->reply path (tighter T_wresp). The live
 *        AUTH/PWD/READ counters stay active. Off = full logging for diagnostics.
 */
void hitag_worker_set_emu_lean(HitagWorker* worker, uint8_t lean);

/**
 * @brief Fast/marginal-coupling emulate mode: 1 = answer the config page on ANY 32-bit
 *        frame (skip the pwd==RWD gate). We emulate a fixed-password badge, so the reader
 *        can only send that one password; under marginal coupling it is often mis-decoded,
 *        and gating on an exact match drops those valid attempts. Off = normal (gated).
 */
void hitag_worker_set_emu_fast(HitagWorker* worker, uint8_t fast);

/**
 * @brief Live counts of reader commands received during emulation, by type. Lets the UI
 *        show coupling quality in real time (a non-zero PASSWORD/READ = the reader
 *        accepted our UID reply and advanced). Safe to poll while emulating.
 */
void hitag_worker_get_emu_counts(
    HitagWorker* worker,
    uint16_t* auth,
    uint16_t* pwd,
    uint16_t* read);

/**
 * @brief Live read coupling gauge: best decoded frame bit-count since the last call
 *        (37 = a full clean reply, <37 = weak/truncated coupling), then resets. Poll it
 *        during a Hitag2 read to show a signal-quality meter for badge positioning.
 */
uint8_t hitag_worker_get_read_best_bits(HitagWorker* worker);

/**
 * @brief Free a HitagWorker instance
 * 
 * @param worker HitagWorker instance
 */
void hitag_worker_free(HitagWorker* worker);

/**
 * @brief Start hitag worker  from own generated field
 * 
 * @param worker HitagWorker instance
 * @param setting read/emulate
 */
void hitag_worker_start(HitagWorker* worker, HitagWorkerSetting setting);

/**
 * @brief Set the Hitag2 password-mode password (RWD, page 1). Default 4D 49 4B 52 ("MIKR").
 *
 * @param worker HitagWorker instance
 * @param password 4-byte password, MSB first as transmitted
 */
void hitag_worker_set_password(HitagWorker* worker, const uint8_t password[4]);

/**
 * @brief Set the Hitag S emulate secrets (typed by the user in the app):
 *        the 48-bit crypto key (6 bytes, same order as the reader's -k, e.g. ONMIKR) and the
 *        8268/8310 password (4 bytes, e.g. BB DD 33 99). Call before starting EmulateHitagS.
 */
void hitag_worker_set_hts_key(HitagWorker* worker, const uint8_t key[6]);
void hitag_worker_set_hts_82xx(HitagWorker* worker, const uint8_t pwd[4]);

/**
 * @brief Stop worker
 * 
 * @param worker 
 */
void hitag_worker_stop(HitagWorker* worker);

#ifdef __cplusplus
}
#endif