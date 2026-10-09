#pragma once

// Internal header shared by the Hitag worker core and the per-protocol modules
// (hitag1 / hitag2 / hitags). It holds the worker state struct, the on-air frame
// types, the timing/framing constants, and the declarations of everything that
// crosses a file boundary (shared helpers + the per-protocol threads/validators).
//
// This is NOT the public API: app code includes hitag_worker.h, never this file.

#include "hitag_worker.h" // public API + the furi / buffer_stream / varint dependencies
#include "hitag_frames.h" // Hitag2 + Hitag S reader-command classifiers
#include "hitag2_cipher.h" // Hitag2 stream cipher (Hitag2 crypto + Hitag S challenge auth)

#define DMA_BUFFER_SIZE \
    3000 //big enough for HT/TC refill timing, small enough to keep Hitag2 password injection within the tag's ~40ms inter-frame window
#define HITAG_CMD_BUFFER_SIZE 100 //this was originally 1000, but can be lowered

#define READ_BUFFER_SIZE 4000
#define READ_BUFFER_COUNT 4

#define EMULATE_BUFFER_SIZE 50
#define EMULATE_BUFFER_COUNT 50

//bitlength/ID for read cmd structure
#define HITAG_STOP 102
#define HITAG_ON 101
#define HITAG_OFF 100
#define HITAG_SET 5
#define HITAG_SELECT 5
#define HITAG_CMD 4
#define HITAG_BYTE 8
#define HITAG_CRC 8

//carrier periods for read cmd structure
#define HITAG_LOW 7
#define HITAG_STOP_HIGH 40
#define HITAG_1_HIGH 21
#define HITAG_0_HIGH 15

//bitlength for emulate reply cmd structure
#define HITAG_PAGE 32
#define HITAG_STARTBIT 1
#define HITAG_STARTBIT3 3
#define HITAG_STARTBIT6 6
#define HITAG_ACK 3
#define HITAG_ACK_ADV 8

#define HITAG_BASEPERIOD 8

//carrier periods for read reply decoding
#define HITAG_DURATION_S 256
#define HITAG_DURATION_M 384
#define HITAG_DURATION_L 512
#define HITAG_DURATION_ERROR_MARGIN 0.20

#define HITAG_BITPERIODS_AC 64
#define HITAG_BITPERIODS_MC 32

// sniff targets (worker->sniff_target): what a passive sniff extracts
#define HITAG_SNIFF_TGT_PWD 0 // Hitag2 reader password (plaintext 32-bit frame)
#define HITAG_SNIFF_TGT_NONCE 1 // Hitag2 crypto nR/aR pairs (64-bit auth frames)
#define HITAG_SNIFF_TGT_82XX 2 // Hitag S 8268/8310 password (write to virtual page 64)

//MISC
#define READ 1
#define WRITE 2

#define CRC_PRESET 0xFF
#define CRC_POLYNOM 0x1D

// Hitag2 tag response delay (T_wresp, spec 204..212 carrier periods): where the
// emulator places its load-modulated reply so the reader is sampling for it.
// Expressed in microseconds (1 carrier period = 8us at 125kHz) so the reply can be timed
// against the hardware us timeline (furi_hal_rfid_rtf_carrier_in_edge_us), which is immune
// to the worker falling behind the capture ISR (the cause of consecutive-read failures).
#define HITAG2_EMU_WAIT_RESP    208
#define HITAG2_EMU_WAIT_RESP_US (HITAG2_EMU_WAIT_RESP * 8)

#define TAG "HitagWorker"

typedef enum {
    HitagProtocolAntiCollision,
    HitagProtocolManchesterCoding,
} HitagProtocol;

typedef enum {
    HitagWorkerSignalHalfTransfer,
    HitagWorkerSignalTransferComplete,
    HitagWorkerSignalStop,
} HitagWorkerSignal;

typedef enum {
    HitagStateIdle,
    HitagStateSelected,
    HitagStateQuiet,
} HitagState;

typedef enum {
    HitagModeBasic,
    HitagModeAdvanced,
} HitagMode;

typedef struct {
    uint32_t timer_buffer_arr[DMA_BUFFER_SIZE];
    uint32_t timer_buffer_ccr[DMA_BUFFER_SIZE];
} TimerDMAData;

typedef struct {
    uint32_t CMDvalue[HITAG_CMD_BUFFER_SIZE]; //this can likely be a uint16_t instead of uint32_t
    uint8_t CMDtype[HITAG_CMD_BUFFER_SIZE];
    uint16_t CMDlength;
    uint16_t CMDposition;
    uint16_t CMDsubposition;
    bool CMDloop;
    bool CMDactive;
    uint32_t CMDcount;
} HitagCMDData;

typedef struct {
    uint32_t replyvalue[HITAG_CMD_BUFFER_SIZE]; //this can likely be a uint8_t instead of uint32_t
    uint8_t replytype[HITAG_CMD_BUFFER_SIZE];
    uint16_t replylength;
} HitagReplyData;

typedef struct {
    BufferStream* stream;
    VarintPair* pair;
    uint32_t capCounter;
} HitagCaptureData;

typedef struct {
    uint8_t pageData[HITAG_PAGES * HITAG_PAGEBYTES];
    uint8_t pageKnown[HITAG_PAGES];
    uint8_t tagData[HITAG_PAGES * HITAG_PAGEBYTES + HITAG_PAGES];
    uint8_t pageRW[HITAG_PAGES];
    uint8_t pagePublic[HITAG_PAGES];
} HitagTag;

// main worker
struct HitagWorker {
    FuriThread* thread;
    FuriEventFlag* events;
    uint8_t DMAeventCount;

    uint8_t carrierPrescaler;

    HitagTag* tag;

    HitagStatus workerstatus;

    uint8_t password[4]; // Hitag2 password-mode RWD password (page 1)
    bool sniff; // when true, the emulate thread passively captures the reader password
    bool emulate_hitag2; // when true, the emulate thread emulates a Hitag2 tag
    bool emulate_hitagS; // when true, the emulate thread emulates a Hitag S tag (plain mode)
    bool emulate_hitag2_crypto; // when true, emulate a Hitag2 tag in CRYPTO mode (nRaR + cipher)
    uint32_t hts_82xx_pwd; // Hitag S 8268/8310 auth password (default BBDD3399)
    uint64_t hts_crypto_key; // Hitag S 48-bit crypto key (MemLe of the -k bytes; default ONMIKR)

    // full-transaction sniff log: every decoded reader command (START_AUTH / password / READ)
    uint8_t sniff_log_len[HITAG_SNIFF_LOG_MAX];
    uint32_t sniff_log_val[HITAG_SNIFF_LOG_MAX];
    uint16_t sniff_log_cnt;

    // sniff scope: carrier-in cells (us) of the real tag reply, armed at the first START_AUTH
    uint16_t sniff_scope[HITAG_SNIFF_SCOPE_MAX];
    uint8_t sniff_scope_cnt;
    bool sniff_scope_arm; // currently recording the reply window
    bool sniff_scope_done; // first reply captured -> freeze

    // what a sniff run extracts: reader password (Hitag2), crypto nonces (Hitag2), or the
    // 82xx password write (Hitag S). Selected via the worker setting; routes both the reader
    // validator and the secret-extraction in the frame-log block.
    uint8_t sniff_target; // 0 = HT2 password, 1 = HT2 crypto nonces, 2 = Hitag S 82xx
    // Hitag2 crypto: captured nR/aR pairs (one per 64-bit reader auth frame)
    uint32_t sniff_nonce_nr[HITAG_SNIFF_NONCE_MAX];
    uint32_t sniff_nonce_ar[HITAG_SNIFF_NONCE_MAX];
    uint8_t sniff_nonce_cnt;
    // Hitag S 82xx: the reader writes its password to virtual page 64 -> capture the data frame
    bool sniff_hts_w64; // last command was WRITE(page 64); the next data frame is the password
    bool sniff_82xx_got; // an 82xx password was captured
    uint32_t sniff_82xx_pwd; // the captured 82xx password (MSB-aligned as transmitted)

    // emulate reply tuning (bench A/B of the framing shift)
    uint8_t emu_preamble; // preamble '1' count (default 4)
    uint32_t emu_wresp_us; // T_wresp in us (default 1664)
    uint8_t emu_leadbit; // 1 = prepend a '0' data bit (clean preamble/data boundary)
    uint8_t emu_lean; // 1 = skip the live command-log write (min reply-path latency/jitter)
    uint8_t emu_fast; // 1 = answer config on ANY 32-bit frame (skip pwd==RWD gate); marginal-coupling mode

    // live emulate counts by reader-command type (coupling-quality readout).
    // Intentional benign data race: written only by the worker thread, read only by the GUI
    // timer callback (via hitag_worker_get_emu_counts). A torn read of a uint16 gauge is
    // harmless, so no lock/atomic — same for read_best_bits and workerstatus.
    uint16_t emu_auth;
    uint16_t emu_pwd;
    uint16_t emu_read;

    // read coupling meter: best decoded frame bit-count since the last poll (37 = a full
    // clean reply). Lets the UI show a live signal-quality gauge so the user can position
    // the badge until decodes complete, instead of moving it blindly.
    uint8_t read_best_bits;
};

// Reader-command class, shared by the Hitag2 classifier and the emulate counters.
typedef enum {
    Ht2CmdNone = 0,
    Ht2CmdAuth, // START_AUTH (0b11000, 5b nominal)
    Ht2CmdRead, // READ page n (0b11..., 10b nominal)
    Ht2CmdPwd, // 32-bit password frame
} Ht2CmdType;

// Store a 32-bit page value MSB-first (as transmitted on air) into pageData[page*4 .. +3].
// Single source of truth for the byte-split that was open-coded across the read/sniff paths
// (a mistyped shift in one copy would silently corrupt a page).
static inline void hitag_store_page(uint8_t* pageData, uint8_t page, uint32_t val) {
    pageData[page * 4 + 0] = (uint8_t)(val >> 24);
    pageData[page * 4 + 1] = (uint8_t)(val >> 16);
    pageData[page * 4 + 2] = (uint8_t)(val >> 8);
    pageData[page * 4 + 3] = (uint8_t)val;
}


// --- shared helpers (defined in hitag_worker.c, called across the protocol modules) ---
void hitag_worker_calc_crc(uint8_t* crc, uint8_t data, uint8_t bitcount);
bool hitag_worker_validate_command(uint32_t* bits, uint8_t len);
void hitag_worker_combine_tag_data(HitagTag* tag);
void hitag_worker_initialize_tag_data(HitagTag* tag);
void hitag_worker_process_config_page(HitagTag* tag);
void hitag_worker_decoder_feed(
    uint32_t pulse,
    uint32_t duration,
    uint32_t* memBlock,
    uint8_t* bits,
    bool* half,
    bool* finished,
    HitagProtocol protocol,
    uint8_t startBits);
void hitag_worker_yield_dma_buffer_BPLM(
    HitagCMDData* dataCMD,
    HitagCMDData* backupCMD,
    TimerDMAData* dataDMA,
    size_t start,
    size_t len);
// ISR callbacks the reader threads hand to the RFID HAL (capture-in / carrier-out DMA)
void hitag_worker_capture_in_cc_callback(bool level, uint32_t duration, void* context);
void hitag_worker_carrier_out_dma_callback(bool half, void* dma_context);

// --- per-protocol reader read-threads (FuriThread callbacks, dispatched by hitag_worker_start) ---
int32_t hitag1_worker_read_thread(void* thread_context);
int32_t hitag2_worker_read_thread(void* thread_context);
int32_t hitags_worker_read_thread(void* thread_context);

// --- per-protocol reader-frame validators (dispatched by hitag_emu_validate) ---
bool hitag1_worker_validate_bits(uint32_t* bits, uint8_t bitcounter);
bool hitag2_worker_validate_bits(uint32_t* bits, uint8_t bitcounter);
bool hitags_worker_validate_bits(uint32_t* bits, uint8_t bitcounter);
bool hitag2crypto_worker_validate_bits(uint32_t* bits, uint8_t bitcounter);

// --- per-protocol helpers used by the emulate branch ---
Ht2CmdType hitag2_classify_cmd(uint8_t size, uint32_t bits0);
bool hitags_page_writable(const uint8_t* pageData, uint8_t page);
