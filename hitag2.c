// Hitag2 (125 kHz LF) reader + tag support, split out of the shared worker.
//
// Contents: the Hitag2 password-mode reader read-thread (Flipper-as-reader), the
// reader-frame validators (password + crypto) and the command classifier shared by
// the live counters and the reply builder. The Hitag2 emulate REPLY (password and
// crypto) lives in the shared emulate thread (hitag_worker.c); this file provides
// the pieces that thread dispatches to. Constants/types come from hitag_worker_i.h.

#include "hitag_worker_i.h"

// Recognise reader commands for Hitag2 CRYPTO emulation. Once crypto is active every frame is
// stream-encrypted, so the opcode/content can't be matched — accept purely by LENGTH (START_AUTH
// 5, READ 10, write-data 32, nRaR 64) and leave the frame MSB-aligned in bits[0]/bits[1] for the
// crypto handler to decrypt. Only used for the dedicated crypto emulate mode.
bool hitag2crypto_worker_validate_bits(uint32_t* bits, uint8_t bitcounter) {
    (void)bits;
    if(66 >= bitcounter && bitcounter >= 62) return true; // nRaR (64)
    if(34 >= bitcounter && bitcounter >= 31) return true; // 32-bit write data
    if(12 >= bitcounter && bitcounter >= 10) return true; // READ (10)
    if(7 >= bitcounter && bitcounter >= 5) return true; // START_AUTH (5)
    return false;
}

// Recognise reader commands for Hitag2 emulation. Unlike Hitag1 these carry no
// CRC, so validate by length (+ START_AUTH content) and left-align the command
// into bits[0] for the caller. Commands: START_AUTH=5b (0b11000), READ=10b
// (starts 0b11), password=32b (any value).
bool hitag2_worker_validate_bits(uint32_t* bits, uint8_t bitcounter) {
    if(34 >= bitcounter && bitcounter >= 31) {
        //32-bit password frame (align to 32 if slightly over)
        for(uint8_t i = 0; i < bitcounter - 31; i++) {
            if(i > 0) bits[0] = bits[0] << 1 | bits[1] >> (32 - 1);
        }
        return true;
    } else if(12 >= bitcounter && bitcounter >= 10) {
        for(uint8_t i = 0; i < bitcounter - 9; i++) {
            if(i > 0) bits[0] = bits[0] << 1;
            if((bits[0] >> (32 - 2)) == 0b11) return true; //READ starts with 11
        }
    } else if(7 >= bitcounter && bitcounter >= 5) {
        for(uint8_t i = 0; i < bitcounter - 4; i++) {
            if(i > 0) bits[0] = bits[0] << 1;
            if((bits[0] >> (32 - 5)) == 0b11000) return true; //START_AUTH
        }
    }
    return false;
}

// Single source of truth for classifying a decoded Hitag2 reader command by its bit
// length (+ START_AUTH opcode). Both the live coupling counters and the reply builder
// use this, so the tolerant size ranges can never drift apart (a size==5-vs-5..7 style
// mismatch between the two paths was the "many AUTH, 0 PWD" bug). Ranges are widened to
// absorb spurious trailing edges under marginal coupling.
Ht2CmdType hitag2_classify_cmd(uint8_t size, uint32_t bits0) {
    if(size >= 5 && size <= 7) return ((bits0 >> (32 - 5)) == 0b11000) ? Ht2CmdAuth : Ht2CmdNone;
    if(size >= 10 && size <= 12) return Ht2CmdRead;
    if(size >= 31 && size <= 34) return Ht2CmdPwd;
    return Ht2CmdNone;
}


// Hitag2 password-mode read (reader perspective):
// Hitag2 session (reader perspective):
//   reader: START_AUTH (0b11000, 5 bits)   ->  tag: 32-bit UID (page 0)
//   reader: 32-bit password RWD (page 1)   ->  tag: 32-bit config+pwdTAG (discarded)
//   reader: READ page n (10 bits)          ->  tag: 32-bit page n     (n = 0..7)
// Reader modulation (BPLM) is identical to Hitag1 and reuses the shared encoder.
// Tag replies are Manchester coded; reuse the shared MC decoder.
// Unlike Hitag1 (stateless re-selection), the authenticated session must be kept
// alive: once a UID is captured the looping idle command is switched from
// START_AUTH to a plain field-on filler so we never re-trigger authentication.

// Number of leading '1' sync bits in a Hitag2 tag reply, and total expected
// bits per reply (preamble + 32 data). Best-effort; tune against hardware.
#define HITAG2_STARTBITS 5
#define HITAG2_REPLY_BITS (HITAG2_STARTBITS + 32)
#define HITAG2_READ_THRESHOLD 1

int32_t hitag2_worker_read_thread(void* thread_context) {
    HitagWorker* worker = (HitagWorker*)thread_context;

    //reset the persistent tag for a fresh read
    hitag_worker_initialize_tag_data(worker->tag);
    worker->read_best_bits = 0; //fresh coupling meter

    //prep variables for decoder (Hitag2 replies are always Manchester)
    HitagProtocol currentProtocol = HitagProtocolManchesterCoding;
    uint8_t startBits = HITAG2_STARTBITS;
    uint32_t memBlock[HITAG_BLOCKPAGES] = {0};
    uint8_t bits = 0;
    bool halfBit = false;
    bool finished = false;

    //prep variables for worker
    uint8_t expectedBits = HITAG2_REPLY_BITS;

    // Mapping replies to pages, content-based + one-READ-per-loop. The loop is
    // START_AUTH -> (UID) ; password -> (config=page3) ; READ(target) -> (page[target]).
    // The reply right after the loop marker is the UID (reliable anchor). Once the
    // UID and the config value are known, the only reply that is neither = page[target],
    // and we KNOW target because we chose it. A 2-read confidence filter absorbs the
    // command-switch (DMA) latency when target advances.
    bool uid_known = false;
    uint32_t uid_val = 0;
    uint32_t uid_cand = 0;
    uint8_t uid_cnt = 0;
    bool config_known = false;
    uint32_t config_val = 0;
    uint32_t cfg_cand = 0;
    uint8_t cfg_cnt = 0;
    // marker-free bootstrap: during the target=3 phase each loop replies
    // UID, config, page3(=config) -> two consecutive EQUAL replies are the config;
    // a reply that differs from the known config is the UID.
    uint32_t prev_reply = 0;
    uint8_t target = 3; // page currently being READ (start with 3 to learn the config)
    uint32_t cand_val = 0; // confidence filter for the current target
    uint8_t cand_cnt = 0;
    uint32_t cand_val2 = 0; // 2nd voting slot: tolerate a noisy decode BETWEEN two good ones
    uint8_t cand_cnt2 = 0; //   (2-of-window instead of strictly-consecutive confidence)
    uint8_t settle = 0; // ignore stale replies for a few frames after a target switch
    uint32_t prev_val = 0; // value of the previously-stored page (stale-reply guard)
    uint16_t read_tx0_idx = 0; // backupCMD indices of the READ command bytes, for patching
    uint16_t read_tail_idx = 0;

    // setup pins for reading (identical to Hitag1 read thread)
    furi_hal_ibutton_pin_configure();
    furi_hal_ibutton_pin_write(false);
    furi_hal_gpio_init(&gpio_nfc_irq_rfid_pull, GpioModeOutputPushPull, GpioPullNo, GpioSpeedLow);
    furi_hal_gpio_write(&gpio_nfc_irq_rfid_pull, false);
    furi_hal_gpio_init_ex(
        &gpio_rfid_carrier_out,
        GpioModeAltFunctionPushPull,
        GpioPullNo,
        GpioSpeedLow,
        GpioAltFn1TIM1);
    furi_hal_gpio_init(&gpio_rfid_data_in, GpioModeAnalog, GpioPullNo, GpioSpeedLow);

    //one-shot command (password / READ), injected when a reply advances the state
    HitagCMDData* dataCMD = malloc(sizeof(HitagCMDData));
    furi_check(dataCMD);
    dataCMD->CMDlength = 0;
    dataCMD->CMDposition = 0;
    dataCMD->CMDsubposition = 0;
    dataCMD->CMDactive = false;

    //Scripted password-mode sequence, looped continuously. Hitag2 auth is too
    //timing-sensitive for reactive command injection, so instead of reacting to
    //each reply we blast a fixed sequence with proper inter-frame timing and map
    //the tag's responses by position (the UID self-syncs each loop):
    //  START_AUTH -> UID | password -> config | READ1..READ7 -> page1..page7
    //Each frame = settle(ON) + command bits + STOP + read window(ON).
    HitagCMDData* backupCMD = malloc(sizeof(HitagCMDData));
    furi_check(backupCMD);
    {
        const uint32_t readwin = 2000; //T_wresp + up to ~15ms reply (37 MC cells) + margin; do
        //   NOT trim below ~2000 or busy replies get truncated -> lost decodes
        uint16_t n = 0;
        // START_AUTH (0b11000, 5 bits)
        backupCMD->CMDvalue[n] = 128;
        backupCMD->CMDtype[n++] = HITAG_ON;
        backupCMD->CMDvalue[n] = 0b11000;
        backupCMD->CMDtype[n++] = HITAG_SET;
        backupCMD->CMDvalue[n] = 1;
        backupCMD->CMDtype[n++] = HITAG_STOP;
        backupCMD->CMDvalue[n] = readwin;
        backupCMD->CMDtype[n++] = HITAG_ON;
        // PASSWORD (32 bits, RWD)
        backupCMD->CMDvalue[n] = 128;
        backupCMD->CMDtype[n++] = HITAG_ON;
        for(uint8_t i = 0; i < 4; i++) {
            backupCMD->CMDvalue[n] = worker->password[i];
            backupCMD->CMDtype[n++] = HITAG_BYTE;
        }
        backupCMD->CMDvalue[n] = 1;
        backupCMD->CMDtype[n++] = HITAG_STOP;
        backupCMD->CMDvalue[n] = readwin;
        backupCMD->CMDtype[n++] = HITAG_ON;
        // single READ(target) per loop (10-bit command). The bytes are patched in
        // place when target advances (indices recorded here).
        backupCMD->CMDvalue[n] = 128;
        backupCMD->CMDtype[n++] = HITAG_ON;
        read_tx0_idx = n;
        backupCMD->CMDvalue[n] = 0xC0 | (target << 3) | ((target ^ 7) >> 2);
        backupCMD->CMDtype[n++] = HITAG_BYTE;
        read_tail_idx = n;
        backupCMD->CMDvalue[n] = (target ^ 7) & 0b11;
        backupCMD->CMDtype[n++] = 2;
        backupCMD->CMDvalue[n] = 1;
        backupCMD->CMDtype[n++] = HITAG_STOP;
        backupCMD->CMDvalue[n] = readwin;
        backupCMD->CMDtype[n++] = HITAG_ON;
        // inter-loop idle (field on, no modulation). This MUST exceed the tag's session
        // hold time T_wsc (~40ms) so the tag drops its auth session between loops and the
        // next START_AUTH always starts from a clean state. Undershooting it (e.g. 12ms)
        // leaves the tag mid-session when START_AUTH arrives -> it stalls until the field
        // is cut (the user had to physically move the badge to force a reset). 6000 = 48ms:
        // safely past T_wsc, yet still far below the original 10000 (80ms) dead time.
        backupCMD->CMDvalue[n] = 6000;
        backupCMD->CMDtype[n++] = HITAG_ON;
        backupCMD->CMDlength = n;
    }
    backupCMD->CMDposition = 0;
    backupCMD->CMDsubposition = 0;
    backupCMD->CMDloop = true;
    backupCMD->CMDactive = true;

    TimerDMAData* dataDMA = malloc(sizeof(TimerDMAData));
    furi_check(dataDMA);
    hitag_worker_yield_dma_buffer_BPLM(dataCMD, backupCMD, dataDMA, 0, DMA_BUFFER_SIZE / 2);
    hitag_worker_yield_dma_buffer_BPLM(
        dataCMD, backupCMD, dataDMA, DMA_BUFFER_SIZE / 2, DMA_BUFFER_SIZE / 2);

    furi_hal_rfid_rtf_carrier_out_start(
        dataDMA->timer_buffer_arr,
        dataDMA->timer_buffer_ccr,
        DMA_BUFFER_SIZE,
        hitag_worker_carrier_out_dma_callback,
        worker);

    HitagCaptureData* capData = malloc(sizeof(HitagCaptureData));
    furi_check(capData);
    capData->stream = buffer_stream_alloc(READ_BUFFER_SIZE, READ_BUFFER_COUNT);
    capData->pair = varint_pair_alloc();
    furi_hal_rfid_tim_read_capture_start(hitag_worker_capture_in_cc_callback, capData);

    while(1) {
        Buffer* buffer = buffer_stream_receive(capData->stream, 1);

        if(buffer != NULL) {
            size_t buffsize = buffer_get_size(buffer);
            uint8_t* buffdata = buffer_get_data(buffer);

            size_t index = 0;
            while(expectedBits > 0 && index < buffsize) {
                uint32_t duration;
                uint32_t pulse;
                size_t tmp_size;

                if(!varint_pair_unpack(
                       &buffdata[index], buffsize - index, &pulse, &duration, &tmp_size)) {
                    FURI_LOG_E(TAG, "can't unpack varint pair");
                    break;
                }
                index += tmp_size;

                hitag_worker_decoder_feed(
                    pulse,
                    duration,
                    memBlock,
                    &bits,
                    &halfBit,
                    &finished,
                    currentProtocol,
                    startBits);

                if(finished) {
                    //coupling meter: track the best frame bit-count seen (37 = full clean
                    //reply). The UI polls-and-resets this to gauge live signal quality.
                    if(bits > worker->read_best_bits) worker->read_best_bits = bits;
                    //DIAG: one line per completed reply frame. bits==37 = clean decode;
                    //bits<37 = truncated/missed-edge (analog coupling); tgt = page being READ.
                    if(bits > 0) {
                        FURI_LOG_D(
                            TAG, "rx b=%u v=%08lX tgt=%u", bits, (unsigned long)memBlock[0], target);
                    }
                    //publish the accumulated page state to the dict (propagates UID/config,
                    //which are committed to pageData in the confirmation logic below)
                    if(bits > 0) {
                        hitag_worker_combine_tag_data(worker->tag);
                    }
                    if(bits == expectedBits) {
                        uint32_t val = memBlock[0];

                        if(!config_known) {
                            //config = two consecutive EQUAL replies (the password reply
                            //and the page3 readback during the target=3 phase)
                            if(val == prev_reply) {
                                if(val == cfg_cand) {
                                    cfg_cnt++;
                                } else {
                                    cfg_cand = val;
                                    cfg_cnt = 1;
                                }
                                if(cfg_cnt >= 2) {
                                    config_val = val;
                                    config_known = true;
                                    hitag_store_page(worker->tag->pageData, 3, val);
                                    worker->tag->pageKnown[3] = 1;
                                }
                            }
                        } else if(!uid_known) {
                            //uid = a reply that differs from the known config
                            if(val != config_val) {
                                if(val == uid_cand) {
                                    uid_cnt++;
                                } else {
                                    uid_cand = val;
                                    uid_cnt = 1;
                                }
                                if(uid_cnt >= 2) {
                                    uid_val = val;
                                    uid_known = true;
                                    dolphin_deed(DolphinDeedRfidReadSuccess);
                                    worker->workerstatus = HitagStatusDetected;
                                    hitag_store_page(worker->tag->pageData, 0, val);
                                    worker->tag->pageKnown[0] = 1;
                                    //start reading the remaining pages
                                    target = 1;
                                    backupCMD->CMDvalue[read_tx0_idx] =
                                        0xC0 | (target << 3) | ((target ^ 7) >> 2);
                                    backupCMD->CMDvalue[read_tail_idx] = (target ^ 7) & 0b11;
                                    settle = 3; //prev_val guard covers stale replies; 8 was overkill
                                    prev_val = config_val;
                                    cand_val = 0;
                                    cand_cnt = 0;
                                    cand_val2 = 0;
                                    cand_cnt2 = 0;
                                }
                            }
                        } else {
                            //map by content: UID and config (page3) are known anchors,
                            //anything else is the reply to READ(target).
                            uint8_t pg = 0xff;
                            bool advance = false;
                            if(val == uid_val || val == config_val) {
                                //page0 / page3 already captured -> ignore
                            } else if(settle > 0) {
                                settle--; //stale reply right after a target switch
                            } else if(val == prev_val) {
                                //leftover reply from the previous target -> ignore
                            } else {
                                //2-of-window confidence: accept a value seen twice among
                                //recent decodes for this target, NOT necessarily consecutive.
                                //Two voting slots tolerate a single noisy decode landing
                                //between two good ones (the strictly-consecutive filter reset
                                //on any such noise -> the read stalled and needed the badge
                                //re-approached until two clean decodes happened back-to-back).
                                //On acceptance `val` IS the winning value (we just matched it).
                                if(val == cand_val) {
                                    cand_cnt++;
                                } else if(val == cand_val2) {
                                    cand_cnt2++;
                                } else if(cand_cnt == 0) {
                                    cand_val = val;
                                    cand_cnt = 1;
                                } else if(cand_cnt2 == 0) {
                                    cand_val2 = val;
                                    cand_cnt2 = 1;
                                } else {
                                    //both slots hold different singletons: drop the older one
                                    cand_val = val;
                                    cand_cnt = 1;
                                }
                                if(cand_cnt >= 2 || cand_cnt2 >= 2) {
                                    pg = target;
                                    advance = true;
                                }
                            }

                            if(pg < 8) {
                                hitag_store_page(worker->tag->pageData, pg, val);
                                worker->tag->pageKnown[pg] = 1;

                                if(advance) {
                                    //move target to the next still-unknown page (cycle 1..7)
                                    uint8_t next = target;
                                    for(uint8_t s = 0; s < 7; s++) {
                                        next = (next % 7) + 1;
                                        if(!worker->tag->pageKnown[next]) break;
                                    }
                                    target = next;
                                    backupCMD->CMDvalue[read_tx0_idx] =
                                        0xC0 | (target << 3) | ((target ^ 7) >> 2);
                                    backupCMD->CMDvalue[read_tail_idx] = (target ^ 7) & 0b11;
                                    settle = 3; //prev_val guard covers stale replies; 8 was overkill
                                    prev_val = val;
                                    cand_val = 0;
                                    cand_cnt = 0;
                                    cand_val2 = 0;
                                    cand_cnt2 = 0;
                                }

                                hitag_worker_combine_tag_data(worker->tag);

                                uint8_t pk = 0;
                                for(uint8_t q = 0; q < 8; q++)
                                    pk += worker->tag->pageKnown[q] ? 1 : 0;
                                if(pk >= 8) {
                                    worker->workerstatus = HitagStatusRead;
                                    furi_event_flag_set(
                                        worker->events, 1 << HitagWorkerSignalStop);
                                }
                            }
                        }
                        prev_reply = val; //for the consecutive-equal config detection
                    }
                    memset(memBlock, 0, HITAG_BLOCKPAGES * sizeof(memBlock[0]));
                    bits = 0;
                    finished = false;
                }
            }

            buffer_reset(buffer);
        }

        if(buffer_stream_get_overrun_count(capData->stream) > 0) {
            FURI_LOG_E(TAG, "Read overrun, recovering");
            buffer_stream_reset(capData->stream);
        }

        uint32_t flags = furi_event_flag_get(worker->events);
        if(FURI_BIT(flags, HitagWorkerSignalStop)) {
            break;
        }

        if(FURI_BIT(flags, HitagWorkerSignalHalfTransfer)) {
            hitag_worker_yield_dma_buffer_BPLM(
                dataCMD, backupCMD, dataDMA, 0, DMA_BUFFER_SIZE / 2);
        }
        if(FURI_BIT(flags, HitagWorkerSignalTransferComplete)) {
            hitag_worker_yield_dma_buffer_BPLM(
                dataCMD, backupCMD, dataDMA, DMA_BUFFER_SIZE / 2, DMA_BUFFER_SIZE / 2);
        }
        worker->DMAeventCount = 0;
        furi_event_flag_clear(worker->events, flags);
    }

    furi_hal_rfid_tim_read_capture_stop();
    furi_hal_rfid_rtf_carrier_out_stop();

    free(dataCMD);
    free(backupCMD);
    free(dataDMA);
    varint_pair_free(capData->pair);
    buffer_stream_free(capData->stream);
    free(capData);

    //keep the worker alive until the view signals stop (mirrors Hitag1 read thread)
    if(worker->workerstatus == HitagStatusRead) {
        const uint32_t available_flags = (1 << HitagWorkerSignalStop);
        while(true) {
            uint32_t flags = furi_event_flag_wait(
                worker->events, available_flags, FuriFlagWaitAny, FuriWaitForever);
            if(FURI_BIT(flags, HitagWorkerSignalStop)) {
                break;
            }
        }
    }

    furi_event_flag_clear(worker->events, 1 << HitagWorkerSignalStop);

    return 0;
}
