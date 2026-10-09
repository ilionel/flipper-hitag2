// Hitag worker core: the shared signal path behind the per-protocol modules.
//
// This file owns the reader-command decoder, the DMA reply plumbing, the CRC helpers
// and the whole emulate tag -- Hitag1, Hitag2 (password + crypto) and Hitag S are all
// built in one emulate thread here. The per-protocol reader read-threads and frame
// validators live in hitag1.c / hitag2.c / hitags.c; the shared struct, on-air types
// and constants are in hitag_worker_i.h.

#include "hitag_worker_i.h"

static int32_t hitag_worker_emulate_thread(void* thread_context);
HitagWorker* hitag_worker_alloc(void) {
    HitagWorker* worker = malloc(sizeof(HitagWorker));
    furi_check(worker);

    worker->thread = furi_thread_alloc_ex("HitagWorker", 2048, NULL, worker);

    worker->events = furi_event_flag_alloc();
    worker->DMAeventCount = 0;

    worker->carrierPrescaler = 2;

    worker->workerstatus = HitagStatusScanning;
    worker->sniff = false;
    worker->emulate_hitag2 = false;
    worker->sniff_log_cnt = 0;
    worker->sniff_scope_cnt = 0;
    worker->sniff_scope_arm = false;
    worker->sniff_scope_done = false;
    // PROVEN on PM3 (autotune logs): only preamble 4 completes the read; 5/6/7 never do.
    // preamble 4 + leadbit (+pre-shift) -> correct UID 12345678.
    worker->emu_preamble = 4;
    worker->emu_wresp_us = HITAG2_EMU_WAIT_RESP_US;
    worker->emu_leadbit = 1;
    worker->emu_lean = 0;
    worker->emu_fast = 0;

    // Default Hitag2 transport password "MIKR" (0x4D 0x49 0x4B 0x52)
    worker->password[0] = 0x4D;
    worker->password[1] = 0x49;
    worker->password[2] = 0x4B;
    worker->password[3] = 0x52;

    // Persistent tag store: the app sets pages before emulate and reads them after a read,
    // so it outlives the worker threads (which only reset/populate it).
    worker->tag = malloc(sizeof(HitagTag));
    furi_check(worker->tag);
    hitag_worker_initialize_tag_data(worker->tag);

    return worker;
}

void hitag_worker_set_password(HitagWorker* worker, const uint8_t password[4]) {
    memcpy(worker->password, password, 4);
}

void hitag_worker_set_hts_key(HitagWorker* worker, const uint8_t key[6]) {
    // key_le = MemLe of the 6 key bytes (matches the reader's MemLeToUint6byte(-k))
    worker->hts_crypto_key = (uint64_t)key[0] | ((uint64_t)key[1] << 8) |
                             ((uint64_t)key[2] << 16) | ((uint64_t)key[3] << 24) |
                             ((uint64_t)key[4] << 32) | ((uint64_t)key[5] << 40);
}

void hitag_worker_set_hts_82xx(HitagWorker* worker, const uint8_t pwd[4]) {
    // stored MSB-first to compare directly against the decoded 32-bit write-data frame
    worker->hts_82xx_pwd = (uint32_t)pwd[0] << 24 | (uint32_t)pwd[1] << 16 |
                           (uint32_t)pwd[2] << 8 | (uint32_t)pwd[3];
}

void hitag_worker_get_pages(
    HitagWorker* worker,
    uint8_t pages[32],
    uint8_t known[8]) {
    memcpy(pages, worker->tag->pageData, 32);
    memcpy(known, worker->tag->pageKnown, 8);
}

void hitag_worker_set_pages(HitagWorker* worker, const uint8_t pages[32]) {
    hitag_worker_initialize_tag_data(worker->tag);
    memcpy(worker->tag->pageData, pages, 32);
    for(uint8_t p = 0; p < 8; p++) worker->tag->pageKnown[p] = 1;
    //build tagData so the emulate thread's split_tag_data stays consistent
    hitag_worker_combine_tag_data(worker->tag);
}

void hitag_worker_free(HitagWorker* worker) {
    furi_thread_free(worker->thread);
    furi_event_flag_free(worker->events);
    free(worker->tag);
    free(worker);
}

HitagStatus hitag_worker_get_status(HitagWorker* worker) {
    return worker->workerstatus;
}

void hitag_worker_start(HitagWorker* worker, HitagWorkerSetting setting) {
    if(furi_thread_get_state(worker->thread) == FuriThreadStateStopped) {
        worker->sniff = false;
        worker->emulate_hitag2 = false;
        worker->emulate_hitagS = false;
        worker->emulate_hitag2_crypto = false;
        worker->sniff_target = HITAG_SNIFF_TGT_PWD;
        worker->sniff_nonce_cnt = 0;
        worker->sniff_hts_w64 = false;
        worker->sniff_82xx_got = false;
        worker->sniff_82xx_pwd = 0;
        switch(setting) {
        case(HitagWorkerSettingRead):
            dolphin_deed(DolphinDeedRfidRead);
            furi_thread_set_callback(worker->thread, hitag1_worker_read_thread);
            break;
        case(HitagWorkerSettingReadHitag2):
            dolphin_deed(DolphinDeedRfidRead);
            furi_thread_set_callback(worker->thread, hitag2_worker_read_thread);
            break;
        case(HitagWorkerSettingReadHitagS):
            dolphin_deed(DolphinDeedRfidRead);
            furi_thread_set_callback(worker->thread, hitags_worker_read_thread);
            break;
        case(HitagWorkerSettingSniffHitag2):
            dolphin_deed(DolphinDeedRfidRead);
            //sniff reuses the emulate thread's passive reader-command decoder
            worker->sniff = true;
            worker->sniff_target = HITAG_SNIFF_TGT_PWD;
            worker->sniff_log_cnt = 0;
            worker->sniff_scope_cnt = 0;
            worker->sniff_scope_arm = false;
            worker->sniff_scope_done = false;
            furi_thread_set_callback(worker->thread, hitag_worker_emulate_thread);
            break;
        case(HitagWorkerSettingSniffHitag2Nonce):
            dolphin_deed(DolphinDeedRfidRead);
            // passive crypto sniff: the reader validator accepts the 64-bit nRaR frame so
            // it is logged, and the frame-log block stores each nR/aR pair.
            worker->sniff = true;
            worker->sniff_target = HITAG_SNIFF_TGT_NONCE;
            worker->sniff_nonce_cnt = 0;
            worker->sniff_log_cnt = 0;
            worker->sniff_scope_cnt = 0;
            worker->sniff_scope_arm = false;
            worker->sniff_scope_done = false;
            furi_thread_set_callback(worker->thread, hitag_worker_emulate_thread);
            break;
        case(HitagWorkerSettingSniffHitagS82xx):
            dolphin_deed(DolphinDeedRfidRead);
            // passive Hitag S sniff: route the Hitag S validator (recognises WRITE + the
            // CRC-checked 40-bit data frame) so a WRITE(page 64) then the password land in
            // the frame-log block, where the data frame is captured as the 82xx password.
            worker->sniff = true;
            worker->sniff_target = HITAG_SNIFF_TGT_82XX;
            worker->sniff_hts_w64 = false;
            worker->sniff_82xx_got = false;
            worker->sniff_log_cnt = 0;
            worker->sniff_scope_cnt = 0;
            worker->sniff_scope_arm = false;
            worker->sniff_scope_done = false;
            furi_thread_set_callback(worker->thread, hitag_worker_emulate_thread);
            break;
        case(HitagWorkerSettingEmulate):
            dolphin_deed(DolphinDeedRfidEmulate);
            furi_thread_set_callback(worker->thread, hitag_worker_emulate_thread);
            break;
        case(HitagWorkerSettingEmulateHitag2):
            dolphin_deed(DolphinDeedRfidEmulate);
            worker->emulate_hitag2 = true;
            worker->sniff_log_cnt = 0; // log the reader handshake for diagnostics
            worker->emu_auth = 0;
            worker->emu_pwd = 0;
            worker->emu_read = 0;
            furi_thread_set_callback(worker->thread, hitag_worker_emulate_thread);
            break;
        case(HitagWorkerSettingEmulateHitag2Crypto):
            dolphin_deed(DolphinDeedRfidEmulate);
            worker->emulate_hitag2_crypto = true;
            worker->emu_auth = 0; // reused: START_AUTH / nRaR-accepted / READ counters
            worker->emu_pwd = 0;
            worker->emu_read = 0;
            if(worker->emu_wresp_us == 0) worker->emu_wresp_us = 1664; // hw-timed reply window
            if(worker->hts_crypto_key == 0) worker->hts_crypto_key = 0x524B494D4E4FULL; // ONMIKR
            // FRAMING FIX (bench-cracked via the PM3 source): preamble = reader tag_sof (4) and
            // NO leadbit/pre-shift -> the reader reads all 32 bits FAITHFULLY, including bit31=1
            // (the leadbit pre-shift dropped bit31 -> 0xAA read as 0x2A). Essential for crypto,
            // whose encrypted replies are random 32-bit values.
            worker->emu_preamble = 4;
            worker->emu_leadbit = 0;
            furi_thread_set_callback(worker->thread, hitag_worker_emulate_thread);
            break;
        case(HitagWorkerSettingEmulateHitagS):
            dolphin_deed(DolphinDeedRfidEmulate);
            worker->emulate_hitagS = true;
            worker->emu_auth = 0; // reused as UID_REQ / SELECT / READ counters (coupling readout)
            worker->emu_pwd = 0;
            worker->emu_read = 0;
            // hts_82xx_pwd / hts_crypto_key are set by the app before start (set_hts_*);
            // fall back to the ONMIKR / BBDD3399 defaults if the app never set them.
            if(worker->hts_82xx_pwd == 0) worker->hts_82xx_pwd = 0xBBDD3399;
            if(worker->hts_crypto_key == 0) worker->hts_crypto_key = 0x524B494D4E4FULL;
            // Reply via the hardware-timed T_wresp path (same as Hitag2). Same silicon family, so
            // start from the proven 1664us; the app can retune it via set_emu_tuning if needed.
            if(worker->emu_wresp_us == 0) worker->emu_wresp_us = 1664;
            furi_thread_set_callback(worker->thread, hitag_worker_emulate_thread);
            break;
        default: //safety meassure, not to start a thread without a callback function
            furi_thread_set_callback(worker->thread, hitag1_worker_read_thread);
            break;
        }
        furi_thread_start(worker->thread);
    }
}

void hitag_worker_stop(HitagWorker* worker) {
    //idempotent: safe to call again (e.g. read buffers -> stop -> teardown -> stop)
    if(furi_thread_get_state(worker->thread) == FuriThreadStateStopped) return;
    furi_event_flag_set(worker->events, 1 << HitagWorkerSignalStop);
    furi_thread_join(worker->thread);
}

// Read-path timer & DMA capture callbacks (handed to the RFID HAL).
void hitag_worker_capture_in_cc_callback(bool level, uint32_t duration, void* context) {
    HitagCaptureData* capData = context;

    //check if there is a new pair available: pulse + period
    bool need_to_send = varint_pair_pack(capData->pair, level, duration);

    //if so put it on buffer stream so it can be processed outside this interrupt routine
    if(need_to_send) {
        buffer_stream_send_from_isr(
            capData->stream,
            varint_pair_get_data(capData->pair),
            varint_pair_get_size(capData->pair));
        varint_pair_reset(capData->pair);
    }
}

void hitag_worker_carrier_out_dma_callback(bool half, void* dma_context) {
    HitagWorker* worker = (HitagWorker*)dma_context;
    worker->DMAeventCount++;

    if(half) {
        furi_event_flag_set(worker->events, 1 << HitagWorkerSignalHalfTransfer);
    } else {
        furi_event_flag_set(worker->events, 1 << HitagWorkerSignalTransferComplete);
    }
}

// Emulate-path timer callback.
static void
    hitag_worker_carrier_in_callback(bool level, uint32_t duration, void* capture_context) {
    UNUSED(level);

    HitagCaptureData* capData = capture_context;
    capData->capCounter++;
    //pack varint (as part of a pair)
    //cleaner would be to pack as a varint iso varint_pair, though i'm not sure if I can get the data & size of a packed varint
    varint_pair_pack(capData->pair, true, duration);
    //but send anyhow, doesn't matter that it's not a pair
    buffer_stream_send_from_isr(
        capData->stream, varint_pair_get_data(capData->pair), varint_pair_get_size(capData->pair));
    varint_pair_reset(capData->pair);
}

// Tag-data helpers: page <-> combined buffer, and config-page parsing.

void hitag_worker_yield_dma_buffer_BPLM(
    HitagCMDData* dataCMD,
    HitagCMDData* backupCMD,
    TimerDMAData* dataDMA,
    size_t start,
    size_t len) {
    //based on interal timer with freq of 1MHz (period of 1us)
    //use active command
    HitagCMDData* data = dataCMD;
    if(!data->CMDactive) {
        data = backupCMD;
    }
    uint16_t lastarrposition = 0;
    size_t toskip = 0;
    bool itemProcessed = true;
    size_t s = start;
    //for ( ; data->CMDloop || data->CMDposition < data->CMDlength ; data->CMDposition++){
    while(1) {
        //at the end of current command (real or backup), check if there's unprocessed CMD available, if not switch to backup
        if(data->CMDposition == data->CMDlength) {
            data->CMDcount++;
            if(dataCMD->CMDposition <
               dataCMD
                   ->CMDlength) { //currently backup & new unprocessed command available --> switch over to real CMD
                data->CMDactive = false;
                data = dataCMD;
                data->CMDactive = true;
                data->CMDcount = 0;
            } else if(dataCMD
                          ->CMDloop) { //if looping (real or backup) --> reset real (current) CMD to startposition
                data->CMDposition = 0;
                data->CMDsubposition = 0;
            } else if(dataCMD
                          ->CMDactive) { //real command and not looping --> switch to backup CMD and reset backup CMD to startposition
                data->CMDactive = false;
                data = backupCMD;
                data->CMDactive = true;
                data->CMDposition = 0;
                data->CMDsubposition = 0;
                data->CMDcount = 0;
            } else { //backupCMD but set to not loop --> loop anyway: reset to startposition
                data->CMDposition = 0;
                data->CMDsubposition = 0;
            }
        }
        //start processing the next CMD item
        lastarrposition = s;
        if(s == start) {
            toskip = data->CMDsubposition;
        } else {
            toskip = 0;
            data->CMDsubposition = 0;
        }
        switch(data->CMDtype[data->CMDposition]) {
        case HITAG_STOP: //just 1 STOP cycle (HITAG_LOW lows + HITAG_STOP_HIGH highs)
            if(s > start) {
                dataDMA->timer_buffer_arr[s - 1] += HITAG_LOW * HITAG_BASEPERIOD;
            }
            for(size_t t = 0; t < HITAG_STOP_HIGH - toskip; t++) {
                if(s == len + start) {
                    //arrays are filled, do not continue out
                    itemProcessed = false;
                    break;
                }
                dataDMA->timer_buffer_ccr[s] = HITAG_BASEPERIOD / 2;
                dataDMA->timer_buffer_arr[s] = HITAG_BASEPERIOD - 1;
                s++;
            }
            break;
        case HITAG_ON: //x ON cycles --> update next X arr/ccr values
            for(size_t x = 0; x < data->CMDvalue[data->CMDposition] - toskip; x++) {
                if(s == len + start) {
                    //arrays are filled, do not continue out
                    itemProcessed = false;
                    break;
                }
                dataDMA->timer_buffer_ccr[s] = HITAG_BASEPERIOD / 2;
                dataDMA->timer_buffer_arr[s] = HITAG_BASEPERIOD - 1;
                s++;
            }
            break;
        case HITAG_OFF: //x OFF cycles (update previous arr value)
            if(s > start) {
                dataDMA->timer_buffer_arr[s - 1] +=
                    data->CMDvalue[data->CMDposition] * HITAG_BASEPERIOD;
            }
            break;
        default: // <=HITAG_BYTE: //bits to be sent
            //get each bit & update arr/ccr accordingly (7 lows + HITAG_0_HIGH/HITAG_1_HIGH highs)
            for(size_t b = 8 - data->CMDtype[data->CMDposition]; b < 8; b++) {
                if(s > start) {
                    dataDMA->timer_buffer_arr[s - 1] += HITAG_LOW * HITAG_BASEPERIOD;
                }
                if(0x80 & (data->CMDvalue[data->CMDposition] << b)) {
                    for(size_t t = 0; t < HITAG_1_HIGH; t++) {
                        if(s == len + start) {
                            //arrays are filled, do not continue out
                            itemProcessed = false;
                            break;
                        }
                        dataDMA->timer_buffer_ccr[s] = HITAG_BASEPERIOD / 2;
                        dataDMA->timer_buffer_arr[s] = HITAG_BASEPERIOD - 1;
                        s++;
                        if(toskip > 0) {
                            toskip--;
                            s--;
                        }
                    }
                } else {
                    for(size_t t = 0; t < HITAG_0_HIGH; t++) {
                        if(s == len + start) {
                            //arrays are filled, do not continue out
                            itemProcessed = false;
                            break;
                        }
                        dataDMA->timer_buffer_ccr[s] = HITAG_BASEPERIOD / 2;
                        dataDMA->timer_buffer_arr[s] = HITAG_BASEPERIOD - 1;
                        s++;
                        if(toskip > 0) {
                            toskip--;
                            s--;
                        }
                    }
                }
                if(!itemProcessed) {
                    break;
                }
            }
            break;
        }
        if(!itemProcessed) {
            break;
        }
        data->CMDposition++;
    }

    //set starting position for next time:
    data->CMDsubposition += (len + start) - lastarrposition;
}

static uint16_t hitag_worker_yield_dma_buffer_MC(
    HitagReplyData* dataReply,
    TimerDMAData* dataDMA,
    uint8_t carrierPrescaler) {
    //based on external carrier with freq of 125kHz (period of 8us)

    uint16_t dma_len = 0;

    bool bit = false;
    bool prevBit = true; //must be true to initialze MC yield for first bit

    //process reply bits and add HIGH-LOW for 1 or LOW-HIGH for 0
    for(uint8_t i = 0; i < dataReply->replylength; i++) {
        for(int8_t b = dataReply->replytype[i] - 1; b >= 0; b--) {
            bit = (dataReply->replyvalue[i] >> b & 0b00000001);
            if(bit) { //HIGH-LOW
                if(prevBit) { //if first bit (initial value of prevBit=true) or if prev bit was 1: start of new default cycle
                    dataDMA->timer_buffer_arr[dma_len] = 32 - 1;
                    dataDMA->timer_buffer_ccr[dma_len] = 16;
                    dma_len++;
                } else { //previous bit was 0, so extend the ccr and arr with 16
                    dataDMA->timer_buffer_arr[dma_len - 1] += 16;
                    dataDMA->timer_buffer_ccr[dma_len - 1] += 16;
                }
            } else { //LOW-HIGH
                if(prevBit) { //previous bit was 1 so extend the LOW (arr only) of prev cycle with 16 and add new default cycle
                    dataDMA->timer_buffer_arr[dma_len - 1] += 16;

                    dataDMA->timer_buffer_arr[dma_len] = 32 - 1;
                    dataDMA->timer_buffer_ccr[dma_len] = 16;
                    dma_len++;
                } else { //previous bit was 0 so just add new default cycle
                    dataDMA->timer_buffer_arr[dma_len] = 32 - 1;
                    dataDMA->timer_buffer_ccr[dma_len] = 16;
                    dma_len++;
                }
            }
            prevBit = bit;
        }
    }

    //add extra period, to reset timer back to normal carrier_in detection after reply has finished
    //also required to make sure the last real dma values are fully executed before dma signals transfer complete, which resets worker into command detection
    dataDMA->timer_buffer_arr[dma_len] = carrierPrescaler - 1;
    dataDMA->timer_buffer_ccr[dma_len] = 0;
    dma_len++;

    return dma_len;
}

static uint16_t hitag_worker_yield_dma_buffer_AC(
    HitagReplyData* dataReply,
    TimerDMAData* dataDMA,
    uint8_t carrierPrescaler) {
    //based on external carrier with freq of 125kHz (period of 8us)

    uint16_t dma_len = 0;

    //process reply bits and add 2 short pulses for 1 or 1 long pulse for 0
    for(uint8_t i = 0; i < dataReply->replylength; i++) {
        for(int8_t b = dataReply->replytype[i] - 1; b >= 0; b--) {
            if(dataReply->replyvalue[i] >> b & 0b00000001) {
                dataDMA->timer_buffer_arr[dma_len] = 32 - 1;
                dataDMA->timer_buffer_ccr[dma_len] = 16; //16
                dma_len++;
                dataDMA->timer_buffer_arr[dma_len] = 32 - 1;
                dataDMA->timer_buffer_ccr[dma_len] = 16; //16
                dma_len++;
            } else {
                dataDMA->timer_buffer_arr[dma_len] = 64 - 1;
                dataDMA->timer_buffer_ccr[dma_len] = 32; //32
                dma_len++;
            }
        }
    }

    //add extra period, to reset timer back to normal carrier_in detection after reply has finished
    //also required to make sure the last real dma values are fully executed before dma signals transfer complete, which resets worker into command detection
    dataDMA->timer_buffer_arr[dma_len] = carrierPrescaler - 1;
    dataDMA->timer_buffer_ccr[dma_len] = 0;
    dma_len++;

    return dma_len;
}

// Fast-rate (double bit rate) variants of the MC/AC yields, for the Hitag S FADV reader mode:
// MC8K (16-period Manchester cells) and AC4K (16/32-period anticollision pulses) — every cell
// duration of the MC4K/AC2K originals halved. Kept as SEPARATE functions so the MC4K/AC2K path
// used by Hitag1 and the proven password-mode Hitag2 emulate is byte-for-byte untouched. FADV only.
static uint16_t hitag_worker_yield_dma_buffer_MC8(
    HitagReplyData* dataReply,
    TimerDMAData* dataDMA,
    uint8_t carrierPrescaler) {
    uint16_t dma_len = 0;
    bool bit = false;
    bool prevBit = true; // must be true to initialise MC yield for the first bit
    for(uint8_t i = 0; i < dataReply->replylength; i++) {
        for(int8_t b = dataReply->replytype[i] - 1; b >= 0; b--) {
            bit = (dataReply->replyvalue[i] >> b & 0b00000001);
            if(bit) { // HIGH-LOW
                if(prevBit) {
                    dataDMA->timer_buffer_arr[dma_len] = 16 - 1;
                    dataDMA->timer_buffer_ccr[dma_len] = 8;
                    dma_len++;
                } else {
                    dataDMA->timer_buffer_arr[dma_len - 1] += 8;
                    dataDMA->timer_buffer_ccr[dma_len - 1] += 8;
                }
            } else { // LOW-HIGH
                if(prevBit) {
                    dataDMA->timer_buffer_arr[dma_len - 1] += 8;
                    dataDMA->timer_buffer_arr[dma_len] = 16 - 1;
                    dataDMA->timer_buffer_ccr[dma_len] = 8;
                    dma_len++;
                } else {
                    dataDMA->timer_buffer_arr[dma_len] = 16 - 1;
                    dataDMA->timer_buffer_ccr[dma_len] = 8;
                    dma_len++;
                }
            }
            prevBit = bit;
        }
    }
    dataDMA->timer_buffer_arr[dma_len] = carrierPrescaler - 1;
    dataDMA->timer_buffer_ccr[dma_len] = 0;
    dma_len++;
    return dma_len;
}

static uint16_t hitag_worker_yield_dma_buffer_AC4(
    HitagReplyData* dataReply,
    TimerDMAData* dataDMA,
    uint8_t carrierPrescaler) {
    uint16_t dma_len = 0;
    for(uint8_t i = 0; i < dataReply->replylength; i++) {
        for(int8_t b = dataReply->replytype[i] - 1; b >= 0; b--) {
            if(dataReply->replyvalue[i] >> b & 0b00000001) { // 1 = two short pulses
                dataDMA->timer_buffer_arr[dma_len] = 16 - 1;
                dataDMA->timer_buffer_ccr[dma_len] = 8;
                dma_len++;
                dataDMA->timer_buffer_arr[dma_len] = 16 - 1;
                dataDMA->timer_buffer_ccr[dma_len] = 8;
                dma_len++;
            } else { // 0 = one long pulse
                dataDMA->timer_buffer_arr[dma_len] = 32 - 1;
                dataDMA->timer_buffer_ccr[dma_len] = 16;
                dma_len++;
            }
        }
    }
    dataDMA->timer_buffer_arr[dma_len] = carrierPrescaler - 1;
    dataDMA->timer_buffer_ccr[dma_len] = 0;
    dma_len++;
    return dma_len;
}

void hitag_worker_decoder_feed(
    uint32_t pulse,
    uint32_t duration,
    uint32_t* memBlock,
    uint8_t* bits,
    bool* half,
    bool* finished,
    HitagProtocol protocol,
    uint8_t startBits) {
    uint32_t bit = 1 << (32 - 1);
    if(*bits == 0) {
        *half = false;
    }
    if(protocol == HitagProtocolManchesterCoding) {
        if(HITAG_DURATION_S * (1 - HITAG_DURATION_ERROR_MARGIN) <= duration &&
           duration <= HITAG_DURATION_S * (1 + HITAG_DURATION_ERROR_MARGIN)) {
            //short period (HL) detected: same bit as previous
            if(*bits < startBits) {
                //don't store startbits in memory, just increase bitcounter
                (*bits)++;
            } else if(*bits == startBits) {
                //same as previous bit (last startbit it 1, so add 1 to the memBlock)
                memBlock[(*bits - startBits) / 32] |= (bit >> ((*bits - startBits) % 32)); //add 1
                (*bits)++;
            } else {
                //add same as previous bit
                if(memBlock[(*bits - startBits - 1) / 32] &
                   (bit >> ((*bits - startBits - 1) % 32))) {
                    memBlock[(*bits - startBits) / 32] |=
                        (bit >> ((*bits - startBits) % 32)); //add 1
                    (*bits)++;
                } else {
                    (*bits)++; //no mem action for 0, just increase bitcounter
                }
            }
        } else if(
            HITAG_DURATION_M * (1 - HITAG_DURATION_ERROR_MARGIN) <= duration &&
            duration <= HITAG_DURATION_M * (1 + HITAG_DURATION_ERROR_MARGIN)) {
            //medium period (H|HL or HL|L) detected: half 0 + full 1 or full 1 + half 0 detected
            if(*bits < startBits) {
                //assuming all startbits are 1's, this can only happen on last startbit followed by 0
                //don't store startbits, no mem action for 0, just increase bitcounter twice
                (*bits)++;
                (*bits)++;
                *half = true;
            } else if(*bits == startBits) {
                //assuming all startbits were 1's, this is a data 10 detection
                memBlock[(*bits - startBits) / 32] |= (bit >> ((*bits - startBits) % 32)); //add 1
                (*bits)++;
                (*bits)++; //no mem action for 0, just increase bitcounter
                *half = true;
            } else {
                //if we're in half of a bit, add 1, else add 10 and set half flag
                if(*half) {
                    memBlock[(*bits - startBits) / 32] |=
                        (bit >> ((*bits - startBits) % 32)); //add 1
                    (*bits)++;
                    *half = false;
                } else {
                    memBlock[(*bits - startBits) / 32] |=
                        (bit >> ((*bits - startBits) % 32)); //add 1
                    (*bits)++;
                    (*bits)++; //no mem action for 0, just increase bitcounter
                    *half = true;
                }
            }
        } else if(
            HITAG_DURATION_L * (1 - HITAG_DURATION_ERROR_MARGIN) <= duration &&
            duration <= HITAG_DURATION_L * (1 + HITAG_DURATION_ERROR_MARGIN)) {
            //long period (H|HL|L) detected: half 0 + full 1 + half 0 detected
            if(*bits <= startBits) {
                //TODO: throw error since this can't happen till after first real bit, since all startbits should be 1's
            } else {
                //TODO check that prev bit is indeed 0
                //add 10 to the memBlock
                memBlock[(*bits - startBits) / 32] |= (bit >> ((*bits - startBits) % 32)); //add 1
                (*bits)++;
                (*bits)++; //no mem action for 0, just increase bitcounter
            }
        } else if(HITAG_DURATION_L * (1 + HITAG_DURATION_ERROR_MARGIN) < duration) {
            //end of modulation by tag, check if this pulse duration includes a bit
            if(*bits > 0) {
                if(*half && pulse < HITAG_DURATION_S) {
                    //second half of 0 bit, no action
                } else if(*half && pulse < HITAG_DURATION_M) {
                    //second half or 0 bit + another 1 bit
                    memBlock[(*bits - startBits) / 32] |=
                        (bit >> ((*bits - startBits) % 32)); //add 1
                    (*bits)++;
                } else if(!(*half) && pulse < HITAG_DURATION_S) {
                    //another 1 bit
                    memBlock[(*bits - startBits) / 32] |=
                        (bit >> ((*bits - startBits) % 32)); //add 1
                    (*bits)++;
                } else {
                    //invalid pulse duration --> reset?
                }
                *finished = true;
            }
        } else {
            //invalid pulse duration: reset tempData if necessary
            if(*bits > 0) {
                memset(memBlock, 0, HITAG_BLOCKPAGES * sizeof(memBlock[0]));
                *bits = 0;
                *finished = false;
            }
        }
    } else if(protocol == HitagProtocolAntiCollision) {
        if(HITAG_DURATION_S * (1 - HITAG_DURATION_ERROR_MARGIN) <= duration &&
           duration <= HITAG_DURATION_S * (1 + HITAG_DURATION_ERROR_MARGIN)) {
            //short period (HL): first or second half of a 1 detected
            //if first short: add 1 to memBlock and increase half counter
            if(*half == false) {
                if(*bits >= startBits) {
                    memBlock[(*bits - startBits) / 32] |= ((bit >> (*bits - startBits) % 32));
                }
                (*bits)++;
                *half = true;
            } else {
                //if second small: reset half counter
                *half = false;
            }
        } else if(
            HITAG_DURATION_L * (1 - HITAG_DURATION_ERROR_MARGIN) <= duration &&
            duration <= HITAG_DURATION_L * (1 + HITAG_DURATION_ERROR_MARGIN)) {
            //long period (HHLL): 0 detected
            //should only happen after full detection of 1 or after startBits
            if(*bits < startBits || *half) {
                //reset
                memset(memBlock, 0, HITAG_BLOCKPAGES * sizeof(memBlock[0]));
                *bits = 0;
                *finished = false;
            } else {
                (*bits)++; //add 0 to memBlock
            }
        } else if(HITAG_DURATION_L * (1 + HITAG_DURATION_ERROR_MARGIN) < duration) {
            //end of modulation by tag, check if this pulse duration includes a bit
            if(*bits > 0) {
                if(!(*half) && pulse > HITAG_DURATION_S) {
                    (*bits)++; //add 0 to memBlock
                } else {
                    //invalid pulse duration: reset?
                }
                *finished = true;
            }
        } else {
            //invalid pulse duration: reset tempData if necessary
            if(*bits > 0) {
                memset(memBlock, 0, HITAG_BLOCKPAGES * sizeof(memBlock[0]));
                *bits = 0;
                *finished = false;
            }
        }
    }
}

void hitag_worker_calc_crc(uint8_t* crc, uint8_t data, uint8_t bitcount) {
    *crc ^= data; // crc = crc (exor) data
    do {
        if(*crc & 0x80) // if (MSB-CRC == 1)
        {
            *crc <<= 1; // CRC = CRC bit-shift left
            *crc ^= CRC_POLYNOM; // CRC = CRC (exor) CRC_POLYNOM
        } else {
            *crc <<= 1; // CRC = CRC bit-shift left
        }
    } while(--bitcount);
}

bool hitag_worker_validate_command(uint32_t* bits, uint8_t len) {
    if(len == 5 && (bits[0] >> (32 - 5)) == 0b11001) {
        //SET_CCNEW
        return true;
    } else if(len == 5 && (bits[0] >> (32 - 5)) == 0b00110) {
        //SET_CC
        return true;
    } else if(len == 45 && (bits[0] >> (32 - 5)) == 0b00000) {
        //SELECT

        //calculate CRC for first 37 bits (4bytes + 5 bits)
        uint8_t byte1 = bits[0] >> 24 & 0xff;
        uint8_t byte2 = bits[0] >> 16 & 0xff;
        uint8_t byte3 = bits[0] >> 8 & 0xff;
        uint8_t byte4 = bits[0] & 0xff;
        uint8_t byte5 = bits[1] >> 24 & 0b11111000;
        uint8_t crcRead = bits[1] >> 19 & 0xff;

        uint8_t crc = CRC_PRESET;
        hitag_worker_calc_crc(&crc, byte1, 8);
        hitag_worker_calc_crc(&crc, byte2, 8);
        hitag_worker_calc_crc(&crc, byte3, 8);
        hitag_worker_calc_crc(&crc, byte4, 8);
        hitag_worker_calc_crc(&crc, byte5, 5);

        //and compare result with received crc
        return (crcRead == crc);
    }
    //else if (len == 20 && (bits[0]>>31 ||  (bits[0]>>(32-4)) == 0b0111)){
    else if(len == 20 && bits[0] > 0x70000000) {
        //R/W page/block (cmd starting with 1) or HALT (0111) --> so bit0 should be >= 0b01110000 00000000 00000000 00000000 (0x70000000)
        //calculate CRC for first 12 bits (1byte + 4 bits)
        uint8_t byte1 = bits[0] >> 24 & 0xff;
        uint8_t byte2 = bits[0] >> 16 & 0b11110000;
        uint8_t crcRead = bits[0] >> 12 & 0xff;

        uint8_t crc = CRC_PRESET;
        hitag_worker_calc_crc(&crc, byte1, 8);
        hitag_worker_calc_crc(&crc, byte2, 4);

        //and compare result with received crc
        return (crcRead == crc);
    }
    return false;
}


//dispatch reader-command validation to the Hitag1 or Hitag2 validator (emulate)
static bool
    hitag_emu_validate(HitagWorker* worker, uint32_t* bits, uint8_t bitcounter) {
    // sniff: route the reader-frame validator by what we want to capture, so the right frames
    // are recognized and logged. Password sniff = Hitag2 validator (START_AUTH/READ/password);
    // crypto-nonce sniff = crypto validator (adds the 64-bit nRaR frame); 82xx sniff = Hitag S
    // validator (adds WRITE + the CRC-checked 40-bit data frame).
    if(worker->sniff) {
        if(worker->sniff_target == HITAG_SNIFF_TGT_NONCE)
            return hitag2crypto_worker_validate_bits(bits, bitcounter);
        if(worker->sniff_target == HITAG_SNIFF_TGT_82XX)
            return hitags_worker_validate_bits(bits, bitcounter);
        return hitag2_worker_validate_bits(bits, bitcounter);
    }
    if(worker->emulate_hitag2) return hitag2_worker_validate_bits(bits, bitcounter);
    if(worker->emulate_hitagS) return hitags_worker_validate_bits(bits, bitcounter);
    if(worker->emulate_hitag2_crypto)
        return hitag2crypto_worker_validate_bits(bits, bitcounter);
    return hitag1_worker_validate_bits(bits, bitcounter);
}

uint16_t hitag_worker_get_sniff_count(HitagWorker* worker) {
    return worker->sniff_log_cnt;
}

uint16_t hitag_worker_get_sniff_log(
    HitagWorker* worker,
    uint8_t lens[HITAG_SNIFF_LOG_MAX],
    uint32_t vals[HITAG_SNIFF_LOG_MAX]) {
    uint16_t n = worker->sniff_log_cnt;
    if(n > HITAG_SNIFF_LOG_MAX) n = HITAG_SNIFF_LOG_MAX;
    memcpy(lens, worker->sniff_log_len, n);
    memcpy(vals, worker->sniff_log_val, n * sizeof(uint32_t));
    return n;
}

uint8_t hitag_worker_get_sniff_scope(
    HitagWorker* worker,
    uint16_t cells[HITAG_SNIFF_SCOPE_MAX]) {
    uint8_t n = worker->sniff_scope_cnt;
    if(n > HITAG_SNIFF_SCOPE_MAX) n = HITAG_SNIFF_SCOPE_MAX;
    memcpy(cells, worker->sniff_scope, n * sizeof(uint16_t));
    return n;
}

uint8_t hitag_worker_get_nonces(
    HitagWorker* worker,
    uint32_t nr[HITAG_SNIFF_NONCE_MAX],
    uint32_t ar[HITAG_SNIFF_NONCE_MAX]) {
    uint8_t n = worker->sniff_nonce_cnt;
    if(n > HITAG_SNIFF_NONCE_MAX) n = HITAG_SNIFF_NONCE_MAX;
    memcpy(nr, worker->sniff_nonce_nr, n * sizeof(uint32_t));
    memcpy(ar, worker->sniff_nonce_ar, n * sizeof(uint32_t));
    return n;
}

bool hitag_worker_get_sniff_82xx(HitagWorker* worker, uint8_t pwd[4]) {
    if(!worker->sniff_82xx_got) return false;
    pwd[0] = (worker->sniff_82xx_pwd >> 24) & 0xff;
    pwd[1] = (worker->sniff_82xx_pwd >> 16) & 0xff;
    pwd[2] = (worker->sniff_82xx_pwd >> 8) & 0xff;
    pwd[3] = worker->sniff_82xx_pwd & 0xff;
    return true;
}

void hitag_worker_set_emu_tuning(
    HitagWorker* worker,
    uint8_t preamble,
    uint32_t wresp_us,
    uint8_t leadbit) {
    worker->emu_preamble = preamble;
    worker->emu_wresp_us = wresp_us;
    worker->emu_leadbit = leadbit;
}

void hitag_worker_set_emu_lean(HitagWorker* worker, uint8_t lean) {
    worker->emu_lean = lean ? 1 : 0;
}

void hitag_worker_set_emu_fast(HitagWorker* worker, uint8_t fast) {
    worker->emu_fast = fast ? 1 : 0;
}

void hitag_worker_get_emu_counts(
    HitagWorker* worker,
    uint16_t* auth,
    uint16_t* pwd,
    uint16_t* read) {
    *auth = worker->emu_auth;
    *pwd = worker->emu_pwd;
    *read = worker->emu_read;
}

uint8_t hitag_worker_get_read_best_bits(HitagWorker* worker) {
    //return the best frame bit-count since the last poll, then reset -> the value
    //reflects the CURRENT coupling window (a live gauge), not an all-time high.
    uint8_t v = worker->read_best_bits;
    worker->read_best_bits = 0;
    return v;
}

static uint8_t hitag_worker_validate_ripple_delta(uint32_t delta) {
    if(18 <= delta && delta <= 22) return 1;
    if(26 <= delta && delta <= 32) return 1;
    return 0;
}

void hitag_worker_initialize_tag_data(HitagTag* tag) {
    //initialize a tag datastructure
    //set all pages to 0x00000000
    memset(tag->pageData, 0, sizeof(tag->pageData));

    //set all pages to unknown
    for(uint8_t i = 0; i < HITAG_PAGES; i++) {
        tag->pageKnown[i] = 0;
    }

    //default RW settings:
    memset(tag->pageRW, READ, HITAG_PAGES / 2 * sizeof(tag->pageRW[0]));
    memset(tag->pageRW + HITAG_PAGES / 2, READ | WRITE, HITAG_PAGES / 2 * sizeof(tag->pageRW[0]));
    tag->pageRW[2] = 0;
    tag->pageRW[3] = 0;

    //default public/secret settings:
    for(uint8_t i = 0; i < HITAG_PAGES; i++) {
        tag->pagePublic[i] = 1;
    }
    for(uint8_t i = 2; i <= 31; i++) {
        tag->pagePublic[i] = 0;
    }
}

void hitag_worker_combine_tag_data(HitagTag* tag) {
    memcpy(tag->tagData, tag->pageData, HITAG_PAGES * HITAG_PAGEBYTES);
    memcpy(tag->tagData + HITAG_PAGES * HITAG_PAGEBYTES, tag->pageKnown, HITAG_PAGES);
}

static void hitag_worker_split_tag_data(HitagTag* tag) {
    memcpy(tag->pageData, tag->tagData, HITAG_PAGES * HITAG_PAGEBYTES);
    memcpy(tag->pageKnown, tag->tagData + HITAG_PAGES * HITAG_PAGEBYTES, HITAG_PAGES);
}

void hitag_worker_process_config_page(HitagTag* tag) {
    //RW settings via byte 0
    if(tag->pageData[4 + 0] & 0b10000000) { //block 1 (logData) RW or 0
        memset(tag->pageRW + 1 * 4, READ | WRITE, 4 * sizeof(tag->pageRW[0]));
    } else {
        memset(tag->pageRW + 1 * 4, 0, 4 * sizeof(tag->pageRW[0]));
    }
    if(tag->pageData[4 + 0] & 0b01000000) { //key A&B (page 2&3) W or 0
        memset(tag->pageRW + 2, WRITE, 2 * sizeof(tag->pageRW[0]));
    } else {
        memset(tag->pageRW + 2, 0, 2 * sizeof(tag->pageRW[0]));
    }
    if(tag->pageData[4 + 0] & 0b00100000) { //block 2 RW or RO
        memset(tag->pageRW + 2 * 4, READ | WRITE, 4 * sizeof(tag->pageRW[0]));
    } else {
        memset(tag->pageRW + 2 * 4, READ, 4 * sizeof(tag->pageRW[0]));
    }
    if(tag->pageData[4 + 0] & 0b00010000) { //block 3 RW or RO
        memset(tag->pageRW + 3 * 4, READ | WRITE, 4 * sizeof(tag->pageRW[0]));
    } else {
        memset(tag->pageRW + 3 * 4, READ, 4 * sizeof(tag->pageRW[0]));
    }
    if(tag->pageData[4 + 0] & 0b00001000) { //block 4 RW or RO
        memset(tag->pageRW + 4 * 4, READ | WRITE, 4 * sizeof(tag->pageRW[0]));
    } else {
        memset(tag->pageRW + 4 * 4, READ, 4 * sizeof(tag->pageRW[0]));
    }
    if(tag->pageData[4 + 0] & 0b00000100) { //block 5 RW or RO
        memset(tag->pageRW + 5 * 4, READ | WRITE, 4 * sizeof(tag->pageRW[0]));
    } else {
        memset(tag->pageRW + 5 * 4, READ, 4 * sizeof(tag->pageRW[0]));
    }
    if(tag->pageData[4 + 0] & 0b00000010) { //block 6 RW or RO
        memset(tag->pageRW + 6 * 4, READ | WRITE, 4 * sizeof(tag->pageRW[0]));
    } else {
        memset(tag->pageRW + 6 * 4, READ, 4 * sizeof(tag->pageRW[0]));
    }
    if(tag->pageData[4 + 0] & 0b00000001) { //block 7 RW or RO
        memset(tag->pageRW + 7 * 4, READ | WRITE, 4 * sizeof(tag->pageRW[0]));
    } else {
        memset(tag->pageRW + 7 * 4, READ, 4 * sizeof(tag->pageRW[0]));
    }
    //RW settings via byte 1
    if(tag->pageData[4 + 1] & 0b00010000) { //config page (1) RW or RO
        tag->pageRW[1] = READ | WRITE;
    } else {
        tag->pageRW[1] = READ;
    }

    //public/secret settings via byte 1
    if(tag->pageData[4 + 1] & 0b00000001) { //block 4-7 public or secret
        for(uint8_t i = 4 * 4; i < 8 * 4; i++) {
            tag->pagePublic[i] = 1;
        }
    } else {
        for(uint8_t i = 4 * 4; i < 8 * 4; i++) {
            tag->pagePublic[i] = 0;
        }
    }
}

// Emulate worker thread — the shared, timing-critical signal path for every emulate mode
// (Hitag1 / Hitag2 password+crypto / Hitag S) and the passive sniff. It is one big function
// ON PURPOSE: GCC register-allocates the whole thing as a single arena, so pulling code into
// helpers reshuffles that allocation and shifts the T_wresp-critical reply codegen — proven
// with tools/codegen_fp.py (no extraction of this function comes out byte-identical). Don't
// split it without a codegen-identical diff (see tools/README.md). Phase map (grep the anchor):
//
//   1. SETUP         tag load/reset + GPIO + carrier-in DMA + decoder state   @ carrier_in_start
//   2. RX LOOP       per carrier-in cell: carrier on/off detection            @ if(!carrier_on)
//   3. RIPPLE DECODE mirrored local-MAX / local-MIN delta->bit recovery of    @ "detect local MAX"
//                    the reader command; a validated bitstring sets cmd (+1 max / -1 min)
//   4. SNIFF         password capture / transaction log / secret extraction   @ if(worker->sniff)
//                    (Hitag2 crypto nonce, Hitag S 82xx)
//   5. EMIT + REPLY  classify the cmd, build the MC/AC reply per mode, then    @ if(!worker->sniff && cmd
//                    arm it at the HARDWARE-timed T_wresp window               @ pull_out_dma_start
//   6. TEARDOWN      stop capture, free buffers, clear the stop flag          @ carrier_in_stop

static int32_t hitag_worker_emulate_thread(void* thread_context) {
    HitagWorker* worker = (HitagWorker*)thread_context;

    //tag pages are loaded by the app via hitag_worker_set_pages() before start.
    //sniff captures fresh, so reset the persistent tag for it.
    if(worker->sniff) {
        hitag_worker_initialize_tag_data(worker->tag);
    }

    hitag_worker_split_tag_data(worker->tag);
    //TODO: check if a tag has been properly loaded with known serial nr & config page
    // Hitag1 config-page semantics only; Hitag2 and Hitag S carry their own page layout,
    // and the Hitag S emulate branch keys off pageKnown[] (set by set_pages) directly.
    if(!worker->emulate_hitag2 && !worker->emulate_hitagS && !worker->emulate_hitag2_crypto)
        hitag_worker_process_config_page(worker->tag);

    //init capData for carrier_in
    HitagCaptureData* capData = malloc(sizeof(HitagCaptureData));
    furi_check(capData);
    capData->stream = buffer_stream_alloc(EMULATE_BUFFER_SIZE, EMULATE_BUFFER_COUNT);
    capData->pair = varint_pair_alloc();
    capData->capCounter = 0;

    //init dmaData for emulate mode:
    uint16_t dmaLen = 0;
    TimerDMAData* dataDMA = malloc(sizeof(TimerDMAData));
    furi_check(dataDMA);

    HitagReplyData* dataReply = malloc(sizeof(HitagReplyData));
    furi_check(dataReply);

    // setup pins for emulating
    // ibutton low
    furi_hal_ibutton_pin_configure();
    furi_hal_ibutton_pin_write(false);
    // comparator in
    furi_hal_gpio_init(&gpio_rfid_data_in, GpioModeAnalog, GpioPullNo, GpioSpeedLow);
    // carrier_out to fixed low state
    furi_hal_gpio_init(&gpio_rfid_carrier_out, GpioModeOutputPushPull, GpioPullNo, GpioSpeedLow);
    furi_hal_gpio_write(&gpio_rfid_carrier_out, false);
    // PA15 carrier_in to alt ftn 1 (TIM2 CH1) to use it for input capture
    furi_hal_gpio_init_ex(
        &gpio_rfid_carrier, GpioModeAltFunctionPushPull, GpioPullNo, GpioSpeedLow, GpioAltFn1TIM2);
    // pull to alternate function 1 (TIM2 CH3) to drive low (for command detection) or pull antenna via DMA (for command replies)
    furi_hal_gpio_init_ex(
        &gpio_nfc_irq_rfid_pull,
        GpioModeAltFunctionPushPull,
        GpioPullNo,
        GpioSpeedLow,
        GpioAltFn1TIM2);

    //start capture via carrier in instead of rfid in
    furi_hal_rfid_rtf_carrier_in_start(
        capData,
        worker->carrierPrescaler,
        dataDMA->timer_buffer_arr,
        dataDMA->timer_buffer_ccr,
        dmaLen,
        hitag_worker_carrier_in_callback);

    uint8_t prescaler = worker->carrierPrescaler;
    uint8_t period = 8 * prescaler - 1;

    bool carrier_on = false;
    int8_t carrier_count = 0;
    uint8_t carrier_threshold_on = 5;
    int8_t carrier_threshold_off = -5;

    uint32_t periodcounter = 0;

    uint8_t localMax = 0;
    uint8_t localMin = 255;
    uint32_t localMaxIndex = 0;
    uint32_t localMinIndex = 0;
    uint32_t lastMaxIndex = 0;
    uint32_t lastMinIndex = 0;
    uint8_t maxBitCounter = 0;
    uint8_t minBitCounter = 0;
    uint32_t maxBits[5];
    uint32_t minBits[5];
    int8_t cmd = 0;
    uint32_t one = 1 << (32 - 1);
    uint32_t cmdIndex = 0;

    //RTF emulate reply timing (backlog-immune): mirror the HAL's continuous us timeline by
    //summing every consumed duration. localMax/MinIndex_us snapshot that sum at each ripple
    //extreme, so cmd_end_us holds the true hardware timestamp of the command's last edge even
    //if the worker decoded it late. T_wresp is then (carrier_in_edge_us() - cmd_end_us).
    uint32_t accum_us = 0;
    uint32_t localMaxIndex_us = 0;
    uint32_t localMinIndex_us = 0;
    uint32_t cmd_end_us = 0;

    //sniff mode: capture the reader's 32-bit plaintext password frame (page1 RWD)
    uint32_t sniff_cand = 0;
    uint8_t sniff_cnt = 0;
    bool sniff_seen32 = false; // edge-detect: count one capture per 32-bit frame

    uint32_t miniMaxDelta = 0;
    uint32_t miniMaxIndex = 0;
    uint32_t prevMaxDelta = 0;
    uint32_t maxDelta = 0;

    uint32_t miniMinDelta = 0;
    uint32_t miniMinIndex = 0;
    uint32_t prevMinDelta = 0;
    uint32_t minDelta = 0;

    uint32_t prevduration = 0;
    uint32_t duration = 0;
    uint8_t durationcounter = 0;
    uint8_t durationthreshold = 5;

    uint8_t tagState = HitagStateIdle;
    uint8_t tagMode = HitagModeBasic;
    bool htsFast = false; // Hitag S FADV reader mode -> double-rate replies (MC8K/AC4K)
    bool htsWriting = false; // Hitag S: a WRITE_PAGE was ACKed, next 40-bit frame is its data
    uint8_t htsWritePage = 0; // Hitag S: target page of the pending write
    bool ht2cActive = false; // Hitag2 crypto: cipher engaged (all frames en/decrypted)
    uint64_t ht2cCs = 0; // Hitag2 crypto: running cipher state

    while(1) {
        Buffer* buffer = buffer_stream_receive(capData->stream, 1);

        if(buffer != NULL) {
            size_t buffsize = buffer_get_size(buffer);
            uint8_t* buffdata = buffer_get_data(buffer);

            //parse carrier_in duration & scan for cmds
            size_t index = 0;
            while(index < buffsize) {
                prevduration = duration;
                size_t tmp_size =
                    varint_uint32_unpack(&duration, &buffdata[index], buffsize - index);

                if(tmp_size == 0) {
                    FURI_LOG_E(TAG, "can't unpack varint pair");
                    break;
                } else {
                    index += tmp_size;

                    periodcounter++;
                    //mirror the HAL us timeline: sum every duration we consume (same values
                    //the ISR sums into carrier_in_accum_us) so our timestamps share its clock.
                    accum_us += duration;

                    //sniff scope: once armed (at the first START_AUTH) record the carrier-in
                    //cells of the real tag reply window for waveform comparison vs our emulate.
                    if(worker->sniff_scope_arm) {
                        if(worker->sniff_scope_cnt < HITAG_SNIFF_SCOPE_MAX) {
                            worker->sniff_scope[worker->sniff_scope_cnt++] =
                                (duration > UINT16_MAX) ? UINT16_MAX : (uint16_t)duration;
                        } else {
                            worker->sniff_scope_arm = false;
                            worker->sniff_scope_done = true;
                        }
                    }

                    if(!carrier_on) { //detect if carrier is available
                        if(0.75 * period <= duration && duration <= 1.25 * period) {
                            carrier_count++;
                            if(carrier_count >= carrier_threshold_on) {
                                carrier_on = true;
                                localMax = 0;
                                localMin = 255;
                                minBitCounter = 0;
                                maxBitCounter = 0;
                                minBits[0] = 0;
                                minBits[1] = 0;
                                maxBits[0] = 0;
                                maxBits[1] = 0;

                                carrier_count = 0;
                                //TODO reset tagstate to Idle & tagMode to basic after power_on_reset (no carrier for 10ms)
                            }
                        } else {
                            carrier_count = 0;
                        }
                    } else {
                        //detect if carrier is still available
                        if(duration <= 0.75 * period || 1.25 * period <= duration) {
                            carrier_count--;
                            if(carrier_count <= carrier_threshold_off) {
                                carrier_on = false;
                                carrier_count = 0;
                            }
                        } else {
                            carrier_count = 0;
                        }

                        if(carrier_on) { //if carrier is still available
                            //finetune the average period for reference
                            if(prevduration == duration) {
                                durationcounter++;
                                if(durationcounter == durationthreshold && period != duration) {
                                    period = duration;
                                }
                            } else {
                                durationcounter = 0;
                            }

                            //detect local MAX, and update maxCmd detection
                            if(duration > prevduration && duration > period) {
                                //rising edge above the normal periodduration: update localMax
                                localMax = duration;
                                localMaxIndex = periodcounter;
                                localMaxIndex_us = accum_us;
                            } else if(
                                duration < prevduration && localMax > period &&
                                periodcounter <= localMaxIndex + 2) {
                                //we passed a local maximum, derive length between current and prev max index
                                if(miniMaxDelta == 0) {
                                    prevMaxDelta = maxDelta;
                                }
                                maxDelta = (localMaxIndex - lastMaxIndex) * prescaler;

                                //check if there's a miniDelta and if it should be added to previous or next delta
                                if(miniMaxDelta > 0) {
                                    //by default minidelta is added to next
                                    //in case doing this does not result in 2 consequtive valid deltas, but adding it to previous does result in 2 consequtive valid deltas, then assign it to previous delta
                                    if((hitag_worker_validate_ripple_delta(
                                            prevMaxDelta + miniMaxDelta) +
                                        hitag_worker_validate_ripple_delta(
                                            maxDelta - miniMaxDelta)) >
                                       (hitag_worker_validate_ripple_delta(prevMaxDelta) +
                                        hitag_worker_validate_ripple_delta(maxDelta))) {
                                        //update the previous (last) bit from 0 to 1 if a command was ongoing
                                        if(maxBitCounter > 0) {
                                            maxBits[(maxBitCounter - 1) / 32] |=
                                                (one >> ((maxBitCounter - 1) % 32));
                                        }
                                        maxDelta -= miniMaxDelta;
                                        lastMaxIndex = miniMaxIndex;
                                    }
                                    miniMaxDelta = 0;
                                }

                                //now process the (possibly updated) delta
                                if(maxDelta >= 18) {
                                    if(maxDelta <= 22) {
                                        maxBitCounter++;
                                    } else if(26 <= maxDelta && maxDelta <= 32) {
                                        maxBits[(maxBitCounter) / 32] |=
                                            (one >> ((maxBitCounter) % 32));
                                        maxBitCounter++;
                                    } else if(maxBitCounter > 0) {
                                        //end of bitstring caused by invalid delta

                                        if(hitag_emu_validate(
                                               worker, maxBits, maxBitCounter)) {
                                            cmd = 1;
                                            cmdIndex = localMaxIndex;
                                            cmd_end_us = localMaxIndex_us;

                                            //CMD found, stop searching for minCMD: reset the minCmd detection
                                            minBits[0] = 0;
                                            minBits[1] = 0;
                                            minBitCounter = 0;
                                        } else {
                                            //reset the maxCmd detection
                                            maxBits[0] = 0;
                                            maxBits[1] = 0;
                                            maxBitCounter = 0;
                                        }
                                    }
                                    lastMaxIndex = localMaxIndex;
                                } else {
                                    miniMaxDelta = maxDelta;
                                    miniMaxIndex = localMaxIndex;
                                }
                                localMax = 0;
                            }

                            //terminate bitstring ico absence of next delta (a true end)
                            if(periodcounter == lastMaxIndex + 40 / prescaler &&
                               maxBitCounter > 0) {
                                if(hitag_emu_validate(worker, maxBits, maxBitCounter)) {
                                    cmd = 1;
                                    cmdIndex = localMaxIndex;
                                    cmd_end_us = localMaxIndex_us;

                                    //CMD found, stop searching for minCMD: reset the minCmd detection
                                    minBits[0] = 0;
                                    minBits[1] = 0;
                                    minBitCounter = 0;
                                } else {
                                    //reset the maxCmd detection
                                    maxBits[0] = 0;
                                    maxBits[1] = 0;
                                    maxBitCounter = 0;
                                }
                            }

                            //detect local MIN, and update minCmd detection
                            if(duration < prevduration && duration < period) {
                                //rising edge above the normal periodduration: update localMax
                                localMin = duration;
                                localMinIndex = periodcounter;
                                localMinIndex_us = accum_us;
                            } else if(
                                duration > prevduration && localMin < period &&
                                periodcounter <= localMinIndex + 2) {
                                //we passed a local minimum, derive length between current and prev max index
                                if(miniMinDelta == 0) {
                                    prevMinDelta = minDelta;
                                }
                                minDelta = (localMinIndex - lastMinIndex) * prescaler;

                                //check if there's a miniDelta and if it should be added to previous or next delta
                                if(miniMinDelta > 0) {
                                    //by default minidelta is added to next
                                    //in case doing this does not result in 2 consequtive valid deltas, but adding it to previous does result in 2 consequtive valid deltas, then assign it to previous delta
                                    if((hitag_worker_validate_ripple_delta(
                                            prevMinDelta + miniMinDelta) +
                                        hitag_worker_validate_ripple_delta(
                                            minDelta - miniMinDelta)) >
                                       (hitag_worker_validate_ripple_delta(prevMinDelta) +
                                        hitag_worker_validate_ripple_delta(minDelta))) {
                                        //update the previous (last) bit from 0 to 1 if a command was ongoing
                                        if(minBitCounter > 0) {
                                            minBits[(minBitCounter - 1) / 32] |=
                                                (one >> ((minBitCounter - 1) % 32));
                                        }
                                        minDelta -= miniMinDelta;
                                        lastMinIndex = miniMinIndex;
                                    }
                                    miniMinDelta = 0;
                                }

                                //now process the (possibly updated) delta
                                if(minDelta >= 18) {
                                    if(minDelta <= 22) {
                                        minBitCounter++;
                                    } else if(26 <= minDelta && minDelta <= 32) {
                                        minBits[(minBitCounter) / 32] |=
                                            (one >> ((minBitCounter) % 32));
                                        minBitCounter++;
                                    } else if(minBitCounter > 0) {
                                        //end of bitstring caused by invalid delta
                                        if(hitag_emu_validate(
                                               worker, minBits, minBitCounter)) {
                                            cmd = -1;
                                            cmdIndex = localMinIndex;
                                            cmd_end_us = localMinIndex_us;

                                            //CMD found, stop searching for maxCMD: reset the maxCmd detection
                                            maxBits[0] = 0;
                                            maxBits[1] = 0;
                                            maxBitCounter = 0;
                                        } else {
                                            //reset the minCmd detection
                                            minBits[0] = 0;
                                            minBits[1] = 0;
                                            minBitCounter = 0;
                                        }
                                    }
                                    lastMinIndex = localMinIndex;
                                } else {
                                    miniMinDelta = minDelta;
                                    miniMinIndex = localMinIndex;
                                }
                                localMin = 255;
                            }

                            //terminate of bitstring caused by absence of next delta (a true end)
                            if(periodcounter == lastMinIndex + 40 / prescaler &&
                               minBitCounter > 0) {
                                if(hitag_emu_validate(worker, minBits, minBitCounter)) {
                                    cmd = -1;
                                    cmdIndex = localMinIndex;
                                    cmd_end_us = localMinIndex_us;

                                    //CMD found, stop searching for maxCMD: reset the maxCmd detection
                                    maxBits[0] = 0;
                                    maxBits[1] = 0;
                                    maxBitCounter = 0;
                                } else {
                                    //reset the minCmd detection
                                    minBits[0] = 0;
                                    minBits[1] = 0;
                                    minBitCounter = 0;
                                }
                            }

                            //SNIFF: the reader's plaintext password is a 32-bit frame.
                            //validate_bits only knows 5/20/45-bit Hitag1 commands, so a
                            //32-bit frame never sets cmd; capture it straight from the
                            //bit accumulators (one capture per frame via edge-detect).
                            if(worker->sniff) {
                                uint32_t pw = 0;
                                bool got = false;
                                if(maxBitCounter == 32) {
                                    pw = maxBits[0];
                                    got = true;
                                } else if(minBitCounter == 32) {
                                    pw = minBits[0];
                                    got = true;
                                }
                                if(got && !sniff_seen32) {
                                    sniff_seen32 = true;
                                    if(pw == sniff_cand) {
                                        sniff_cnt++;
                                    } else {
                                        sniff_cand = pw;
                                        sniff_cnt = 1;
                                    }
                                    if(sniff_cnt >= 2 &&
                                       worker->workerstatus != HitagStatusRead) {
                                        //store the sniffed password into Hitag2 page 1 (RWD)
                                        hitag_store_page(worker->tag->pageData, 1, pw);
                                        worker->tag->pageKnown[1] = 1;
                                        hitag_worker_combine_tag_data(worker->tag);
                                        dolphin_deed(DolphinDeedRfidReadSuccess);
                                        worker->workerstatus = HitagStatusRead;
                                    }
                                } else if(!got) {
                                    sniff_seen32 = false; //frame ended, re-arm for the next
                                }
                            }

                            //SNIFF full-transaction log: record every decoded reader command
                            //(START_AUTH / READ / password) with its length and value, then
                            //consume it (the password capture above already ran this iteration).
                            if(worker->sniff && cmd != 0) {
                                uint32_t v, vlo;
                                uint8_t size;
                                if(cmd == 1) {
                                    v = maxBits[0];
                                    vlo = maxBits[1];
                                    size = maxBitCounter;
                                    maxBits[0] = 0;
                                    maxBits[1] = 0;
                                    maxBitCounter = 0;
                                } else {
                                    v = minBits[0];
                                    vlo = minBits[1];
                                    size = minBitCounter;
                                    minBits[0] = 0;
                                    minBits[1] = 0;
                                    minBitCounter = 0;
                                }
                                cmd = 0;
                                if(worker->sniff_log_cnt < HITAG_SNIFF_LOG_MAX) {
                                    worker->sniff_log_len[worker->sniff_log_cnt] = size;
                                    worker->sniff_log_val[worker->sniff_log_cnt] = v;
                                    worker->sniff_log_cnt++;
                                }
                                //arm the scope on the first START_AUTH: the cells that follow
                                //are the real tag's UID reply (good coupling, badge present).
                                if(!worker->sniff_scope_done && size >= 5 && size <= 7 &&
                                   (v >> 27) == 0x18) {
                                    worker->sniff_scope_cnt = 0;
                                    worker->sniff_scope_arm = true;
                                }
                                //target-specific secret extraction from the just-decoded frame:
                                if(worker->sniff_target == HITAG_SNIFF_TGT_NONCE) {
                                    //Hitag2 crypto: the 64-bit reader auth frame = nR (high 32)
                                    //|| aR (low 32). Store clean 64-bit captures; drop an exact
                                    //repeat of the previous pair (reader retries under marginal
                                    //coupling). These pairs + the UID feed the PC-side cracker.
                                    if(size == 64 &&
                                       worker->sniff_nonce_cnt < HITAG_SNIFF_NONCE_MAX) {
                                        uint8_t n = worker->sniff_nonce_cnt;
                                        if(n == 0 || worker->sniff_nonce_nr[n - 1] != v ||
                                           worker->sniff_nonce_ar[n - 1] != vlo) {
                                            worker->sniff_nonce_nr[n] = v;
                                            worker->sniff_nonce_ar[n] = vlo;
                                            worker->sniff_nonce_cnt = n + 1;
                                        }
                                    }
                                } else if(worker->sniff_target == HITAG_SNIFF_TGT_82XX) {
                                    //Hitag S 82xx: the reader WRITEs its password to virtual page
                                    //64. Watch for WRITE(addr 64), then capture the next 40-bit
                                    //data frame (the validator already checked its CRC) as the
                                    //4-byte password. A fresh UID_REQ cancels a pending write.
                                    uint8_t addrW = 0xff;
                                    HitagSFrameKind kS = hitag_classify_frame_s(size, v, &addrW);
                                    if(kS == HitagSFrameWrite && addrW == 64) {
                                        worker->sniff_hts_w64 = true;
                                    } else if(
                                        worker->sniff_hts_w64 && size >= 39 && size <= 42) {
                                        worker->sniff_82xx_pwd = v;
                                        worker->sniff_82xx_got = true;
                                        worker->sniff_hts_w64 = false;
                                        dolphin_deed(DolphinDeedRfidReadSuccess);
                                    } else if(kS == HitagSFrameUidReq) {
                                        worker->sniff_hts_w64 = false;
                                    }
                                }
                            }

                            //if a valid cmd has been detected: process it & reply
                            if(!worker->sniff && cmd != 0) {
                                uint32_t bits[5];
                                uint8_t size = 0;
                                //select the cmd bit source (max or min detection)
                                if(cmd == 1) {
                                    bits[0] = maxBits[0];
                                    bits[1] = maxBits[1];
                                    size = maxBitCounter;

                                    maxBits[0] = 0;
                                    maxBits[1] = 0;
                                    maxBitCounter = 0;
                                } else {
                                    bits[0] = minBits[0];
                                    bits[1] = minBits[1];
                                    size = minBitCounter;

                                    minBits[0] = 0;
                                    minBits[1] = 0;
                                    minBitCounter = 0;
                                }
                                cmd = 0;

                                //EMULATE diagnostic: log every reader command we receive, so a
                                //failed reader attempt shows how far the handshake got (reuses the
                                //sniff log buffer: START_AUTH / password / READ page n ...).
                                //classify once (O6): shared by the counters and the reply
                                //builder so the tolerant ranges cannot drift apart.
                                Ht2CmdType ht2cmd = Ht2CmdNone;
                                if(worker->emulate_hitag2) {
                                    ht2cmd = hitag2_classify_cmd(size, bits[0]);
                                    //lean run: skip the per-command log buffer write to shave
                                    //latency/jitter off the cmd->reply path (tighter T_wresp).
                                    //The cheap type counters below stay (live coupling readout).
                                    if(!worker->emu_lean &&
                                       worker->sniff_log_cnt < HITAG_SNIFF_LOG_MAX) {
                                        worker->sniff_log_len[worker->sniff_log_cnt] = size;
                                        worker->sniff_log_val[worker->sniff_log_cnt] = bits[0];
                                        worker->sniff_log_cnt++;
                                    }
                                    //live coupling readout: count commands by type
                                    if(ht2cmd == Ht2CmdAuth)
                                        worker->emu_auth++;
                                    else if(ht2cmd == Ht2CmdRead)
                                        worker->emu_read++;
                                    else if(ht2cmd == Ht2CmdPwd)
                                        worker->emu_pwd++;
                                }

                                dmaLen = 0;
                                if(worker->emulate_hitag2) {
                                    //Hitag2 password-mode tag emulation. All replies are
                                    //Manchester: 5-bit '1' preamble + 32 data bits.
                                    uint8_t pg = 0xff;
                                    switch(ht2cmd) {
                                    case Ht2CmdAuth:
                                        //START_AUTH -> reply UID (page 0). The classifier
                                        //tolerates 5..7 bits (a spurious trailing edge under
                                        //marginal coupling inflates the size) while still
                                        //requiring the 0b11000 opcode, so we never miss a reply
                                        //(the "many AUTH, 0 PWD" bug) yet never mis-fire on noise.
                                        pg = 0;
                                        break;
                                    case Ht2CmdPwd: {
                                        //password frame -> reply the config page (page 3).
                                        //NORMAL mode: only if the frame matches our RWD (page 1) —
                                        //this is the proven path that was accepted by a real reader.
                                        //FAST mode (emu_fast): answer config on ANY 32-bit frame.
                                        //We emulate a KNOWN fixed-password badge (MIKR), and under
                                        //marginal coupling the 32-bit password is often mis-decoded
                                        //(field logs: ~5/40 clean) so the gate drops valid attempts
                                        //and the reader rarely reaches READ. Unconditional = ~8x more
                                        //chances. Only the password is 32-bit after START_AUTH, safe.
                                        if(worker->emu_fast) {
                                            pg = 3;
                                        } else {
                                            uint32_t pwd = bits[0];
                                            uint32_t myp =
                                                worker->tag->pageData[1 * 4 + 0] << 24 |
                                                worker->tag->pageData[1 * 4 + 1] << 16 |
                                                worker->tag->pageData[1 * 4 + 2] << 8 |
                                                worker->tag->pageData[1 * 4 + 3];
                                            if(pwd == myp) pg = 3;
                                        }
                                        break;
                                    }
                                    case Ht2CmdRead: {
                                        //READ page n: command top byte = 0xC0|(n<<3)|...
                                        uint8_t n = (bits[0] >> 27) & 0x07;
                                        if(n < 8) pg = n;
                                        break;
                                    }
                                    default:
                                        break;
                                    }
                                    if(pg < 8) {
                                        //Reply = Hitag2 SOF (preamble ones) + 32 Manchester data
                                        //bits, matching the tag side of PM3 hitag_send_frame.
                                        //Preamble length is tunable for bench A/B (default 4).
                                        uint8_t pre = worker->emu_preamble;
                                        if(pre == 0 || pre > 16) pre = 5;
                                        uint8_t k = 0;
                                        dataReply->replyvalue[k] = (uint32_t)((1u << pre) - 1);
                                        dataReply->replytype[k] = pre;
                                        k++;
                                        uint32_t v = ((uint32_t)worker->tag->pageData[pg * 4 + 0] << 24) |
                                                     ((uint32_t)worker->tag->pageData[pg * 4 + 1] << 16) |
                                                     ((uint32_t)worker->tag->pageData[pg * 4 + 2] << 8) |
                                                     ((uint32_t)worker->tag->pageData[pg * 4 + 3]);
                                        // leadbit: prepend a '0' data bit -> clean 1->0 preamble/data
                                        // boundary. PROVEN on PM3 to change the reader framing from
                                        // (real>>1)|0x80000000 (MSB forced, unfixable) to a pure
                                        // (real>>1). We then PRE-SHIFT the data left by 1 so the
                                        // reader reads (v<<1)>>1 = v exactly (for MSB-0 pages incl.
                                        // the UID). Bench A/B via emu_leadbit.
                                        if(worker->emu_leadbit) {
                                            dataReply->replyvalue[k] = 0;
                                            dataReply->replytype[k] = 1;
                                            k++;
                                            v <<= 1; // pre-compensate the reader's >>1
                                        }
                                        dataReply->replyvalue[k] = (v >> 24) & 0xff;
                                        dataReply->replytype[k++] = HITAG_BYTE;
                                        dataReply->replyvalue[k] = (v >> 16) & 0xff;
                                        dataReply->replytype[k++] = HITAG_BYTE;
                                        dataReply->replyvalue[k] = (v >> 8) & 0xff;
                                        dataReply->replytype[k++] = HITAG_BYTE;
                                        dataReply->replyvalue[k] = v & 0xff;
                                        dataReply->replytype[k++] = HITAG_BYTE;
                                        dataReply->replylength = k;
                                        dmaLen = hitag_worker_yield_dma_buffer_MC(
                                            dataReply, dataDMA, worker->carrierPrescaler);
                                    }
                                } else if(worker->emulate_hitag2_crypto) {
                                    // Hitag2 CRYPTO-mode tag emulation (nRaR mutual auth + 48-bit
                                    // stream cipher). A SEPARATE mode from the proven password path
                                    // above, which stays byte-identical. Mirrors PM3 hitag2.c:
                                    //   START_AUTH -> UID (page 0), plain, reset crypto.
                                    //   nRaR (64b) -> cipher_reset(key,uid,nR) + authenticate(aR);
                                    //     on success engage the cipher and reply page 3 encrypted
                                    //     (the reader discards this response, only its presence
                                    //     matters), then every later frame is decrypted in and
                                    //     every reply encrypted out.
                                    //   READ (10b) -> the addressed page, encrypted.
                                    // fb[9], not [8]: the crypto validator tolerates a 62..66-bit
                                    // nRaR frame (coupling noise), so size/8 can reach 8 and the
                                    // trailing-bits transcrypt below writes fb[bytes] == fb[8].
                                    uint8_t fb[9] = {0};
                                    fb[0] = bits[0] >> 24;
                                    fb[1] = bits[0] >> 16;
                                    fb[2] = bits[0] >> 8;
                                    fb[3] = bits[0];
                                    fb[4] = bits[1] >> 24;
                                    fb[5] = bits[1] >> 16;
                                    fb[6] = bits[1] >> 8;
                                    fb[7] = bits[1];
                                    if(ht2cActive)
                                        ht2_hitag2_cipher_transcrypt(
                                            &ht2cCs, fb, size / 8, size % 8);
                                    uint8_t txb[4] = {0};
                                    bool haveReply = false;
                                    if(size >= 5 && size <= 7) {
                                        ht2cActive = false; // START_AUTH -> plain UID, reset crypto
                                        memcpy(txb, &worker->tag->pageData[0], 4);
                                        haveReply = true;
                                        worker->emu_auth++;
                                    } else if(size >= 62 && size <= 66) {
                                        uint32_t uid_le = (uint32_t)worker->tag->pageData[0] |
                                                          ((uint32_t)worker->tag->pageData[1] << 8) |
                                                          ((uint32_t)worker->tag->pageData[2]
                                                           << 16) |
                                                          ((uint32_t)worker->tag->pageData[3] << 24);
                                        uint32_t nr_le = (uint32_t)fb[0] | ((uint32_t)fb[1] << 8) |
                                                         ((uint32_t)fb[2] << 16) |
                                                         ((uint32_t)fb[3] << 24);
                                        ht2cCs = ht2_hitag2_init(
                                            HT2_REV64(worker->hts_crypto_key),
                                            HT2_REV32(uid_le),
                                            HT2_REV32(nr_le));
                                        if(ht2_hitag2_cipher_authenticate(&ht2cCs, &fb[4])) {
                                            ht2cActive = true; // engage before encrypting the reply
                                            memcpy(txb, &worker->tag->pageData[3 * 4], 4);
                                            haveReply = true;
                                            worker->emu_pwd++;
                                        }
                                    } else if(size >= 10 && size <= 12 && ht2cActive) {
                                        if((fb[0] & 0xC6) == 0xC0) { // READ_PAGE
                                            uint8_t sector = (fb[0] >> 3) & 0x07;
                                            memcpy(txb, &worker->tag->pageData[sector * 4], 4);
                                            haveReply = true;
                                            worker->emu_read++;
                                        }
                                    }
                                    if(haveReply) {
                                        if(ht2cActive)
                                            ht2_hitag2_cipher_transcrypt(&ht2cCs, txb, 4, 0);
                                        uint8_t pre = worker->emu_preamble;
                                        if(pre == 0 || pre > 16) pre = 5;
                                        uint8_t k = 0;
                                        dataReply->replyvalue[k] = (uint32_t)((1u << pre) - 1);
                                        dataReply->replytype[k++] = pre;
                                        uint32_t v = ((uint32_t)txb[0] << 24) |
                                                     ((uint32_t)txb[1] << 16) |
                                                     ((uint32_t)txb[2] << 8) | (uint32_t)txb[3];
                                        if(worker->emu_leadbit) {
                                            dataReply->replyvalue[k] = 0;
                                            dataReply->replytype[k++] = 1;
                                            v <<= 1;
                                        }
                                        dataReply->replyvalue[k] = (v >> 24) & 0xff;
                                        dataReply->replytype[k++] = HITAG_BYTE;
                                        dataReply->replyvalue[k] = (v >> 16) & 0xff;
                                        dataReply->replytype[k++] = HITAG_BYTE;
                                        dataReply->replyvalue[k] = (v >> 8) & 0xff;
                                        dataReply->replytype[k++] = HITAG_BYTE;
                                        dataReply->replyvalue[k] = v & 0xff;
                                        dataReply->replytype[k++] = HITAG_BYTE;
                                        dataReply->replylength = k;
                                        dmaLen = hitag_worker_yield_dma_buffer_MC(
                                            dataReply, dataDMA, worker->carrierPrescaler);
                                    }
                                } else if(worker->emulate_hitagS) {
                                    // Hitag S plain-mode tag emulation. All replies are Manchester
                                    // (like Hitag2) with a 6-bit SOF + data + CRC8, matching a real
                                    // Hitag S advanced tag. UID_REQ (STD/ADV opcode) -> UID (page 0,
                                    // no CRC). SELECT(00000 + UID + CRC8) -> config (page 1). READ
                                    // (1100/1101 + addr + CRC8) -> requested page. Self-contained:
                                    // reuses the shared classifier + calc_crc + MC yield, and the
                                    // Hitag1 command validator (same framing/CRC). Reply timing
                                    // rides the Hitag1 branch of the commit below. Hitag1/Hitag2
                                    // reply paths untouched.
                                    uint8_t firstPageS = 0xff; // page to reply from (0xff = no reply)
                                    bool withCrcS = false; // UID reply has no CRC; SELECT/READ do
                                    bool htsSendAck = false; // send the 2-bit write ACK "01"
                                    bool htsChallenge = false; // send the encrypted auth response
                                    if(htsWriting && htsWritePage == 64 && size >= 39 &&
                                       size <= 42) {
                                        // 82xx auth: the reader writes its password to virtual page
                                        // 64. Grant (ACK) only if it matches, so a wrong password is
                                        // rejected; never store (page 64 is not real memory).
                                        htsWriting = false;
                                        if(bits[0] == worker->hts_82xx_pwd) htsSendAck = true;
                                    } else if(htsWriting && size >= 39 && size <= 42) {
                                        // WRITE-DATA frame (validated by CRC): store the 32 bits
                                        // into the pending page and ACK. Mirrors hitagS.c case 40.
                                        worker->tag->pageData[htsWritePage * 4 + 0] =
                                            (bits[0] >> 24) & 0xff;
                                        worker->tag->pageData[htsWritePage * 4 + 1] =
                                            (bits[0] >> 16) & 0xff;
                                        worker->tag->pageData[htsWritePage * 4 + 2] =
                                            (bits[0] >> 8) & 0xff;
                                        worker->tag->pageData[htsWritePage * 4 + 3] = bits[0] & 0xff;
                                        worker->tag->pageKnown[htsWritePage] = 1;
                                        hitag_worker_combine_tag_data(worker->tag);
                                        htsWriting = false;
                                        htsSendAck = true;
                                    } else {
                                    uint8_t addrS = 0xff;
                                    HitagSFrameKind kindS =
                                        hitag_classify_frame_s(size, bits[0], &addrS);
                                    // live coupling readout (reuse the emulate counters/UI):
                                    // UID_REQ -> AUTH, SELECT -> PWD, READ -> RD. Lets the screen
                                    // show which handshake stage the reader reached.
                                    if(kindS == HitagSFrameUidReq)
                                        worker->emu_auth++;
                                    else if(kindS == HitagSFrameSelect)
                                        worker->emu_pwd++;
                                    else if(kindS == HitagSFrameRead)
                                        worker->emu_read++;
                                    if(kindS == HitagSFrameUidReq) {
                                        htsWriting = false; // a fresh session cancels any pending write
                                        tagState = HitagStateIdle;
                                        // Track the reader's protocol mode from the UID_REQ opcode:
                                        // STD (00110) -> Basic (1-bit SOF, no CRC); ADV1/ADV2
                                        // (11001/11000) -> Advanced (3/6-bit SOF, CRC on SELECT/READ).
                                        tagMode = ((bits[0] >> (32 - 5)) == 0b00110) ?
                                                      HitagModeBasic :
                                                      HitagModeAdvanced;
                                        // FADV (11010) = Advanced framing but DOUBLE bit rate.
                                        htsFast = ((bits[0] >> (32 - 5)) == 0b11010);
                                        firstPageS = 0; // reply the UID (page 0)
                                    } else if(kindS == HitagSFrameSelect) {
                                        // SELECT UID = 5-bit opcode then 32-bit UID over bits[0..1]
                                        uint32_t SN_cmd = bits[0] << 5 | bits[1] >> (32 - 5);
                                        uint32_t SN_tag = worker->tag->pageData[0] << 24 |
                                                          worker->tag->pageData[1] << 16 |
                                                          worker->tag->pageData[2] << 8 |
                                                          worker->tag->pageData[3];
                                        if(SN_cmd == SN_tag) {
                                            tagState = HitagStateSelected;
                                            firstPageS = 1; // reply the config page (page 1)
                                            withCrcS = true;
                                        }
                                    } else if(
                                        kindS == HitagSFrameRead &&
                                        tagState == HitagStateSelected) {
                                        // READ page addr -> reply it if we hold it. In auth mode
                                        // (config.auth) with LKP set, the key pages 2/3 are
                                        // "no access" -> stay silent, exactly like a real tag
                                        // (hitagS.c: LKP + auth -> *txlen = 0 for page 2/3).
                                        uint8_t con1S = worker->tag->pageData[1 * 4 + 1];
                                        bool lkp_no_access = (con1S & 0x80) && (con1S & 0x01) &&
                                                             (addrS == 2 || addrS == 3);
                                        if(addrS < HITAG_PAGES && worker->tag->pageKnown[addrS] &&
                                           !lkp_no_access) {
                                            firstPageS = addrS;
                                            withCrcS = true;
                                        }
                                    } else if(
                                        kindS == HitagSFrameWrite &&
                                        tagState == HitagStateSelected) {
                                        // WRITE_PAGE addr -> ACK now; the next 40-bit frame carries
                                        // the data. Page 64 is the virtual 82xx auth page (password
                                        // write) — always ACK the command and let the data frame
                                        // check the password. For real pages, honour the config-page
                                        // lock bits (LKP/LCON/LCKn): a locked page gets no ACK, so
                                        // the reader sees "no write access" like a real tag.
                                        if(addrS == 64) {
                                            htsWriting = true;
                                            htsWritePage = 64;
                                            htsSendAck = true;
                                        } else if(
                                            addrS < HITAG_PAGES &&
                                            hitags_page_writable(
                                                worker->tag->pageData, addrS)) {
                                            htsWriting = true;
                                            htsWritePage = addrS;
                                            htsSendAck = true;
                                        }
                                    } else if(
                                        size >= 62 && size <= 66 &&
                                        tagState == HitagStateSelected) {
                                        // Crypto/auth challenge (rnd + authenticator, 64-bit).
                                        // Reply the encrypted con2/password exactly like a real
                                        // tag (hitagS.c case 64): init the Hitag2 cipher from the
                                        // key+UID+rnd, drop 4 keystream bytes, XOR the plaintext.
                                        // (The reader gates auth on the response length only and
                                        // reads pages plain, but the faithful ciphertext lets a
                                        // reader with the correct key recover the real password.)
                                        htsChallenge = true;
                                        worker->emu_pwd++;
                                    }
                                    }
                                    if(htsSendAck) {
                                        // 2-bit ACK "01" (reader checks rx[0]>>6 == 0b01), Manchester,
                                        // same SOF as the SELECT/READ replies for this mode, no CRC.
                                        uint8_t k = 0;
                                        bool adv = (tagMode == HitagModeAdvanced);
                                        if(adv) {
                                            dataReply->replyvalue[k] = 0b00111111;
                                            dataReply->replytype[k++] = HITAG_STARTBIT6;
                                        } else {
                                            dataReply->replyvalue[k] = 0b00000001;
                                            dataReply->replytype[k++] = HITAG_STARTBIT;
                                        }
                                        dataReply->replyvalue[k] = 0b00000001;
                                        dataReply->replytype[k++] = 2; // data bits "01"
                                        dataReply->replylength = k;
                                        dmaLen = htsFast ?
                                                     hitag_worker_yield_dma_buffer_MC8(
                                                         dataReply, dataDMA, worker->carrierPrescaler) :
                                                     hitag_worker_yield_dma_buffer_MC(
                                                         dataReply, dataDMA, worker->carrierPrescaler);
                                    } else if(htsChallenge) {
                                        // Encrypted auth response (hitagS.c case 64): cipher inputs
                                        // are key/UID/rnd bit-reversed, matching the reader so a
                                        // reader with the right key recovers con2/pwdh0/pwdl0/pwdl1.
                                        uint32_t rnd_be = bits[0]; // 32-bit rnd, MSB-first decoded
                                        uint32_t le_rx = ((rnd_be >> 24) & 0xff) |
                                                         ((rnd_be >> 8) & 0xff00) |
                                                         ((rnd_be << 8) & 0xff0000) |
                                                         ((rnd_be << 24) & 0xff000000); // MemLe
                                        uint32_t uid_le =
                                            (uint32_t)worker->tag->pageData[0] |
                                            ((uint32_t)worker->tag->pageData[1] << 8) |
                                            ((uint32_t)worker->tag->pageData[2] << 16) |
                                            ((uint32_t)worker->tag->pageData[3] << 24);
                                        // 48-bit key set by the user via the "Hitag S key" menu
                                        // (the app can't edit tag pages directly, so the key is a
                                        // typed field, not read from the dump). The reader's -k
                                        // must match it.
                                        uint64_t st = ht2_hitag2_init(
                                            HT2_REV64(worker->hts_crypto_key),
                                            HT2_REV32(uid_le),
                                            HT2_REV32(le_rx));
                                        for(uint8_t d = 0; d < 4; d++) ht2_hitag2_byte(&st);
                                        uint8_t pt[4] = {
                                            worker->tag->pageData[1 * 4 + 2], // con2
                                            worker->tag->pageData[1 * 4 + 3], // pwdh0
                                            worker->tag->pageData[2 * 4 + 0], // pwdl0
                                            worker->tag->pageData[2 * 4 + 1], // pwdl1
                                        };
                                        uint8_t crcp = CRC_PRESET;
                                        for(uint8_t d = 0; d < 4; d++)
                                            hitag_worker_calc_crc(&crcp, pt[d], 8);
                                        bool adv = (tagMode == HitagModeAdvanced);
                                        uint8_t k = 0;
                                        if(adv) {
                                            dataReply->replyvalue[k] = 0b00111111;
                                            dataReply->replytype[k++] = HITAG_STARTBIT6;
                                        } else {
                                            dataReply->replyvalue[k] = 0b00000001;
                                            dataReply->replytype[k++] = HITAG_STARTBIT;
                                        }
                                        for(uint8_t d = 0; d < 4; d++) {
                                            dataReply->replyvalue[k] =
                                                pt[d] ^ (uint8_t)ht2_hitag2_byte(&st);
                                            dataReply->replytype[k++] = HITAG_BYTE;
                                        }
                                        if(adv) {
                                            dataReply->replyvalue[k] =
                                                crcp ^ (uint8_t)ht2_hitag2_byte(&st);
                                            dataReply->replytype[k++] = HITAG_BYTE;
                                        }
                                        dataReply->replylength = k;
                                        dmaLen = htsFast ?
                                                     hitag_worker_yield_dma_buffer_MC8(
                                                         dataReply, dataDMA, worker->carrierPrescaler) :
                                                     hitag_worker_yield_dma_buffer_MC(
                                                         dataReply, dataDMA, worker->carrierPrescaler);
                                    } else if(firstPageS != 0xff) {
                                        uint8_t k = 0;
                                        bool adv = (tagMode == HitagModeAdvanced);
                                        if(!withCrcS) {
                                            // UID response: the reader requests the UID with ac_seq
                                            // (PM3 hts_select_tag) -> ANTICOLLISION coding (AC2K),
                                            // 32 data bits, no CRC. SOF = 3 bits in ADV mode, 1 bit
                                            // in STD (per hts_set_frame_modulation).
                                            if(adv) {
                                                dataReply->replyvalue[k] = 0b00000111;
                                                dataReply->replytype[k++] = HITAG_STARTBIT3;
                                            } else {
                                                dataReply->replyvalue[k] = 0b00000001;
                                                dataReply->replytype[k++] = HITAG_STARTBIT;
                                            }
                                            for(uint8_t b = 0; b < 4; b++) {
                                                dataReply->replyvalue[k] =
                                                    worker->tag->pageData[firstPageS * 4 + b];
                                                dataReply->replytype[k++] = HITAG_BYTE;
                                            }
                                            dataReply->replylength = k;
                                            dmaLen = htsFast ?
                                                         hitag_worker_yield_dma_buffer_AC4(
                                                             dataReply,
                                                             dataDMA,
                                                             worker->carrierPrescaler) :
                                                         hitag_worker_yield_dma_buffer_AC(
                                                             dataReply,
                                                             dataDMA,
                                                             worker->carrierPrescaler);
                                        } else {
                                            // SELECT/READ response: Manchester (MC4K), 32 data bits.
                                            // SOF = 6 bits in ADV, 1 bit in STD. CRC8 is appended
                                            // only in ADV/FADV (STD carries no CRC, per hitagS.c).
                                            if(adv) {
                                                dataReply->replyvalue[k] = 0b00111111;
                                                dataReply->replytype[k++] = HITAG_STARTBIT6;
                                            } else {
                                                dataReply->replyvalue[k] = 0b00000001;
                                                dataReply->replytype[k++] = HITAG_STARTBIT;
                                            }
                                            uint8_t crcS = CRC_PRESET;
                                            for(uint8_t b = 0; b < 4; b++) {
                                                uint8_t d =
                                                    worker->tag->pageData[firstPageS * 4 + b];
                                                dataReply->replyvalue[k] = d;
                                                dataReply->replytype[k++] = HITAG_BYTE;
                                                hitag_worker_calc_crc(&crcS, d, 8);
                                            }
                                            if(adv) {
                                                dataReply->replyvalue[k] = crcS;
                                                dataReply->replytype[k++] = HITAG_CRC;
                                            }
                                            dataReply->replylength = k;
                                            dmaLen = htsFast ?
                                                         hitag_worker_yield_dma_buffer_MC8(
                                                             dataReply,
                                                             dataDMA,
                                                             worker->carrierPrescaler) :
                                                         hitag_worker_yield_dma_buffer_MC(
                                                             dataReply,
                                                             dataDMA,
                                                             worker->carrierPrescaler);
                                        }
                                    }
                                } else if(size == 5 && (bits[0] >> (32 - 5)) == 0b11001) { //SET_CCNEW
                                    if(tagState != HitagStateQuiet) {
                                        //reset selected state
                                        tagState = HitagStateIdle;

                                        //set tag in advanced mode
                                        tagMode = HitagModeAdvanced;

                                        //prepare emulate DMA buffer with advanced SN reply (page 0)
                                        dataReply->replyvalue[0] = 0b00000111;
                                        dataReply->replytype[0] = HITAG_STARTBIT3;
                                        dataReply->replyvalue[1] = worker->tag->pageData[0];
                                        dataReply->replytype[1] = HITAG_BYTE;
                                        dataReply->replyvalue[2] = worker->tag->pageData[1];
                                        dataReply->replytype[2] = HITAG_BYTE;
                                        dataReply->replyvalue[3] = worker->tag->pageData[2];
                                        dataReply->replytype[3] = HITAG_BYTE;
                                        dataReply->replyvalue[4] = worker->tag->pageData[3];
                                        dataReply->replytype[4] = HITAG_BYTE;

                                        dataReply->replylength = 5;

                                        dmaLen = hitag_worker_yield_dma_buffer_AC(
                                            dataReply, dataDMA, worker->carrierPrescaler);
                                    }
                                } else if(size == 5 && (bits[0] >> (32 - 5)) == 0b00110) { //SET_CC
                                    if(tagState != HitagStateQuiet) {
                                        //reset selected state
                                        tagState = HitagStateIdle;

                                        //do not (re)set tag in basic mode, this only happens during power on reset

                                        //prepare emulate DMA buffer with basic SN reply (page 0)
                                        dataReply->replyvalue[0] = 0b00000001;
                                        dataReply->replytype[0] = HITAG_STARTBIT;
                                        dataReply->replyvalue[1] = worker->tag->pageData[0];
                                        dataReply->replytype[1] = HITAG_BYTE;
                                        dataReply->replyvalue[2] = worker->tag->pageData[1];
                                        dataReply->replytype[2] = HITAG_BYTE;
                                        dataReply->replyvalue[3] = worker->tag->pageData[2];
                                        dataReply->replytype[3] = HITAG_BYTE;
                                        dataReply->replyvalue[4] = worker->tag->pageData[3];
                                        dataReply->replytype[4] = HITAG_BYTE;

                                        dataReply->replylength = 5;

                                        dmaLen = hitag_worker_yield_dma_buffer_AC(
                                            dataReply, dataDMA, worker->carrierPrescaler);
                                    }
                                } else if(size == 45 && (bits[0] >> (32 - 5)) == 0b00000) { //SELECT
                                    //check if SN is matching
                                    uint32_t SN_cmd = bits[0] << 5 | bits[1] >> (32 - 5);
                                    uint32_t SN_tag = worker->tag->pageData[0] << 24 |
                                                      worker->tag->pageData[1] << 16 |
                                                      worker->tag->pageData[2] << 8 |
                                                      worker->tag->pageData[3];
                                    if(SN_cmd == SN_tag) {
                                        //reply with config (page 1 from tag memory)
                                        tagState = HitagStateSelected;

                                        //prepare emulate DMA buffer with basic/advanced config page reply (page 1)
                                        if(tagMode == HitagModeBasic) {
                                            dataReply->replyvalue[0] = 0b00000001;
                                            dataReply->replytype[0] = HITAG_STARTBIT;

                                            dataReply->replyvalue[1] =
                                                worker->tag->pageData[4 + 0];
                                            dataReply->replytype[1] = HITAG_BYTE;
                                            dataReply->replyvalue[2] =
                                                worker->tag->pageData[4 + 1];
                                            dataReply->replytype[2] = HITAG_BYTE;
                                            dataReply->replyvalue[3] =
                                                worker->tag->pageData[4 + 2];
                                            dataReply->replytype[3] = HITAG_BYTE;
                                            dataReply->replyvalue[4] =
                                                worker->tag->pageData[4 + 3];
                                            dataReply->replytype[4] = HITAG_BYTE;

                                            dataReply->replylength = 5;
                                        } else if(tagMode == HitagModeAdvanced) {
                                            dataReply->replyvalue[0] = 0b00111111;
                                            dataReply->replytype[0] = HITAG_STARTBIT6;

                                            dataReply->replyvalue[1] =
                                                worker->tag->pageData[4 + 0];
                                            dataReply->replytype[1] = HITAG_BYTE;
                                            dataReply->replyvalue[2] =
                                                worker->tag->pageData[4 + 1];
                                            dataReply->replytype[2] = HITAG_BYTE;
                                            dataReply->replyvalue[3] =
                                                worker->tag->pageData[4 + 2];
                                            dataReply->replytype[3] = HITAG_BYTE;
                                            dataReply->replyvalue[4] =
                                                worker->tag->pageData[4 + 3];
                                            dataReply->replytype[4] = HITAG_BYTE;

                                            uint8_t crc = CRC_PRESET;
                                            hitag_worker_calc_crc(
                                                &crc, dataReply->replyvalue[1], 8);
                                            hitag_worker_calc_crc(
                                                &crc, dataReply->replyvalue[2], 8);
                                            hitag_worker_calc_crc(
                                                &crc, dataReply->replyvalue[3], 8);
                                            hitag_worker_calc_crc(
                                                &crc, dataReply->replyvalue[4], 8);

                                            dataReply->replyvalue[5] = crc;
                                            dataReply->replytype[5] = HITAG_CRC;

                                            dataReply->replylength = 6;
                                        }

                                        dmaLen = hitag_worker_yield_dma_buffer_MC(
                                            dataReply, dataDMA, worker->carrierPrescaler);
                                    }
                                } else if(size == 20 && (bits[0] >> (31))) { //R/W
                                    if(tagState == HitagStateSelected) {
                                        //reply with requested pages in case of read public (ignore secret block/pages & ignore write cmd)
                                        uint8_t rwCmd = bits[0] >> (32 - 4);
                                        uint8_t addr = bits[0] >> 20 & 0xff;
                                        uint8_t pages = 0;
                                        switch(rwCmd) {
                                        case(0b1100):
                                            //read public page. Bound addr first: a garbage or
                                            //hostile reader frame can carry addr 64..255, past
                                            //the 64-entry (HITAG_PAGES) tag arrays -> guard
                                            //before indexing, like the Hitag S path does.
                                            if(addr < HITAG_PAGES &&
                                               worker->tag->pageKnown[addr] &&
                                               worker->tag->pagePublic[addr]) {
                                                pages = 1;
                                            }
                                            break;
                                        case(0b1101):
                                            //read public block. Same bound: reject an
                                            //out-of-range base addr, and never let the block
                                            //span past the last page (HITAG_PAGES).
                                            if(addr >= HITAG_PAGES) break;
                                            pages = (64 - addr) % 4;
                                            if(pages == 0) {
                                                pages = 4;
                                            }
                                            if(addr + pages > HITAG_PAGES) {
                                                pages = 0;
                                                break;
                                            }
                                            for(uint8_t p = addr; p < addr + pages; p++) {
                                                if(!worker->tag->pageKnown[p] ||
                                                   !worker->tag->pagePublic[p]) {
                                                    pages = 0;
                                                    break;
                                                }
                                            }
                                            break;
                                        }
                                        if(pages > 0) {
                                            //pages
                                            for(uint8_t i = 0; i < pages; i++) {
                                                dataReply->replyvalue[1 + i * 4 + 0] =
                                                    worker->tag->pageData[(addr + i) * 4 + 0];
                                                dataReply->replytype[1 + i * 4 + 0] = HITAG_BYTE;
                                                dataReply->replyvalue[1 + i * 4 + 1] =
                                                    worker->tag->pageData[(addr + i) * 4 + 1];
                                                dataReply->replytype[1 + i * 4 + 1] = HITAG_BYTE;
                                                dataReply->replyvalue[1 + i * 4 + 2] =
                                                    worker->tag->pageData[(addr + i) * 4 + 2];
                                                dataReply->replytype[1 + i * 4 + 2] = HITAG_BYTE;
                                                dataReply->replyvalue[1 + i * 4 + 3] =
                                                    worker->tag->pageData[(addr + i) * 4 + 3];
                                                dataReply->replytype[1 + i * 4 + 3] = HITAG_BYTE;
                                            }
                                            //startsequence & CRC
                                            if(tagMode == HitagModeBasic) {
                                                dataReply->replyvalue[0] = 0b00000001;
                                                dataReply->replytype[0] = HITAG_STARTBIT;

                                                dataReply->replylength = 1 + pages * 4;
                                            } else if(tagMode == HitagModeAdvanced) {
                                                dataReply->replyvalue[0] = 0b00111111;
                                                dataReply->replytype[0] = HITAG_STARTBIT6;

                                                uint8_t crc = CRC_PRESET;

                                                for(uint8_t i = 0; i < pages; i++) {
                                                    hitag_worker_calc_crc(
                                                        &crc,
                                                        dataReply->replyvalue[1 + i * 4 + 0],
                                                        8);
                                                    hitag_worker_calc_crc(
                                                        &crc,
                                                        dataReply->replyvalue[1 + i * 4 + 1],
                                                        8);
                                                    hitag_worker_calc_crc(
                                                        &crc,
                                                        dataReply->replyvalue[1 + i * 4 + 2],
                                                        8);
                                                    hitag_worker_calc_crc(
                                                        &crc,
                                                        dataReply->replyvalue[1 + i * 4 + 3],
                                                        8);
                                                }

                                                dataReply->replyvalue[1 + pages * 4] = crc;
                                                dataReply->replytype[1 + pages * 4] = HITAG_CRC;

                                                dataReply->replylength = 2 + pages * 4;
                                            }

                                            dmaLen = hitag_worker_yield_dma_buffer_MC(
                                                dataReply, dataDMA, worker->carrierPrescaler);
                                        }
                                    }
                                } else if(size == 20 && (bits[0] >> (32 - 4)) == 0b0111) { //HALT
                                    //TODO validate if dummy address is a valid one (one of the default public pages (32-63))

                                    //acknowledge & go silent untill next reset
                                    if(tagState == HitagStateSelected) {
                                        tagState = HitagStateQuiet;

                                        if(tagMode == HitagModeBasic) {
                                            dataReply->replyvalue[0] = 0b00000101;
                                            dataReply->replytype[0] = HITAG_ACK;
                                        } else if(tagMode == HitagModeAdvanced) {
                                            dataReply->replyvalue[0] = 0b11111101;
                                            dataReply->replytype[0] = HITAG_ACK_ADV;
                                        }

                                        dataReply->replylength = 1;

                                        dmaLen = hitag_worker_yield_dma_buffer_MC(
                                            dataReply, dataDMA, worker->carrierPrescaler);
                                    }
                                }

                                if(dmaLen > 0) { //switch to reply mode
                                    //switch carrier mode to ETR required for replying
                                    furi_hal_rfid_rtf_carrier_in_ETR_mode(prescaler);

                                    //respect the tag response delay before modulating.
                                    if(worker->emulate_hitag2 || worker->emulate_hitagS ||
                                       worker->emulate_hitag2_crypto) {
                                        //O2 — HARDWARE-TIMED T_wresp. The old software poll loop
                                        //could be preempted by the scheduler, firing ~9% of replies
                                        //up to ~350us LATE, out of the 204..212 Tc window a strict
                                        //reader (a strict reader) samples -> capricious acceptance.
                                        //Instead PREPEND an inactive DMA cell (CCR3=0 -> no
                                        //load-mod) of the REMAINING wait; the pull_out timer then
                                        //counts T_wresp in HARDWARE, immune to preemption ->
                                        //deterministic landing. FAP-only: pull_out_dma_start already
                                        //pre-arms buffer[0], so buffer[0]=the wait cell just works.
                                        //Measure elapsed as late as possible so wait_ticks lands
                                        //the reply at cmd_end + T_wresp. ETR tick = 1 carrier
                                        //period = 8us. (No critical section: the hardware timer
                                        //already makes the wait itself preemption-proof; masking
                                        //IRQs around the DMA start was only a few-us refinement and
                                        //a needless risk.)
                                        uint32_t elapsed =
                                            furi_hal_rfid_rtf_carrier_in_edge_us() - cmd_end_us;
                                        uint32_t wait_us = (elapsed < worker->emu_wresp_us) ?
                                                               (worker->emu_wresp_us - elapsed) :
                                                               16; //already late -> fire ASAP
                                        uint32_t wait_ticks = wait_us / 8;
                                        if(wait_ticks < 2) wait_ticks = 2;
                                        memmove(
                                            &dataDMA->timer_buffer_arr[1],
                                            &dataDMA->timer_buffer_arr[0],
                                            dmaLen * sizeof(dataDMA->timer_buffer_arr[0]));
                                        memmove(
                                            &dataDMA->timer_buffer_ccr[1],
                                            &dataDMA->timer_buffer_ccr[0],
                                            dmaLen * sizeof(dataDMA->timer_buffer_ccr[0]));
                                        dataDMA->timer_buffer_arr[0] = wait_ticks - 1;
                                        dataDMA->timer_buffer_ccr[0] = 0; //inactive during the wait
                                        furi_hal_rfid_rtf_pull_out_dma_start((size_t)(dmaLen + 1));
                                        FURI_LOG_D(TAG, "hwwait=%lu", (unsigned long)wait_us);
                                    } else {
                                        //Hitag1: keep the PR's edge-count based delay, then fire.
                                        uint32_t wait1_periods = 180 / prescaler;
                                        while(capData->capCounter - cmdIndex < wait1_periods) {
                                            furi_delay_us(40);
                                        }
                                        furi_hal_rfid_rtf_pull_out_dma_start((size_t)dmaLen);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            //reset buffer
            buffer_reset(buffer);
        }

        if(buffer_stream_get_overrun_count(capData->stream) > 0) {
            FURI_LOG_E(TAG, "Read overrun, recovering");
            buffer_stream_reset(capData->stream);
            //dropped entries desync our us mirror from the HAL's; re-anchor to the HAL clock
            //so reply timing stays valid for subsequent commands (this one's timing is lost).
            accum_us = furi_hal_rfid_rtf_carrier_in_edge_us();
        }

        uint32_t flags = furi_event_flag_get(worker->events);
        if(FURI_BIT(flags, HitagWorkerSignalStop)) {
            break;
        }
    }

    //stop carrier capture in
    furi_hal_rfid_rtf_carrier_in_stop();

    free(dataDMA);
    free(dataReply);
    varint_pair_free(capData->pair);
    buffer_stream_free(capData->stream);
    free(capData);

    //clear the stop flag on workder so that i can use the worker to launch a new read routine without having to restart the app
    furi_event_flag_clear(worker->events, 1 << HitagWorkerSignalStop);

    return 0;
}

