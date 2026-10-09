// Hitag S (125 kHz LF, incl. 8268/8310) reader + tag support, split out of the
// shared worker -- the per-protocol file that previously did not exist.
//
// Contents: the Hitag S plain-mode reader read-thread (UID_REQ -> SELECT, Flipper-
// as-reader), the Hitag S reader-frame validator (adds the UID_REQ opcodes, the
// CRC-checked WRITE-data frame and the crypto challenge) and the config-page
// write-permission (lock-bit) check. The full Hitag S emulate tag -- all four
// reader modes, WRITE, locks, 82xx and crypto -- is built in the shared emulate
// thread (hitag_worker.c); this file holds the reader side plus the helpers that
// thread dispatches to. Constants/types come from hitag_worker_i.h.

#include "hitag_worker_i.h"

// Recognise reader commands for Hitag S emulation. SELECT (45b) and READ (20b) share the
// Hitag1 framing + CRC8, so reuse that validator; only the 5-bit UID request differs — a
// Hitag S reader may use any of the STD/ADV opcodes (00110/11000/11001/11010), wider than the
// two the Hitag1 validator accepts. Left-align the command into bits[0] like the others.
bool hitags_worker_validate_bits(uint32_t* bits, uint8_t bitcounter) {
    if(66 >= bitcounter && bitcounter >= 62) {
        // Crypto/auth challenge (32-bit rnd + 32-bit authenticator, no CRC). Accept by length;
        // the reader only checks the response length for auth success (per hitagS.c hts_read).
        return true;
    } else if(42 >= bitcounter && bitcounter >= 39) {
        // WRITE-DATA frame: 32 data bits + 8-bit CRC8 (the reader's second write phase). Accept
        // only if the CRC matches (rejects a mis-decode so we never store garbage into a page).
        uint8_t crc = CRC_PRESET;
        hitag_worker_calc_crc(&crc, (bits[0] >> 24) & 0xff, 8);
        hitag_worker_calc_crc(&crc, (bits[0] >> 16) & 0xff, 8);
        hitag_worker_calc_crc(&crc, (bits[0] >> 8) & 0xff, 8);
        hitag_worker_calc_crc(&crc, bits[0] & 0xff, 8);
        return (((bits[1] >> 24) & 0xff) == crc);
    } else if(47 >= bitcounter && bitcounter >= 45) {
        for(uint8_t i = 0; i < bitcounter - 44; i++) {
            if(i > 0) {
                bits[0] = bits[0] << 1 | bits[1] >> (32 - 1);
                bits[1] = bits[1] << 1;
            }
            if(hitag_worker_validate_command(bits, 45)) return true;
        }
    } else if(22 >= bitcounter && bitcounter >= 20) {
        for(uint8_t i = 0; i < bitcounter - 19; i++) {
            if(i > 0) bits[0] = bits[0] << 1;
            if(hitag_worker_validate_command(bits, 20)) return true;
        }
    } else if(7 >= bitcounter && bitcounter >= 5) {
        for(uint8_t i = 0; i < bitcounter - 4; i++) {
            if(i > 0) bits[0] = bits[0] << 1;
            if(hitag_classify_frame_s(5, bits[0], NULL) == HitagSFrameUidReq) return true;
        }
    }
    return false;
}

// Hitag S write-permission check from the emulated config page (page 1). Bit layout per
// include/hitag.h hitags_config_t (LSB-first): con1 = pageData[5] -> LKP bit0 (pages 2/3),
// LCON bit1 (config page 1); con2 = pageData[6] -> LCK0 bit0 (pages 48-63) .. LCK7 bit7
// (pages 4/5). Returns false when the target page is locked read-only, so the emulate WRITE
// handler withholds the ACK exactly like a real locked tag.
bool hitags_page_writable(const uint8_t* pageData, uint8_t page) {
    uint8_t con1 = pageData[1 * 4 + 1];
    uint8_t con2 = pageData[1 * 4 + 2];
    if(page == 1 && (con1 & 0x02)) return false; // LCON: config read-only
    if((page == 2 || page == 3) && (con1 & 0x01)) return false; // LKP: key pages read-only
    if((con2 & 0x80) && page >= 4 && page <= 5) return false; // LCK7
    if((con2 & 0x40) && page >= 6 && page <= 7) return false; // LCK6
    if((con2 & 0x20) && page >= 8 && page <= 11) return false; // LCK5
    if((con2 & 0x10) && page >= 12 && page <= 15) return false; // LCK4
    if((con2 & 0x08) && page >= 16 && page <= 23) return false; // LCK3
    if((con2 & 0x04) && page >= 24 && page <= 31) return false; // LCK2
    if((con2 & 0x02) && page >= 32 && page <= 47) return false; // LCK1
    if((con2 & 0x01) && page >= 48 && page <= 63) return false; // LCK0
    return true;
}


// Hitag S plain-mode read FSM (self-contained; reuses the shared BPLM encoder + decoder + the
// proven Hitag1 SELECT/CRC idiom read-only, touches neither the Hitag2 nor the Hitag1 thread):
//   state 0 UID_REQ  -> send UID_REQ_ADV2 (11000), decode the Manchester UID reply -> page 0.
//   state 1 SELECT   -> send SELECT(00000 + UID + CRC8), decode the config/page-1 reply -> page 1.
// Both hops share the same Manchester framing and CRC-8 (poly 0x1D/init 0xFF) as Hitag1, so the
// SELECT machinery is reused rather than reinvented. Milestone 1 (UID) proved the TX/RX chain on
// hardware (Sig up to 4/37 vs PM3 `hts sim`); the SELECT hop is code-complete and awaits a stable
// reader->tag coupling to validate end to end. startBits are tuned on-device. Heavy logging so
// the PM3 `hts sim` decode can be observed.
int32_t hitags_worker_read_thread(void* thread_context) {
    HitagWorker* worker = (HitagWorker*)thread_context;
    hitag_worker_initialize_tag_data(worker->tag);
    worker->read_best_bits = 0;

    HitagProtocol currentProtocol = HitagProtocolManchesterCoding;
    // Use UID_REQ_ADV2 (11000) — the "Hitag2 START_AUTH compatible" mode — so the tag replies
    // in a framing the Hitag2-tuned Manchester decoder can lock onto. ADV MC reply = 6 SOF bits
    // (STD=1 gave Sig 2, startBits 5 gave Sig 4). Tuned on-device.
    uint8_t startBits = 5;
    uint32_t memBlock[HITAG_BLOCKPAGES] = {0};
    uint8_t bits = 0;
    bool halfBit = false;
    bool finished = false;

    uint32_t uid_cand = 0;
    uint8_t uid_cnt = 0;
    bool uid_known = false;

    // FSM: 0 = UID_REQ (discover UID via MC reply), 1 = SELECT (read the config/page-1 reply).
    // After the UID, Hitag S plain mode uses the same SELECT(00000+UID+CRC8) and Manchester
    // reply framing as Hitag1 (see the Hitag1 read thread), so we reuse the proven calc_crc +
    // command idiom rather than a separate protocol. Kept strictly inside this thread.
    uint8_t htsState = 0;
    uint32_t cfg_cand = 0;
    uint8_t cfg_cnt = 0;
    bool cfg_known = false;

    // pins (identical to the Hitag2 read thread)
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

    HitagCMDData* dataCMD = malloc(sizeof(HitagCMDData));
    furi_check(dataCMD);
    dataCMD->CMDlength = 0;
    dataCMD->CMDposition = 0;
    dataCMD->CMDsubposition = 0;
    dataCMD->CMDactive = false;

    // Scripted loop: settle + UID_REQ_STD (5b 00110) + STOP + reply window + inter-loop idle.
    HitagCMDData* backupCMD = malloc(sizeof(HitagCMDData));
    furi_check(backupCMD);
    {
        const uint32_t readwin = 2000;
        uint16_t n = 0;
        backupCMD->CMDvalue[n] = 128;
        backupCMD->CMDtype[n++] = HITAG_ON;
        backupCMD->CMDvalue[n] = 0x18; // UID_REQ_ADV2 opcode 11000 in the low 5 bits
        backupCMD->CMDtype[n++] = HITAG_SET; // HITAG_SET == 5 bits
        backupCMD->CMDvalue[n] = 1;
        backupCMD->CMDtype[n++] = HITAG_STOP;
        backupCMD->CMDvalue[n] = readwin;
        backupCMD->CMDtype[n++] = HITAG_ON;
        backupCMD->CMDvalue[n] = 6000; // inter-loop idle (drop the tag session between loops)
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
            while(index < buffsize) {
                uint32_t duration, pulse;
                size_t tmp_size;
                if(!varint_pair_unpack(
                       &buffdata[index], buffsize - index, &pulse, &duration, &tmp_size)) {
                    break;
                }
                index += tmp_size;
                hitag_worker_decoder_feed(
                    pulse, duration, memBlock, &bits, &halfBit, &finished, currentProtocol, startBits);
                if(finished) {
                    if(bits > worker->read_best_bits) worker->read_best_bits = bits;
                    if(bits > 0)
                        FURI_LOG_D(TAG, "hts rx b=%u v=%08lX", bits, (unsigned long)memBlock[0]);
                    if(htsState == 0 && bits >= 32 && !uid_known) {
                        uint32_t val = memBlock[0];
                        if(val == uid_cand) {
                            uid_cnt++;
                        } else {
                            uid_cand = val;
                            uid_cnt = 1;
                        }
                        if(uid_cnt >= 2 && val != 0) {
                            uid_known = true;
                            dolphin_deed(DolphinDeedRfidReadSuccess);
                            worker->workerstatus = HitagStatusDetected;
                            hitag_store_page(worker->tag->pageData, 0, val);
                            worker->tag->pageKnown[0] = 1;
                            hitag_worker_combine_tag_data(worker->tag);
                            FURI_LOG_D(TAG, "hts UID = %08lX", (unsigned long)val);

                            // Transition to SELECT: rewrite the looping command script to
                            // SELECT(00000 + UID + CRC8) and read back the config/page-1 reply
                            // (33-bit Manchester). Same framing/CRC as the Hitag1 SELECT path.
                            uint8_t sn0 = val >> 24 & 0xff, sn1 = val >> 16 & 0xff,
                                    sn2 = val >> 8 & 0xff, sn3 = val & 0xff;
                            uint8_t selcrc = CRC_PRESET;
                            hitag_worker_calc_crc(&selcrc, (0b00000 << (8 - 5)), 5);
                            hitag_worker_calc_crc(&selcrc, sn0, 8);
                            hitag_worker_calc_crc(&selcrc, sn1, 8);
                            hitag_worker_calc_crc(&selcrc, sn2, 8);
                            hitag_worker_calc_crc(&selcrc, sn3, 8);
                            uint16_t m = 0;
                            backupCMD->CMDvalue[m] = 128;
                            backupCMD->CMDtype[m++] = HITAG_ON; // settle
                            backupCMD->CMDvalue[m] = 0b00000;
                            backupCMD->CMDtype[m++] = HITAG_SELECT; // SELECT opcode (5 bits)
                            backupCMD->CMDvalue[m] = sn0;
                            backupCMD->CMDtype[m++] = HITAG_BYTE;
                            backupCMD->CMDvalue[m] = sn1;
                            backupCMD->CMDtype[m++] = HITAG_BYTE;
                            backupCMD->CMDvalue[m] = sn2;
                            backupCMD->CMDtype[m++] = HITAG_BYTE;
                            backupCMD->CMDvalue[m] = sn3;
                            backupCMD->CMDtype[m++] = HITAG_BYTE;
                            backupCMD->CMDvalue[m] = selcrc;
                            backupCMD->CMDtype[m++] = HITAG_CRC;
                            backupCMD->CMDvalue[m] = 1;
                            backupCMD->CMDtype[m++] = HITAG_STOP;
                            backupCMD->CMDvalue[m] =
                                (uint32_t)(1.05 * 33 * HITAG_BITPERIODS_MC); // reply window
                            backupCMD->CMDtype[m++] = HITAG_ON;
                            backupCMD->CMDvalue[m] = 6000; // inter-loop idle
                            backupCMD->CMDtype[m++] = HITAG_ON;
                            backupCMD->CMDlength = m;
                            backupCMD->CMDposition = 0;
                            backupCMD->CMDsubposition = 0;
                            htsState = 1;
                        }
                    } else if(htsState == 1 && bits >= 33 && !cfg_known) {
                        // SELECT reply = config / page 1 (32 data bits in memBlock[0]).
                        uint32_t cval = memBlock[0];
                        if(cval == cfg_cand) {
                            cfg_cnt++;
                        } else {
                            cfg_cand = cval;
                            cfg_cnt = 1;
                        }
                        if(cfg_cnt >= 2) {
                            cfg_known = true;
                            hitag_store_page(worker->tag->pageData, 1, cval);
                            worker->tag->pageKnown[1] = 1;
                            hitag_worker_combine_tag_data(worker->tag);
                            worker->workerstatus = HitagStatusRead;
                            FURI_LOG_D(TAG, "hts CFG(pg1) = %08lX", (unsigned long)cval);
                            // TODO (HITAG_ROADMAP.md T2.1, DEFERRED): add htsState 2 here = loop
                            // READ(1100 + page + CRC8) over pages 2..N (mirror the SELECT command
                            // build above), decoding each reply into pageData[page]. Held until a
                            // real Hitag S tag / better coupling can validate the full read — the
                            // Flipper-as-reader path does not couple on the PM3-sim bench.
                        }
                    }
                    memset(memBlock, 0, HITAG_BLOCKPAGES * sizeof(memBlock[0]));
                    bits = 0;
                    finished = false;
                }
            }
            buffer_reset(buffer);
        }
        if(buffer_stream_get_overrun_count(capData->stream) > 0) {
            buffer_stream_reset(capData->stream);
        }
        uint32_t flags = furi_event_flag_get(worker->events);
        if(FURI_BIT(flags, HitagWorkerSignalStop)) break;
        if(FURI_BIT(flags, HitagWorkerSignalHalfTransfer))
            hitag_worker_yield_dma_buffer_BPLM(dataCMD, backupCMD, dataDMA, 0, DMA_BUFFER_SIZE / 2);
        if(FURI_BIT(flags, HitagWorkerSignalTransferComplete))
            hitag_worker_yield_dma_buffer_BPLM(
                dataCMD, backupCMD, dataDMA, DMA_BUFFER_SIZE / 2, DMA_BUFFER_SIZE / 2);
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
    furi_event_flag_clear(worker->events, 1 << HitagWorkerSignalStop);
    return 0;
}
