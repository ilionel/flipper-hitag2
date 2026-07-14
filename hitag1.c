// Hitag1 (125 kHz LF) reader + tag support, split out of the shared worker.
//
// Contents: the Hitag1 reader read-thread (RTF anticollision, Flipper-as-reader)
// and the Hitag1 reader-frame validator used by the emulate dispatcher. The Hitag1
// emulate REPLY itself is built inside the shared emulate thread (hitag_worker.c),
// which also owns the BPLM encoder, the reply decoder and the DMA plumbing this
// file leans on via hitag_worker_i.h.
//
// Note: Hitag1 is untested end to end -- no Hitag1 tag was available during
// development (the read/emulate chain is wired but unproven on hardware).

#include "hitag_worker_i.h"

bool hitag1_worker_validate_bits(uint32_t* bits, uint8_t bitcounter) {
    if(47 >= bitcounter && bitcounter >= 45) {
        for(uint8_t i = 0; i < bitcounter - 44; i++) {
            if(i > 0) {
                bits[0] = bits[0] << 1 | bits[1] >> (32 - 1);
                bits[1] = bits[1] << 1;
            }
            if(hitag_worker_validate_command(bits, 45)) return true;
        }
    } else if(22 >= bitcounter && bitcounter >= 20) {
        for(uint8_t i = 0; i < bitcounter - 19; i++) {
            if(i > 0) {
                bits[0] = bits[0] << 1; // | bits[1]>>(32-1);
                //bits[1] = bits[1]<<1;
            }
            if(hitag_worker_validate_command(bits, 20)) return true;
        }
    } else if(7 >= bitcounter && bitcounter >= 5) {
        for(uint8_t i = 0; i < bitcounter - 4; i++) {
            if(i > 0) {
                bits[0] = bits[0] << 1; // | bits[1]>>(32-1);
                //bits[1] = bits[1]<<1;
            }
            if(hitag_worker_validate_command(bits, 5)) return true;
        }
    }
    return false;
}

int32_t hitag1_worker_read_thread(void* thread_context) {
    HitagWorker* worker = (HitagWorker*)thread_context;

    //reset the persistent tag for a fresh read
    hitag_worker_initialize_tag_data(worker->tag);

    //prep variables for decoder
    HitagProtocol currentProtocol = HitagProtocolAntiCollision;
    uint8_t startBits = 1;
    uint32_t memBlock[HITAG_BLOCKPAGES] = {0};
    uint8_t bits = 0;
    bool halfBit = false;
    bool finished = false;

    //prep variables for worker
    uint8_t expectedBits = 33;
    uint8_t readings = 0;
    uint8_t currPage = 0;
    bool readSucces = false;
    uint8_t readThreshold = 3;

    // setup pins for reading
    // ibutton low
    furi_hal_ibutton_pin_configure();
    furi_hal_ibutton_pin_write(false);
    // dont pull rfid antenna
    furi_hal_gpio_init(&gpio_nfc_irq_rfid_pull, GpioModeOutputPushPull, GpioPullNo, GpioSpeedLow);
    furi_hal_gpio_write(&gpio_nfc_irq_rfid_pull, false);
    // carrier pin to timer out
    furi_hal_gpio_init_ex(
        &gpio_rfid_carrier_out,
        GpioModeAltFunctionPushPull,
        GpioPullNo,
        GpioSpeedLow,
        GpioAltFn1TIM1);
    // comparator in
    furi_hal_gpio_init(&gpio_rfid_data_in, GpioModeAnalog, GpioPullNo, GpioSpeedLow);

    //and setup TIM1 CH1N with DMA
    //fill the DMA arr & ccr buffers
    /*start with looping SETCC command*/
    HitagCMDData* dataCMD = malloc(sizeof(HitagCMDData));
    furi_check(dataCMD);
    dataCMD->CMDlength = 0;
    dataCMD->CMDposition = 0;
    dataCMD->CMDsubposition = 0;
    dataCMD->CMDactive = false;

    HitagCMDData* backupCMD = malloc(sizeof(HitagCMDData));
    furi_check(backupCMD);
    uint32_t value[] = {
        128,
        0b00110,
        1,
        213,
        (uint32_t)(1.05 * 33 * HITAG_BITPERIODS_AC)}; //always take 5% reading time buffer
    uint8_t type[] = {HITAG_ON, HITAG_SET, HITAG_STOP, HITAG_ON, HITAG_ON};
    for(size_t i = 0; i < 5; i++) {
        backupCMD->CMDvalue[i] = value[i];
        backupCMD->CMDtype[i] = type[i];
    }
    backupCMD->CMDlength = 5;
    backupCMD->CMDposition = 0;
    backupCMD->CMDsubposition = 0;
    backupCMD->CMDloop =
        true; //not really required since by definition the backup cmd is looping already in yield code
    backupCMD->CMDactive = true;

    TimerDMAData* dataDMA = malloc(sizeof(TimerDMAData));
    furi_check(dataDMA);
    hitag_worker_yield_dma_buffer_BPLM(dataCMD, backupCMD, dataDMA, 0, DMA_BUFFER_SIZE / 2);
    hitag_worker_yield_dma_buffer_BPLM(
        dataCMD, backupCMD, dataDMA, DMA_BUFFER_SIZE / 2, DMA_BUFFER_SIZE / 2);

    //start TIM1 with DMA function
    furi_hal_rfid_rtf_carrier_out_start(
        dataDMA->timer_buffer_arr,
        dataDMA->timer_buffer_ccr,
        DMA_BUFFER_SIZE,
        hitag_worker_carrier_out_dma_callback,
        worker);

    // start capture
    HitagCaptureData* capData = malloc(sizeof(HitagCaptureData));
    furi_check(capData);
    capData->stream = buffer_stream_alloc(READ_BUFFER_SIZE, READ_BUFFER_COUNT);
    capData->pair = varint_pair_alloc();
    furi_hal_rfid_tim_read_capture_start(hitag_worker_capture_in_cc_callback, capData);

    while(1) {
        Buffer* buffer = buffer_stream_receive(capData->stream, 1);

        //process data if available
        if(buffer != NULL) {
            size_t buffsize = buffer_get_size(buffer);
            uint8_t* buffdata = buffer_get_data(buffer);

            //if scanning for tagdata, then also parse buffer data
            size_t index = 0;
            while(expectedBits > 0 && index < buffsize) {
                uint32_t duration;
                uint32_t pulse;
                size_t tmp_size;

                if(!varint_pair_unpack(
                       &buffdata[index], buffsize - index, &pulse, &duration, &tmp_size)) {
                    FURI_LOG_E(TAG, "can't unpack varint pair");
                    break;
                } else {
                    index += tmp_size;

                    //feed pulse duration to decoder
                    hitag_worker_decoder_feed(
                        pulse,
                        duration,
                        memBlock,
                        &bits,
                        &halfBit,
                        &finished,
                        currentProtocol,
                        startBits);

                    //see if i have a valid bit sequence
                    if(finished) {
                        //bitsequence ready for validation
                        if(bits ==
                           expectedBits) { //eligable bitsequence detected, accept it only after x consequtive readings
                            //reset the backupCMD count to ensure some pause between bitsequence detection & the CMD injection
                            backupCMD->CMDcount = 0;

                            if(readings == 0) {
                                for(uint8_t p = 0; p < (expectedBits - 1) / 32; p++) {
                                    worker->tag->pageData[(currPage + p) * 4 + 0] =
                                        memBlock[p] >> 24 & 0xff;
                                    worker->tag->pageData[(currPage + p) * 4 + 1] =
                                        memBlock[p] >> 16 & 0xff;
                                    worker->tag->pageData[(currPage + p) * 4 + 2] =
                                        memBlock[p] >> 8 & 0xff;
                                    worker->tag->pageData[(currPage + p) * 4 + 3] = memBlock[p] &
                                                                                    0xff;
                                    worker->tag->pageKnown[currPage + p] = 0;
                                }
                                readings = 1;
                            } else if(readings < readThreshold) {
                                bool match = true;
                                for(uint8_t p = 0; p < (expectedBits - 1) / 32; p++) {
                                    if(worker->tag->pageData[(currPage + p) * 4 + 0] !=
                                           (memBlock[p] >> 24 & 0xff) ||
                                       worker->tag->pageData[(currPage + p) * 4 + 1] !=
                                           (memBlock[p] >> 16 & 0xff) ||
                                       worker->tag->pageData[(currPage + p) * 4 + 2] !=
                                           (memBlock[p] >> 8 & 0xff) ||
                                       worker->tag->pageData[(currPage + p) * 4 + 3] !=
                                           (memBlock[p] & 0xff)) {
                                        match = false;
                                        break;
                                    }
                                }
                                if(match) {
                                    readings++;
                                    if(readings == readThreshold) {
                                        //succesful page(s) reading
                                        readSucces = true;

                                        for(uint8_t p = 0; p < (expectedBits - 1) / 32; p++) {
                                            worker->tag->pageKnown[currPage + p] = 1;
                                        }

                                        readings = 0;
                                        expectedBits = 0; //to prevent further updates to tag data
                                    }
                                } else {
                                    for(uint8_t p = 0; p < (expectedBits - 1) / 32; p++) {
                                        worker->tag->pageData[(currPage + p) * 4 + 0] =
                                            memBlock[p] >> 24 & 0xff;
                                        worker->tag->pageData[(currPage + p) * 4 + 1] =
                                            memBlock[p] >> 16 & 0xff;
                                        worker->tag->pageData[(currPage + p) * 4 + 2] =
                                            memBlock[p] >> 8 & 0xff;
                                        worker->tag->pageData[(currPage + p) * 4 + 3] =
                                            memBlock[p] & 0xff;
                                        worker->tag->pageKnown[currPage + p] = 0;
                                    }
                                    readings = 1;
                                }
                            }
                        }
                        //reset tempdata for next bitsequence readout
                        memset(memBlock, 0, HITAG_BLOCKPAGES * sizeof(memBlock[0]));
                        bits = 0;
                        finished = false;
                    }
                }
            }

            //reset buffer
            buffer_reset(buffer);
        }

        //if bitsequence found & after pause, prep & launch the command for reading out next bit of data
        if(readSucces && backupCMD->CMDcount >= 7) {
            readSucces = false;
            backupCMD->CMDcount =
                0; //required since otherwise the 'relaunch' of cmd is triggered straightaway

            //update tag data
            hitag_worker_combine_tag_data(worker->tag);

            if(currPage == 0) { //read config page next via SELECT cmd
                FURI_LOG_D(
                    TAG,
                    "Hitag1, [%02X %02X %02X %02X] found",
                    worker->tag->pageData[0],
                    worker->tag->pageData[1],
                    worker->tag->pageData[2],
                    worker->tag->pageData[3]);
                dolphin_deed(DolphinDeedRfidReadSuccess);
                worker->workerstatus = HitagStatusDetected;

                currentProtocol = HitagProtocolManchesterCoding;
                expectedBits = 33;
                currPage = 1;
            } else if(currPage == 1) { //process config page and start reading public blocks
                hitag_worker_process_config_page(worker->tag);
                FURI_LOG_D(
                    TAG,
                    "Hitag1, [%02X %02X %02X %02X] config page read",
                    worker->tag->pageData[0],
                    worker->tag->pageData[1],
                    worker->tag->pageData[2],
                    worker->tag->pageData[3]);
                //find next public readible block
                for(currPage = 4; currPage <= HITAG_PAGES - 4; currPage += 4) {
                    if(worker->tag->pagePublic[currPage] &&
                       (worker->tag->pageRW[currPage] & READ)) { //public readible page/block found
                        expectedBits = 129;
                        break;
                    } else {
                        FURI_LOG_D(
                            TAG,
                            "Hitag1, [%02X %02X %02X %02X] block %u not public/readible",
                            worker->tag->pageData[0],
                            worker->tag->pageData[1],
                            worker->tag->pageData[2],
                            worker->tag->pageData[3],
                            currPage / 4);
                    }
                }
            } else if(currPage < HITAG_PAGES - 4) { //scan for next public readible page
                FURI_LOG_D(
                    TAG,
                    "Hitag1, [%02X %02X %02X %02X] block %u read",
                    worker->tag->pageData[0],
                    worker->tag->pageData[1],
                    worker->tag->pageData[2],
                    worker->tag->pageData[3],
                    currPage / 4);
                for(currPage += 4; currPage <= HITAG_PAGES - 4; currPage += 4) {
                    if(worker->tag->pagePublic[currPage] &&
                       (worker->tag->pageRW[currPage] & READ)) { //public readible page/block found
                        expectedBits = 129;
                        break;
                    } else {
                        FURI_LOG_D(
                            TAG,
                            "Hitag1, [%02X %02X %02X %02X] block %u not public/readible",
                            worker->tag->pageData[0],
                            worker->tag->pageData[1],
                            worker->tag->pageData[2],
                            worker->tag->pageData[3],
                            currPage / 4);
                    }
                }
            } else if(
                currPage ==
                HITAG_PAGES -
                    4) { //all public readible pages read: signal view & break out of while loop (stops the worker)
                FURI_LOG_D(
                    TAG,
                    "Hitag1, [%02X %02X %02X %02X] block %u read",
                    worker->tag->pageData[0],
                    worker->tag->pageData[1],
                    worker->tag->pageData[2],
                    worker->tag->pageData[3],
                    currPage / 4);

                worker->workerstatus = HitagStatusRead;
                break;
            }

            if(expectedBits > 0) { //inject CMD
                //prep SELECT cmd bytes
                uint8_t SN0 = worker->tag->pageData[0];
                uint8_t SN1 = worker->tag->pageData[1];
                uint8_t SN2 = worker->tag->pageData[2];
                uint8_t SN3 = worker->tag->pageData[3];
                uint8_t crc = CRC_PRESET;
                hitag_worker_calc_crc(&crc, (0b00000 << (8 - 5)), 5);
                hitag_worker_calc_crc(&crc, SN0, 8);
                hitag_worker_calc_crc(&crc, SN1, 8);
                hitag_worker_calc_crc(&crc, SN2, 8);
                hitag_worker_calc_crc(&crc, SN3, 8);

                //prep SELECT cmd array
                uint32_t value[] = {
                    128,
                    0b00000,
                    SN0,
                    SN1,
                    SN2,
                    SN3,
                    crc,
                    1,
                    213,
                    (uint32_t)(1.05 * 33 *
                               HITAG_BITPERIODS_MC)}; //always take 5% reading time buffer
                uint8_t type[] = {
                    HITAG_ON,
                    HITAG_SELECT,
                    HITAG_BYTE,
                    HITAG_BYTE,
                    HITAG_BYTE,
                    HITAG_BYTE,
                    HITAG_CRC,
                    HITAG_STOP,
                    HITAG_ON,
                    HITAG_ON};
                uint16_t len = 10;
                uint16_t cnt = 1;
                for(size_t i = 0; i < cnt * len; i++) {
                    dataCMD->CMDvalue[i] = value[i % len];
                    dataCMD->CMDtype[i] = type[i % len];
                }
                dataCMD->CMDlength = cnt * len;
                dataCMD->CMDposition = 0;
                dataCMD->CMDsubposition = 0;
                dataCMD->CMDloop = false;

                if(currPage < 4 * 4) { //add READPAGE cmd to array
                    crc = CRC_PRESET;
                    hitag_worker_calc_crc(&crc, (0b1100 << (8 - 4)), 4);
                    hitag_worker_calc_crc(&crc, currPage, 8);
                    uint32_t value2[] = {
                        128,
                        0b1100,
                        currPage,
                        crc,
                        1,
                        213,
                        (uint32_t)(1.05 * 33 *
                                   HITAG_BITPERIODS_MC)}; //always take 5% reading time buffer
                    uint8_t type2[] = {
                        HITAG_ON, HITAG_CMD, HITAG_BYTE, HITAG_CRC, HITAG_STOP, HITAG_ON, HITAG_ON};
                    uint16_t len2 = 7;
                    uint16_t cnt2 = 5;
                    for(size_t i = 0; i < cnt2 * len2; i++) {
                        dataCMD->CMDvalue[cnt * len + i] = value2[i % len2];
                        dataCMD->CMDtype[cnt * len + i] = type2[i % len2];
                    }
                    dataCMD->CMDlength += cnt2 * len2;
                } else { //add READBLOCK cmd to array
                    crc = CRC_PRESET;
                    hitag_worker_calc_crc(&crc, (0b1101 << (8 - 4)), 4);
                    hitag_worker_calc_crc(&crc, currPage, 8);
                    uint32_t value2[] = {
                        128,
                        0b1101,
                        currPage,
                        crc,
                        1,
                        213,
                        (uint32_t)(1.05 * 129 *
                                   HITAG_BITPERIODS_MC)}; //always take 5% reading time buffer
                    uint8_t type2[] = {
                        HITAG_ON, HITAG_CMD, HITAG_BYTE, HITAG_CRC, HITAG_STOP, HITAG_ON, HITAG_ON};
                    uint16_t len2 = 7;
                    uint16_t cnt2 = 5;
                    for(size_t i = 0; i < cnt2 * len2; i++) {
                        dataCMD->CMDvalue[cnt * len + i] = value2[i % len2];
                        dataCMD->CMDtype[cnt * len + i] = type2[i % len2];
                    }
                    dataCMD->CMDlength += cnt2 * len2;
                }
            }
        }

        //while not having x consequtive reads, relaunch the (already prepared) command
        if(!readSucces && backupCMD->CMDcount >= 7 && currPage > 0 && expectedBits > 0) {
            backupCMD->CMDcount = 0;
            dataCMD->CMDposition = 0;
            dataCMD->CMDsubposition = 0;
        }

        if(buffer_stream_get_overrun_count(capData->stream) > 0) {
            FURI_LOG_E(TAG, "Read overrun, recovering");
            buffer_stream_reset(capData->stream);
        }

        //check for stop events
        uint32_t flags = furi_event_flag_get(worker->events);
        if(FURI_BIT(flags, HitagWorkerSignalStop)) {
            break;
        }

        //check for DMA HT/TC signals to repopulate the DMA buffer
        if(worker->DMAeventCount > 1) {
            FURI_LOG_E(TAG, "DMA refilling can't keep up %u", worker->DMAeventCount);
        }
        if(FURI_BIT(flags, HitagWorkerSignalHalfTransfer)) {
            //refill first half of dma buffer
            hitag_worker_yield_dma_buffer_BPLM(
                dataCMD, backupCMD, dataDMA, 0, DMA_BUFFER_SIZE / 2);
        }
        if(FURI_BIT(flags, HitagWorkerSignalTransferComplete)) {
            //refill second half of dma buffer
            hitag_worker_yield_dma_buffer_BPLM(
                dataCMD, backupCMD, dataDMA, DMA_BUFFER_SIZE / 2, DMA_BUFFER_SIZE / 2);
        }
        worker->DMAeventCount = 0;
        //clear all flags (i have processed all known/expected events)
        furi_event_flag_clear(worker->events, flags);
    }

    //stop timers
    furi_hal_rfid_tim_read_capture_stop();
    furi_hal_rfid_rtf_carrier_out_stop();

    //free memory
    free(dataCMD);
    free(backupCMD);
    free(dataDMA);
    varint_pair_free(capData->pair);
    buffer_stream_free(capData->stream);
    free(capData);

    //allow the view that started the thread to signal the stop, which will properly merge the threads & de-init the worker
    if(currPage == HITAG_PAGES - 4) {
        const uint32_t available_flags = (1 << HitagWorkerSignalStop);
        while(true) {
            uint32_t flags = furi_event_flag_wait(
                worker->events, available_flags, FuriFlagWaitAny, FuriWaitForever);

            if(FURI_BIT(flags, HitagWorkerSignalStop)) {
                break;
            }
        }
    }

    //clear the stop flag on workder so that i can use the same worker to launch a new routine
    furi_event_flag_clear(worker->events, 1 << HitagWorkerSignalStop);

    return 0;
}
