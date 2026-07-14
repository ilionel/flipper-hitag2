// See hitag_frames.h. Pure reader-frame classifiers (Hitag2 + Hitag S) and the
// Hitag1/Hitag S CRC-8, with no Flipper/SDK dependency so they stay unit-testable.

#include "hitag_frames.h"

HitagFrameKind hitag_classify_frame(uint8_t len, uint32_t val, uint8_t* out_page) {
    if(len >= 5 && len <= 7 && (val >> 27) == 0x18) {
        return HitagFrameStartAuth;
    }
    if(len >= 10 && len <= 12 && (val >> 30) == 0x3) {
        if(out_page) *out_page = (uint8_t)((val >> 27) & 0x07);
        return HitagFrameRead;
    }
    if(len >= 31 && len <= 34) {
        return HitagFramePassword;
    }
    return HitagFrameUnknown;
}

HitagSFrameKind hitag_classify_frame_s(uint8_t len, uint32_t val, uint8_t* out_addr) {
    // 5-bit UID request: opcode in the top 5 bits (STD/ADV2/ADV1/FADV).
    if(len >= 5 && len <= 7) {
        uint32_t op = val >> 27;
        if(op == 0x06 || op == 0x18 || op == 0x19 || op == 0x1A) return HitagSFrameUidReq;
        return HitagSFrameUnknown;
    }
    // SELECT: 5b opcode 00000 + 32b UID + 8b CRC = 45 bits.
    if(len >= 44 && len <= 46 && (val >> 27) == 0x00) return HitagSFrameSelect;
    // READ/WRITE: 4b opcode + 8b addr + 8b CRC = 20 bits. addr = the 8 bits after the opcode.
    if(len >= 19 && len <= 21) {
        uint32_t op4 = val >> 28;
        uint8_t addr = (uint8_t)((val >> 20) & 0xff);
        if(op4 == 0xC || op4 == 0xD) { // READ_PAGE / READ_BLOCK
            if(out_addr) *out_addr = addr;
            return HitagSFrameRead;
        }
        if(op4 == 0x8 || op4 == 0x9) { // WRITE_PAGE / WRITE_BLOCK
            if(out_addr) *out_addr = addr;
            return HitagSFrameWrite;
        }
    }
    return HitagSFrameUnknown;
}

uint8_t hitag_crc8(const uint8_t* data, uint16_t nbits) {
    uint8_t crc = 0xFF;
    for(uint16_t i = 0; i < nbits; i++) {
        uint8_t bit = (data[i >> 3] >> (7 - (i & 7))) & 1u;
        uint8_t fb = ((crc >> 7) & 1u) ^ bit;
        crc = (uint8_t)(crc << 1);
        if(fb) crc ^= 0x1D;
    }
    return crc;
}
