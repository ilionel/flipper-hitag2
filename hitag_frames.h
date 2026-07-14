// PURE classification of captured Hitag2 reader frames (sniff / emulate log).
// No Flipper/SDK dependency (uint only) -> unit-testable off device.
// Recognises commands by bit length + head pattern:
//   START_AUTH (5-7 bits, head 0b11000), READ page (10-12 bits, head 0b11),
//   PASSWORD (31-34 bits). Everything else = unknown.
#pragma once

#include <stdint.h>

typedef enum {
    HitagFrameUnknown = 0,
    HitagFrameStartAuth,
    HitagFrameRead,
    HitagFramePassword,
} HitagFrameKind;

// Classify a frame (len = bit count, val = MSB-first bits in a uint32).
// For HitagFrameRead, *out_page (if non-NULL) receives the page number (0..7).
HitagFrameKind hitag_classify_frame(uint8_t len, uint32_t val, uint8_t* out_page);

// --- Hitag S reader frames (independent classifier; leaves the Hitag2 one untouched) ---
// Opcodes from Proxmark3 include/protocols.h (MSB-aligned in the frame):
//   UID_REQ 5b: STD=00110, ADV2=11000 (==HT2 START_AUTH), ADV1=11001 (==HT1 SET_CCNEW), FADV=11010
//   SELECT  5b 00000 + 32b UID + 8b CRC          (= 45 bits)
//   READ    4b 1100(page)/1101(block) + 8b addr + 8b CRC   (= 20 bits)
//   WRITE   4b 1000(page)/1001(block) + 8b addr + 8b CRC + data
typedef enum {
    HitagSFrameUnknown = 0,
    HitagSFrameUidReq,
    HitagSFrameSelect,
    HitagSFrameRead,
    HitagSFrameWrite,
} HitagSFrameKind;

// Classify a Hitag S reader frame (len = bit count, val = bits MSB-first in a uint32).
// For HitagSFrameRead/Write, *out_addr (if non-NULL) receives the 8-bit page/block address.
HitagSFrameKind hitag_classify_frame_s(uint8_t len, uint32_t val, uint8_t* out_addr);

// CRC-8/Hitag (poly 0x1D, init 0xFF, MSB-first, no reflection, no final XOR), computed over
// the first `nbits` bits of `data` (MSB-first). Matches PM3 CRC8Hitag1Bits. Used to build /
// validate Hitag S SELECT (over opcode+UID) and READ (over opcode+addr) commands.
uint8_t hitag_crc8(const uint8_t* data, uint16_t nbits);
