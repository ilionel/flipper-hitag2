// Off-device (gcc) test of the PURE Hitag2 reader-frame classifier.
// Build & run: `make` in this folder.

#include "../hitag_frames.h"
#include "../hitag2_cipher.h"
#include <stdio.h>

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, ...)                                \
    do {                                                \
        if(cond) { g_pass++; }                          \
        else { g_fail++; printf("  FAIL: " __VA_ARGS__); printf(" [%d]\n", __LINE__); } \
    } while(0)

int main(void) {
    printf("== Test hitag_classify_frame ==\n");
    uint8_t page = 0xFF;

    // START_AUTH: 5-7 bits, head 0b11000 (0x18 in the top 5 bits).
    CHECK(hitag_classify_frame(5, 0x18u << 27, NULL) == HitagFrameStartAuth, "start_auth 5b\n");
    CHECK(hitag_classify_frame(7, 0x18u << 27, NULL) == HitagFrameStartAuth, "start_auth 7b\n");
    CHECK(hitag_classify_frame(8, 0x18u << 27, NULL) != HitagFrameStartAuth, "8b != start_auth\n");
    CHECK(hitag_classify_frame(5, 0x10u << 27, NULL) == HitagFrameUnknown, "bad head\n");

    // READ: 10-12 bits, head 0b11 (top 2 bits), page = next bits (3 bits).
    page = 0xFF;
    CHECK(hitag_classify_frame(10, (0x3u << 30) | (5u << 27), &page) == HitagFrameRead, "read 10b\n");
    CHECK(page == 5, "page extraite = 5\n");
    page = 0xFF;
    CHECK(hitag_classify_frame(12, (0x3u << 30) | (0u << 27), &page) == HitagFrameRead, "read page 0\n");
    CHECK(page == 0, "page extraite = 0\n");
    CHECK(hitag_classify_frame(13, 0x3u << 30, NULL) != HitagFrameRead, "13b != read\n");

    // PASSWORD: 31-34 bits.
    CHECK(hitag_classify_frame(32, 0xDEADBEEFu, NULL) == HitagFramePassword, "password 32b\n");
    CHECK(hitag_classify_frame(31, 0u, NULL) == HitagFramePassword, "password 31b\n");
    CHECK(hitag_classify_frame(34, 0u, NULL) == HitagFramePassword, "password 34b\n");
    CHECK(hitag_classify_frame(35, 0u, NULL) == HitagFrameUnknown, "35b inconnu\n");

    // Misc unknowns
    CHECK(hitag_classify_frame(0, 0, NULL) == HitagFrameUnknown, "0b inconnu\n");
    CHECK(hitag_classify_frame(20, 0, NULL) == HitagFrameUnknown, "20b inconnu\n");

    // ---- Hitag S classifier ----
    printf("== Test hitag_classify_frame_s ==\n");
    uint8_t addr = 0xFF;

    // UID request: 5b opcodes STD=00110, ADV2=11000, ADV1=11001, FADV=11010.
    CHECK(hitag_classify_frame_s(5, 0x06u << 27, NULL) == HitagSFrameUidReq, "uidreq STD\n");
    CHECK(hitag_classify_frame_s(5, 0x18u << 27, NULL) == HitagSFrameUidReq, "uidreq ADV2\n");
    CHECK(hitag_classify_frame_s(5, 0x19u << 27, NULL) == HitagSFrameUidReq, "uidreq ADV1\n");
    CHECK(hitag_classify_frame_s(5, 0x1Au << 27, NULL) == HitagSFrameUidReq, "uidreq FADV\n");
    CHECK(hitag_classify_frame_s(5, 0x11u << 27, NULL) == HitagSFrameUnknown, "5b mauvaise tete\n");

    // SELECT: 45 bits, opcode 00000.
    CHECK(hitag_classify_frame_s(45, 0x00u, NULL) == HitagSFrameSelect, "select 45b\n");
    CHECK(hitag_classify_frame_s(45, 0x08u << 27, NULL) == HitagSFrameUnknown, "45b tete!=0\n");
    CHECK(hitag_classify_frame_s(5, 0x00u, NULL) == HitagSFrameUnknown, "5b op0 != select\n");

    // READ: 20 bits, opcode 1100(page)/1101(block), addr in the next 8 bits.
    addr = 0xFF;
    CHECK(
        hitag_classify_frame_s(20, (0xCu << 28) | (7u << 20), &addr) == HitagSFrameRead,
        "read page\n");
    CHECK(addr == 7, "read addr = 7\n");
    addr = 0xFF;
    CHECK(
        hitag_classify_frame_s(20, (0xDu << 28) | (0x2Au << 20), &addr) == HitagSFrameRead,
        "read block\n");
    CHECK(addr == 0x2A, "read addr = 0x2A\n");

    // WRITE: opcode 1000(page)/1001(block).
    addr = 0xFF;
    CHECK(
        hitag_classify_frame_s(20, (0x8u << 28) | (3u << 20), &addr) == HitagSFrameWrite,
        "write page\n");
    CHECK(addr == 3, "write addr = 3\n");

    // 82xx auth: the reader writes its password to virtual page 64 (0x40). This exact frame
    // (WRITE + addr 64) is what arms the 82xx-password capture in the sniff worker.
    addr = 0xFF;
    CHECK(
        hitag_classify_frame_s(20, (0x8u << 28) | (64u << 20), &addr) == HitagSFrameWrite,
        "write page 64 (82xx)\n");
    CHECK(addr == 64, "82xx write addr = 64\n");
    addr = 0xFF;
    CHECK(
        hitag_classify_frame_s(20, (0x9u << 28) | (64u << 20), &addr) == HitagSFrameWrite,
        "write block 64 (82xx)\n");
    CHECK(addr == 64, "82xx write-block addr = 64\n");

    // Boundaries / unknowns.
    CHECK(hitag_classify_frame_s(20, (0xFu << 28), NULL) == HitagSFrameUnknown, "20b op F unknown\n");
    CHECK(hitag_classify_frame_s(30, 0, NULL) == HitagSFrameUnknown, "30b unknown\n");

    // ---- CRC-8/Hitag (vectors cross-checked against a Python reference of poly 0x1D/init 0xFF) ----
    printf("== Test hitag_crc8 ==\n");
    const uint8_t v_01020304[] = {0x01, 0x02, 0x03, 0x04};
    const uint8_t v_deadbeef[] = {0xDE, 0xAD, 0xBE, 0xEF};
    const uint8_t v_00[] = {0x00};
    const uint8_t v_c070[] = {0xC0, 0x70};
    // SELECT bits: 00000 (5) + UID 0x01020304 (32) = 37 bits, MSB-aligned.
    const uint8_t v_sel[] = {0x00, 0x08, 0x10, 0x18, 0x20};
    CHECK(hitag_crc8(v_01020304, 32) == 0x98, "crc 01020304 = 0x98\n");
    CHECK(hitag_crc8(v_deadbeef, 32) == 0x4C, "crc deadbeef = 0x4C\n");
    CHECK(hitag_crc8(v_00, 8) == 0xC4, "crc 00/8b = 0xC4\n");
    CHECK(hitag_crc8(v_c070, 12) == 0xF8, "crc C070/12b = 0xF8\n");
    CHECK(hitag_crc8(v_sel, 37) == 0x47, "crc SELECT 37b = 0x47\n");

    // ---- Hitag2 stream cipher (keystream vector cross-checked against the PM3 reference
    //      common/hitag2/hitag2_crypto.c: init(0x524B494D4E4F, 0x1B147619, 0x11223344)) ----
    printf("== Test ht2 cipher keystream ==\n");
    uint64_t st = ht2_hitag2_init(0x524B494D4E4FULL, 0x1B147619U, 0x11223344U);
    const uint8_t ks_expect[8] = {0x0F, 0x38, 0xA9, 0xB8, 0x5C, 0x8A, 0xD0, 0xCE};
    for(int i = 0; i < 8; i++) {
        uint8_t k = (uint8_t)ht2_hitag2_byte(&st);
        CHECK(k == ks_expect[i], "keystream byte %d = %02X (exp %02X)\n", i, k, ks_expect[i]);
    }

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
