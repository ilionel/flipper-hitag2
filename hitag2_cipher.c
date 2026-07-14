// See hitag2_cipher.h. Ported verbatim from proxmark3 common/hitag2/hitag2_crypto.c
// (I.C. Wiener's public-domain Hitag2 stream cipher), keeping only init + keystream.
#include "hitag2_cipher.h"

static const uint32_t ht2_f4a = 0x2C79; // 0010 1100 0111 1001
static const uint32_t ht2_f4b = 0x6671; // 0110 0110 0111 0001
static const uint32_t ht2_f5c = 0x7907287B; // 0111 1001 0000 0111 0010 1000 0111 1011

// build a 4-bit index from four state bits
#define i4(x, a, b, c, d)                                                          \
    ((uint32_t)((((x) >> (a)) & 1) + (((x) >> (b)) & 1) * 2 + (((x) >> (c)) & 1) * 4 + \
                (((x) >> (d)) & 1) * 8))

// the non-linear filter function
static uint32_t ht2_f20(const uint64_t state) {
    uint32_t i5 = ((ht2_f4a >> i4(state, 1, 2, 4, 5)) & 1) * 1 +
                  ((ht2_f4b >> i4(state, 7, 11, 13, 14)) & 1) * 2 +
                  ((ht2_f4b >> i4(state, 16, 20, 22, 25)) & 1) * 4 +
                  ((ht2_f4b >> i4(state, 27, 28, 30, 32)) & 1) * 8 +
                  ((ht2_f4a >> i4(state, 33, 42, 43, 45)) & 1) * 16;
    return (ht2_f5c >> i5) & 1;
}

uint64_t ht2_hitag2_init(const uint64_t key, const uint32_t serial, const uint32_t iv) {
    uint64_t x = ((key & 0xFFFF) << 32) + serial;
    for(uint32_t i = 0; i < 32; i++) {
        x >>= 1;
        x += (uint64_t)(ht2_f20(x) ^ (((iv >> i) ^ (key >> (i + 16))) & 1)) << 47;
    }
    return x;
}

// advance the 48-bit LFSR one step and return one keystream bit
static uint64_t ht2_hitag2_bit(uint64_t* state) {
    uint64_t x = *state;
    x = (x >> 1) + ((((x >> 0) ^ (x >> 2) ^ (x >> 3) ^ (x >> 6) ^ (x >> 7) ^ (x >> 8) ^
                      (x >> 16) ^ (x >> 22) ^ (x >> 23) ^ (x >> 26) ^ (x >> 30) ^ (x >> 41) ^
                      (x >> 42) ^ (x >> 43) ^ (x >> 46) ^ (x >> 47)) &
                     1)
                    << 47);
    *state = x;
    return ht2_f20(x);
}

uint32_t ht2_hitag2_byte(uint64_t* state) {
    uint32_t c = 0;
    c += (uint32_t)ht2_hitag2_bit(state) << 7;
    c += (uint32_t)ht2_hitag2_bit(state) << 6;
    c += (uint32_t)ht2_hitag2_bit(state) << 5;
    c += (uint32_t)ht2_hitag2_bit(state) << 4;
    c += (uint32_t)ht2_hitag2_bit(state) << 3;
    c += (uint32_t)ht2_hitag2_bit(state) << 2;
    c += (uint32_t)ht2_hitag2_bit(state) << 1;
    c += (uint32_t)ht2_hitag2_bit(state) << 0;
    return c;
}

int ht2_hitag2_cipher_authenticate(uint64_t* state, const uint8_t* authenticator) {
    uint8_t should[4];
    should[0] = ~(uint8_t)ht2_hitag2_byte(state);
    should[1] = ~(uint8_t)ht2_hitag2_byte(state);
    should[2] = ~(uint8_t)ht2_hitag2_byte(state);
    should[3] = ~(uint8_t)ht2_hitag2_byte(state);
    return (should[0] == authenticator[0] && should[1] == authenticator[1] &&
            should[2] == authenticator[2] && should[3] == authenticator[3]);
}

void ht2_hitag2_cipher_transcrypt(uint64_t* state, uint8_t* data, uint16_t bytes, uint16_t bits) {
    for(uint16_t i = 0; i < bytes; i++)
        data[i] ^= (uint8_t)ht2_hitag2_byte(state);
    for(uint16_t i = 0; i < bits; i++)
        data[bytes] ^= (uint8_t)(ht2_hitag2_bit(state) << (7 - i));
}
