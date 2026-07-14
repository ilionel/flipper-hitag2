// Minimal Hitag2 48-bit stream cipher (the "simple" variant used by the PM3 Hitag S tag
// simulation: armsrc/hitagS.c). Ported verbatim from proxmark3 common/hitag2/hitag2_crypto.c —
// only the pieces a tag needs to answer a crypto/challenge authentication: init + keystream.
// The key-recovery/rollback machinery (hitag_state_t, nstep, buildlfsr, recoverkey) is NOT
// needed here and is intentionally omitted.
#pragma once
#include <stdint.h>

// Bit-reversal helpers (proxmark3 common/commonutil.h), used to feed key/serial/iv in the
// bit order the cipher expects.
#define HT2_REV8(x)                                                                      \
    ((((x) >> 7) & 1) + ((((x) >> 6) & 1) << 1) + ((((x) >> 5) & 1) << 2) +              \
     ((((x) >> 4) & 1) << 3) + ((((x) >> 3) & 1) << 4) + ((((x) >> 2) & 1) << 5) +       \
     ((((x) >> 1) & 1) << 6) + (((x) & 1) << 7))
#define HT2_REV16(x) (HT2_REV8(x) + (HT2_REV8((x) >> 8) << 8))
#define HT2_REV32(x) (HT2_REV16(x) + ((uint32_t)HT2_REV16((x) >> 16) << 16))
#define HT2_REV64(x) (HT2_REV32(x) + ((uint64_t)HT2_REV32((x) >> 32) << 32))

// Initialise the cipher from the 48-bit key, 32-bit serial (UID) and 32-bit IV (nonce),
// returning the internal state. Feed key/serial/iv already bit-reversed (HT2_REV*), exactly
// as hitagS.c does: ht2_hitag2_init(REV64(key), REV32(uid), REV32(iv)).
uint64_t ht2_hitag2_init(const uint64_t key, const uint32_t serial, const uint32_t iv);

// Advance the cipher by 8 bits and return the next keystream byte (MSB first).
uint32_t ht2_hitag2_byte(uint64_t* state);

// Verify the reader's 4-byte authenticator against the keystream (Hitag2 crypto mutual auth):
// the tag expects ~keystream for each of 4 bytes. Returns 1 on match. Advances the state 32 bits.
int ht2_hitag2_cipher_authenticate(uint64_t* state, const uint8_t* authenticator);

// XOR `bytes` whole bytes then `bits` leading bits of data[bytes] with the keystream, advancing
// the state accordingly. Used to en/decrypt every frame once Hitag2 crypto is active.
void ht2_hitag2_cipher_transcrypt(uint64_t* state, uint8_t* data, uint16_t bytes, uint16_t bits);
