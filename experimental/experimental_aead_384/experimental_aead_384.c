#include "experimental_aead_384.h"

#include <stdint.h>
#include <string.h>

#define EXP_RATE 16u
#define EXP_ROUNDS 12u

typedef struct {
  uint32_t w[12]; /* 384-bit state: 128-bit rate, 256-bit capacity */
} exp_state_t;

/* SHA-256("Experimental-AEAD-384-v0 round N")[0..3], little-endian. */
static const uint32_t ROUND_CONSTANTS[EXP_ROUNDS] = {
    0xB0E55E27u, 0x20B291F7u, 0xD693BCF6u, 0x21B4E54Du,
    0x8CB4C5B5u, 0x4FBB5B2Bu, 0x413D55BFu, 0xCB50DE3Du,
    0x77C90594u, 0xA7A31D01u, 0x47D51C4Au, 0x565B1279u};

static uint32_t rotl32(uint32_t x, unsigned int n) {
  return (x << n) | (x >> (32u - n));
}

static void mix(uint32_t *a, uint32_t *b, unsigned int r, unsigned int q) {
  *a += *b;
  *b = rotl32(*b, r) ^ *a;
  *a = rotl32(*a, q);
}

static void exp_permute(exp_state_t *s) {
  unsigned int round;
  for (round = 0; round < EXP_ROUNDS; ++round) {
    const uint32_t c = ROUND_CONSTANTS[round];
    s->w[0] ^= c;
    s->w[5] += rotl32(c, 11u);
    s->w[10] ^= ~c;

    mix(&s->w[0], &s->w[1], 5u, 16u);
    mix(&s->w[2], &s->w[3], 7u, 12u);
    mix(&s->w[4], &s->w[5], 9u, 8u);
    mix(&s->w[6], &s->w[7], 13u, 7u);
    mix(&s->w[8], &s->w[9], 17u, 5u);
    mix(&s->w[10], &s->w[11], 21u, 3u);

    mix(&s->w[0], &s->w[3], 11u, 9u);
    mix(&s->w[2], &s->w[5], 15u, 13u);
    mix(&s->w[4], &s->w[7], 19u, 17u);
    mix(&s->w[6], &s->w[9], 23u, 21u);
    mix(&s->w[8], &s->w[11], 27u, 25u);
    mix(&s->w[10], &s->w[1], 29u, 27u);

    mix(&s->w[0], &s->w[5], 3u, 11u);
    mix(&s->w[2], &s->w[7], 7u, 15u);
    mix(&s->w[4], &s->w[9], 13u, 19u);
    mix(&s->w[6], &s->w[11], 17u, 23u);
    mix(&s->w[8], &s->w[1], 19u, 29u);
    mix(&s->w[10], &s->w[3], 23u, 5u);
  }
}

static uint32_t load32_le(const uint8_t *p) {
  return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t x) {
  p[0] = (uint8_t)x;
  p[1] = (uint8_t)(x >> 8);
  p[2] = (uint8_t)(x >> 16);
  p[3] = (uint8_t)(x >> 24);
}

static uint8_t state_byte(const exp_state_t *s, size_t i) {
  return (uint8_t)(s->w[i >> 2] >> (8u * (unsigned int)(i & 3u)));
}

static void state_set_byte(exp_state_t *s, size_t i, uint8_t value) {
  const unsigned int shift = 8u * (unsigned int)(i & 3u);
  const uint32_t mask = (uint32_t)0xffu << shift;
  s->w[i >> 2] = (s->w[i >> 2] & ~mask) | ((uint32_t)value << shift);
}

static void state_xor_byte(exp_state_t *s, size_t i, uint8_t value) {
  s->w[i >> 2] ^= (uint32_t)value << (8u * (unsigned int)(i & 3u));
}

static void wipe(void *ptr, size_t len) {
  volatile uint8_t *p = (volatile uint8_t *)ptr;
  while (len-- != 0u) *p++ = 0u;
}

static void initialize(exp_state_t *s, const uint8_t nonce[16],
                       const uint8_t key[16]) {
  unsigned int i;
  for (i = 0; i < 4u; ++i) s->w[i] = load32_le(key + 4u * i);
  for (i = 0; i < 4u; ++i) s->w[4u + i] = load32_le(nonce + 4u * i);
  s->w[8] = 0x34383345u;  /* "E384" in little-endian */
  s->w[9] = 0x30564541u;  /* "AEV0" */
  s->w[10] = 0x00000080u; /* claimed key size, not a security claim */
  s->w[11] = 0x00100c00u; /* rate=16, rounds=12, version=0 */
  exp_permute(s);
  for (i = 0; i < 4u; ++i) s->w[8u + i] ^= load32_le(key + 4u * i);
}

static void absorb_block(exp_state_t *s, const uint8_t block[EXP_RATE]) {
  unsigned int i;
  for (i = 0; i < 4u; ++i) s->w[i] ^= load32_le(block + 4u * i);
  exp_permute(s);
}

static void absorb_ad(exp_state_t *s, const uint8_t *ad, size_t ad_len) {
  uint8_t last[EXP_RATE] = {0};
  while (ad_len >= EXP_RATE) {
    absorb_block(s, ad);
    ad += EXP_RATE;
    ad_len -= EXP_RATE;
  }
  if (ad_len != 0u) memcpy(last, ad, ad_len);
  last[ad_len] ^= 0x01u;
  last[EXP_RATE - 1u] ^= 0x80u;
  absorb_block(s, last);
  s->w[11] ^= 0x41440001u; /* AD/message domain separation */
  wipe(last, sizeof(last));
}

static void encrypt_message(exp_state_t *s, uint8_t *out,
                            const uint8_t *in, size_t len) {
  unsigned int i;
  while (len >= EXP_RATE) {
    for (i = 0; i < 4u; ++i) {
      s->w[i] ^= load32_le(in + 4u * i);
      store32_le(out + 4u * i, s->w[i]);
    }
    exp_permute(s);
    in += EXP_RATE;
    out += EXP_RATE;
    len -= EXP_RATE;
  }
  for (i = 0; i < len; ++i) {
    const uint8_t mixed = state_byte(s, i) ^ in[i];
    state_set_byte(s, i, mixed);
    out[i] = mixed;
  }
  state_xor_byte(s, len, 0x01u);
  state_xor_byte(s, EXP_RATE - 1u, 0x80u);
}

static void decrypt_message(exp_state_t *s, uint8_t *out,
                            const uint8_t *in, size_t len) {
  unsigned int i;
  while (len >= EXP_RATE) {
    for (i = 0; i < 4u; ++i) {
      const uint32_t c = load32_le(in + 4u * i);
      store32_le(out + 4u * i, s->w[i] ^ c);
      s->w[i] = c;
    }
    exp_permute(s);
    in += EXP_RATE;
    out += EXP_RATE;
    len -= EXP_RATE;
  }
  for (i = 0; i < len; ++i) {
    const uint8_t c = in[i];
    out[i] = state_byte(s, i) ^ c;
    state_set_byte(s, i, c);
  }
  state_xor_byte(s, len, 0x01u);
  state_xor_byte(s, EXP_RATE - 1u, 0x80u);
}

static void finalize(exp_state_t *s, uint8_t tag[16],
                     const uint8_t key[16]) {
  unsigned int i;
  s->w[7] ^= 0x46494e01u; /* finalization domain */
  for (i = 0; i < 4u; ++i) s->w[8u + i] ^= load32_le(key + 4u * i);
  exp_permute(s);
  for (i = 0; i < 4u; ++i) {
    s->w[8u + i] ^= load32_le(key + 4u * i);
    store32_le(tag + 4u * i, s->w[8u + i]);
  }
}

int exp_aead_384_seal(uint8_t *ciphertext_and_tag, size_t ciphertext_capacity,
                   size_t *ciphertext_len, const uint8_t *plaintext,
                   size_t plaintext_len, const uint8_t *associated_data,
                   size_t associated_data_len, const uint8_t nonce[16],
                   const uint8_t key[16]) {
  exp_state_t state;
  uint8_t empty = 0u;

  if (ciphertext_len != NULL) *ciphertext_len = 0u;
  if (ciphertext_and_tag == NULL || ciphertext_len == NULL || nonce == NULL ||
      key == NULL || (plaintext == NULL && plaintext_len != 0u) ||
      (associated_data == NULL && associated_data_len != 0u) ||
      plaintext_len > SIZE_MAX - EXP_AEAD_384_TAG_SIZE ||
      ciphertext_capacity < plaintext_len + EXP_AEAD_384_TAG_SIZE) {
    return -1;
  }
  if (plaintext == NULL) plaintext = &empty;
  if (associated_data == NULL) associated_data = &empty;

  initialize(&state, nonce, key);
  absorb_ad(&state, associated_data, associated_data_len);
  encrypt_message(&state, ciphertext_and_tag, plaintext, plaintext_len);
  finalize(&state, ciphertext_and_tag + plaintext_len, key);
  wipe(&state, sizeof(state));
  *ciphertext_len = plaintext_len + EXP_AEAD_384_TAG_SIZE;
  return 0;
}

int exp_aead_384_open(uint8_t *plaintext, size_t plaintext_capacity,
                   size_t *plaintext_len, const uint8_t *ciphertext_and_tag,
                   size_t ciphertext_len, const uint8_t *associated_data,
                   size_t associated_data_len, const uint8_t nonce[16],
                   const uint8_t key[16]) {
  exp_state_t state;
  uint8_t expected_tag[EXP_AEAD_384_TAG_SIZE];
  uint8_t dummy = 0u;
  uint32_t difference = 0u;
  size_t message_len;
  unsigned int i;

  if (plaintext_len != NULL) *plaintext_len = 0u;
  if (plaintext_len == NULL || ciphertext_and_tag == NULL || nonce == NULL ||
      key == NULL || ciphertext_len < EXP_AEAD_384_TAG_SIZE ||
      (associated_data == NULL && associated_data_len != 0u)) {
    return -1;
  }
  message_len = ciphertext_len - EXP_AEAD_384_TAG_SIZE;
  if ((plaintext == NULL && message_len != 0u) ||
      plaintext_capacity < message_len) {
    return -1;
  }
  if (plaintext == NULL) plaintext = &dummy;
  if (associated_data == NULL) associated_data = &dummy;

  initialize(&state, nonce, key);
  absorb_ad(&state, associated_data, associated_data_len);
  decrypt_message(&state, plaintext, ciphertext_and_tag, message_len);
  finalize(&state, expected_tag, key);

  for (i = 0; i < EXP_AEAD_384_TAG_SIZE; ++i) {
    difference |= (uint32_t)(expected_tag[i] ^
                             ciphertext_and_tag[message_len + i]);
  }
  wipe(expected_tag, sizeof(expected_tag));
  wipe(&state, sizeof(state));
  if (difference != 0u) {
    wipe(plaintext, message_len);
    return -2;
  }
  *plaintext_len = message_len;
  return 0;
}
