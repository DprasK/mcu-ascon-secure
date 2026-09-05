#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "experimental_aead_384.h"

static void round_trip_size(size_t length) {
  uint8_t key[16];
  uint8_t nonce[16];
  uint8_t ad[19];
  uint8_t message[80];
  uint8_t ciphertext[80 + EXP_AEAD_384_TAG_SIZE];
  uint8_t recovered[80];
  size_t ciphertext_len = 0u;
  size_t recovered_len = 0u;
  size_t i;

  for (i = 0; i < sizeof(key); ++i) key[i] = (uint8_t)(0xa0u + i);
  for (i = 0; i < sizeof(nonce); ++i) nonce[i] = (uint8_t)(0x10u + i);
  for (i = 0; i < sizeof(ad); ++i) ad[i] = (uint8_t)(3u * i + 1u);
  for (i = 0; i < sizeof(message); ++i) message[i] = (uint8_t)(7u * i + 2u);

  assert(exp_aead_384_seal(ciphertext, sizeof(ciphertext), &ciphertext_len,
                        message, length, ad, sizeof(ad), nonce, key) == 0);
  assert(ciphertext_len == length + EXP_AEAD_384_TAG_SIZE);
  assert(exp_aead_384_open(recovered, sizeof(recovered), &recovered_len,
                        ciphertext, ciphertext_len, ad, sizeof(ad), nonce,
                        key) == 0);
  assert(recovered_len == length);
  assert(memcmp(message, recovered, length) == 0);

  ciphertext[length / 2u] ^= 0x40u;
  memset(recovered, 0x55, sizeof(recovered));
  assert(exp_aead_384_open(recovered, sizeof(recovered), &recovered_len,
                        ciphertext, ciphertext_len, ad, sizeof(ad), nonce,
                        key) == -2);
  assert(recovered_len == 0u);
  for (i = 0; i < length; ++i) assert(recovered[i] == 0u);
}

int main(void) {
  static const size_t lengths[] = {0u, 1u, 15u, 16u, 17u, 31u, 32u, 63u, 80u};
  size_t i;
  for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
    round_trip_size(lengths[i]);
  }
  puts("Experimental-AEAD-384-v0 tests passed (not a security validation)");
  return 0;
}
