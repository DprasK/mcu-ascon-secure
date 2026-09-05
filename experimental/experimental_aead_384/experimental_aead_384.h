#ifndef EXPERIMENTAL_AEAD_384_H
#define EXPERIMENTAL_AEAD_384_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EXP_AEAD_384_KEY_SIZE 16u
#define EXP_AEAD_384_NONCE_SIZE 16u
#define EXP_AEAD_384_TAG_SIZE 16u

/*
 * EXPERIMENTAL RESEARCH API -- NOT FOR PRODUCTION OR REAL SECRETS.
 *
 * This is a new, unaudited construction. Passing its tests proves only that
 * the implementation is internally consistent and detects tested changes.
 */
int exp_aead_384_seal(uint8_t *ciphertext_and_tag,
                   size_t ciphertext_capacity,
                   size_t *ciphertext_len,
                   const uint8_t *plaintext,
                   size_t plaintext_len,
                   const uint8_t *associated_data,
                   size_t associated_data_len,
                   const uint8_t nonce[EXP_AEAD_384_NONCE_SIZE],
                   const uint8_t key[EXP_AEAD_384_KEY_SIZE]);

int exp_aead_384_open(uint8_t *plaintext,
                   size_t plaintext_capacity,
                   size_t *plaintext_len,
                   const uint8_t *ciphertext_and_tag,
                   size_t ciphertext_len,
                   const uint8_t *associated_data,
                   size_t associated_data_len,
                   const uint8_t nonce[EXP_AEAD_384_NONCE_SIZE],
                   const uint8_t key[EXP_AEAD_384_KEY_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* EXPERIMENTAL_AEAD_384_H */
