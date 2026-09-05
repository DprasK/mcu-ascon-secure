#ifndef MCU_SECURE_H
#define MCU_SECURE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MCU_SECURE_KEY_SIZE 16u
#define MCU_SECURE_NONCE_SIZE 16u
#define MCU_SECURE_TAG_SIZE 16u
#define MCU_SECURE_HEADER_SIZE 20u
#define MCU_SECURE_OVERHEAD (MCU_SECURE_HEADER_SIZE + MCU_SECURE_TAG_SIZE)

typedef enum {
  MCU_SECURE_OK = 0,
  MCU_SECURE_ERR_ARGUMENT = -1,
  MCU_SECURE_ERR_CAPACITY = -2,
  MCU_SECURE_ERR_COUNTER_EXHAUSTED = -3,
  MCU_SECURE_ERR_FORMAT = -4,
  MCU_SECURE_ERR_AUTH = -5,
  MCU_SECURE_ERR_REPLAY = -6
} mcu_secure_result_t;

/*
 * A transmit context may use only a counter range that was durably reserved
 * before mcu_secure_tx_init() is called. Never reuse a counter with the same
 * key + device_id + key_epoch tuple.
 */
typedef struct {
  uint8_t key[MCU_SECURE_KEY_SIZE];
  uint32_t device_id;
  uint32_t key_epoch;
  uint64_t next_counter;
  uint64_t remaining;
} mcu_secure_tx_t;

/* This receiver uses a strict monotonic replay check (reordering is rejected). */
typedef struct {
  uint8_t key[MCU_SECURE_KEY_SIZE];
  uint32_t expected_device_id;
  uint32_t expected_key_epoch;
  uint64_t last_counter;
  bool has_last_counter;
} mcu_secure_rx_t;

/* Returns 0 when plaintext_len cannot be represented safely. */
size_t mcu_secure_packet_size(size_t plaintext_len);

mcu_secure_result_t mcu_secure_tx_init(
    mcu_secure_tx_t *ctx,
    const uint8_t key[MCU_SECURE_KEY_SIZE],
    uint32_t device_id,
    uint32_t key_epoch,
    uint64_t first_reserved_counter,
    uint64_t reserved_count);

mcu_secure_result_t mcu_secure_rx_init(
    mcu_secure_rx_t *ctx,
    const uint8_t key[MCU_SECURE_KEY_SIZE],
    uint32_t expected_device_id,
    uint32_t expected_key_epoch,
    bool has_persisted_counter,
    uint64_t persisted_last_counter);

/* plaintext and packet_out must not overlap. */
mcu_secure_result_t mcu_secure_seal(
    mcu_secure_tx_t *ctx,
    uint8_t message_type,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *packet_out,
    size_t packet_capacity,
    size_t *packet_len_out);

/* packet and plaintext_out must not overlap. */
mcu_secure_result_t mcu_secure_open(
    mcu_secure_rx_t *ctx,
    const uint8_t *packet,
    size_t packet_len,
    uint8_t *plaintext_out,
    size_t plaintext_capacity,
    size_t *plaintext_len_out,
    uint8_t *message_type_out,
    uint64_t *counter_out);

/* Erases keys and state from RAM (subject to platform/compiler guarantees). */
void mcu_secure_tx_destroy(mcu_secure_tx_t *ctx);
void mcu_secure_rx_destroy(mcu_secure_rx_t *ctx);

const char *mcu_secure_result_string(mcu_secure_result_t result);

#ifdef __cplusplus
}
#endif

#endif /* MCU_SECURE_H */
