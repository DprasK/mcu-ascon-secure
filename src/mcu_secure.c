#include "mcu_secure.h"

#include <limits.h>
#include <string.h>

#include "crypto_aead.h"

#define MCU_SECURE_MAGIC_0 0x4du /* M */
#define MCU_SECURE_MAGIC_1 0x53u /* S */
#define MCU_SECURE_VERSION 0x01u

#define OFFSET_MAGIC_0 0u
#define OFFSET_MAGIC_1 1u
#define OFFSET_VERSION 2u
#define OFFSET_MESSAGE_TYPE 3u
#define OFFSET_DEVICE_ID 4u
#define OFFSET_KEY_EPOCH 8u
#define OFFSET_COUNTER 12u

static void write_u32_le(uint8_t *dst, uint32_t value) {
  dst[0] = (uint8_t)value;
  dst[1] = (uint8_t)(value >> 8);
  dst[2] = (uint8_t)(value >> 16);
  dst[3] = (uint8_t)(value >> 24);
}

static void write_u64_le(uint8_t *dst, uint64_t value) {
  unsigned int i;
  for (i = 0; i < 8u; ++i) {
    dst[i] = (uint8_t)(value >> (8u * i));
  }
}

static uint32_t read_u32_le(const uint8_t *src) {
  return ((uint32_t)src[0]) | ((uint32_t)src[1] << 8) |
         ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

static uint64_t read_u64_le(const uint8_t *src) {
  uint64_t value = 0;
  unsigned int i;
  for (i = 0; i < 8u; ++i) {
    value |= ((uint64_t)src[i]) << (8u * i);
  }
  return value;
}

static void secure_wipe(void *ptr, size_t len) {
  volatile uint8_t *p = (volatile uint8_t *)ptr;
  while (len-- != 0u) {
    *p++ = 0u;
  }
}

size_t mcu_secure_packet_size(size_t plaintext_len) {
  if (plaintext_len > SIZE_MAX - MCU_SECURE_OVERHEAD) {
    return 0u;
  }
  return plaintext_len + MCU_SECURE_OVERHEAD;
}

mcu_secure_result_t mcu_secure_tx_init(
    mcu_secure_tx_t *ctx,
    const uint8_t key[MCU_SECURE_KEY_SIZE],
    uint32_t device_id,
    uint32_t key_epoch,
    uint64_t first_reserved_counter,
    uint64_t reserved_count) {
  if (ctx == NULL || key == NULL || reserved_count == 0u) {
    return MCU_SECURE_ERR_ARGUMENT;
  }
  if ((reserved_count - 1u) > (UINT64_MAX - first_reserved_counter)) {
    return MCU_SECURE_ERR_ARGUMENT;
  }

  memcpy(ctx->key, key, MCU_SECURE_KEY_SIZE);
  ctx->device_id = device_id;
  ctx->key_epoch = key_epoch;
  ctx->next_counter = first_reserved_counter;
  ctx->remaining = reserved_count;
  return MCU_SECURE_OK;
}

mcu_secure_result_t mcu_secure_rx_init(
    mcu_secure_rx_t *ctx,
    const uint8_t key[MCU_SECURE_KEY_SIZE],
    uint32_t expected_device_id,
    uint32_t expected_key_epoch,
    bool has_persisted_counter,
    uint64_t persisted_last_counter) {
  if (ctx == NULL || key == NULL) {
    return MCU_SECURE_ERR_ARGUMENT;
  }

  memcpy(ctx->key, key, MCU_SECURE_KEY_SIZE);
  ctx->expected_device_id = expected_device_id;
  ctx->expected_key_epoch = expected_key_epoch;
  ctx->last_counter = persisted_last_counter;
  ctx->has_last_counter = has_persisted_counter;
  return MCU_SECURE_OK;
}

mcu_secure_result_t mcu_secure_seal(
    mcu_secure_tx_t *ctx,
    uint8_t message_type,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *packet_out,
    size_t packet_capacity,
    size_t *packet_len_out) {
  uint8_t zero = 0u;
  const uint8_t *message = plaintext;
  unsigned long long encrypted_len = 0u;
  size_t required;
  uint64_t counter;
  int crypto_result;

  if (packet_len_out != NULL) {
    *packet_len_out = 0u;
  }
  if (ctx == NULL || packet_out == NULL || packet_len_out == NULL ||
      (plaintext == NULL && plaintext_len != 0u)) {
    return MCU_SECURE_ERR_ARGUMENT;
  }
  if (ctx->remaining == 0u) {
    return MCU_SECURE_ERR_COUNTER_EXHAUSTED;
  }

  required = mcu_secure_packet_size(plaintext_len);
  if (required == 0u || packet_capacity < required ||
      plaintext_len > (size_t)(ULLONG_MAX - MCU_SECURE_TAG_SIZE)) {
    return MCU_SECURE_ERR_CAPACITY;
  }
  if (message == NULL) {
    message = &zero;
  }

  counter = ctx->next_counter;
  packet_out[OFFSET_MAGIC_0] = MCU_SECURE_MAGIC_0;
  packet_out[OFFSET_MAGIC_1] = MCU_SECURE_MAGIC_1;
  packet_out[OFFSET_VERSION] = MCU_SECURE_VERSION;
  packet_out[OFFSET_MESSAGE_TYPE] = message_type;
  write_u32_le(packet_out + OFFSET_DEVICE_ID, ctx->device_id);
  write_u32_le(packet_out + OFFSET_KEY_EPOCH, ctx->key_epoch);
  write_u64_le(packet_out + OFFSET_COUNTER, counter);

  /* Header is authenticated; bytes 4..19 are also the unique 128-bit nonce. */
  crypto_result = crypto_aead_encrypt(
      packet_out + MCU_SECURE_HEADER_SIZE, &encrypted_len, message,
      (unsigned long long)plaintext_len, packet_out, MCU_SECURE_HEADER_SIZE,
      NULL, packet_out + OFFSET_DEVICE_ID, ctx->key);
  if (crypto_result != 0 || encrypted_len !=
                                (unsigned long long)(plaintext_len +
                                                     MCU_SECURE_TAG_SIZE)) {
    secure_wipe(packet_out, required);
    return MCU_SECURE_ERR_AUTH;
  }

  --ctx->remaining;
  if (ctx->remaining != 0u) {
    ++ctx->next_counter;
  }
  *packet_len_out = required;
  return MCU_SECURE_OK;
}

mcu_secure_result_t mcu_secure_open(
    mcu_secure_rx_t *ctx,
    const uint8_t *packet,
    size_t packet_len,
    uint8_t *plaintext_out,
    size_t plaintext_capacity,
    size_t *plaintext_len_out,
    uint8_t *message_type_out,
    uint64_t *counter_out) {
  uint8_t dummy = 0u;
  uint8_t *output = plaintext_out;
  unsigned long long decrypted_len = 0u;
  size_t payload_len;
  uint32_t device_id;
  uint32_t key_epoch;
  uint64_t counter;
  int crypto_result;

  if (plaintext_len_out != NULL) {
    *plaintext_len_out = 0u;
  }
  if (ctx == NULL || packet == NULL || plaintext_len_out == NULL ||
      packet_len < MCU_SECURE_OVERHEAD) {
    return MCU_SECURE_ERR_ARGUMENT;
  }
  payload_len = packet_len - MCU_SECURE_OVERHEAD;
  if ((plaintext_out == NULL && payload_len != 0u) ||
      plaintext_capacity < payload_len ||
      (packet_len - MCU_SECURE_HEADER_SIZE) > (size_t)ULLONG_MAX) {
    return MCU_SECURE_ERR_CAPACITY;
  }
  if (output == NULL) {
    output = &dummy;
  }

  if (packet[OFFSET_MAGIC_0] != MCU_SECURE_MAGIC_0 ||
      packet[OFFSET_MAGIC_1] != MCU_SECURE_MAGIC_1 ||
      packet[OFFSET_VERSION] != MCU_SECURE_VERSION) {
    return MCU_SECURE_ERR_FORMAT;
  }
  device_id = read_u32_le(packet + OFFSET_DEVICE_ID);
  key_epoch = read_u32_le(packet + OFFSET_KEY_EPOCH);
  counter = read_u64_le(packet + OFFSET_COUNTER);
  if (device_id != ctx->expected_device_id ||
      key_epoch != ctx->expected_key_epoch) {
    return MCU_SECURE_ERR_FORMAT;
  }

  crypto_result = crypto_aead_decrypt(
      output, &decrypted_len, NULL, packet + MCU_SECURE_HEADER_SIZE,
      (unsigned long long)(packet_len - MCU_SECURE_HEADER_SIZE), packet,
      MCU_SECURE_HEADER_SIZE, packet + OFFSET_DEVICE_ID, ctx->key);
  if (crypto_result != 0 || decrypted_len != (unsigned long long)payload_len) {
    secure_wipe(output, payload_len);
    return MCU_SECURE_ERR_AUTH;
  }

  if (ctx->has_last_counter && counter <= ctx->last_counter) {
    secure_wipe(output, payload_len);
    return MCU_SECURE_ERR_REPLAY;
  }

  ctx->last_counter = counter;
  ctx->has_last_counter = true;
  *plaintext_len_out = payload_len;
  if (message_type_out != NULL) {
    *message_type_out = packet[OFFSET_MESSAGE_TYPE];
  }
  if (counter_out != NULL) {
    *counter_out = counter;
  }
  return MCU_SECURE_OK;
}

void mcu_secure_tx_destroy(mcu_secure_tx_t *ctx) {
  if (ctx != NULL) {
    secure_wipe(ctx, sizeof(*ctx));
  }
}

void mcu_secure_rx_destroy(mcu_secure_rx_t *ctx) {
  if (ctx != NULL) {
    secure_wipe(ctx, sizeof(*ctx));
  }
}

const char *mcu_secure_result_string(mcu_secure_result_t result) {
  switch (result) {
    case MCU_SECURE_OK:
      return "ok";
    case MCU_SECURE_ERR_ARGUMENT:
      return "invalid argument";
    case MCU_SECURE_ERR_CAPACITY:
      return "buffer capacity/length error";
    case MCU_SECURE_ERR_COUNTER_EXHAUSTED:
      return "reserved counter range exhausted";
    case MCU_SECURE_ERR_FORMAT:
      return "invalid packet/device/key epoch";
    case MCU_SECURE_ERR_AUTH:
      return "authentication failed";
    case MCU_SECURE_ERR_REPLAY:
      return "replayed or out-of-order packet";
    default:
      return "unknown error";
  }
}
