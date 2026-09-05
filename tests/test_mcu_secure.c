#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto_aead.h"
#include "mcu_secure.h"

static void test_nist_known_answer(void) {
  const uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                           0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                           0x0c, 0x0d, 0x0e, 0x0f};
  const uint8_t nonce[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                             0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                             0x1c, 0x1d, 0x1e, 0x1f};
  const uint8_t expected[16] = {0x4f, 0x9c, 0x27, 0x82, 0x11, 0xbe,
                                0xc9, 0x31, 0x6b, 0xf6, 0x8f, 0x46,
                                0xee, 0x8b, 0x2e, 0xc6};
  uint8_t ciphertext[16];
  uint8_t empty = 0u;
  unsigned long long ciphertext_len = 0u;

  assert(crypto_aead_encrypt(ciphertext, &ciphertext_len, &empty, 0u, &empty,
                             0u, NULL, nonce, key) == 0);
  assert(ciphertext_len == sizeof(expected));
  assert(memcmp(ciphertext, expected, sizeof(expected)) == 0);
}

static void test_round_trip_tamper_replay_and_counter_limit(void) {
  const uint8_t key[16] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
                           0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
                           0xac, 0xad, 0xae, 0xaf};
  const uint8_t message[] = "suhu=25.4";
  uint8_t packet[sizeof(message) + MCU_SECURE_OVERHEAD];
  uint8_t packet2[sizeof(message) + MCU_SECURE_OVERHEAD];
  uint8_t output[sizeof(message)];
  size_t packet_len = 0u;
  size_t packet2_len = 0u;
  size_t output_len = 99u;
  uint8_t type = 0u;
  uint64_t counter = 0u;
  mcu_secure_tx_t tx;
  mcu_secure_rx_t rx;

  assert(mcu_secure_tx_init(&tx, key, 7u, 3u, 42u, 2u) == MCU_SECURE_OK);
  assert(mcu_secure_rx_init(&rx, key, 7u, 3u, false, 0u) == MCU_SECURE_OK);

  assert(mcu_secure_seal(&tx, 9u, message, sizeof(message), packet,
                         sizeof(packet), &packet_len) == MCU_SECURE_OK);
  assert(mcu_secure_open(&rx, packet, packet_len, output, sizeof(output),
                         &output_len, &type, &counter) == MCU_SECURE_OK);
  assert(output_len == sizeof(message));
  assert(type == 9u);
  assert(counter == 42u);
  assert(memcmp(output, message, sizeof(message)) == 0);

  memset(output, 0x55, sizeof(output));
  output_len = 99u;
  assert(mcu_secure_open(&rx, packet, packet_len, output, sizeof(output),
                         &output_len, NULL, NULL) == MCU_SECURE_ERR_REPLAY);
  assert(output_len == 0u);
  for (size_t i = 0; i < sizeof(output); ++i) assert(output[i] == 0u);

  memcpy(packet2, packet, packet_len);
  packet2[MCU_SECURE_HEADER_SIZE] ^= 0x01u;
  memset(output, 0x55, sizeof(output));
  assert(mcu_secure_open(&rx, packet2, packet_len, output, sizeof(output),
                         &output_len, NULL, NULL) == MCU_SECURE_ERR_AUTH);
  for (size_t i = 0; i < sizeof(output); ++i) assert(output[i] == 0u);

  assert(mcu_secure_seal(&tx, 9u, message, sizeof(message), packet2,
                         sizeof(packet2), &packet2_len) == MCU_SECURE_OK);
  assert(packet2_len == packet_len);
  assert(memcmp(packet, packet2, packet_len) != 0);
  assert(mcu_secure_seal(&tx, 9u, message, sizeof(message), packet2,
                         sizeof(packet2), &packet2_len) ==
         MCU_SECURE_ERR_COUNTER_EXHAUSTED);

  packet[3] ^= 0x01u;
  assert(mcu_secure_rx_init(&rx, key, 7u, 3u, false, 0u) == MCU_SECURE_OK);
  assert(mcu_secure_open(&rx, packet, packet_len, output, sizeof(output),
                         &output_len, NULL, NULL) == MCU_SECURE_ERR_AUTH);
}

static void test_empty_message(void) {
  const uint8_t key[16] = {0};
  uint8_t packet[MCU_SECURE_OVERHEAD];
  size_t packet_len = 0u;
  size_t output_len = 1u;
  mcu_secure_tx_t tx;
  mcu_secure_rx_t rx;

  assert(mcu_secure_tx_init(&tx, key, 1u, 1u, 0u, 1u) == MCU_SECURE_OK);
  assert(mcu_secure_rx_init(&rx, key, 1u, 1u, false, 0u) == MCU_SECURE_OK);
  assert(mcu_secure_seal(&tx, 0u, NULL, 0u, packet, sizeof(packet),
                         &packet_len) == MCU_SECURE_OK);
  assert(packet_len == MCU_SECURE_OVERHEAD);
  assert(mcu_secure_open(&rx, packet, packet_len, NULL, 0u, &output_len, NULL,
                         NULL) == MCU_SECURE_OK);
  assert(output_len == 0u);
}

int main(void) {
  test_nist_known_answer();
  test_round_trip_tamper_replay_and_counter_limit();
  test_empty_message();
  puts("all tests passed");
  return 0;
}
