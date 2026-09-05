#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mcu_secure.h"

int main(void) {
  /* Provision this from a CSPRNG; never use a source-code key in production. */
  const uint8_t demo_key[MCU_SECURE_KEY_SIZE] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  const uint8_t sensor_data[] = {0x19, 0x64, 0x01, 0x00};
  uint8_t packet[sizeof(sensor_data) + MCU_SECURE_OVERHEAD];
  uint8_t recovered[sizeof(sensor_data)];
  size_t packet_len = 0u;
  size_t recovered_len = 0u;
  uint8_t message_type = 0u;
  uint64_t counter = 0u;
  mcu_secure_tx_t tx;
  mcu_secure_rx_t rx;
  mcu_secure_result_t result;

  /* In real firmware, reserve [1000, 2023] durably before this call. */
  result = mcu_secure_tx_init(&tx, demo_key, 0x12345678u, 1u, 1000u, 1024u);
  if (result != MCU_SECURE_OK) return 1;
  result = mcu_secure_rx_init(&rx, demo_key, 0x12345678u, 1u, false, 0u);
  if (result != MCU_SECURE_OK) return 1;

  result = mcu_secure_seal(&tx, 0x01u, sensor_data, sizeof(sensor_data),
                           packet, sizeof(packet), &packet_len);
  if (result != MCU_SECURE_OK) {
    printf("encrypt: %s\n", mcu_secure_result_string(result));
    return 1;
  }

  result = mcu_secure_open(&rx, packet, packet_len, recovered,
                           sizeof(recovered), &recovered_len, &message_type,
                           &counter);
  if (result != MCU_SECURE_OK) {
    printf("decrypt: %s\n", mcu_secure_result_string(result));
    return 1;
  }

  printf("ok: type=%u counter=%llu bytes=%lu\n", (unsigned)message_type,
         (unsigned long long)counter, (unsigned long)recovered_len);

  mcu_secure_tx_destroy(&tx);
  mcu_secure_rx_destroy(&rx);
  return memcmp(sensor_data, recovered, sizeof(sensor_data)) == 0 ? 0 : 1;
}
