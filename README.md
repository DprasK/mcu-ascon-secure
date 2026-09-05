# Enkripsi ringan dan aman untuk mikrokontroler

Modul ini memakai **Ascon-AEAD128**, standar lightweight cryptography NIST
SP 800-232. AEAD mengenkripsi data sekaligus mendeteksi perubahan, kunci salah,
header palsu, dan tag yang rusak. Implementasi primitif kriptonya diambil tanpa
modifikasi dari repositori resmi `ascon/ascon-c` (CC0-1.0).

Saat mengambil repository ini, sertakan submodule implementasi Ascon:

```sh
git clone --recurse-submodules URL_REPOSITORY
```

Jika repository sudah terlanjur di-clone tanpa submodule:

```sh
git submodule update --init --recursive
```

## Ringkasan keamanan

- Kunci: 128 bit (16 byte).
- Nonce: 128 bit, dibentuk dari `device_id || key_epoch || counter`.
- Tag autentikasi: 128 bit (16 byte), tidak dipotong.
- Proteksi replay: counter diterima secara monoton; paket lama dan paket yang
  datang tidak berurutan ditolak.
- Overhead paket: 36 byte (`20-byte header + 16-byte tag`).
- Tidak membutuhkan random number generator untuk setiap paket.
- Kegagalan autentikasi menghapus plaintext sementara dari buffer keluaran.

Ascon aman hanya jika nonce tidak pernah diulang dengan kunci yang sama.
Karena itu `mcu_secure_tx_init()` hanya menerima **rentang counter yang sudah
dicadangkan secara permanen** di flash/EEPROM.

## Format paket versi 1

| Offset | Panjang | Isi |
|---:|---:|---|
| 0 | 2 | Magic `MS` |
| 2 | 1 | Versi `1` |
| 3 | 1 | Tipe pesan/aplikasi |
| 4 | 4 | Device ID, little-endian |
| 8 | 4 | Epoch kunci, little-endian |
| 12 | 8 | Counter, little-endian |
| 20 | N | Ciphertext |
| 20+N | 16 | Tag autentikasi |

Seluruh header diautentikasi. Byte 4 sampai 19 juga menjadi nonce Ascon.

## Cara pakai singkat

```c
#include "mcu_secure.h"

uint8_t key[16];          /* isi dari provisioning yang aman */
mcu_secure_tx_t tx;

/* Flash sudah dinaikkan dari 1000 ke 2024 dan diverifikasi SEBELUM init. */
mcu_secure_tx_init(&tx, key, DEVICE_ID, KEY_EPOCH, 1000, 1024);

uint8_t packet[64 + MCU_SECURE_OVERHEAD];
size_t packet_len;
mcu_secure_result_t rc = mcu_secure_seal(
    &tx, 1, payload, payload_len, packet, sizeof(packet), &packet_len);
```

Contoh lengkap ada di `example/example.c`.

### Reservasi counter tahan mati listrik

Misalkan nilai `nvm_next` di flash adalah 1000 dan blok reservasi 1024:

1. Baca `first = nvm_next`.
2. Hitung `new_next = first + 1024`, sambil memeriksa overflow.
3. Tulis `new_next` ke flash memakai mekanisme atomic/journal dua-slot.
4. Baca kembali dan verifikasi bahwa nilai tersimpan benar.
5. Baru panggil `mcu_secure_tx_init(..., first, 1024)`.
6. Saat blok habis, hentikan pengiriman sampai blok baru berhasil dicadangkan.

Jika listrik mati, sisa counter di blok lama sengaja dibuang. Jangan pernah
mengembalikan `nvm_next` ke nilai lama. Ukuran blok 1024 berarti sekitar satu
penulisan flash per 1024 paket.

`key_epoch` harus dinaikkan saat mengganti kunci. Jangan memakai kembali tuple
`key + device_id + key_epoch + counter`. Jika satu kunci dipakai oleh beberapa
perangkat, setiap `device_id` wajib unik; kunci unik per perangkat lebih baik.

## Build dan test di komputer

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Test mencakup known-answer test resmi NIST, round-trip, perubahan ciphertext,
perubahan header, replay, pesan kosong, dan habisnya rentang counter.

## Integrasi firmware

Untuk implementasi portabel, masukkan file berikut ke build system firmware:

- `src/mcu_secure.c`
- `vendor/ascon-c/crypto_aead/asconaead128/ref/aead.c`
- include path `include/`
- include path `vendor/ascon-c/crypto_aead/asconaead128/ref/`
- include path `vendor/ascon-c/tests/` (hanya berisi deklarasi API eBACS)

Gunakan C99 atau lebih baru. Buffer input dan output tidak boleh overlap.

Untuk produksi, pilih implementasi resmi sesuai CPU dan uji kembali KAT:

- ARM Cortex-M / MCU 32-bit: `opt32_lowsize`, `bi32_lowsize`, atau implementasi
  ARM yang sesuai target.
- ESP32: `esp32`.
- AVR 8-bit: `opt8` atau `bi8`.

Daftar file per backend berbeda; ikuti README dan CMake pada repositori vendor.
Mulailah dengan `ref` sampai seluruh test lulus, lalu ukur flash, RAM, dan waktu
eksekusi pada perangkat sebenarnya sebelum memilih backend tercepat/terkecil.

## Aturan produksi yang wajib

1. Buat kunci 16 byte dari CSPRNG saat provisioning; jangan dari password,
   MAC address, serial number, atau contoh di source code.
2. Simpan kunci di secure element/OTP/flash yang readout protection-nya aktif.
3. Jangan log kunci, plaintext rahasia, atau buffer setelah autentikasi gagal.
4. Cadangkan counter secara durable sebelum penggunaan seperti prosedur di atas.
5. Simpan replay state penerima jika replay setelah reboot juga harus ditolak.
6. Batasi percobaan gagal dan rotasi kunci jika perangkat diduga terekspos.
7. Proteksi fisik/side-channel memerlukan hardware dan implementasi masked;
   modul portable ini tidak menjanjikan proteksi terhadap power analysis atau
   fault injection.

## Struktur dan dependensi

`vendor/ascon-c` dikunci pada commit
`446347f21b209f3921c65ece70027c366cbe1693` saat modul dibuat. Lisensi upstream
tersedia di `vendor/ascon-c/LICENSE`.

## Algoritma eksperimen

Folder `experimental/experimental_aead_384/` berisi Experimental-AEAD-384-v0
untuk riset/pembelajaran. Algoritma ini sengaja tidak ikut build default dan
**tidak boleh dipakai untuk data nyata** karena belum diaudit atau
dikriptanalisis.
Aktifkan hanya untuk eksperimen dengan `-DMCU_SECURE_BUILD_EXPERIMENTAL=ON`.
