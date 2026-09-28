# CardPass

Offline KeePass (KDBX 4.x, AES-KDF only) password manager for the M5Stack Cardputer ADV
(ESP32-S3, 512 KB SRAM, no PSRAM), ESP-IDF 5.x. Full plan: `PLAN.md`. Status: `PROGRESS.md`.
Work one stage per session; update `PROGRESS.md` at the end.

## Hard security rules

```
- Never log, print, or send secrets anywhere (passwords, keys, decrypted fields,
  TOTP secrets, passkey private keys), even in debug builds. Debug hex dumps of
  intermediate crypto values are allowed ONLY behind DEBUG_SECRETS, which must
  refuse to compile in release builds.
- Release builds: log level NONE, core dumps disabled, panic handler = silent reboot,
  USB CDC serial console disabled.
- Nothing decrypted is ever written to SD, flash, or NVS. No temp files with plaintext.
- No Arduino String / std::string for secrets. Fixed buffers only, wiped with
  mbedtls_platform_zeroize() immediately after use.
- Protected fields are decrypted on demand and wiped right after display/typing.
- All randomness from the hardware RNG (esp_fill_random) with an entropy source
  active. Since Wi-Fi is never on while unlocked, use bootloader_random_enable()
  around every generation (passwords, salts, IVs, keys), then
  bootloader_random_disable(). It conflicts with the ADC, so pause battery
  readings while it is enabled. Never rand().
- Random selection must use rejection sampling (no modulo bias).
- Wi-Fi may only be enabled while the database is LOCKED, and only for NTP.
- Bluetooth only on while BLE typing is actively in use.
- On lock / timeout / USB drive mode / sleep: wipe all keys, index, and buffers.
- Never test with a real password database until the stage's tests pass on test files.
- NEVER burn eFuses or enable Secure Boot / flash encryption. The firmware must stay
  flashable by M5Burner and SD-card launchers.
- Everything the app needs (wordlist, fonts, layouts) is embedded in the app binary.
  No custom partitions; settings go in NVS or a settings file on the SD card.
```

## Layout

- `components/kdbx/` — portable C (mbedTLS + tinfl only, no ESP-IDF deps). `yxml/` is vendored.
- `tests/host/` — CMake host build + acceptance test; `asan.sh` for ASan/LSan/UBSan (Linux/WSL).
- `tools/` — `make_test_dbs.py` (test DBs), `ref_dump.py` (reference values, `testdata/*.expected`).
- `testdata/` — test databases only (passwords in `tools/ref_dump.py`, not secrets).

## Host build

```
cmake -S tests/host -B tests/host/build -G Ninja -DCMAKE_TLS_CAINFO=<ca-bundle.crt>
cmake --build tests/host/build && tests/host/build/test_kdbx testdata
wsl sh /mnt/d/cardpass/tests/host/asan.sh     # after the configure above
```
`CMAKE_TLS_CAINFO` is only needed where CMake has no CA store (this Windows box: copy
Git's `mingw64/etc/ssl/certs/ca-bundle.crt` to a path without spaces).
