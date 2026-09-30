# Later (agreed with the owner: do these at the very end)

Nothing here is started. Order: unlock speed and progress first (small, useful now), Argon2 last.
All speed numbers below are estimates: measure on the device first (`docs/first-hardware.md`).

## 1. Faster unlocking (AES-KDF is almost all of the unlock time)

Today `kdbx_aes_kdf` (components/kdbx/kdbx.c) calls `mbedtls_aes_crypt_ecb` twice per round. On ESP-IDF each call
locks the AES peripheral, enables its clock, reloads the 256-bit key, does one block, releases it: that overhead
probably dominates. Unlock runs the KDF once; a normal save reuses the derived key (no second KDF).

1. **Hold the AES hardware for the whole loop** (biggest win, maybe several times faster): one
   `esp_aes_acquire_hardware()`, one `aes_hal_setkey()`, then a tight loop of `aes_hal_transform_block()` on both
   16-byte halves, release at the end (headers: mbedtls/port/include/aes/esp_aes.h, hal/aes_hal.h). Device-only
   fast path; keep the mbedTLS loop for the host and as a fallback; check both against the existing KDF test vectors.
2. **Unlock progress screen** (owner request): a dedicated screen while the KDF runs, with the percentage, elapsed
   time and estimated time remaining (today there is only a percent bar on the unlock screen, `ap_kdf_progress`
   in app.c). Must still wipe everything if it is cancelled or the battery dies; consider allowing Esc to cancel.
3. **"Target N seconds" for the round count** in Change password: time a few thousand rounds on the device and
   pick the round count for N seconds. A database tuned on a PC for 1 s can take much longer on the Cardputer.
4. Stay at 240 MHz during the loop (DFS lock): small gain, cheap.
5. Not recommended without a decision: keeping the derived key in RAM for a session behind a short PIN (near-instant
   re-unlock, but a short PIN weakens the protection). Second core / parallel work does not help: the AES engine is shared.

## 2. Argon2id through an encrypted SD swap

Argon2id needs tens of MiB; the device has ~330 KB of free heap at best and no PSRAM. The only way to open normal
Argon2 databases is to keep the blocks on the SD card, encrypted with a random per-unlock key that lives only in RAM
and is wiped afterwards (AES-CTR with nonce = block index + pass number, so no keystream is reused). This needs an
exception to the "nothing password-derived on SD" rule, which is safe only because of the ephemeral key.

Cost estimate (64 MiB, 3 passes): about 3 KiB of SD traffic per block (1 KiB random read, 1 KiB sequential read of
the old contents from pass 2 on, 1 KiB sequential write), roughly 600 MiB total. At ~2.5 MB/s that is ~4 min, plus
card latency: 5-10 min is realistic. About 200 MiB is written to the card per unlock. The SD slot is SPI only.

Optimisations, biggest payoff first:
1. Raw sector access on a contiguous region (or a preallocated contiguous file with a known start sector): no FAT walks.
2. SPI at 40 MHz if the card tolerates it, DMA, and a card with low random-read latency (A1/A2 class).
3. Batch the sequential traffic in 8-16 KiB chunks, pre-erase the write region.
4. Overlap computing with the sequential I/O (the random read cannot be prefetched in the Argon2d part).
5. Prefetch the data-independent first half of pass 1 (small gain).
6. Hardware AES for the swap encryption (costs almost nothing next to the SD).
Caching in RAM or running in parallel will not help (250 KB is 0.4% of 64 MiB; the bus is shared).

Cheaper first step: accept Argon2 only when memory <= ~256 KiB and parallelism is 1 (needs our own Argon2, mbedTLS has
none), and otherwise refuse with a message telling the user to switch the database to AES-KDF in KeePassXC.

Before building any of it: add an SD benchmark to `docs/first-hardware.md` (raw random-read latency and throughput at
20 and 40 MHz). Also fix the unlock RAM peak first (`docs/qemu.md`).
