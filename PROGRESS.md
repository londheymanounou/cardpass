# Progress

## Stage 0 — Host core: DONE (2026-09-28)

**Done**
- `components/kdbx`: streaming KDBX 4.x unlock: header → AES-KDF → header HMAC (wrong-key check)
  → HMAC blocks → AES-256-CBC / ChaCha20 → gzip (tinfl, 32 KB window) → inner header
  (attachments skipped) → yxml → compact index. Key files: XML v1/v2, raw 32, hex 64, hash-of-anything.
- Index: groups (name, parent, UUID) and entries (UUID, group, all String fields, tags, expiry).
  Protected values stay as raw ciphertext + inner ChaCha20 keystream offset; `kdbx_reveal()`
  seeks and decrypts one value on demand. History is parsed only to count keystream bytes.
- All index memory lives in a chunked arena (never realloc'd), wiped + freed by `kdbx_close()`.
- `tools/make_test_dbs.py`, `tools/ref_dump.py` (manual crypto, checked against each file's HMACs).

**Tested** (`tests/host/test_kdbx.c`, 18 manifest cases + tamper/key-file checks)
- AES and ChaCha20, pykeepass-written and KeePassXC-resaved, UTF-8 password, all 5 key-file
  formats, key-file-only, 1,000 entries, multi-block (1.5 MB attachment).
- Composite key, transformed key, master key, HMAC base key match the reference script;
  every entry / field (incl. protected ones) / tag / expiry matches pykeepass.
- Wrong password and missing key file fail at the header HMAC; Argon2 → clean KDF error;
  KDBX 3.1 (hand-made + real KeePassXC `db-create`) → clean version error;
  damaged header / payload → "corrupted"; bad XML v2 key-file hash rejected.
- Clean under ASan + LeakSanitizer + UBSan (WSL gcc, `tests/host/asan.sh`).

**Deviations from PLAN.md (deliberate)**
- No `crypto/` wrapper component: `kdbx` calls mbedTLS directly (ESP-IDF's mbedTLS already
  routes AES/SHA to hardware). Add a wrapper only if a second backend appears.
- Index stores decoded ciphertext, not base64 (25% less RAM). It also keeps notes and custom
  fields so the entry view needs no second pass over the file.
- Decrypted data is parsed before its 1 MiB block's HMAC is verified (can't buffer 1 MiB);
  on any failure everything is wiped and no index is returned.

**Known limits / notes**
- gzip header with optional fields (FNAME etc.) is rejected — KeePass/KeePassXC never write them.
- Inner stream must be ChaCha20 (KDBX 4 default); Salsa20 → cipher error.
- `kdbx_aes_kdf` runs both halves on one core; Stage 1 benchmarks splitting them across cores
  and hardware vs software AES (ESP-IDF's per-call AES HW locking may be slow for 1-block calls).
- Index RAM grows with notes size; measure the high-water mark on device (Stage 1/9).
- Host Windows gcc (WinLibs) has no ASan; sanitizer runs use WSL.

**Next step:** Stage 1 — ESP-IDF project, display, keyboard, SD, DB picker, unlock on device
(add `components/kdbx/CMakeLists.txt` for IDF; ROM `tinfl` via `rom/miniz.h`, enable
`CONFIG_MBEDTLS_CHACHA20_C`).
