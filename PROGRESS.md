# Progress

Device (Cardputer ADV) not in hand yet (2026-09-28): everything that can be built and
tested on a PC is done first. All host suites: `ctest` in `tests/host/build` (7 suites) and
`tests/host/asan.sh` (ASan + LeakSanitizer + UBSan, WSL); saved/created files are also
checked by independent readers with `python tools/check_saved.py`.

## Stage 0 — Host core: DONE
- `components/kdbx`: streaming KDBX 4.x unlock (header → AES-KDF → header HMAC → HMAC blocks →
  AES-256-CBC / ChaCha20 → tinfl → inner header → yxml → compact index). Key files: XML v1/v2,
  raw 32, hex 64, hash-of-anything.
- Index: groups, entries (all String fields, tags, expiry, auto-type sequence), recycle-bin
  settings. Protected values stay ciphertext + inner keystream offset; `kdbx_reveal()` decrypts one.
- Chunked arena (never realloc'd), wiped by `kdbx_close()`.
- Tested: 18 manifest cases (AES/ChaCha20, pykeepass + KeePassXC-written, UTF-8 password, all key
  file formats, 1,000 entries, multi-block), intermediates vs `tools/ref_dump.py`, Argon2 / KDBX 3.1
  rejected cleanly, tamper detection.

## Attachments (text view)
- Index lists each entry's attachments (name, size; content skipped at unlock).
  `kdbx_attachment_read()` re-reads the file with the cached key (every block HMAC checked,
  no KDF) and copies the first N bytes; `kdbx_is_text()` decides text vs binary.
- Tested: text/binary detection, truncation mid-character, 1.5 MB multi-block attachment,
  wrong file rejected, still readable after edits/moves. PLAN.md decision updated.
- TODO on device: viewer screen (scroll, wipe buffer on leave/lock), pick the size cap.

## Stage 2 — Output methods: logic DONE, hardware TODO
- `components/typing`: layouts US, UK, FR AZERTY, DE QWERTZ (strings per key level, dead keys,
  compose table); auto-type parser/executor (`{USERNAME}`… `{S:Name}`, `{TOTP}`, special keys with
  repeat, `{DELAY n}`, `{DELAY=n}`, `+ ^ %` modifiers, `~`, literal escapes). The whole sequence
  is checked before the first keystroke: untypeable characters / unknown placeholders type nothing.
- Tested: all printable ASCII on every layout, layout accents, specific keystrokes, sequences.
- TODO on device: USB HID / BLE HID, keystroke delay, layout test string on real hosts
  (dead keys follow Windows; Linux/macOS may differ), QR code.

## Stage 3 — TOTP: logic DONE, time keeping TODO
- `components/totp`: RFC 6238/4226 (SHA-1/256/512, 6–8 digits, periods), `otpauth://`, KeePass 2
  `TimeOtp-*` (UTF-8/hex/base32/base64 secrets), Steam.
- Tested: RFC 6238 vectors, all encodings, matches `keepassxc-cli show -t` live.
- TODO on device: manual time set, NTP, Grove RTC, validity tracking.

## Stage 1 pieces done on host
- `components/search`: accent/case-insensitive scored subsequence search over title/user/URL/tags,
  multi-term, favorites + recent boost, empty query = home order. 0.4 ms / query / 1,000 entries
  on the PC (device estimate 8–16 ms, target 30 ms).

## Stage 5 — Editing: core DONE, UI TODO
- `components/kdbx/save.c`: streaming rewrite. Original re-read and turned into XML events;
  unknown XML, history, attachments, custom data carried over; protected values re-encrypted with
  a fresh inner stream key; new master seed + IV every save (KDF seed kept unless rekeying —
  avoids a 2–4 s KDF per save; transformed key cached in RAM while unlocked, wiped on close).
- Edits: entry create / update (old version → History, `HistoryMaxItems` enforced) / move /
  delete; group create / rename / move / delete; `kdbx_delete_entry/group()` give KeePass
  semantics (recycle bin, created on demand; permanent + DeletedObjects when already in it or
  disabled). Moves use a first capture pass. Master key / rounds change.
- Safe save: `.tmp` → verify by re-opening → original kept as `.bak` → rename;
  `kdbx_recover()` finishes an interrupted rename. Failed saves leave the original byte-identical.
- Output compression: own LZ77 + fixed-Huffman deflate (~16 KB RAM; miniz's tdefl needs ~300 KB),
  stored-block fallback for incompressible data. big1000: 51 KB (KeePassXC) → 100 KB (ours).
- Tested: no-op saves of all test DBs identical per pykeepass XML, attachments and KeePassXC
  XML export; every edit type; history content; DeletedObjects; moved entry keeps its attachment;
  rekey; recovery; ChaCha20 and multi-block files.
- TODO: generator/editor UI, favorites toggle UI (= tags edit), device RAM check during save.

## Stage 6 — Create database: DONE (host)
- `kdbx_create()` (AES or ChaCha20, AES-KDF rounds, password and/or key file, recycle bin on),
  `kdbx_keyfile_create()` (KeePass XML v2). Tested with pykeepass and KeePassXC.
  KeePass 2 not available here: check once on a PC with KeePass 2.

## Stage 5 generators: DONE
- `components/gen`: password (sets, look-alikes, require-each, exact entropy incl. inclusion–
  exclusion) and passphrase (EFF long list embedded front-coded, 33 KB; separators, caps,
  digit/symbol appended to a random word; exact entropy; ambiguity warning). Rejection sampling.

## Stage 6b — Strength: estimator DONE, audit UI TODO
- `components/strength`: cheapest split into common words (leet/caps), EFF words, sequences,
  repeats, keyboard walks, years, brute force. Same Weak/Strong label as KeePassXC on 19 reference
  passwords (numbers from `keepassxc-cli estimate`), incl. password1 / azerty123 / Summer2024!.

## RAM budget (tests/host/mem_probe, ESP32-S3 struct sizes from xtensa gcc)
| | index | unlock peak | save (on top of index) | attachment view |
|---|---|---|---|---|
| 5 entries | ~6.5 KB | ~86 KB | ~121 KB | ~56 KB + view buffer |
| 1,000 minimal entries | ~232 KB | ~370 KB (host) | ~101 KB | same |
- ~230 B per minimal entry (struct 80 B + 16 B per field + the text itself); notes and custom
  fields add their length. With ~300 KB free heap (no framebuffer!) that is ~800 typical entries;
  measure the real free heap on the device first.
- Done: standard field names shared, strings unaligned, empty values not stored, fields packed
  per entry (was 321 KB for 1,000); save verifies the written file without building an index and
  frees the old index before building the new one (was +528 KB for 1,000).
- Lesson from ../deck (same hardware): a 65 KB full-frame sprite left it ~1 KB from a boot
  failure. CardPass UI must draw straight to the panel / small strips, no full framebuffer.

## Deviations from PLAN.md (deliberate)
- No `crypto/` wrapper: mbedTLS is called directly (ESP-IDF's routes to hardware).
- Index stores decoded ciphertext (not base64) and all string fields (entry view needs no re-read).
- Decrypted data is parsed before its 1 MiB block's HMAC is checked (can't buffer 1 MiB);
  any failure wipes everything.
- Passphrase digit/symbol are appended to a random word (not a random character position) so
  the entropy stays exact.
- Platform RNG is one function, `cp_random()`, used by kdbx and gen (device: `esp_fill_random`
  inside `bootloader_random_enable/disable`).

## Known limits
- gzip with optional header fields rejected (never written by KeePass/KeePassXC).
- Inner stream must be ChaCha20 (KDBX 4 default).
- Save: Entry/Group must have UUID as first child (KeePass always writes it so);
  `PreviousParentGroup` / `LocationChanged` not updated on moves; `HistoryMaxSize` not enforced;
  modifier groups `+(abc)` in auto-type unsupported (reported, never typed).
- Moving a large group holds its subtree in RAM during save.
- Host Windows gcc has no ASan: sanitizer runs use WSL.

## Next step
Stage 1 on the device when it arrives: ESP-IDF project (`components/*/CMakeLists.txt` for IDF,
ROM `tinfl` via `rom/miniz.h`, `CONFIG_MBEDTLS_CHACHA20_C`, FATFS long file names for `.tmp`/`.bak`),
display, keyboard, SD, DB picker, unlock timing, AES-KDF benchmark (HW vs SW, 1 vs 2 cores).
