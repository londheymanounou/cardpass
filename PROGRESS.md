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

## Stage 1 UI core (host): DONE, device glue TODO
- `components/ui`: strip renderer (screens draw into a 240x16 band pushed to the panel; no
  65 KB framebuffer), Cozette 6x13 (MIT) + Spleen 8x16 (BSD) with Latin-1 + Extended-A +
  icons (tools/gen_font.py; licenses in components/ui/FONT_LICENSES.txt), dark/light palettes.
- Screens (`app.c` core, `app_edit.c`, `app_tools.c`): database picker (last one preselected),
  unlock (masked, key file via Tab, KDF progress bar, errors), home (expiry alert, favorites,
  recent, groups), groups, live search, entry view (↵ type field, A auto-type, R reveal,
  Q QR, F favorite, E edit, fn+bksp delete → recycle bin), edit/new entry (inline editor,
  G generator, custom fields add/remove/protect, tags, fn+S save, confirm on leave), generator
  (password/passphrase, exact bits, types standalone), Tab menu, settings (theme, size, reveal,
  auto-lock, layout, key delay, time zone, weak threshold, expiry days, default auto-type; saved
  via the platform), password audit (weakest first, weak-only), expiring entries, new database
  (name, password twice, cipher, unlock-time target from a KDF benchmark, optional generated key
  file), key help (?). Status toasts; everything re-found by UUID after a save.
- `tests/host/render.c`: scripted key presses through the real app; after each step only dirty
  strips are redrawn (like the device) and compared with a full redraw; PNGs in
  `tests/host/build/renders/`. `tools/check_qr.py` decodes the QR screens with OpenCV.
- `tools/check_ui_files.py`: the databases the render script edited/created, checked with
  pykeepass + keepassxc-cli (edited URL + history, new entry in the recycle bin, protected custom
  field, created ChaCha20 database with its generated key file).
- TODO (device): the loop (TCA8418 keys, display push, sleep), USB/BLE HID, manual time set / NTP
  screens, group management screens (create/rename/move exist in kdbx, no UI yet).

## Stage 7 — Passkeys: core DONE, USB TODO
- `components/fido`: CBOR, CTAP2 getInfo + getAssertion over KeePassXC `KPEX_PASSKEY_*` entries
  (field names/format checked against KeePassXC's BrowserService.cpp/BrowserPasskeys.cpp:
  authData = SHA-256(rpId) | UP UV [BE BS] | counter 0; DER signature over authData||clientDataHash).
  ES256 + RS256; Ed25519 -> CTAP2_ERR_UNSUPPORTED_ALGORITHM (not in mbedTLS 3.6). Discoverable and
  allow-list requests; the user picks the account on the device; makeCredential/reset refused.
  CTAPHID framing (INIT/PING/WINK/CBOR, errors, reassembly).
- Tested (`test_fido`, `tools/check_passkeys.py`): assertions verified with pycryptodomex against
  the public keys; flags, counter, credential id, user handle checked; error paths.
- Open questions for real browsers: `up=false` requests are still confirmed by the user;
  `uv=true` declared because unlocking = master password. KEEPALIVE while waiting for the key press
  belongs to the device loop.

## Fuzzing
- `tests/host/fuzz.c` (in asan.sh): outer header, whole files with the right key (payload parsed
  before its HMAC), decrypted payloads (gzip → inner header → index), key files, otpauth /
  TimeOtp, auto-type, search, strength, CTAP2 requests, CTAPHID reports. No memory errors found.

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
- QEMU measurement (docs/qemu.md): ~262 B per entry in the index, unlock peak = index + ~60 KB; 800 entries
  unlock AND save on the 330 KB QEMU heap, 1,000 do not. Saving used to need the old index on top of ~110 KB of
  save buffers; `kdbx_save` now frees the index first and reopens afterwards, so a save costs the same as an unlock.
  Every pointer into the old index is dead after a save (the UI already re-finds things by uuid).
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

## Firmware skeleton: BUILDS (2026-09-30), never run on a device
- Framework decided and installed: PlatformIO `espressif32@6.12.0` + ESP-IDF 5.5 (mbedTLS 3.6).
- `firmware/`: platformio.ini, launcher-compatible partitions (same as ../deck), sdkconfig.defaults
  (silent panics, log NONE, no coredump, no secure boot / flash encryption, ChaCha20, LFN FAT).
  `firmware/src`: hw_display.c (ST7789 via esp_lcd panel-IO, M5GFX values), hw_keys.c (TCA8418,
  FIFO drain + wedge watchdog), hw_sd.c (pins verified in ../deck), hw_misc.c (RNG pool under
  bootloader_random, ADC battery, NVS settings, time), main.c (platform vtable + loop).
- Every shared component got a CMakeLists.txt; the whole app compiles for the ESP32-S3 with -Werror.
  IDF found real issues the host build had not: message truncations, an uninitialised variable, and
  the ROM `miniz.h` location.
- USB (esp_tinyusb 1.7.6 managed component, fetched by the IDF component manager): composite device
  with a HID keyboard (typing, `hw_usb_stroke`) and a FIDO HID interface. FIDO reports are queued
  by the USB task and handled in the main loop; a browser request opens a modal confirmation
  screen (`app_ask_passkey`: choose account, Enter approves, ` denies, 30 s timeout, auto-lock and
  fn+L suspended meanwhile) while CTAPHID KEEPALIVE packets go out every 100 ms. CDC (serial) is
  disabled: nothing can leak through the port.
- **USB drive mode (plan stage 4)**: Tab menu -> "USB drive" -> confirm. The app locks and wipes the
  database, unmounts FAT, opens the SD card raw (`hw_sd_raw_open`) and re-enumerates USB as a
  mass-storage-ONLY device (`hw_usb_drive`, esp_tinyusb MSC over `sdmmc_read/write_sectors`; no
  keyboard, no security key, no database open). Leaving (or `) waits for the last deferred write,
  drops MSC, remounts FAT, restores the composite HID device and rescans the files. Host-tested:
  locked before entering, nothing else reachable, a file copied meanwhile is listed afterwards.
  The SD/USB part is compile-verified only.
- **Setting the clock** (no RTC on the ADV): Tab menu -> "Set time" (also `T` on a TOTP row when the
  time is not set). By hand: date + time fields (typed, arrows, +-1 with wrap), entered as LOCAL time,
  converted to UTC with the time zone setting, live UTC preview, "set a few seconds ahead and press
  Enter on the beat". Over Wi-Fi + NTP: scan list, password (masked) with "remember this network"
  (up to 4, stored as hex in the settings text, i.e. NVS), saved networks reconnect without asking,
  wrong password can be retyped, 10 s connect / 10 s NTP timeouts, pool.ntp.org + time.cloudflare.com.
  Any time earlier than the firmware build date is rejected (also for manual entry). Wi-Fi is refused
  while a database is open (in the app AND in main.c), the radio is fully deinitialised after every
  call, and IDF stores no credentials (RAM storage, no NVS wifi data). "Set N min ago" shown.
  Host-tested end to end with stubs (57 screens/checks). The radio/NTP driver is compile-verified only.
- **Power management** (plan section 4, battery): idle stages dim (20 s) -> screen off (45 s) -> auto-lock
  (5 min), all in settings; a key that wakes a dark screen is swallowed (cannot type anything);
  never dims while a browser waits for a passkey; a dark screen draws nothing (dirty range is kept
  for the wake-up redraw) and the keyboard is polled at 20 Hz. Critical battery (<= 3 % in three
  readings 5 s apart, so load sag cannot trigger it): lock + wipe, message, deep sleep woken only by the
  keyboard interrupt. CPU: DFS 240/80 MHz with a max-frequency lock held only while the screen is at
  full brightness; NO light sleep (TinyUSB would not survive it). Host-tested with stubbed backlight /
  shutdown / battery; the actual current draw is a device measurement.
- **Change password / key file / unlock time**: current password re-verified against the file
  (`kdbx_check_key`: KDF + header HMAC, no second index), new password (+ generated or kept key file),
  unlock-time target from the benchmark; the old `.bak` is deleted (it still opens with the old
  password). Found and fixed on the way: generated key file name `name.kdbx` -> `name.keyx`.
- **Groups**: create, rename, move (tree chooser: never into itself/below itself, no no-op targets),
  delete via the recycle bin (root and recycle bin protected); `M` in the entry view moves an entry.
- **Attachment viewer**: Enter on a file row; first 16 KB as wrapped read-only text (16 KB, not 64: RAM),
  binary refused, buffer wiped on exit/lock.
- **Optional animations** (Settings -> Animations, default on): selection cross-fade, rows slide in
  on entering a list/entry, toast slides up, backlight fades in the firmware. No framebuffer needed:
  every effect is a function of state + time inside the strip drawing. Off automatically when dimmed,
  below 15 % battery and during passkey prompts; a key press ends the slide. `tools/make_anim_gif.py`
  renders them to dist/animations.gif from the real drawing code.
- **Bio-Resonant UI** (from D:/bio-resonant-ui): IBM Plex Sans (4-bit anti-aliased; 12 / 12 Medium / 13 / 21 px,
  888 glyphs each, Cozette kept as the fallback for icons), the four circadian modes as themes (Dusk, Deep night,
  Daylight, Sunrise) generated from its tokens.css with APCA re-checked after RGB565 (contrast-preserving
  quantisation: every ink keeps its exact Lc within 0.3), superellipse / capsule shapes (selection capsule with accent
  ring, sunken fields with focus ring, raised toasts, accent scroll thumb), title + rule header, geometry = its tokens
  scaled 13/21. Ink on the accent fill is always the on-accent ink (renderer rule). Deep night discloses its trade.
  Generators: tools/gen_br_theme.py, gen_br_font.py, gen_logo.py.
  Speed ("Nintendo" style): no framebuffer (strips), glyph index, 16-colour blend ramps, 32-bit fills, cached corner
  coverage, the logo pre-baked as a 26 KB ROM sprite (splash 269 -> 27 us/frame on the host), tests/host/bench.sh
  (fast paths on vs off: 1.6-1.9x). Device: double-buffered DMA strips (draw n+1 while n is sent), strips on a fixed
  grid with a 64-bit hash each, unchanged strips not sent, column window set once, RAMWRC between strips; the hashes
  are wiped when the database closes (they fingerprint what was on screen). Cost: a second 7.5 KB DMA buffer.
  Flash 1.12 -> 1.40 MB (fonts). Compile-checked only on the device.
- **Argon2** (`components/kdbx/argon2.c`): Argon2d / Argon2id (Argon2i too), versions 0x10 / 0x13, BLAKE2b, KDBX 4
  parameters (S, P, M, I, V, K, A). Memory in RAM when it fits, else an ENCRYPTED SD swap file (AES-256-CTR, random
  one-time key; processing-order layout so pass 0 appends and "rewritten this pass" = index < current; cache of
  recent blocks, batched writes, read-ahead). Saving keeps the parameters; a new password gives a new salt (still
  Argon2) unless a round count is chosen, which switches the database to AES-KDF.
  Verified: 50 vectors from argon2-cffi (reference C code) + RFC 9106 (secret + data) + 45 BLAKE2b, each in RAM and
  twice through swap; KeePass' default argon2.kdbx (64 MiB, 14 passes), pykeepass and KeePassXC-saved Argon2 files
  open with exact contents in RAM and swap; saved / rekeyed Argon2 files open in pykeepass and KeePassXC; UI unlock
  through swap; memscan: no key, composite key or Argon2 memory block left after lock (RAM and swap), and it fails
  when either wipe is removed (mutation tests; the test heap is configured like the ESP32's: no mmap, no trim).
  Bug caught on the way: a dangling `else` after turning the rekey KDF call into an error check made password changes
  write files that opened with neither password (the existing rekey test failed at once). Device speed: unmeasured;
  KeePass defaults (64 MiB, 10+ passes) will take tens of minutes on SD swap.
- **Memory paranoia** (`tests/host/memscan.sh`, Linux/WSL): drives the real app through a full session on a database
  with unique secrets (unlock, reveal, type, auto-type, TOTP, QR, edit + save, change master password, wrong
  password, lock), then scans the process's own writable memory (heap incl. freed blocks, stack incl. dead stack,
  libc data, .bss) for the master passwords, entry/protected/TOTP secrets, notes, the composite key, the AES-KDF
  chain value and the transformed key. Result: nothing left after lock, flat heap over 40 lock/unlock cycles.
  The scanner is validated three ways: it must find the transformed key while unlocked, find a planted secret in
  freed heap and in dead stack, and (mutation test, done by hand) it fails when the wipe in `kdbx_close` is removed.
  The scanner searches the last 12 bytes of each secret because glibc overwrites the first 16 bytes of a freed block.
  Not covered (hardware): the S3 AES/SHA peripheral registers (the AES fast path now overwrites its data registers
  with a zero block; SHA registers are overwritten by the HMAC blocks that follow), and the real device's RAM.
- **AES-KDF accelerator + unlock progress screen**: `kdbx_set_kdf_accel` hook in the portable code; `hw_aes.c` runs
  the S3 AES engine in plain block mode (mbedTLS sends each 16-byte block through GDMA, far slower), with a boot
  selftest against the portable loop. Host-tested (hook, chunking, fallback, progress), QEMU-checked (its AES model
  agrees), NOT run on the real chip: see docs/first-hardware.md 3h. The unlock / create / change-password progress
  screen shows percent, bar, elapsed and estimated time left. The rounds benchmark ("Unlock in N s") uses an
  adaptive probe so it times the fast path properly.
- **Splash / logo**: a tilted blank card with a key inside (from the owner's sketch), drawn from distance
  functions in `app_splash.c` (no bitmap, anti-aliased, follows the dark/light theme). Shown at start-up for
  3 s, any key skips it, Settings -> Splash turns it off (`splash=off` in the settings file). Host-tested.
- **Bluetooth typing** (plan stage 2): Tab menu -> Bluetooth. The radio is OFF until the user switches it
  on; it goes off again after 2 min without typing, on lock, and when USB drive mode starts. NimBLE
  HID-over-GATT keyboard "CardPass", LE Secure Connections with NUMERIC COMPARISON (6-digit code shown
  on the Cardputer, Enter confirms; a pairing request pops the code up wherever you are), bonding kept
  in NVS ("F" forgets all pairings). Security rules in `hw_ble.c`: sm_mitm + sc required, any other
  pairing method is refused, a link that is not encrypted AND authenticated is dropped, and a HID report
  is never sent unless the link is authenticated. Typing uses Bluetooth when a host is connected, else
  USB. Host-tested with stubs (80 screens/checks); the radio code is compile-verified only.
- **Size with everything: 1.10 MB app (27.6%), static RAM 68 KB** (USB + Wi-Fi + Bluetooth stacks; Wi-Fi/BT
  heap is only used while they are on). Free heap with a big database is THE number to measure first.
- (earlier) Size with animations: 926 KB app (23.2%), static RAM 56 KB.
- (earlier) Size with USB + drive mode + Wi-Fi + power: 915 KB app (22.9%), static RAM 56 KB.
- (earlier) Size with USB + drive mode + Wi-Fi: 902 KB app (22.6% of the 3.9 MB partition), static RAM 55 KB**
  (Wi-Fi/lwIP driver state; freed when Wi-Fi is off). Before Wi-Fi: 538 KB / 33 KB. dist/CardPass.bin
  (launcher) and CardPass-full.bin (M5Burner, merged) come from tools/package.py; header validated.
- Tested on the host: confirmation flow (approve second account / deny / timeout / not stuck).
  Everything USB-specific is compile-verified only.
- TODO: light sleep when no USB host is attached, real-device checks (docs/first-hardware.md), optional Grove RTC.
- LATER, at the very end (details in `docs/LATER.md`): faster unlocking (hold the AES hardware through the KDF loop),
  an unlock progress screen with elapsed/remaining time, a "target N seconds" round count, and Argon2id.
- LATER (owner likes it, not now): Argon2id via an encrypted SD swap. Argon2 blocks live on the SD card,
  encrypted with a random per-unlock key held only in RAM and wiped after; estimated 5-10 min per unlock for
  64 MiB (SPI-only SD, random 1 KiB reads, ~200 MiB written per unlock) - measure before promising. Needs an
  exception to the "nothing password-derived on SD" rule (safe only because of the ephemeral key). Cheaper
  first step: Argon2 only when memory <= ~256 KiB, else refuse and tell the user to switch to AES-KDF.
  Unlock RAM peak must be fixed first (see docs/qemu.md).

## Framework decision (was open)
- `../deck` (same Cardputer ADV) runs PlatformIO + Arduino-ESP32 2.x + M5Cardputer/M5GFX; its
  lessons are in this repo's notes (TCA8418 INT pin 11, drain the FIFO, wedge watchdog; RAM ceiling).
  Its code is PolyForm-Noncommercial: ideas only, nothing copied.
- CardPass's crypto uses mbedTLS 3.6 APIs = ESP-IDF 5.x. Arduino 2.x ships mbedTLS 2.28.
  Options: PlatformIO `framework = espidf` (IDF 5) + M5GFX as an IDF component + own TCA8418
  driver (recommended), or pioarduino (Arduino 3 on IDF 5) + M5Cardputer.

## Next step
Stage 1 on the device when it arrives: ESP-IDF project (`components/*/CMakeLists.txt` for IDF,
ROM `tinfl` via `rom/miniz.h`, `CONFIG_MBEDTLS_CHACHA20_C`, FATFS long file names for `.tmp`/`.bak`),
display, keyboard, SD, DB picker, unlock timing, AES-KDF benchmark (HW vs SW, 1 vs 2 cores).
