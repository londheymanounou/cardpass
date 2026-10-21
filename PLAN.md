# CardPass — KeePass (KDBX 4.1) client for M5Stack Cardputer ADV

A fast, offline password manager with strict software-level secret handling, running on the Cardputer ADV (ESP32-S3FN8, 512 KB SRAM, 8 MB flash, no PSRAM), compatible with KeePassXC / KeePass 2 databases.

## 1. Decisions (from requirements)

| Topic | Decision |
|---|---|
| Framework | ESP-IDF (v5.x), C for the core, C or C++ for UI |
| Optimization priority | 1. Unlock/UI speed → 2. Battery life → 3. Low RAM → 4. Firmware size |
| Format | KDBX 4.0 / 4.1 read + write. KDBX 3.1 and older are detected and rejected with a clear message |
| KDF | AES-KDF only. Argon2 databases are detected and rejected with a clear message |
| Cipher | AES-256-CBC and ChaCha20 (both supported) |
| Unlock | Master password + optional key file |
| Re-lock | Stay unlocked until timeout, then full password again (no PIN) |
| Databases | Multiple `.kdbx` files, chosen at unlock |
| Output | Screen, QR code, USB keyboard typing, Bluetooth keyboard typing |
| Keyboard layouts | Multiple, selectable (host layout matters for typing) |
| TOTP time | Manual entry + Wi-Fi NTP sync (locked state only). Optional Grove RTC module supported if plugged in |
| Sync | Manual file copy: remove SD card, or USB drive (MSC) mode |
| Editing | Add / edit / delete entries, password generator, create new database |
| Passkeys | Use KeePassXC passkeys stored in the KDBX; register new ones (ES256, saved as KeePassXC-compatible entries) |
| Hardening | Software-only. NO eFuse burning (no Secure Boot, no flash encryption, no JTAG fuse) |
| Distribution | Must flash and run from M5Burner and SD-card launchers (e.g. M5Launcher), like any normal Cardputer firmware |
| Password reveal | Setting: "hold key to reveal" OR "press key to toggle reveal" (user's choice) |
| Attachments & custom icons | Attachments are listed (name, size) and can be opened read-only as text (UTF-8 only, first 64 KB; binary files show "can't display"). Never decoded as images/PDF, never written anywhere. Custom icons never displayed; every entry shows one built-in key icon. Both preserved untouched on save |
| Favorites | Stored as a `favorite` tag in the database itself (syncs with KeePassXC, nothing stored on the device) |
| Recent entries | RAM only, per session; cleared on lock (no usage history written anywhere) |
| Not included (by choice) | Wrong-password delay, rotating backups (a single `.bak` from safe-save remains), attachment viewing, database merging, self-destruct |

## 2. Hard security rules (copy these into CLAUDE.md)

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

## 3. Architecture

```
components/
  kdbx/        Portable C, NO ESP-IDF deps. Header, KDF, HMAC blocks, decrypt,
               inflate, inner header, streaming XML, index, streaming rewrite.
  crypto/      Thin wrapper over mbedTLS (SHA-256, HMAC, AES, ChaCha20, ECDSA P-256,
               HMAC-SHA1/256/512). Host build uses the same mbedTLS.
  ui/          Screens, input, list rendering (esp_lcd or LovyanGFX/M5GFX).
  kbd_layout/  Char → HID keycode+modifier tables per host layout.
  usb/         esp_tinyusb composite device: HID keyboard + FIDO HID + MSC.
  ble_hid/     NimBLE HID keyboard.
  fido/        Minimal CTAP2 (getInfo, getAssertion) + CTAPHID transport.
  totp/        RFC 6238 over RFC 4226, otpauth:// and KeePass 2 TimeOtp-* parsing.
  timekeep/    Manual set, Wi-Fi NTP sync, optional Grove RTC driver, time-validity tracking.
  storage/     SD card (FAT), safe-save, file listing.
  gen/         Password + passphrase generator (EFF long wordlist in flash).
tests/host/    CMake host build of kdbx/crypto/totp/gen + test vectors.
tools/         Python reference scripts (pykeepass) to dump intermediate values.
```

The `kdbx`, `totp` and `gen` components must build and pass tests on a PC before touching hardware. This allows most of the work to be done before the device arrives.

## 4. Core design (speed + low RAM)

**Unlock pipeline (streaming, no full-file buffers):**
1. Read outer header; reject unless KDBX 4.x + AES-KDF.
2. Composite key = SHA-256(SHA-256(password) ‖ keyfile_hash). Support KeePass key file formats: XML v1/v2, 32-byte raw, 64-char hex, and hash-of-anything.
3. AES-KDF: the two 16-byte halves run in parallel, one per core. Key schedule computed once. Use hardware AES where faster; benchmark hardware vs software AES per core and pick the fastest combo.
4. Verify header HMAC → this is the "wrong password" check (fast fail).
5. Stream HMAC blocks → decrypt → inflate (ROM tinfl / miniz, 32 KB window) → XML parser (yxml, streaming).
6. Build a compact in-RAM **index**: per entry title, username, URL, group, tags, UUID, and for each protected field its **base64 ciphertext + inner-stream (ChaCha20) byte offset**. ChaCha20 is seekable, so any protected value can be decrypted on demand without keeping plaintext in RAM.

**Targets:**
- Boot to database picker: < 1 s
- Unlock (excluding KDF): < 1 s for a few hundred entries
- KDF: user-tuned, target 2–4 s (built-in benchmark → recommended rounds)
- Search: results update per keystroke, < 30 ms for 1,000 entries
- UI: redraw only changed regions, no full-screen redraws while scrolling

**Battery:**
- Dynamic frequency scaling + automatic light sleep when idle
- Keyboard input via interrupt, not polling (check whether the ADV keyboard controller supports it)
- Backlight dimming and screen off after short idle, lock on longer idle
- Radios off by default

## 5. Stages

Each stage has acceptance tests. Don't start the next until they pass.

### Stage 0 — Host core (no device needed)
- Test databases made in KeePassXC (select **"AES-KDF (KDBX 4)"**, not "AES-KDF (KDBX 3.1)", which produces an old-format file): AES-256 + AES-KDF, ChaCha20 + AES-KDF, with key file, with attachments/history/tags/custom fields, one Argon2 DB (must be rejected), 1,000-entry DB.
- Python script (pykeepass + manual crypto) printing composite key, transformed key, HMAC key, first block HMAC.
- Implement the unlock pipeline + index on the host.
- ✅ All test DBs open, values match the reference script, wrong password fails at the header HMAC, Argon2 DB gives a clean error, no leaks under AddressSanitizer/Valgrind.

### Stage 1 — Device basics: read-only client
- ESP-IDF project, display, keyboard, SD card, database picker (all `.kdbx` in a folder).
- Password entry screen (masked), optional key file picker.
- Group browser and entry view. Every entry and group uses a built-in key/folder icon; custom icons and attachments are skipped by the parser (only their byte ranges are remembered for the streaming rewrite).
- **Home screen:** favorites (entries tagged `favorite`) first, then recent entries of this session, then groups.
- **Text & accents:** titles/usernames/notes are UTF-8. The UI font must include Latin accented characters (é, è, à, ç, ü, ñ, etc.); anything missing shows a placeholder glyph, never garbage.
- **Fuzzy search:** case- and accent-insensitive ("cafe" finds "Café") subsequence matching with scoring ("gml" → "Gmail"), across title, username, URL, and tags; results ranked with favorites/recent boosted; updates on every keystroke.
- **Entry view:** title, username, URL, tags, notes, custom fields (protected custom fields hidden like passwords), expiry date.
- **Reveal:** per the setting, hold a key to reveal (hidden again on release) or press a key to toggle; either way hidden again when leaving the entry or on lock.
- **Battery:** indicator in the status bar; at a critical level, lock and wipe secrets before shutdown.
- **Settings screen:** theme, brightness, auto-lock time, font size, reveal mode, keyboard layout, typing speed, default autotype sequence, time zone. Stored in NVS (no secrets).
- **Light and dark mode:** all UI colors come from one palette struct (RGB565, precomputed at compile time), with a light and a dark palette; no hard-coded colors anywhere in UI code. Switching theme applies instantly with one full redraw. Default: dark. Both palettes must keep good contrast (warnings/weak passwords, TOTP countdown, selection highlight readable in both). QR codes are always drawn black-on-white regardless of theme so phones can scan them.
- Auto-lock timeout (configurable) + lock key; wipe everything on lock.
- KDF benchmark screen.
- ✅ Open all test DBs on device, unlock time within target, memory freed and zeroed on lock.

### Stage 2 — Output methods
- **USB HID keyboard:** type username, password, or the entry's autotype sequence.
- **Autotype sequences:** parse KeePass autotype syntax per entry (`{USERNAME}`, `{PASSWORD}`, `{TOTP}`, `{TAB}`, `{ENTER}`, `{DELAY n}`, `{URL}`, custom fields `{S:Name}`, repeat counts like `{TAB 2}`). Default sequence from settings when the entry has none. Unsupported placeholders are reported, never typed literally.
- **Typing speed:** configurable delay between keystrokes (some PCs, VMs, and remote desktops drop fast keys).
- **Layouts:** tables for US QWERTY, FR AZERTY, DE QWERTZ, UK, plus an easy format to add more. Layout selectable in settings and remembered. Warn when a character can't be typed on the chosen layout. A "layout test" that types a test string.
- **QR code:** Nayuki qrcodegen, shown full-height; cleared on any key or after a few seconds.
- **BLE HID keyboard:** NimBLE, bonding; BT on only while in use.
- **Non-ASCII typing:** layout tables include characters the layout has directly (e.g. `é è à ç ù` on AZERTY) and dead-key combinations where needed; anything the chosen layout can't type triggers a warning before typing starts, never a partial/wrong password.
- ✅ Typing is correct on each layout for a string containing all printable ASCII, plus that layout's accented characters.

### Stage 3 — TOTP
- Parse KeePassXC `otp` field (`otpauth://`) and KeePass 2 `TimeOtp-*` fields.
- SHA-1/256/512, 6–8 digits, custom period; countdown bar.
- **Type TOTP:** send the current code over USB/BLE typing (also usable as `{TOTP}` in autotype). If the code has under ~3 s left, wait for the next one before typing.
- Time is kept internally in UTC (TOTP uses UTC). The local time zone is a display-only setting.
- **Manual set screen:** date + time entry from the keyboard, with a live preview and a seconds field (TOTP needs accuracy within a few seconds).
- **Internet sync (NTP):**
  - Only available while the database is LOCKED. Wi-Fi turns on, syncs via ESP-IDF SNTP (several servers, e.g. pool.ntp.org + time.cloudflare.com), then turns Wi-Fi fully off.
  - Wi-Fi network picker (scan + password entry). Saved networks stored in NVS (not secret-critical, but never store anything from the database there, except a Wi-Fi password the user fetches from the entry named like the network, on the Wi-Fi password screen: the database is opened, that one password taken, the database locked and wiped, and only then does Wi-Fi start; it is saved like a typed password, only after it connected). Option to not save a network.
  - Timeout (~10 s) with clear success/failure message. Sanity check: reject any time earlier than the firmware build date.
- **Optional Grove RTC:** if a supported RTC module is detected on I2C at boot, read time from it, and write to it after every manual set or NTP sync.
- **Time validity:** track whether time was set since the last power-on (or comes from the RTC). If not, TOTP screen shows "Time not set" with shortcuts to manual set / NTP instead of showing wrong codes.
- Time survives deep sleep via the ESP32 internal timer, but may drift; show "last synced" age on the TOTP screen and suggest resync after long sleeps.
- ✅ Matches RFC 6238 test vectors and KeePassXC codes.

### Stage 4 — USB drive mode + multi-DB polish
- MSC mode exposes the SD card to the PC. Entering it locks the database and unmounts FAT on the device; leaving it remounts and rescans.
- ✅ Copy files both ways without corruption; database always locked in drive mode.

### Stage 5 — Editing + password generator
- **Streaming rewrite:** re-read the original file and write a new one, copying all unknown XML verbatim (history, attachments, custom data, 4.1 tags, etc.) and applying edits on the fly. Protected values are re-encrypted with a new inner stream key. New salts/IVs each save.
- Add / edit / delete entries. Delete follows KeePass semantics (recycle bin if enabled, else DeletedObjects). Edits add a history entry.
- **Safe save:** write `name.kdbx.tmp` → fully re-open and verify → keep `name.kdbx.bak` → rename.
- **Generator:** length, character sets, exclude look-alikes, require each set, exact entropy shown in bits (known from the generation settings, so no estimate needed).
- **Passphrase generator (English only):**
  - EFF long wordlist (7,776 words, ~12.9 bits/word) embedded in the app binary, compressed if it helps firmware size. Keep the EFF license/attribution (CC BY) in the repo and an About screen.
  - Word count 4–10 (default 6 ≈ 78 bits); words picked with the hardware RNG using rejection sampling.
  - Separator: `-`, space, `.`, `_`, or none.
  - Capitalization: none, first letter of each word, or one random word.
  - Optional extra digit and/or symbol inserted at a random position.
  - Exact entropy computed from all chosen options and shown live, e.g. `6 words · 77.5 bits`.
  - Warn when the separator is "none" and capitalization is off (word boundaries become ambiguous; entropy shown stays correct but typing/reading gets harder).
- **Custom fields and notes:** add, edit, delete; mark a custom field as protected.
- **Favorites:** toggle the `favorite` tag from the entry view (saved to the database).
- **Group management:** create, rename, move, delete groups (delete = move to recycle bin if enabled); move entries between groups.
- **Change master password / key file / AES-KDF rounds:** re-save the database with new settings, with rounds suggested from the benchmark. Requires the current password again before changing.
- ✅ A DB edited on the device opens in KeePassXC with all original data intact. Power loss during save never corrupts the original.

### Stage 6 — Create database
- New KDBX 4.1 DB: choose cipher, AES-KDF rounds (from benchmark), password, optional key file (generate a KeePass XML v2 key file).
- ✅ Created DBs open in KeePassXC and KeePass 2.

### Stage 6b — Insights
- **Expiry warnings:** list of expired entries and those expiring within N days (setting); badge on the home screen.
- **Password strength audit (no reuse check):** decrypt one password at a time, estimate its entropy in bits, wipe it immediately. Only the entry reference, bit count, and label are kept.
  - **Estimator (lightweight, no big dictionaries):** start from length × log2(charset size), then apply penalties for repeated characters, sequences (`abc`, `123`), keyboard walks (`qwerty`, `azerty`), years/dates, and a small built-in list of the most common passwords (a few KB, so firmware stays small). Shown as an *estimate*, never as an exact value.
  - **Label:** Weak or Strong, based on a threshold setting (default 64 bits). Always shown together with the bit count, e.g. `Strong · 94 bits`, `Weak · 31 bits`.
  - **Audit screen:** list sorted weakest first; filter to show weak only; jump to the entry to change the password.
- **Entry view:** show the strength label + estimated bits under the (hidden) password, without revealing it.
- ✅ Estimates are in the same range as KeePassXC's strength meter on the test DB (within reason); obviously weak test passwords (`password1`, `azerty123`, `Summer2024!`) are flagged Weak; no plaintext password stays in RAM after the audit.

### Stage 7 — Passkeys (from KeePassXC entries)
- Read KeePassXC passkey attributes (the `KPEX_PASSKEY_*` fields — verify exact names against KeePassXC source).
- CTAPHID transport over the composite USB device; CTAP2 `authenticatorGetInfo`, `authenticatorGetAssertion` and `authenticatorMakeCredential` (ES256, attestation "none", stored as an entry; needs the database unlocked).
- ECDSA P-256 signing with mbedTLS, private key decrypted on demand and wiped after signing.
- User presence = physical key press on the Cardputer. Device unlocked = user verification (verify how to declare this correctly in getInfo).
- Use pico-fido or similar open-source FIDO firmware as a reference only.
- ✅ Sign in to webauthn.io and a real site with a passkey created in KeePassXC.

### Stage 8 — Launcher & M5Burner packaging
- Build a single merged `.bin` (bootloader + partition table + app) for M5Burner, and an app-only `.bin` for SD-card launchers.
- Keep the app small enough for common launcher partition layouts; check the target launcher's app partition size early (from Stage 1 on).
- No custom partitions: wordlist, fonts, and layouts are embedded in the app binary. Settings in NVS or on the SD card (no secrets in either).
- Handle a missing/empty NVS gracefully (launchers may wipe or share it).
- ✅ Firmware installs and runs from M5Burner and from at least one SD launcher, and switching back to other firmware works.

### Stage 9 — Final optimization pass
- Profile unlock, search, and redraw; optimize hot paths.
- Measure idle and active current; tune sleep and backlight.
- Check RAM high-water mark and firmware size (firmware size now matters for launcher compatibility).

## 5b. Security without hardware hardening

What still protects you:
- The `.kdbx` is encrypted; a lost or stolen *locked* device reveals nothing without the master password.
- No secrets in logs, crash dumps, SD, flash, or NVS (section 2 rules).
- While the app runs, TinyUSB uses the USB OTG controller, which should disconnect the chip's built-in USB-Serial-JTAG from the port (verify on device). Auto-lock limits how long secrets sit in RAM.

What is NOT protected (accepted trade-off):
- Someone with physical access could flash modified firmware that records your master password the next time you type it ("evil maid"). Mitigation: keep the device with you, and reflash your own build from a trusted source if it was out of your control.
- Key file: keeping it on the same SD card as the database adds little protection. Keep it elsewhere (a second SD card, or type-in only) if you use one.

## 5c. Development workflow

- **Debug output:** once TinyUSB takes over the USB port, the built-in USB serial console disappears. For development builds, add a TinyUSB CDC (serial) interface to the composite device for logs; it is removed in release builds. A build flag can also disable TinyUSB entirely to get the normal serial console back.
- **Flashing during development:** with TinyUSB running, automatic reset into download mode may not work. Enter download mode manually (hold the Cardputer's boot button, G0, while plugging in or resetting), then flash with `idf.py flash` or M5Burner.
- **Git:** commit after every passing acceptance test. Never commit real databases, key files, or Wi-Fi passwords; test databases and their test passwords are fine.

## 5d. Working with Claude Code

- Put section 2 (security rules) plus a short project summary in `CLAUDE.md`; keep this file as `PLAN.md` in the repo root.
- Work on **one stage per session**. Start each session with: "Read PLAN.md and PROGRESS.md, we're doing Stage N."
- Keep a `PROGRESS.md` that Claude updates at the end of each session: what's done, what's tested, known bugs, next step.
- Ask Claude to write the acceptance tests for a stage **before** the implementation.
- Use the strongest model for Stages 0, 5, 6, 7 (crypto, file format, rewrite, passkeys); a faster model is fine for UI-only work.

## 6. Things to verify once the device arrives

- Keyboard hardware on the ADV (controller chip, interrupt support)
- ~~Built-in RTC?~~ Confirmed: NO RTC chip on the Cardputer ADV. The ESP32-S3 internal timer does not keep time across reboots/power-off, so time must be set (manually or NTP) after each power-on unless a Grove RTC is attached
- Optional: which RTC module to buy for the Grove port (only if resyncing after each power-on gets annoying)
- Real AES-KDF rounds/second (hardware vs software, one vs two cores)
- USB composite device (HID + FIDO + MSC) behaving on Windows, macOS, and Linux
- App partition size used by the launcher(s) you want to support
- That USB-Serial-JTAG is unreachable while the app's USB stack is running
