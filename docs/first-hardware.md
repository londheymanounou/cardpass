# First hardware contact

Nothing in `firmware/` has run on a device yet. Pin numbers and panel settings come from other
firmware for the same board (SD pins were verified on a real ADV there; display, keyboard and
battery values were read from M5GFX / M5Unified for the ADV). Check them in this order, cheapest
and most decisive first. Everything host-testable is already covered by `tests/host`.

## 0. Flash

Power OFF, hold G0, plug USB-C, release G0, then `pio run -t upload` in `firmware/`.
(To get back to a launcher: reflash it, or use its own installer.)

## 1. Display (values from M5GFX, unverified here)

Pins MOSI 35, SCLK 36, DC 34, CS 37, RST 33, BL 38 (PWM); ST7789, 40 MHz, INVON, MADCTL 0x60,
window offset x 40 / y 52 in landscape (`firmware/src/hw_display.c`).

Expected: the picker screen, upright, not mirrored, correct colours (orange folders/stars, dark
grey background). Symptoms and fixes:
- mirrored / upside down: MADCTL 0x60 -> 0xA0 / 0xC0 / 0x00 (rotation table of the ST7789)
- shifted picture or a 1-2 px garbage line on an edge: OFFSET_X / OFFSET_Y
- red and blue swapped: MADCTL bit 3 (0x08)
- colours inverted: remove the INVON command
- speckles: 40 MHz -> 20 MHz (`pclk_hz`)

## 2. Keyboard (TCA8418)

I2C SDA 8 / SCL 9, address 0x34, INT on GPIO 11. Type on the unlock screen: dots must appear,
fn + `;` `,` `.` `/` = arrows, fn + backtick = esc (back), fn + backspace = delete.
Mash keys for a few seconds: input must never freeze (FIFO overflow recovery in `hw_keys.c`).
The sibling firmware found three keys "wrong against the ADV's actual keyboard" in its first
table: if a key types the wrong character, the `MAP` table in `hw_keys.c` is the place.

## 3. SD card

Pins SCK 40, MISO 39, MOSI 14, CS 12 (verified on an ADV in the sibling firmware). Databases are
found in `/cardpass/` first, then the card root. A new database is created in `/cardpass/`.

## 3b. USB typing and passkeys

Plug into a PC: it must enumerate as "CardPass" (a keyboard + a security key). Unlock a database,
open an entry, plug in, press Enter on the User row: the text must appear in a text editor;
try each layout (settings -> Keyboard) with the accented test entries. Passkeys: sign in at
webauthn.io with a passkey created in KeePassXC: the confirmation screen must appear (Enter
approves). If a browser gives up while waiting, the KEEPALIVE timing is the place to look
(`pump()` in `main.c`). Windows can require "Windows Hello / security key" dialogs to be
dismissed first. Also verify that the serial-JTAG port really disappears while the app runs
(PLAN.md section 5b).

## 4. Numbers the plan wants measured

| what | how | target |
|---|---|---|
| AES-KDF rounds/s | create a database with "Unlock in ~2 s": the rounds are printed in the file header | 2-4 s unlock |
| hardware vs software AES per core | `CONFIG_MBEDTLS_HARDWARE_AES` on/off, one vs two cores | pick the fastest |
| free heap while unlocked | `esp_get_free_heap_size()` after unlocking big1000.kdbx | index ~230 KB for 1,000 entries |
| save time and peak heap | edit an entry in big1000.kdbx | ~101 KB extra on top of the index |
| search latency | type in big1000.kdbx | < 30 ms per key |
| current draw idle / active | USB meter | tune backlight and sleep |

## 5. Still to build for the device

USB HID keyboard (+ FIDO HID + mass storage), BLE HID, NTP / manual clock, light sleep, launcher
packaging and testing in M5Burner and an SD launcher, USB-Serial-JTAG check (PLAN.md section 5b).
