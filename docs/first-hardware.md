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

## 3c. USB drive mode

Menu -> USB drive: the PC must show a new drive with the card's files (Windows: eject with
"Safely remove" first, then leave the mode with `). Copy a .kdbx in, leave, and the picker must
list it; a database copied back out must open in KeePassXC. Things to watch: the card must
remount after leaving (otherwise "SD card not remounted: reinsert it"), the keyboard/security key
must come back afterwards, and copying a large file must not corrupt it (compare checksums).

## 3d. Clock

Menu -> Set time. By hand: the entered local time must become the correct UTC (check a TOTP code
against KeePassXC right after). Wi-Fi: the scan list must show your networks; sync must set the
time within a second or two of a phone. Check that Wi-Fi is really off afterwards (current draw)
and that a wrong password is reported as such (the reason codes differ between routers). Free heap
(`esp_get_free_heap_size`) before and after a sync must be the same: the radio must be fully released.

## 3e. Power

The screen must dim after 20 s idle and turn off after 45 s; any key wakes it and that key must do
nothing else. Measure current on a USB meter: bright / dimmed / dark (target: dark and idle well under
the bright figure; the 80 MHz + backlight-off state is where the savings come from). If USB
enumeration ever breaks after dimming, DFS is the suspect (`hw_power_init` in `hw_misc.c`). Battery:
the ADC formula is M5Unified's ((mV*2 - 3300) / 850): compare with a multimeter; the critical level
(3 %) and the deep-sleep wake (keyboard INT, GPIO 11) need one real discharge to confirm.

## 3f. Animations

Settings -> Animations. On: the selection highlight fades between rows, rows slide in when entering
a list or an entry, toasts slide up, the backlight fades when dimming/waking. Judge smoothness and
whether the SPI push (about 8 strips of 16 rows per frame) keeps up at 30 fps; if not, lower
`FRAME_MS` cost by marking fewer rows (`ap_anim_tick` in `components/ui/app_anim.c`). The backlight
fade needs `ledc_fade_func_install` to work next to the other LEDC use (`hw_display.c`).

## 3g. Bluetooth typing

Menu -> Bluetooth -> Enter: "CardPass" must appear in the PC/phone's Bluetooth list. Pairing must
show a 6-digit code on BOTH sides; Enter on the Cardputer confirms. After pairing, typing an entry
field must go over Bluetooth (unplug USB to be sure). Check: a second pairing attempt while connected
is refused; a host that only does "Just Works" pairing is dropped; the pairing survives a reboot
(bond in NVS) and "F" really forgets it; the radio turns off after 2 min idle and on lock. Free heap
before and after a Bluetooth session must match (clean stack teardown). Known risk: repeated
NimBLE init/deinit cycles: watch for a slow leak over many sessions.

## 3h. AES-KDF accelerator (hw_aes.c)
The unlock key derivation uses the AES engine in plain block mode instead of mbedTLS (which sends every 16-byte
block through DMA). A boot-time selftest compares both and only enables it if they match. Check: unlock a
database with a known round count and time it. Expect roughly 2-5 microseconds per round (a few seconds per
million rounds); about 60 us per round means the accelerator is off, and the progress screen then says
"Hardware AES off: slower". Then create a database with Change password / New database (target seconds) and open
it in KeePassXC: it must open (this proves the accelerated KDF output is right on the real chip). Also check
that nothing resets during a long unlock (the idle-task watchdog is fed by a one-tick yield every second).

## 3i. Memory hygiene on the real chip
`tests/host/memscan.sh` proves the portable code leaves nothing behind on a PC. On the device, the things only the
chip can show: free heap after lock must return to the same number after many unlock/lock cycles (print it in a
debug build, as `docs/qemu.md` does), and a USB/BLE capture of typing must show only key codes, nothing else.

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
