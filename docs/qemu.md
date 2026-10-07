# Running the firmware in Espressif's QEMU

What it is good for: the real firmware (app, FreeRTOS, NVS, mbedTLS, KDBX code) on an emulated ESP32-S3,
with real heap numbers and real crashes (stack overflow, bad alloc, panics). What it cannot do: QEMU has no
SPI master, I2C keyboard, SD card, USB, Wi-Fi/Bluetooth or ADC, so the `qemu` PlatformIO env swaps those
for stubs in `firmware/src/hw_qemu.c`. Display, keyboard, SD, USB and radios are still untested until the
device arrives. The `qemu` env is a debug build (logging on, flash mode DIO, no power management, one
core); never flash it.

## Setup (once)
```
# QEMU: https://github.com/espressif/qemu/releases  (qemu-xtensa-softmmu-...-x86_64-w64-mingw32.tar.xz)
# unpack to ~/qemu-esp/qemu  (bin/qemu-system-xtensa.exe)
python tools/make_qemu_dbs.py ~/qemu-esp/fat 200 400 600 800      # test databases, password "test"
python ~/.platformio/packages/framework-espidf/components/fatfs/fatfsgen.py ~/qemu-esp/fat \
   --output_file ~/qemu-esp/storage.bin --partition_size 262144 --sector_size 4096 --long_name_support --fat_type 12
```
## Run
```
cd firmware && python -m platformio run -e qemu
sh tools/qemu_run.sh 300        # merges the image, boots, prints the scripted steps with free/min heap
```
`hw_qemu.c` holds the key script (pick database, unlock, search, open entry, reveal, lock, for each size).
The SD card is the read-only `storage` FAT partition, so saving is not testable here.

## Findings
The QEMU build has no USB/Wi-Fi/Bluetooth stacks and the SD card is a flash FAT partition, so its baseline free
heap (330 KB after boot and mount) is higher than the device's will be: take 30-60 KB off for the real thing.
`storage` is a writable FAT partition here, so the script also edits an entry and saves it.

Free heap after unlock, and the lowest free heap seen so far (a global minimum, so it only moves down as
databases get bigger). Index cost is about 262 bytes per entry (title, user, URL, password):

| entries | free after unlock | lowest free (unlock) | lowest free (after save) |
|---|---|---|---|
| 200 | 275 KB | 215 KB | 206 KB |
| 400 | 222 KB | 155 KB | 154 KB |
| 600 | 169 KB | 103 KB | 101 KB |
| 800 | 117 KB | 53 KB | 50 KB |
| 1,000 | fails: "Out of memory" | 33 KB | |

Correction: an earlier version of this table had the 600 and 800 rows swapped (the script's arrow-key presses
landed on the wrong file because the picker preselects the last database opened).

What changed because of this test:
- Saving used to need the old index in RAM on top of ~110 KB of save buffers, so an 800-entry database could be
  opened but not saved. `kdbx_save` now frees the index before it starts (it only needs the file, the edits and
  the cached key; the edits are copied first because their strings can point into the index) and reopens the
  database after the save's own buffers are freed. A save now needs about the same RAM as an unlock.
- Unlock and save both top out around 800-900 entries here (about 700-800 on the device, to be measured).
  Above that unlock fails with "Out of memory (database too large?)".

## Seeing the screen (interactive)
QEMU has no model of the panel, so the `qemu-ui` build sends every changed 16-row strip over the serial port
(run-length coded, base64) and reads keys back; `tools/qemu_view.py` draws it at the Cardputer's true physical size
(240x135 at 0.1052 mm, scaled from your monitor's real millimetres; F1 zooms 2x/3x/4x) and forwards your keyboard.
```
cd firmware && python -m platformio run -e qemu-ui
python tools/qemu_view.py          # test databases, password "test"
```
This is the real firmware on an emulated ESP32-S3 (not the PC simulator), but timing is the emulator's, not the
chip's: it is for looking, not for judging speed.
