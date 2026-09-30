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

## Findings (first run)
Baseline free heap after boot is 330 KB here, but this build has no USB/Wi-Fi/Bluetooth stacks, so the real
device will have less (measure it). Heap after unlock / lowest free heap during unlock:

| entries | free after unlock | lowest free during unlock |
|---|---|---|
| 200 | 276 KB | 217 KB |
| 400 | 223 KB | 166 KB |
| 600 | 119 KB | 64 KB |
| 800 | 171 KB | 62 KB |
| 1,000 | fails: "Out of memory" | 48 KB at failure |

So the peak while unlocking, not the finished index, is what limits the size, and 1,000 entries do not fit.
The numbers are not linear (600 keeps more than 800 afterwards): something keeps a large buffer alive after
unlock. Both are worth fixing before relying on the ~800-entry claim in PROGRESS.md.
