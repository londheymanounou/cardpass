#!/bin/sh
# merge the PlatformIO qemu build with the FAT image and boot it
cd /d/cardpass/firmware/.pio/build/qemu || exit 1
python ~/.platformio/packages/tool-esptoolpy/esptool.py --chip esp32s3 merge_bin -o ~/qemu-esp/flash.bin --fill-flash-size 8MB --flash_mode dio --flash_freq 80m --flash_size 8MB 0x0 bootloader.bin 0x8000 partitions.bin 0xe000 ota_data_initial.bin 0x10000 firmware.bin 0x7B0000 ~/qemu-esp/storage.bin >/dev/null
cd ~/qemu-esp && timeout ${1:-120} ./qemu/bin/qemu-system-xtensa.exe -M esp32s3 -m 8M -nographic -drive file=flash.bin,if=mtd,format=raw -global driver=timer.esp32s3.timg,property=wdt_disable,value=true 2>&1 | sed -n '/QEMU start/,$p'
