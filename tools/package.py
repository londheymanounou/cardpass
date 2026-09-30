"""Package the firmware build for distribution (PLAN.md stage 8).

  dist/CardPass.bin       app-only image: copy to /apps/ (or the launcher's folder) on the SD card
  dist/CardPass-full.bin  merged image (bootloader + partition table + otadata + app) for M5Burner
                          and `esptool write_flash 0x0`

    cd firmware && pio run && cd .. && python tools/package.py

Prints the app size against the 0x3D0000 (3.8 MB) app partition and the usual launcher limits.
"""
import shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "firmware/.pio/build/cardputer-adv"
DIST = ROOT / "dist"
ESPTOOL = Path.home() / ".platformio/packages/tool-esptoolpy/esptool.py"
APP_PART = 0x3D0000

app = BUILD / "firmware.bin"
parts = [("bootloader.bin", BUILD / "bootloader.bin", 0x0), ("partitions.bin", BUILD / "partitions.bin", 0x8000),
         ("ota_data_initial.bin", BUILD / "ota_data_initial.bin", 0xE000), ("firmware.bin", app, 0x10000)]
for name, p, _ in parts:
    if not p or not Path(p).exists():
        sys.exit(f"missing {name}: build first (cd firmware && pio run)")

DIST.mkdir(exist_ok=True)
shutil.copy(app, DIST / "CardPass.bin")
cmd = [sys.executable, str(ESPTOOL), "--chip", "esp32s3", "merge_bin", "-o", str(DIST / "CardPass-full.bin"),
       "--flash_mode", "dio", "--flash_freq", "80m", "--flash_size", "8MB"]
for _, p, off in parts:
    cmd += [hex(off), str(p)]
subprocess.run(cmd, check=True, capture_output=True)

size = app.stat().st_size
print(f"app image     {size:>9,} B  ({size * 100 / APP_PART:.1f}% of the {APP_PART:,} B app partition)")
print(f"launcher      {DIST / 'CardPass.bin'}")
print(f"M5Burner/full {DIST / 'CardPass-full.bin'}  ({(DIST / 'CardPass-full.bin').stat().st_size:,} B)")
