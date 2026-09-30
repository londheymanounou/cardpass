"""Assemble the animation frames rendered by tests/host/render (anim_*@3x.png, one every 33 ms of
simulated time) into one GIF, so the optional animations can be looked at without a device.

    python tools/make_anim_gif.py [renders dir] [out.gif]
"""
import sys
from pathlib import Path
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
RD = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "tests/host/build/renders"
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "dist/animations.gif"

files = sorted(RD.glob("anim_*@3x.png"))
if not files:
    sys.exit("no anim_*@3x.png frames: run tests/host/render first")
frames = [Image.open(f).convert("P", palette=Image.ADAPTIVE) for f in files]
# real time per frame is 33 ms; hold the end of each part so it can be seen
durations = []
for i, f in enumerate(files):
    part = f.name.split("_")[1]
    nxt = files[i + 1].name.split("_")[1] if i + 1 < len(files) else None
    durations.append(33 if nxt == part else 700)
OUT.parent.mkdir(exist_ok=True)
frames[0].save(OUT, save_all=True, append_images=frames[1:], duration=durations, loop=0, optimize=True)
print(f"{len(frames)} frames -> {OUT} ({OUT.stat().st_size // 1024} KB)")
