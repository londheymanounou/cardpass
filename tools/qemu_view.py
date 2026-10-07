"""See the real firmware's screen: runs the qemu-ui build in Espressif's QEMU and draws what it sends, at the
Cardputer's true physical size (panel 240x135 at 0.1052 mm pitch, from your monitor's real millimetres). Your
keyboard goes to the firmware: type, Enter, Backspace, Tab, Esc (fn+`), arrows, Ctrl+letter = fn+letter,
Delete = fn+Backspace. F1: true size / 2x / 3x / 4x. F2 / F3: calibrate true size (-/+ 5%) if your monitor
reports its millimetres wrong: hold a ruler to the window, the image must be 25.2 mm wide. Test databases: password "test".

    cd firmware && python -m platformio run -e qemu-ui
    python tools/qemu_view.py            (first run builds the SD image from testdata/)
"""
import ctypes, json, socket, shutil, subprocess, sys, threading, time, tkinter as tk
from pathlib import Path
from PIL import Image, ImageTk

ROOT = Path(__file__).resolve().parent.parent
HOME = Path.home() / "qemu-esp"
BUILD = ROOT / "firmware/.pio/build/qemu-ui"
PIO = Path.home() / ".platformio/packages"
W, H, PITCH_MM = 240, 135, 0.1052

# ---- SD card image: a few test databases ----
fat = HOME / "fat_ui/cardpass"
img = HOME / "storage_ui.bin"
if not img.exists():
    fat.mkdir(parents=True, exist_ok=True)
    for n in ("aes_kpxc.kdbx", "big1000.kdbx", "passkeys.kdbx", "argon2id_small.kdbx", "keyfile_xml2.kdbx", "key_xml2.keyx"):
        shutil.copy(ROOT / "testdata" / n, fat / n)
    subprocess.run([sys.executable, str(PIO / "framework-espidf/components/fatfs/wl_fatfsgen.py"), str(HOME / "fat_ui"),
                    "--output_file", str(img), "--partition_size", "3145728", "--sector_size", "4096",
                    "--long_name_support", "--use_default_datetime"], check=True)

# ---- flash image ----
flash = HOME / "flash_ui.bin"
subprocess.run([sys.executable, str(PIO / "tool-esptoolpy/esptool.py"), "--chip", "esp32s3", "merge_bin", "-o", str(flash),
                "--fill-flash-size", "8MB", "--flash_mode", "dio", "--flash_freq", "80m", "--flash_size", "8MB",
                "0x0", str(BUILD / "bootloader.bin"), "0x8000", str(BUILD / "partitions.bin"),
                "0xe000", str(BUILD / "ota_data_initial.bin"), "0x10000", str(BUILD / "firmware.bin"), "0x3E0000", str(img)],
               check=True, stdout=subprocess.DEVNULL)
QMP_PORT = 4444
qemu = subprocess.Popen([str(HOME / "qemu/bin/qemu-system-xtensa.exe"), "-M", "esp32s3", "-m", "8M", "-nographic",
                         "-qmp", f"tcp:127.0.0.1:{QMP_PORT},server,nowait",
                         "-drive", f"file={flash},if=mtd,format=raw",
                         "-global", "driver=timer.esp32s3.timg,property=wdt_disable,value=true"],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

# ---- the screen: the firmware prints where its screen copy lives; we read that memory through QMP ----
# (QEMU's serial port only moves ~12 KB/s: fine for keys and logs, far too slow for pixels.)
fb_addr = None
frame_us = []                                   # the firmware's own render time per frame (emulated)
latest = None                                   # newest screen bytes, set by the poller


def reader():
    global fb_addr
    for line in qemu.stdout:
        if line.startswith(b"\x02FBADDR "):
            fb_addr = int(line.split()[1], 16)
        elif line.startswith(b"\x02FT "):
            frame_us.append(int(line.split()[1]))
            del frame_us[:-30]
        else:
            sys.stdout.write(line.decode("utf-8", "replace"))


def poller():
    global latest
    dump = HOME / "fb.bin"
    while fb_addr is None:
        time.sleep(0.05)
    for _ in range(100):
        try:
            sock = socket.create_connection(("127.0.0.1", QMP_PORT))
            break
        except OSError:
            time.sleep(0.1)
    f = sock.makefile("rwb")
    f.readline()                                # greeting
    def qmp(cmd, **args):
        f.write(json.dumps({"execute": cmd, "arguments": args} if args else {"execute": cmd}).encode() + b"\n")
        f.flush()
        while True:
            r = json.loads(f.readline())
            if "return" in r or "error" in r:
                return r
    qmp("qmp_capabilities")
    while qemu.poll() is None:
        t = time.time()
        if "return" in qmp("memsave", val=fb_addr, size=W * H * 2, filename=str(dump), **{"cpu-index": 0}):
            try:
                latest = dump.read_bytes()
            except OSError:
                pass
        time.sleep(max(0.0, 1 / 120 - (time.time() - t)))   # sample at 120 Hz: never more than half a frame late


threading.Thread(target=reader, daemon=True).start()
threading.Thread(target=poller, daemon=True).start()

# ---- window ----
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
    hdc = ctypes.windll.user32.GetDC(0)
    px_per_mm = ctypes.windll.gdi32.GetDeviceCaps(hdc, 8) / ctypes.windll.gdi32.GetDeviceCaps(hdc, 4)
except Exception:
    px_per_mm = 96 / 25.4
TRUE = W * PITCH_MM * px_per_mm / W           # monitor pixels per panel pixel at true size
scales, si = [TRUE, 2, 3, 4], 3                 # opens at 4x (like the simulator); F1 cycles
panel = Image.new("RGB", (W, H))
root = tk.Tk()
label = tk.Label(root, bg="black")
label.pack()


def title(extra=""):
    title.extra = extra or getattr(title, "extra", "")
    s = scales[si]
    if si == 0:
        what = f"true size: should measure {W * PITCH_MM:.1f} mm wide ({round(W * s)} px, calibration x{scales[0] / TRUE:.2f})  F2/F3 adjust"
    else:
        what = f"{s}x"
    root.title(f"CardPass in QEMU, {what}  F1: zoom{title.extra}")


def show():
    s = scales[si]
    im = panel.resize((max(1, round(W * s)), max(1, round(H * s))), Image.LANCZOS if s < 1 else Image.NEAREST)
    label.photo = ImageTk.PhotoImage(im)
    label.configure(image=label.photo)


shown = None
frames = []                                     # times the window showed a new frame


def poll():
    global shown
    data = latest
    if data is not None and data is not shown and len(data) == W * H * 2:
        shown = data
        panel.paste(Image.frombytes("RGB", (W, H), data, "raw", "BGR;16"))   # RGB565 LE, decoded in C
        show()
        frames.append(time.time())
    now = time.time()
    while frames and now - frames[0] > 1:
        frames.pop(0)
    if int(now * 4) != getattr(poll, "q", None):                      # title 4x a second
        poll.q = int(now * 4)
        avg = sum(frame_us) / len(frame_us) / 1000 if frame_us else 0
        title(f"  |  {len(frames)} fps shown, firmware draws a frame in {avg:.1f} ms (emulated)")
    root.after(4, poll)


K_ENTER, K_FN = 0x110000, 0x1000000
SPECIAL = {"Return": K_ENTER, "BackSpace": K_ENTER + 1, "Tab": K_ENTER + 2, "Escape": K_ENTER + 3, "Up": K_ENTER + 4,
           "Down": K_ENTER + 5, "Left": K_ENTER + 6, "Right": K_ENTER + 7, "Delete": (K_ENTER + 1) | K_FN}


def send(code):
    try:
        qemu.stdin.write(b"k%08x\n" % code)
        qemu.stdin.flush()
    except OSError:
        pass


def on_key(e):
    global si
    if e.keysym == "F1":
        si = (si + 1) % len(scales)
        title()
        show()
    elif e.keysym in ("F2", "F3"):
        scales[0] *= 0.95 if e.keysym == "F2" else 1.05
        si = 0
        title()
        show()
    elif e.keysym in SPECIAL:
        send(SPECIAL[e.keysym])
    elif e.state & 0x4 and e.keysym and len(e.keysym) == 1 and e.keysym.isalpha():
        send(ord(e.keysym.lower()) | K_FN)
    elif e.char and ord(e.char) >= 32:
        send(ord(e.char))


root.bind("<Key>", on_key)
root.protocol("WM_DELETE_WINDOW", lambda: (qemu.kill(), root.destroy()))
title()
show()
poll()
root.mainloop()
qemu.kill()
