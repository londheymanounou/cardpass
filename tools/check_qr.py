"""Decode the QR screens rendered by tests/host/render with OpenCV and compare
with the expected field values (Gmail entry of testdata/aes_kpxc.kdbx).

    python tools/check_qr.py [renders dir]
"""
import sys
from pathlib import Path
import cv2
from pykeepass import PyKeePass

ROOT = Path(__file__).resolve().parent.parent
RD = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "tests/host/build/renders"
g = PyKeePass(str(ROOT / "testdata/aes_kpxc.kdbx"), password="test").find_entries(title="Gmail", first=True)
want = {"qr_password": g.password, "qr_url": g.url, "qr_totp": None}
det = cv2.QRCodeDetector()
fails = 0
for name, value in want.items():
    img = cv2.imread(str(RD / f"{name}@3x.png"))
    text, _, _ = det.detectAndDecode(img)
    ok = bool(text) and (text == value if value is not None else text.isdigit() and len(text) == 6)
    print(f"{name:12} {'OK' if ok else 'FAIL'}  decoded {text!r}")
    fails += not ok
print("check_qr:", fails, "failures")
sys.exit(fails != 0)
