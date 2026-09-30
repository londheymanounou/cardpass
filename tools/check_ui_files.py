"""Check the databases the UI render script edited or created (tests/host/render,
work copies in <renders>/db) with pykeepass and keepassxc-cli.

    python tools/check_ui_files.py [renders dir]
"""
import shutil, subprocess, sys
from pathlib import Path
from pykeepass import PyKeePass

ROOT = Path(__file__).resolve().parent.parent
DB = (Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "tests/host/build/renders") / "db"
KPXC = shutil.which("keepassxc-cli")
fails = 0


def check(c, msg):
    global fails
    print(("ok   " if c else "FAIL ") + msg)
    fails += not c


kp = PyKeePass(str(DB / "aes_kpxc.kdbx"), password="test")
g = kp.find_entries(title="Gmail", first=True)
check(g.url == "https://mail.google.com/mail", f"edited URL: {g.url}")
check(g.password == "Gm@il-p4ss!-v2" and "favorite" in g.tags, "Gmail password and favorite kept")
check(any(h.url == "https://mail.google.com" for h in g.history), "old URL in history")
p = kp.find_entries(title="Proton", first=True)
check(p is not None and p.group.name == "Recycle Bin", "new entry moved to the recycle bin")
check(p is not None and p.username == "bob@proton.me" and len(p.password) >= 20, "new entry user + generated password")
check(p is not None and p.tags == ["mail"], f"new entry tags {p and p.tags}")
pin = p and p._element.xpath('String[Key="PIN"]/Value')
check(bool(pin) and pin[0].text == "4321" and pin[0].get("Protected") == "True", "custom field PIN, protected")

new = PyKeePass(str(DB / "newdb.kdbx"), password="créé 1", keyfile=str(DB / "newdb.keyx"))
check(new.encryption_algorithm == "chacha20" and new.kdf_algorithm == "aeskdf", "created: ChaCha20 + AES-KDF")
check(new.root_group.name == "newdb", "created: root group name")

if KPXC:
    for name, pw, kf in [("aes_kpxc.kdbx", "test", None), ("newdb.kdbx", "créé 1", "newdb.keyx")]:
        cmd = [KPXC, "db-info", "-q"] + (["-k", str(DB / kf)] if kf else []) + [str(DB / name)]
        r = subprocess.run(cmd, input=pw + "\n", capture_output=True, text=True, encoding="utf-8")
        check(r.returncode == 0, f"KeePassXC opens {name}")
print("check_ui_files:", fails, "failures")
sys.exit(fails != 0)
