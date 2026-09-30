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

chg = PyKeePass(str(DB / "chg.kdbx"), password="kf pw", keyfile=str(DB / "chg.keyx"))
check(chg.encryption_algorithm == "chacha20" and chg.kdf_algorithm == "aeskdf", "chg: cipher and AES-KDF kept")
bak = DB / "chg.kdbx.bak"   # later edits make a fresh backup: it must use the NEW credentials, never the old password
if bak.exists():
    PyKeePass(str(bak), password="kf pw", keyfile=str(DB / "chg.keyx"))
    try:
        PyKeePass(str(bak), password="test")
        check(False, "chg: backup must not open with the old password")
    except Exception:
        check(True, "chg: backup opens only with the new credentials")
gm = chg.find_entries(title="Gmail", first=True)
check(gm and gm.group.name == "Café & Bar" and gm.password == "Gm@il-p4ss!-v2", "chg: Gmail moved to Café & Bar, password intact")
job = chg.find_groups(name="Job", first=True)
check(job and job.parentgroup.name == "Recycle Bin", "chg: group Job deleted into the recycle bin")
bank = chg.find_entries(title="Bank", first=True)
check(bank and {a.filename for a in bank.attachments} == {"notes.txt", "scan.bin"}, "chg: attachments intact")
check(len(chg.entries) == 5, f"chg: {len(chg.entries)} entries")
try:
    PyKeePass(str(DB / "chg.kdbx"), password="test")
    check(False, "chg: old password must not open it")
except Exception:
    check(True, "chg: old password does not open it")

if KPXC:
    for name, pw, kf in [("aes_kpxc.kdbx", "test", None), ("newdb.kdbx", "créé 1", "newdb.keyx"), ("chg.kdbx", "kf pw", "chg.keyx")]:
        cmd = [KPXC, "db-info", "-q"] + (["-k", str(DB / kf)] if kf else []) + [str(DB / name)]
        r = subprocess.run(cmd, input=pw + "\n", capture_output=True, text=True, encoding="utf-8")
        check(r.returncode == 0, f"KeePassXC opens {name}")
print("check_ui_files:", fails, "failures")
sys.exit(fails != 0)
