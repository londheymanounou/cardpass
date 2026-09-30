"""Check files written by tests/host/test_save with independent readers.

- no-op saves: pykeepass XML (protected values decrypted) and attachments are
  identical to the original, and KeePassXC's XML export is identical too.
- edit.kdbx: history, recycle bin, DeletedObjects, moved attachment, new key.

    python tools/check_saved.py [work dir]
"""
import re, shutil, subprocess, sys
from pathlib import Path
from lxml import etree
from pykeepass import PyKeePass

ROOT = Path(__file__).resolve().parent.parent
TD = ROOT / "testdata"
WD = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "tests/host/build/save_work"
KPXC = shutil.which("keepassxc-cli")
fails = 0


def check(cond, msg):
    global fails
    if not cond:
        fails += 1
        print("  FAIL", msg)


def canon(kp):
    return etree.tostring(kp.tree.getroot(), method="c14n")


def kpxc_export(path, pw, keyfile=None):
    cmd = [KPXC, "export", "-q", "-f", "xml"] + (["-k", str(keyfile)] if keyfile else []) + \
          (["--no-password"] if pw is None else []) + [str(path)]
    r = subprocess.run(cmd, input=(pw or "") + "\n", capture_output=True, text=True, encoding="utf-8")
    # KeePassXC's export orders Meta/CustomData nondeterministically: drop it
    return r.returncode, re.sub(r"<CustomData>.*?</CustomData>", "", r.stdout, count=1, flags=re.S)


NOOP = [("aes.kdbx", "test", None), ("chacha.kdbx", "test", None), ("aes_kpxc.kdbx", "test", None),
        ("chacha_kpxc.kdbx", "test", None), ("utf8pw.kdbx", "pässwörd€", None),
        ("keyfile_xml2.kdbx", "test", "key_xml2.keyx"), ("keyfile_only.kdbx", None, "key_xml2.keyx"),
        ("big1000.kdbx", "test", None), ("multiblock.kdbx", "test", None)]

for name, pw, kf in NOOP:
    kfp = TD / kf if kf else None
    a = PyKeePass(str(TD / name), password=pw, keyfile=str(kfp) if kfp else None)
    b = PyKeePass(str(WD / f"noop_{name}"), password=pw, keyfile=str(kfp) if kfp else None)
    check(canon(a) == canon(b), f"{name}: XML differs")
    check(list(a.binaries) == list(b.binaries), f"{name}: attachments differ")
    if KPXC:
        ra, xa = kpxc_export(TD / name, pw, kfp)
        rb, xb = kpxc_export(WD / f"noop_{name}", pw, kfp)
        check(ra == 0 and rb == 0, f"{name}: keepassxc-cli export failed ({rb})")
        check(xa == xb, f"{name}: KeePassXC export differs")
    print("noop ok" if not fails else "noop", name)

# ---- edit.kdbx (final password after rekey) ----
kp = PyKeePass(str(WD / "edit.kdbx"), password="n3w pässword")
g = kp.find_entries(title="Gmail", first=True)
check(g.password == 'new-pw! <&>"', "gmail password")
check(g.get_custom_property("Security Q") == "s3cret", "custom field")
check(g.get_custom_property("PIN") is None, "PIN removed")
check(g.tags == ["email"], f"tags {g.tags}")
hist = [h.password for h in g.history]
check(hist[-1] == "Gm@il-p4ss!-v2" and "Gm@il-p4ss!" in hist, f"history {hist}")
check(g.history[-1].get_custom_property("PIN") == "1234", "history keeps old custom fields")
check(g.otp and "JBSWY3DPEHPK3PXP" in g.otp, "otp")

p = kp.find_entries(title="Proton", first=True)
check(p and p.password == "pr0ton" and p.group.name == "Email" and "favorite" in p.tags, "new entry")

bank = kp.find_entries(title="Bank", first=True)
check(bank.group.name == "Travail & Co", "bank moved")
att = {a.filename: a.data for a in bank.attachments}
check(len(att.get("scan.bin", b"")) == 4096 and att.get("notes.txt", b"").startswith("Line 1 é".encode()),
      "bank attachments kept")
check(kp.find_groups(name="Cards", first=True).parentgroup.name == "Email", "cards moved")
check(kp.find_entries(title="Visa", first=True) is None, "visa deleted")
check(kp.recyclebin_group is not None and kp.recyclebin_group.name == "Recycle Bin", "recycle bin")
deleted = kp.tree.findall("Root/DeletedObjects/DeletedObject")
check(len(deleted) >= 3, f"DeletedObjects: {len(deleted)}")  # Visa, Café & Bar, Café Crème

if KPXC:
    rc, xml = kpxc_export(WD / "edit.kdbx", "n3w pässword")
    check(rc == 0 and "Proton" in xml and "Travail &amp; Co" in xml, "KeePassXC opens edit.kdbx")
    for f in ["edit_multiblock.kdbx", "edit_chacha.kdbx"]:
        rc, _ = kpxc_export(WD / f, "test")
        check(rc == 0, f"KeePassXC opens {f}")
    mb = PyKeePass(str(WD / "edit_multiblock.kdbx"), password="test")
    orig = PyKeePass(str(TD / "multiblock.kdbx"), password="test")
    check(mb.binaries[0] == orig.binaries[0], "multiblock attachment")

# ---- databases created by kdbx_create (Stage 6) ----
kf = WD / "created.keyx"
for name, pw, use_kf, cipher in [("created_aes.kdbx", "créé", False, "aes256"),
                                 ("created_chacha_kf.kdbx", "test", True, "chacha20"),
                                 ("created_kf_only.kdbx", None, True, "aes256")]:
    kp = PyKeePass(str(WD / name), password=pw, keyfile=str(kf) if use_kf else None)
    check(kp.encryption_algorithm == cipher and kp.kdf_algorithm == "aeskdf", f"{name}: {kp.encryption_algorithm}")
    check(kp.root_group.name == "My Vault" and kp.find_entries(title="First", first=True).password == "pw1", name)
    if KPXC:
        rc, xml = kpxc_export(WD / name, pw, kf if use_kf else None)
        check(rc == 0 and "First" in xml, f"{name}: KeePassXC")
    print("created ok" if not fails else "created", name)

print("check_saved:", fails, "failures")
sys.exit(fails != 0)
