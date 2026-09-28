"""Generate the Stage 0 test databases into testdata/.

Uses pykeepass for content, then forces AES-KDF (KDBX 4) and the chosen outer
cipher. Some files are re-saved through keepassxc-cli so we also test real
KeePassXC output. Test passwords are NOT secrets.

    python tools/make_test_dbs.py
"""
import base64, datetime, hashlib, os, random, shutil, struct, subprocess, sys
from pathlib import Path

from pykeepass import PyKeePass
from pykeepass.pykeepass import BLANK_DATABASE_LOCATION, BLANK_DATABASE_PASSWORD
from pykeepass.kdbx_parsing.kdbx4 import VariantDictionary

OUT = Path(__file__).resolve().parent.parent / "testdata"
PW = "test"
AES_KDF_UUID = bytes.fromhex("c9d9f39a628a4460bf740d08c18a4fea")
ROUNDS = 1000  # small so tests run fast; device benchmarks pick real values
KPXC = shutil.which("keepassxc-cli")
rng = random.Random(1234)  # deterministic content


def aeskdf_params(rounds):
    item = lambda t, k, v: bytes([t]) + struct.pack("<I", len(k)) + k.encode() + struct.pack("<I", len(v)) + v
    raw = (b"\x00\x01" + item(0x42, "$UUID", AES_KDF_UUID) + item(0x05, "R", struct.pack("<Q", rounds))
           + item(0x42, "S", os.urandom(32)) + b"\x00")
    return VariantDictionary.parse(raw)


def new_db(cipher="aes256", rounds=ROUNDS):
    kp = PyKeePass(BLANK_DATABASE_LOCATION, BLANK_DATABASE_PASSWORD)
    dh = kp.kdbx.header.value.dynamic_header
    dh.kdf_parameters.data = aeskdf_params(rounds)
    dh.cipher_id.data = cipher
    return kp


def save(kp, name, password=PW, keyfile=None):
    kp.password, kp.keyfile = password, keyfile
    path = OUT / name
    kp.save(str(path))
    PyKeePass(str(path), password=password, keyfile=keyfile)  # sanity reopen
    return path


def fill_rich(kp):
    root = kp.root_group
    email = kp.add_group(root, "Email")
    bank = kp.add_group(root, "Banking")
    cards = kp.add_group(bank, "Cards")
    cafe = kp.add_group(root, "Café & Bar")

    g = kp.add_entry(email, "Gmail", "alice@gmail.com", "Gm@il-p4ss!", url="https://mail.google.com",
                     notes="Line 1\nLine 2 — é è à ç ü ñ <tag> & \"quotes\"", tags=["favorite", "email"],
                     otp="otpauth://totp/Google:alice?secret=JBSWY3DPEHPK3PXP&issuer=Google",
                     expiry_time=datetime.datetime(2030, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc))
    g.expires = True
    g.set_custom_property("Recovery", "none")
    g.set_custom_property("PIN", "1234", protect=True)
    g.save_history()
    g.password = "Gm@il-p4ss!-v2"  # history keeps the old one (protected, consumes keystream)

    kp.add_entry(cafe, "Café Crème", "zoë", "p€ss wörd ✓", url="https://café.example", tags=["favorite"])
    kp.add_entry(cards, "Visa", "4111111111111111", "", notes="empty password entry")
    b = kp.add_entry(bank, "Bank", "bob", "B4nk!pw", notes="x" * 5000)
    att = kp.add_binary(os.urandom(4096), protected=False)
    b.add_attachment(att, "scan.bin")
    kp.add_entry(root, "Root entry", "root", "rootpw")


def kpxc_resave(path, password=PW, keyfile=None):
    """Round-trip through KeePassXC (adds a group, which forces a full save)."""
    if not KPXC:
        print("keepassxc-cli not found, skipping", path.name)
        return
    cmd = [KPXC, "mkdir", "-q"] + (["-k", str(keyfile)] if keyfile else []) + (["--no-password"] if password is None else []) + [str(path), "KPXC"]
    subprocess.run(cmd, input=(password or "") + "\n", text=True, check=True, encoding="utf-8")


def main():
    OUT.mkdir(exist_ok=True)

    kp = new_db("aes256"); fill_rich(kp); save(kp, "aes.kdbx")
    kp = new_db("chacha20"); fill_rich(kp); save(kp, "chacha.kdbx")
    kp = new_db("aes256"); fill_rich(kp); p = save(kp, "aes_kpxc.kdbx"); kpxc_resave(p)
    kp = new_db("chacha20"); fill_rich(kp); p = save(kp, "chacha_kpxc.kdbx"); kpxc_resave(p)

    # UTF-8 password
    kp = new_db(); kp.add_entry(kp.root_group, "E", "u", "p"); save(kp, "utf8pw.kdbx", password="pässwörd€")

    # Key file formats
    key = bytes(range(32))
    kfs = {
        "xml2": f'<?xml version="1.0" encoding="UTF-8"?>\n<KeyFile>\n  <Meta>\n    <Version>2.0</Version>\n  </Meta>\n  <Key>\n'
                f'    <Data Hash="{hashlib.sha256(key).hexdigest()[:8].upper()}">\n      {key[:16].hex().upper()}\n'
                f'      {key[16:].hex().upper()}\n    </Data>\n  </Key>\n</KeyFile>\n'.encode(),
        "xml1": f'<?xml version="1.0" encoding="utf-8"?>\n<KeyFile><Meta><Version>1.00</Version></Meta>'
                f'<Key><Data>{base64.b64encode(key).decode()}</Data></Key></KeyFile>'.encode(),
        "raw32": key,
        "hex64": key.hex().encode(),
        "any": b"any file content is hashed with SHA-256\n" * 100,
    }
    for name, data in kfs.items():
        kf = OUT / f"key_{name}.keyx"
        kf.write_bytes(data)
        kp = new_db(); kp.add_entry(kp.root_group, "K", "u", "p")
        save(kp, f"keyfile_{name}.kdbx", keyfile=str(kf))
    kp = new_db(); kp.add_entry(kp.root_group, "K", "u", "p")
    save(kp, "keyfile_only.kdbx", password=None, keyfile=str(OUT / "key_xml2.keyx"))

    # 1,000 entries
    kp = new_db()
    groups = [kp.add_group(kp.root_group, f"Group {i}") for i in range(20)]
    for i in range(1000):
        kp.add_entry(groups[i % 20], f"Site {i:04d}", f"user{i}@example.com", f"pw-{i}-{rng.getrandbits(64):x}",
                     url=f"https://site{i}.example.com", tags=["favorite"] if i % 50 == 0 else None)
    save(kp, "big1000.kdbx")

    # Multiple 1 MiB HMAC blocks: incompressible attachment in the inner header
    kp = new_db(); e = kp.add_entry(kp.root_group, "Big attachment", "u", "p")
    e.add_attachment(kp.add_binary(os.urandom(1_500_000)), "big.bin")
    save(kp, "multiblock.kdbx")

    # Must be rejected: Argon2 KDBX 4 (pykeepass blank DB keeps Argon2d), KDBX 3.1
    kp = PyKeePass(BLANK_DATABASE_LOCATION, BLANK_DATABASE_PASSWORD)
    kp.add_entry(kp.root_group, "A", "u", "p"); save(kp, "argon2.kdbx")
    (OUT / "kdbx31.kdbx").write_bytes(struct.pack("<IIHH", 0x9AA2D903, 0xB54BFB67, 1, 3) + os.urandom(200))
    if KPXC:  # keepassxc-cli db-create writes KDBX 3.1
        p = OUT / "kdbx31_kpxc.kdbx"; p.unlink(missing_ok=True)
        subprocess.run([KPXC, "db-create", "-q", "-p", "-t", "100", str(p)], input=f"{PW}\n{PW}\n",
                       text=True, check=True)

    print("done:", ", ".join(sorted(p.name for p in OUT.glob("*.kdbx"))))


if __name__ == "__main__":
    main()
