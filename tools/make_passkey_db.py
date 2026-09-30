"""testdata/passkeys.kdbx: passkey entries stored the way KeePassXC stores them
(BrowserService.cpp: CREDENTIAL_ID / PRIVATE_KEY_PEM / USER_HANDLE protected,
RELYING_PARTY / USERNAME plain, FLAG_BE / FLAG_BS "1"). Keys are test keys.

    python tools/make_passkey_db.py
"""
import base64, os, sys
from pathlib import Path
from Cryptodome.PublicKey import ECC, RSA

sys.path.insert(0, str(Path(__file__).resolve().parent))
from make_test_dbs import new_db, save  # noqa: E402


def b64url(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def add(kp, title, rp, user, pem, flags=True, strongbox=False):
    e = kp.add_entry(kp.root_group, title, user, "", url=f"https://{rp}")
    cred = b64url(os.urandom(32))
    e.set_custom_property("KPEX_PASSKEY_GENERATED_USER_ID" if strongbox else "KPEX_PASSKEY_CREDENTIAL_ID", cred, protect=True)
    e.set_custom_property("KPEX_PASSKEY_PRIVATE_KEY_PEM", pem, protect=True)
    e.set_custom_property("KPEX_PASSKEY_RELYING_PARTY", rp)
    e.set_custom_property("KPEX_PASSKEY_USERNAME", user)
    e.set_custom_property("KPEX_PASSKEY_USER_HANDLE", b64url(os.urandom(16)), protect=True)
    if flags:
        e.set_custom_property("KPEX_PASSKEY_FLAG_BE", "1")
        e.set_custom_property("KPEX_PASSKEY_FLAG_BS", "1")


def main():
    kp = new_db("aes256")
    ec = lambda: ECC.generate(curve="P-256").export_key(format="PEM")
    add(kp, "webauthn.io alice", "webauthn.io", "alice", ec())
    add(kp, "webauthn.io bob", "webauthn.io", "bob", RSA.generate(2048).export_key(format="PEM", pkcs=8).decode())
    add(kp, "GitHub", "github.com", "carol", ec(), flags=False)
    add(kp, "Ed25519 site", "ed.example", "dave", ECC.generate(curve="Ed25519").export_key(format="PEM"))
    add(kp, "StrongBox", "strongbox.example", "erin", ec(), strongbox=True)
    kp.add_entry(kp.root_group, "Plain entry", "u", "p")
    save(kp, "passkeys.kdbx")
    print("wrote testdata/passkeys.kdbx")


if __name__ == "__main__":
    main()
