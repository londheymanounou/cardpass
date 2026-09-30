"""Verify the assertions written by tests/host/test_fido (fido_out.txt) independently
of mbedTLS: CBOR decoded here, signatures checked with pycryptodomex against the
public keys of the passkeys in testdata/passkeys.kdbx (read with pykeepass).

    python tools/check_passkeys.py [dir with fido_out.txt]
"""
import base64, hashlib, struct, sys
from pathlib import Path
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC, RSA
from Cryptodome.Signature import DSS, pkcs1_15
from pykeepass import PyKeePass

ROOT = Path(__file__).resolve().parent.parent
WD = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "tests/host/build"


def cbor(b, i=0):
    """Minimal CBOR decoder -> (value, next index)."""
    ib = b[i]; major, info = ib >> 5, ib & 31; i += 1
    if info < 24: v = info
    else:
        n = 1 << (info - 24); v = int.from_bytes(b[i:i + n], "big"); i += n
    if major == 0: return v, i
    if major == 1: return -1 - v, i
    if major == 2: return bytes(b[i:i + v]), i + v
    if major == 3: return b[i:i + v].decode(), i + v
    if major == 4:
        out = []
        for _ in range(v):
            x, i = cbor(b, i); out.append(x)
        return out, i
    if major == 5:
        out = {}
        for _ in range(v):
            k, i = cbor(b, i); x, i = cbor(b, i); out[k] = x
        return out, i
    if major == 7: return {20: False, 21: True}[info], i
    raise ValueError("unsupported CBOR")


def b64url(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


kp = PyKeePass(str(ROOT / "testdata/passkeys.kdbx"), password="test")
fails, n = 0, 0
for line in (WD / "fido_out.txt").read_text().splitlines():
    label, rp, resp, cdh = line.split("\t")
    resp, cdh = bytes.fromhex(resp), bytes.fromhex(cdh)
    m, end = cbor(resp)
    e = next(x for x in kp.entries if x.get_custom_property("KPEX_PASSKEY_USERNAME") == label)
    cp = e.get_custom_property
    auth, sig = m[2], m[3]
    flags = auth[32]
    be = cp("KPEX_PASSKEY_FLAG_BE") == "1"
    errs = []
    if end != len(resp): errs.append("trailing bytes")
    if auth[:32] != hashlib.sha256(rp.encode()).digest(): errs.append("rpIdHash")
    if flags & 0x05 != 0x05: errs.append("UP/UV flags")
    if bool(flags & 0x08) != be or bool(flags & 0x10) != be: errs.append("BE/BS flags")
    if struct.unpack(">I", auth[33:37])[0] != 0: errs.append("counter")
    cred = cp("KPEX_PASSKEY_GENERATED_USER_ID") or cp("KPEX_PASSKEY_CREDENTIAL_ID")
    if m[1] != {"id": b64url(cred), "type": "public-key"}: errs.append("credential")
    if m[4]["id"] != b64url(cp("KPEX_PASSKEY_USER_HANDLE")) or m[4]["name"] != label: errs.append("user")
    pem = cp("KPEX_PASSKEY_PRIVATE_KEY_PEM")
    h = SHA256.new(auth + cdh)
    try:
        if "RSA" in pem or len(pem) > 1000:
            pkcs1_15.new(RSA.import_key(pem).public_key()).verify(h, sig)
        else:
            DSS.new(ECC.import_key(pem).public_key(), "fips-186-3", encoding="der").verify(h, sig)
    except (ValueError, TypeError) as ex:
        errs.append(f"signature: {ex}")
    n += 1
    print(f"{label:6} {rp:18} {'OK' if not errs else 'FAIL ' + ', '.join(errs)}")
    fails += bool(errs)

print(f"check_passkeys: {n} assertions, {fails} failures")
sys.exit(1 if fails or n < 4 else 0)
