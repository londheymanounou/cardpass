"""Reference values for the C tests (testdata/*.expected + testdata/manifest.txt).

Key derivation is done by hand here (hashlib + pycryptodomex) and checked
against the HMACs stored in each file; entry contents come from pykeepass.
Test DB passwords are not secrets.

    python tools/ref_dump.py
"""
import base64, hashlib, hmac, re, struct
from pathlib import Path
from Cryptodome.Cipher import AES
from argon2.low_level import Type, hash_secret_raw
from pykeepass import PyKeePass

D = Path(__file__).resolve().parent.parent / "testdata"

# name, password (None = no password), key file, expected result
DBS = [
    ("aes.kdbx", "test", None, "ok"),
    ("chacha.kdbx", "test", None, "ok"),
    ("aes_kpxc.kdbx", "test", None, "ok"),
    ("chacha_kpxc.kdbx", "test", None, "ok"),
    ("utf8pw.kdbx", "pässwörd€", None, "ok"),
    ("keyfile_xml2.kdbx", "test", "key_xml2.keyx", "ok"),
    ("keyfile_xml1.kdbx", "test", "key_xml1.keyx", "ok"),
    ("keyfile_raw32.kdbx", "test", "key_raw32.keyx", "ok"),
    ("keyfile_hex64.kdbx", "test", "key_hex64.keyx", "ok"),
    ("keyfile_any.kdbx", "test", "key_any.keyx", "ok"),
    ("keyfile_only.kdbx", None, "key_xml2.keyx", "ok"),
    ("big1000.kdbx", "test", None, "ok"),
    ("multiblock.kdbx", "test", None, "ok"),
    ("aes.kdbx", "wrong", None, "bad_key"),
    ("keyfile_xml2.kdbx", "test", None, "bad_key"),
    ("argon2.kdbx", "test", None, "ok"),           # KeePass default: Argon2d, 64 MiB, 14 passes
    ("argon2d_small.kdbx", "test", None, "ok"),
    ("argon2id_small.kdbx", "test", None, "ok"),
    ("argon2id_kpxc.kdbx", "test", None, "ok"),
    ("argon2id_64mb.kdbx", "test", None, "ok"),
    ("argon2id_small.kdbx", "wrong", None, "bad_key"),
    ("kdbx31.kdbx", "test", None, "version"),
    ("kdbx31_kpxc.kdbx", "test", None, "version"),
]


def keyfile_hash(data):
    m = re.search(rb"<Version>\s*([\d.]+)\s*</Version>", data)
    if data.lstrip().startswith(b"<") and m:
        d = re.search(rb"<Data(?:\s+Hash=\"([0-9A-Fa-f]+)\")?>\s*([^<]*?)\s*</Data>", data)
        if m.group(1).startswith(b"1."):
            return base64.b64decode(d.group(2))
        key = bytes.fromhex(re.sub(rb"\s", b"", d.group(2)).decode())
        assert hashlib.sha256(key).digest()[:4] == bytes.fromhex(d.group(1).decode())
        return key
    if len(data) == 32:
        return data
    if len(data) == 64 and re.fullmatch(rb"[0-9A-Fa-f]{64}", data):
        return bytes.fromhex(data.decode())
    return hashlib.sha256(data).digest()


def parse_header(raw):
    pos, fields = 12, {}
    while True:
        fid, n = raw[pos], struct.unpack_from("<I", raw, pos + 1)[0]
        fields[fid] = raw[pos + 5:pos + 5 + n]
        pos += 5 + n
        if fid == 0:
            return fields, pos


def variant_dict(b):
    pos, out = 2, {}
    while b[pos] != 0:
        t = b[pos]; kl = struct.unpack_from("<I", b, pos + 1)[0]; k = b[pos + 5:pos + 5 + kl].decode()
        pos += 5 + kl; vl = struct.unpack_from("<I", b, pos)[0]; v = b[pos + 4:pos + 4 + vl]; pos += 4 + vl
        out[k] = struct.unpack("<Q", v)[0] if t == 0x05 else v
    return out


def ref(name, password, keyfile):
    raw = (D / name).read_bytes()
    fields, hend = parse_header(raw)
    kdf = variant_dict(fields[11])
    parts = []
    if password is not None:
        parts.append(hashlib.sha256(password.encode()).digest())
    if keyfile:
        parts.append(keyfile_hash((D / keyfile).read_bytes()))
    composite = hashlib.sha256(b"".join(parts)).digest()
    argon = {bytes.fromhex("ef636ddf8c29444b91f7a9a403e30a0c"): Type.D, bytes.fromhex("9e298b1956db4773b23dfc3ec6f0a1e6"): Type.ID}
    if kdf["$UUID"] in argon:   # Argon2: the reference C implementation (argon2-cffi)
        u32 = lambda b: struct.unpack("<I", b)[0]
        transformed = hash_secret_raw(composite, kdf["S"], time_cost=kdf["I"], memory_cost=kdf["M"] // 1024,
                                      parallelism=u32(kdf["P"]), hash_len=32, type=argon[kdf["$UUID"]], version=u32(kdf["V"]))
    else:
        aes = AES.new(kdf["S"], AES.MODE_ECB)
        t = composite
        for _ in range(kdf["R"]):
            t = aes.encrypt(t)
        transformed = hashlib.sha256(t).digest()
    seed = fields[4]
    hmac_base = hashlib.sha512(seed + transformed + b"\x01").digest()
    master = hashlib.sha256(seed + transformed).digest()

    def block_key(i):
        return hashlib.sha512(struct.pack("<Q", i) + hmac_base).digest()

    assert hashlib.sha256(raw[:hend]).digest() == raw[hend:hend + 32]
    header_hmac = hmac.new(block_key(0xFFFFFFFFFFFFFFFF), raw[:hend], hashlib.sha256).digest()
    ok = header_hmac == raw[hend + 32:hend + 64]
    pos = hend + 64
    stored, n = raw[pos:pos + 32], struct.unpack_from("<I", raw, pos + 32)[0]
    block0 = hmac.new(block_key(0), struct.pack("<QI", 0, n) + raw[pos + 36:pos + 36 + n], hashlib.sha256).digest()
    assert ok == (block0 == stored)
    return ok, dict(composite=composite, transformed=transformed, hmac_base=hmac_base, master=master,
                    header_hmac=header_hmac, block0_hmac=block0)


def main():
    manifest = []
    for i, (name, pw, kf, expect) in enumerate(DBS):
        manifest.append("\t".join([name, pw.encode().hex() if pw is not None else "-", kf or "-", expect]))
        if expect != "ok":
            continue
        ok, keys = ref(name, pw, kf)
        assert ok, name
        kp = PyKeePass(str(D / name), password=pw, keyfile=str(D / kf) if kf else None)
        lines = [f"key\t{k}\t{v.hex()}" for k, v in keys.items()]
        for e in kp.entries:  # current entries only, history excluded
            uuid = e.uuid.bytes.hex()
            path = "/".join(e.group.path) if e.group.path != [None] else ""
            lines.append(f"entry\t{uuid}\t{path.encode().hex()}")
            for s in e._element.findall("String"):
                k, v = s.find("Key").text, s.find("Value")
                prot = "P" if v.get("Protected") == "True" else "U"
                lines.append(f"field\t{uuid}\t{k.encode().hex()}\t{prot}\t{(v.text or '').encode().hex()}")
            if e.expires:
                lines.append(f"expiry	{uuid}	{int(e.expiry_time.timestamp())}")
            if e.tags:
                lines.append(f"tags\t{uuid}\t{';'.join(e.tags).encode().hex()}")
        (D / (name + ".expected")).write_text("\n".join(lines) + "\n")
    (D / "manifest.txt").write_text("\n".join(manifest) + "\n")
    print("ok:", len(manifest), "cases")


if __name__ == "__main__":
    main()
