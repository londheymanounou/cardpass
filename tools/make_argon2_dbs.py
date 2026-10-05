"""Small Argon2 test databases (the existing argon2.kdbx is KeePass' 64 MiB default and stays as is).

    argon2d_small.kdbx      Argon2d,  1 MiB, 3 passes, 2 lanes, AES-256   (pykeepass)
    argon2id_small.kdbx     Argon2id, 512 KiB, 2 passes, 1 lane, ChaCha20 (pykeepass)
    argon2id_kpxc.kdbx      Argon2id, 2 MiB, 2 passes, 2 lanes, re-saved by keepassxc-cli (real KeePassXC output)

Password "test" (not a secret). Then run tools/ref_dump.py for the expected contents.

    python tools/make_argon2_dbs.py
"""
import os, struct, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import make_test_dbs as m
from pykeepass.kdbx_parsing.kdbx4 import VariantDictionary

ARGON2D = bytes.fromhex("ef636ddf8c29444b91f7a9a403e30a0c")
ARGON2ID = bytes.fromhex("9e298b1956db4773b23dfc3ec6f0a1e6")


def argon2_params(uuid, mem, iters, lanes):
    item = lambda t, k, v: bytes([t]) + struct.pack("<I", len(k)) + k.encode() + struct.pack("<I", len(v)) + v
    raw = (b"\x00\x01" + item(0x42, "$UUID", uuid) + item(0x42, "S", os.urandom(32)) + item(0x04, "P", struct.pack("<I", lanes))
           + item(0x05, "M", struct.pack("<Q", mem)) + item(0x05, "I", struct.pack("<Q", iters))
           + item(0x04, "V", struct.pack("<I", 0x13)) + b"\x00")
    return VariantDictionary.parse(raw)


def make(name, cipher, uuid, mem, iters, lanes, kpxc=False):
    kp = m.new_db(cipher)
    kp.kdbx.header.value.dynamic_header.kdf_parameters.data = argon2_params(uuid, mem, iters, lanes)
    m.fill_rich(kp)
    p = m.save(kp, name)
    if kpxc:
        m.kpxc_resave(p)
    print("made", name)


make("argon2d_small.kdbx", "aes256", ARGON2D, 1 << 20, 3, 2)
make("argon2id_small.kdbx", "chacha20", ARGON2ID, 512 << 10, 2, 1)
make("argon2id_kpxc.kdbx", "aes256", ARGON2ID, 2 << 20, 2, 2, kpxc=True)
