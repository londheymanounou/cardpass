"""Reference vectors for tests/host/test_argon2.c -> testdata/argon2_vectors.txt

Argon2 from argon2-cffi (the reference C implementation), BLAKE2b from hashlib. Covers the three types, both
versions, odd memory sizes (rounded down to 4 * lanes blocks), 1-4 lanes, 1-3 passes, empty and long inputs.

    python tools/gen_argon2_vectors.py
"""
import hashlib, random
from pathlib import Path
from argon2.low_level import Type, hash_secret_raw

OUT = Path(__file__).resolve().parent.parent / "testdata" / "argon2_vectors.txt"
rng = random.Random(9106)
TYPES = {0: Type.D, 1: Type.I, 2: Type.ID}

lines = []
for outlen in (1, 16, 32, 63, 64):
    for n in (0, 1, 3, 127, 128, 129, 255, 256, 1000):
        data = bytes(rng.getrandbits(8) for _ in range(n))
        lines.append(f"b2b {outlen} {data.hex() or '-'} {hashlib.blake2b(data, digest_size=outlen).hexdigest()}")

cases = []
for ty in (0, 1, 2):
    for ver in (0x13, 0x10):
        for m, t, p in ((8, 1, 1), (9, 2, 1), (16, 1, 2), (33, 3, 2), (64, 2, 4), (96, 1, 3), (257, 2, 1), (1024, 3, 2)):
            cases.append((ty, ver, t, m, p))
for ty in (0, 2):
    cases.append((ty, 0x13, 2, 4096, 2))   # 4 MiB: lots of cache misses in the swap test
for ty, ver, t, m, p in cases:
    pw = bytes(rng.getrandbits(8) for _ in range(rng.choice((0, 1, 8, 32, 40))))
    salt = bytes(rng.getrandbits(8) for _ in range(rng.choice((8, 16, 32))))
    tag = hash_secret_raw(pw, salt, time_cost=t, memory_cost=m, parallelism=p, hash_len=32, type=TYPES[ty], version=ver)
    lines.append(f"a2 {ty} {ver} {t} {m} {p} {pw.hex() or '-'} {salt.hex()} {tag.hex()}")

OUT.write_text("\n".join(lines) + "\n")
print("wrote", len(lines), "vectors to", OUT)
