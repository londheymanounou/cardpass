"""Build small VeraCrypt containers for the vera component's tests, independently of the C code (OpenSSL via
`cryptography`, hashlib PBKDF2), following VeraCrypt's Common/Volumes.c and Volume/VolumeLayout.cpp: AES-256-XTS,
PBKDF2-HMAC-SHA512 with 500000 iterations, standard header at file offset 0, hidden header at 65536, data area at
131072, XTS data unit = absolute 512-byte position in the file.

  python tools/make_vera_test.py [outdir]       -> vera_test.hc and vera_hidden.hc  (testdata/ by default)
  python tools/make_vera_test.py --check FILE   -> decrypt FILE and verify the data pattern (after test_vera wrote to it)
  python tools/make_vera_test.py --image IMG OUT -> a container whose volume is the FAT image IMG (for the device)
  python tools/make_vera_test.py --hidden-image OUTER_IMG HIDDEN_IMG OUT -> same, with a hidden volume (for the device)

vera_hidden.hc: outer volume opens with PASSWORD, the hidden volume (last 32 sectors of the outer one) with HIDDEN_PASSWORD.
Test passwords only, not secrets."""
import hashlib, os, struct, sys, zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PASSWORD = b"cardpass-vera-test"
HIDDEN_PASSWORD = b"cardpass-hidden-test"
SECTORS = 128
HIDDEN_SECTORS = 32
DATA_START = 131072
HIDDEN_HEADER = 65536
WRITTEN = {5: 0xA5}                                   # sector test_vera overwrites (--check)


def xts(key, unit, data, enc):
    c = Cipher(algorithms.AES(key), modes.XTS(unit.to_bytes(16, "little")))
    op = c.encryptor() if enc else c.decryptor()
    return op.update(data) + op.finalize()


def pattern(i):
    return bytes((i * 7 + j) & 255 for j in range(512))


def hidden_pattern(i):
    return bytes((i * 13 + j * 3 + 1) & 255 for j in range(512))


def header(password, salt, master, size, start, hidden_size):
    """The 512 header bytes: salt, then the encrypted fields."""
    h = bytearray(512)
    h[64:68] = b"VERA"
    struct.pack_into(">HH", h, 68, 5, 0x010B)
    struct.pack_into(">Q", h, 92, hidden_size)
    struct.pack_into(">Q", h, 100, size)
    struct.pack_into(">Q", h, 108, start)
    struct.pack_into(">Q", h, 116, size)
    struct.pack_into(">I", h, 128, 512)
    h[256:512] = master
    struct.pack_into(">I", h, 72, zlib.crc32(bytes(h[256:512])))
    struct.pack_into(">I", h, 252, zlib.crc32(bytes(h[64:252])))
    h[:64] = salt
    dk = hashlib.pbkdf2_hmac("sha512", password, salt, 500000, 64)
    h[64:] = xts(dk, 0, bytes(h[64:]), True)
    return bytes(h)


def keys(tag):
    return hashlib.sha512(tag + b"1").digest() + hashlib.sha512(tag + b"2").digest() + bytes(128)   # 64 key bytes used


def filler(tag, n):                                   # stands in for the random bytes that fill the header areas
    out = b""
    while len(out) < n:
        out += hashlib.sha512(tag + len(out).to_bytes(4, "big")).digest()
    return out[:n]


def area(first, tag):                                 # a 64 KiB header area: the header, then filler
    return first + filler(tag, 65536 - 512)


def build(image=None):
    master = keys(b"master")
    nsec = len(image) // 512 if image else SECTORS
    size = nsec * 512
    hdr = header(PASSWORD, hashlib.sha512(b"salt").digest(), master, size, DATA_START, 0)
    data = b"".join(xts(master[:64], DATA_START // 512 + i, image[i * 512:(i + 1) * 512] if image else pattern(i), True)
                    for i in range(nsec))
    return area(hdr, b"std") + area(filler(b"nohidden", 512), b"nohidden2") + data + bytes(DATA_START)   # + backup header areas


def build_hidden(outer_img=None, hidden_img=None):
    """Patterns by default; FAT images (for the device) when given. The hidden volume sits at the end of the outer one."""
    outer, hid = keys(b"outer"), keys(b"hidden")
    n = len(outer_img) // 512 if outer_img else SECTORS
    nh = len(hidden_img) // 512 if hidden_img else HIDDEN_SECTORS
    hstart = DATA_START + (n - nh) * 512
    h_outer = header(PASSWORD, hashlib.sha512(b"outer salt").digest(), outer, n * 512, DATA_START, 0)
    h_hid = header(HIDDEN_PASSWORD, hashlib.sha512(b"hidden salt").digest(), hid, nh * 512, hstart, nh * 512)
    data = b"".join(xts(outer[:64], DATA_START // 512 + i, outer_img[i * 512:(i + 1) * 512] if outer_img else pattern(i), True)
                    for i in range(n - nh))
    data += b"".join(xts(hid[:64], hstart // 512 + i, hidden_img[i * 512:(i + 1) * 512] if hidden_img else hidden_pattern(i), True)
                     for i in range(nh))
    return area(h_outer, b"outer") + area(h_hid, b"hid") + data + bytes(DATA_START)


def check(path):
    raw = open(path, "rb").read()
    salt = raw[:64]
    dk = hashlib.pbkdf2_hmac("sha512", PASSWORD, salt, 500000, 64)
    h = raw[:64] + xts(dk, 0, raw[64:512], False)
    master = h[256:320]
    assert h[64:68] == b"VERA"
    for i in range(SECTORS):
        got = xts(master, DATA_START // 512 + i,
                  raw[DATA_START + i * 512: DATA_START + (i + 1) * 512], False)
        want = bytes([WRITTEN[i]]) * 512 if i in WRITTEN else pattern(i)
        assert got == want, f"sector {i} differs"
    print("vera check ok:", path)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--image":
        open(sys.argv[3], "wb").write(build(open(sys.argv[2], "rb").read()))
        print("wrote", sys.argv[3])
    elif len(sys.argv) == 5 and sys.argv[1] == "--hidden-image":
        open(sys.argv[4], "wb").write(build_hidden(open(sys.argv[2], "rb").read(), open(sys.argv[3], "rb").read()))
        print("wrote", sys.argv[4])
    elif len(sys.argv) == 3 and sys.argv[1] == "--check":
        check(sys.argv[2])
    else:
        d = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "testdata")
        open(os.path.join(d, "vera_test.hc"), "wb").write(build())
        open(os.path.join(d, "vera_hidden.hc"), "wb").write(build_hidden())
        print("wrote vera_test.hc, vera_hidden.hc in", d)
