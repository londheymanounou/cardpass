#include "vera.h"
#include <string.h>
#include "mbedtls/platform_util.h"
#include "mbedtls/sha512.h"

#define ITERATIONS 500000u          /* SHA-512, PIM 0 */
#define HEADER_SIZE 512
#define SALT 64
#define DATA_START 131072u          /* standard volume: two 64 KiB header areas precede the data */
#define HIDDEN_HEADER 65536u        /* the hidden volume's header: the second 64 KiB header area */

static uint32_t be16(const uint8_t *p) { return (uint32_t)p[0] << 8 | p[1]; }
static uint32_t be32(const uint8_t *p) { return be16(p) << 16 | be16(p + 2); }
static uint64_t be64(const uint8_t *p) { return (uint64_t)be32(p) << 32 | be32(p + 4); }

static uint32_t crc32(const uint8_t *p, size_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    while (n--) {
        c ^= *p++;
        for (int i = 0; i < 8; i++) c = c >> 1 ^ (0xEDB88320u & (0u - (c & 1)));
    }
    return ~c;
}

/* PBKDF2-HMAC-SHA512, one 64-byte block. The ipad/opad states are computed once, so an iteration is two compressions. */
static bool pbkdf2(const uint8_t *pw, size_t pwlen, const uint8_t salt[SALT], uint8_t out[64], void (*progress)(void *, int), void *arg)
{
    uint8_t key[128] = {0}, pad[128], u[64], t[64], in[64];
    mbedtls_sha512_context ic, oc, c;
    bool ok = false;
    mbedtls_sha512_init(&ic);
    mbedtls_sha512_init(&oc);
    mbedtls_sha512_init(&c);
    if (pwlen > sizeof key) {
        if (mbedtls_sha512(pw, pwlen, key, 0)) goto out;
    } else {
        memcpy(key, pw, pwlen);
    }
    for (int i = 0; i < 128; i++) pad[i] = key[i] ^ 0x36;
    if (mbedtls_sha512_starts(&ic, 0) || mbedtls_sha512_update(&ic, pad, sizeof pad)) goto out;
    for (int i = 0; i < 128; i++) pad[i] = key[i] ^ 0x5c;
    if (mbedtls_sha512_starts(&oc, 0) || mbedtls_sha512_update(&oc, pad, sizeof pad)) goto out;

    static const uint8_t one[4] = {0, 0, 0, 1};
    mbedtls_sha512_clone(&c, &ic);
    if (mbedtls_sha512_update(&c, salt, SALT) || mbedtls_sha512_update(&c, one, sizeof one) || mbedtls_sha512_finish(&c, in)) goto out;
    mbedtls_sha512_clone(&c, &oc);
    if (mbedtls_sha512_update(&c, in, 64) || mbedtls_sha512_finish(&c, u)) goto out;
    memcpy(t, u, 64);
    for (uint32_t i = 2; i <= ITERATIONS; i++) {
        mbedtls_sha512_clone(&c, &ic);
        if (mbedtls_sha512_update(&c, u, 64) || mbedtls_sha512_finish(&c, in)) goto out;
        mbedtls_sha512_clone(&c, &oc);
        if (mbedtls_sha512_update(&c, in, 64) || mbedtls_sha512_finish(&c, u)) goto out;
        for (int k = 0; k < 64; k++) t[k] ^= u[k];
        if (progress && i % (ITERATIONS / 100) == 0) progress(arg, (int)(i / (ITERATIONS / 100)));
    }
    memcpy(out, t, 64);
    ok = true;
out:
    mbedtls_platform_zeroize(key, sizeof key);
    mbedtls_platform_zeroize(pad, sizeof pad);
    mbedtls_platform_zeroize(u, sizeof u);
    mbedtls_platform_zeroize(t, sizeof t);
    mbedtls_platform_zeroize(in, sizeof in);
    mbedtls_sha512_free(&ic);
    mbedtls_sha512_free(&oc);
    mbedtls_sha512_free(&c);
    return ok;
}

/* AES-XTS (IEEE 1619) on a whole number of 16-byte blocks, in place; the tweak is the little-endian data unit number.
 * `k1` is the data key's encrypt or decrypt schedule to match `enc`; `k2` the tweak key (always encrypt). */
static void xts(mbedtls_aes_context *k1, mbedtls_aes_context *k2, bool enc, uint64_t unit, uint8_t *buf, size_t len)
{
    uint8_t t[16] = {0}, x[16];
    for (int i = 0; i < 8; i++) t[i] = (uint8_t)(unit >> (8 * i));
    mbedtls_aes_crypt_ecb(k2, MBEDTLS_AES_ENCRYPT, t, t);
    for (size_t o = 0; o < len; o += 16, buf += 16) {
        for (int i = 0; i < 16; i++) x[i] = buf[i] ^ t[i];
        mbedtls_aes_crypt_ecb(k1, enc ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, x, x);
        for (int i = 0; i < 16; i++) buf[i] = x[i] ^ t[i];
        uint8_t carry = 0;                                            /* t *= x in GF(2^128) */
        for (int i = 0; i < 16; i++) {
            uint8_t n = t[i] >> 7;
            t[i] = (uint8_t)(t[i] << 1 | carry);
            carry = n;
        }
        if (carry) t[0] ^= 0x87;
    }
    mbedtls_platform_zeroize(x, sizeof x);
    mbedtls_platform_zeroize(t, sizeof t);
}

/* One header at file offset `hoff` (0: the standard volume, 65536: the hidden volume). The hidden header looks like random
 * data to anyone without its password, so a password that matches neither is simply "wrong password". */
static int try_header(vera *v, const vera_io *io, uint64_t hoff, const uint8_t *pw, size_t pwlen, void (*progress)(void *, int), void *arg)
{
    uint8_t h[HEADER_SIZE], dk[64];
    mbedtls_aes_context hk1, hk2;
    int r = VERA_ERR_PASSWORD;
    memset(v, 0, sizeof *v);
    v->io = *io;
    mbedtls_aes_init(&hk1);
    mbedtls_aes_init(&hk2);
    mbedtls_aes_init(&v->enc);
    mbedtls_aes_init(&v->dec);
    mbedtls_aes_init(&v->tweak);
    if (io->read(io->io, hoff, h, sizeof h)) { r = hoff ? VERA_ERR_PASSWORD : VERA_ERR_IO; goto out; }   /* too short for a hidden header */
    if (!pbkdf2(pw, pwlen, h, dk, progress, arg)) goto out;
    if (mbedtls_aes_setkey_dec(&hk1, dk, 256) || mbedtls_aes_setkey_enc(&hk2, dk + 32, 256)) goto out;
    xts(&hk1, &hk2, false, 0, h + SALT, HEADER_SIZE - SALT);                          /* header: data unit 0 */

    if (be32(h + 64) != 0x56455241u) goto out;                                       /* "VERA" */
    uint32_t ver = be16(h + 68);
    if (ver > 5 || (ver >= 4 && be32(h + 252) != crc32(h + 64, 252 - 64))) goto out;
    if (be32(h + 72) != crc32(h + 256, 256)) goto out;
    uint64_t hidden = be64(h + 92), size = be64(h + 100), start = be64(h + 108), len = be64(h + 116);
    if (hoff && !hidden) goto out;                                                   /* not a hidden header after all */
    r = VERA_ERR_UNSUPPORTED;                                                        /* the password was right from here on */
    uint32_t ss = ver >= 5 ? be32(h + 128) : VERA_SECTOR;
    if (ss != VERA_SECTOR || len != size || !size || size % VERA_SECTOR || start % VERA_SECTOR || size > (1ull << 40)) goto out;
    if (hoff ? (hidden != size || start < DATA_START) : (hidden || start != DATA_START)) goto out;
    /* master key area: key 1 at +0, key 2 (tweak) at +32 */
    if (mbedtls_aes_setkey_enc(&v->enc, h + 256, 256) || mbedtls_aes_setkey_dec(&v->dec, h + 256, 256) ||
        mbedtls_aes_setkey_enc(&v->tweak, h + 256 + 32, 256))
        goto out;
    v->data_off = start;
    v->nsec = size / VERA_SECTOR;
    v->hidden = hoff != 0;
    r = VERA_OK;
out:
    mbedtls_aes_free(&hk1);
    mbedtls_aes_free(&hk2);
    mbedtls_platform_zeroize(h, sizeof h);
    mbedtls_platform_zeroize(dk, sizeof dk);
    if (r) vera_close(v);
    return r;
}

int vera_open(vera *v, const vera_io *io, const uint8_t *pw, size_t pwlen, void (*progress)(void *, int), void *arg)
{
    int r = try_header(v, io, 0, pw, pwlen, progress, arg);
    if (r == VERA_ERR_PASSWORD) {                                                    /* then maybe the hidden volume's */
        if (progress) progress(arg, 0);
        r = try_header(v, io, HIDDEN_HEADER, pw, pwlen, progress, arg);
    }
    return r;
}

bool vera_hidden(const vera *v) { return v->hidden; }

void vera_close(vera *v)
{
    mbedtls_aes_free(&v->enc);
    mbedtls_aes_free(&v->dec);
    mbedtls_aes_free(&v->tweak);
    mbedtls_platform_zeroize(v, sizeof *v);
}

uint64_t vera_sectors(const vera *v) { return v->nsec; }

/* The XTS data unit number of a sector is its absolute 512-byte position in the file. */
int vera_read(vera *v, uint64_t sector, uint32_t count, void *buf)
{
    if (!v->nsec || sector > v->nsec || count > v->nsec - sector) return VERA_ERR_IO;
    uint64_t off = v->data_off + sector * VERA_SECTOR;
    if (v->io.read(v->io.io, off, buf, (size_t)count * VERA_SECTOR)) return VERA_ERR_IO;
    for (uint32_t i = 0; i < count; i++) xts(&v->dec, &v->tweak, false, off / VERA_SECTOR + i, (uint8_t *)buf + (size_t)i * VERA_SECTOR, VERA_SECTOR);
    return VERA_OK;
}

int vera_write(vera *v, uint64_t sector, uint32_t count, const void *buf)
{
    if (!v->nsec || !v->io.write || sector > v->nsec || count > v->nsec - sector) return VERA_ERR_IO;
    uint64_t off = v->data_off + sector * VERA_SECTOR;
    uint8_t s[VERA_SECTOR];
    int r = VERA_OK;
    for (uint32_t i = 0; i < count && !r; i++) {
        memcpy(s, (const uint8_t *)buf + (size_t)i * VERA_SECTOR, VERA_SECTOR);
        xts(&v->enc, &v->tweak, true, off / VERA_SECTOR + i, s, VERA_SECTOR);
        if (v->io.write(v->io.io, off + (uint64_t)i * VERA_SECTOR, s, VERA_SECTOR)) r = VERA_ERR_IO;
    }
    mbedtls_platform_zeroize(s, sizeof s);
    return r;
}
