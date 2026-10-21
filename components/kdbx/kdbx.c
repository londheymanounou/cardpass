/* KDBX 4.x unlock pipeline, fully streaming:
 * file -> HMAC blocks -> AES-CBC / ChaCha20 -> gzip (tinfl) -> inner header -> XML index.
 * Decrypted data is parsed before its block HMAC is checked (blocks are 1 MiB,
 * too big to buffer); on any failure the whole index is wiped and nothing is returned. */
#include <stdlib.h>
#include <string.h>
#include "mbedtls/aes.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "miniz.h" /* host: miniz; device: ESP-IDF ROM (esp_rom/include/miniz.h) */
#include "kdbx_priv.h"

#define CHUNK 4096

const uint8_t KDBX_UUID_AES256[16] = {0x31,0xc1,0xf2,0xe6,0xbf,0x71,0x43,0x50,0xbe,0x58,0x05,0x21,0x6a,0xfc,0x5a,0xff};
const uint8_t KDBX_UUID_CHACHA20[16] = {0xd6,0x03,0x8a,0x2b,0x8b,0x6f,0x4c,0xb5,0xa5,0x24,0x33,0x9a,0x31,0xdb,0xb5,0x9a};
static const uint8_t UUID_AESKDF4[16] = {0xc9,0xd9,0xf3,0x9a,0x62,0x8a,0x44,0x60,0xbf,0x74,0x0d,0x08,0xc1,0x8a,0x4f,0xea};
static const uint8_t UUID_AESKDF3[16] = {0x7c,0x02,0xbb,0x82,0x79,0xa7,0x4a,0xc0,0x92,0x7d,0x11,0x4a,0x00,0x64,0x82,0x38};
const uint8_t KDBX_UUID_ARGON2D[16] = {0xef,0x63,0x6d,0xdf,0x8c,0x29,0x44,0x4b,0x91,0xf7,0xa9,0xa4,0x03,0xe3,0x0a,0x0c};
const uint8_t KDBX_UUID_ARGON2ID[16] = {0x9e,0x29,0x8b,0x19,0x56,0xdb,0x47,0x73,0xb2,0x3d,0xfc,0x3e,0xc6,0xf0,0xa1,0xe6};

const char *kdbx_strerror(kdbx_err e)
{
    switch (e) {
    case KDBX_OK: return "OK";
    case KDBX_ERR_IO: return "Read error or truncated file";
    case KDBX_ERR_FORMAT: return "Not a valid KDBX file";
    case KDBX_ERR_VERSION: return "Unsupported KDBX version (only KDBX 4.x)";
    case KDBX_ERR_KDF: return "Unsupported key derivation settings";
    case KDBX_ERR_CIPHER: return "Unsupported cipher (only AES-256 and ChaCha20)";
    case KDBX_ERR_KEY: return "Wrong password or key file";
    case KDBX_ERR_CORRUPT: return "Database is corrupted";
    case KDBX_ERR_KEYFILE: return "Invalid key file";
    case KDBX_ERR_NOMEM: return "Out of memory (database too large?)";
    case KDBX_ERR_EDIT: return "Invalid edit";
    case KDBX_ERR_REINDEX: return "Saved, but too large to reopen";
    case KDBX_ERR_SWAP: return "Argon2: not enough space on the SD card";
    }
    return "Unknown error";
}

static uint32_t le32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t le64(const uint8_t *p) { return le32(p) | (uint64_t)le32(p + 4) << 32; }
static void put_le64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> 8 * i); }
static bool rd(FILE *f, void *b, size_t n) { return fread(b, 1, n, f) == n; }

/* ---------------- header ---------------- */

static kdbx_err parse_kdf(kdbx_header *h, const uint8_t *p, size_t n)
{
    const uint8_t *end = p + n;
    bool uuid = false, seed = false, lanes = false, mem = false, iter = false, ver = false;
    if (n < 3 || p[1] != 1) return KDBX_ERR_FORMAT; /* VariantDictionary 1.x */
    for (p += 2; p < end && *p;) {
        if (end - p < 9) return KDBX_ERR_FORMAT;
        uint8_t type = *p;
        uint32_t kl = le32(p + 1);
        if (kl > (size_t)(end - p) - 9) return KDBX_ERR_FORMAT;
        const uint8_t *key = p + 5;
        uint32_t vl = le32(key + kl);
        const uint8_t *v = key + kl + 4;
        if (vl > (size_t)(end - v)) return KDBX_ERR_FORMAT;
        if (kl == 5 && !memcmp(key, "$UUID", 5) && vl == 16) {
            if (!memcmp(v, UUID_AESKDF4, 16) || !memcmp(v, UUID_AESKDF3, 16)) h->kdf = KDF_AES;
            else if (!memcmp(v, KDBX_UUID_ARGON2D, 16)) h->kdf = KDF_ARGON2, h->a2_type = KDBX_ARGON2_D;
            else if (!memcmp(v, KDBX_UUID_ARGON2ID, 16)) h->kdf = KDF_ARGON2, h->a2_type = KDBX_ARGON2_ID;
            else return KDBX_ERR_KDF;
            uuid = true;
        } else if (kl == 1 && *key == 'R' && type == 0x05 && vl == 8) {
            h->rounds = le64(v);
        } else if (kl == 1 && *key == 'S' && vl >= 8 && vl <= sizeof h->a2_salt) {
            memcpy(h->a2_salt, v, vl);                     /* AES-KDF seed or Argon2 salt: sorted out below */
            h->a2_saltlen = vl;
            seed = true;
        } else if (kl == 1 && *key == 'P' && type == 0x04 && vl == 4) {
            h->a2_lanes = le32(v), lanes = true;
        } else if (kl == 1 && *key == 'M' && type == 0x05 && vl == 8) {
            h->a2_mem = le64(v), mem = true;
        } else if (kl == 1 && *key == 'I' && type == 0x05 && vl == 8) {
            h->a2_iter = le64(v), iter = true;
        } else if (kl == 1 && *key == 'V' && type == 0x04 && vl == 4) {
            h->a2_version = le32(v), ver = true;
        } else if (kl == 1 && *key == 'K' && vl <= sizeof h->a2_secret) {
            memcpy(h->a2_secret, v, vl), h->a2_secretlen = vl;
        } else if (kl == 1 && *key == 'A' && vl <= sizeof h->a2_ad) {
            memcpy(h->a2_ad, v, vl), h->a2_adlen = vl;
        } else if (kl == 1 && (*key == 'K' || *key == 'A')) {
            return KDBX_ERR_KDF;                           /* longer than we keep: refuse rather than compute wrong */
        }
        p = v + vl;
    }
    if (!uuid || !seed) return KDBX_ERR_KDF;
    if (h->kdf == KDF_AES) {
        if (h->a2_saltlen != 32) return KDBX_ERR_KDF;
        memcpy(h->kdf_seed, h->a2_salt, 32);
        return KDBX_OK;
    }
    if (!lanes || !mem || !iter || !ver || h->a2_iter < 1 || h->a2_iter > 0xFFFFFFFFu || h->a2_mem % 1024 ||
        h->a2_mem / 1024 > KDBX_ARGON2_MAX_KIB || h->a2_lanes < 1 || h->a2_mem / 1024 < 8u * h->a2_lanes ||
        (h->a2_version != 0x10 && h->a2_version != 0x13))
        return KDBX_ERR_KDF;
    return KDBX_OK;
}

kdbx_err kdbx_read_header(FILE *f, kdbx_header *h)
{
    memset(h, 0, sizeof *h);
    uint8_t *r = h->raw;
    if (!rd(f, r, 12)) return KDBX_ERR_IO;
    if (le32(r) != 0x9AA2D903 || le32(r + 4) != 0xB54BFB67) return KDBX_ERR_FORMAT;
    if ((r[10] | r[11] << 8) != 4) return KDBX_ERR_VERSION;
    h->rawlen = 12;
    h->cipher = -1;

    bool seed = false, iv = false, kdf = false, comp = false;
    for (;;) {
        uint8_t *fld = r + h->rawlen;
        if (h->rawlen + 5 > sizeof h->raw || !rd(f, fld, 5)) return h->rawlen + 5 > sizeof h->raw ? KDBX_ERR_FORMAT : KDBX_ERR_IO;
        uint32_t n = le32(fld + 1);
        if (n > sizeof h->raw - h->rawlen - 5) return KDBX_ERR_FORMAT;
        uint8_t *d = fld + 5;
        if (!rd(f, d, n)) return KDBX_ERR_IO;
        h->rawlen += 5 + n;
        kdbx_err err;
        switch (fld[0]) {
        case 0: goto end;
        case 2:
            if (n == 16 && !memcmp(d, KDBX_UUID_AES256, 16)) h->cipher = CIPHER_AES256;
            else if (n == 16 && !memcmp(d, KDBX_UUID_CHACHA20, 16)) h->cipher = CIPHER_CHACHA20;
            else return KDBX_ERR_CIPHER;
            break;
        case 3:
            if (n != 4 || le32(d) > 1) return KDBX_ERR_FORMAT;
            h->gzip = le32(d) == 1;
            comp = true;
            break;
        case 4:
            if (n != 32) return KDBX_ERR_FORMAT;
            memcpy(h->master_seed, d, 32);
            seed = true;
            break;
        case 7:
            if (n != 16 && n != 12) return KDBX_ERR_FORMAT;
            memcpy(h->iv, d, n);
            h->ivlen = n;
            iv = true;
            break;
        case 11:
            if ((err = parse_kdf(h, d, n)) != KDBX_OK) return err;
            kdf = true;
            break;
        default: break; /* public custom data etc. */
        }
    }
end:
    if (h->cipher < 0 || !seed || !iv || !kdf || !comp) return KDBX_ERR_FORMAT;
    if (h->ivlen != (h->cipher == CIPHER_AES256 ? 16u : 12u)) return KDBX_ERR_FORMAT;
    return KDBX_OK;
}

static void (*progress_cb)(void *ctx, int pct);
static void *progress_ctx;

void kdbx_set_progress(void (*cb)(void *ctx, int pct), void *ctx)
{
    progress_cb = cb;
    progress_ctx = ctx;
}

static kdbx_kdf_accel_fn kdf_accel;

void kdbx_set_kdf_accel(kdbx_kdf_accel_fn fn) { kdf_accel = fn; }
bool kdbx_kdf_accel_active(void) { return kdf_accel != NULL; }

static void soft_rounds(const uint8_t seed[32], uint8_t b[32], uint64_t n)
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, seed, 256);
    for (uint64_t i = 0; i < n; i++) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, b, b);
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, b + 16, b + 16);
    }
    mbedtls_aes_free(&aes);
}

#define KDF_MAX_CHUNK 500000u   /* a chunk is one accelerator call: keeps the hardware lock short and the watchdog fed */

kdbx_err kdbx_kdf(const kdbx_header *h, const uint8_t composite[32], uint8_t tk[32])
{
    if (h->kdf == KDF_AES) {
        kdbx_aes_kdf(h->kdf_seed, h->rounds, composite, tk);
        return KDBX_OK;
    }
    kdbx_argon2_params a = {(uint32_t)h->a2_type, h->a2_version, h->a2_lanes, (uint32_t)h->a2_iter, (uint32_t)(h->a2_mem / 1024),
                            h->a2_salt, h->a2_secret, h->a2_ad, h->a2_saltlen, h->a2_secretlen, h->a2_adlen};
    if (progress_cb) progress_cb(progress_ctx, 0);
    return kdbx_argon2(&a, composite, 32, tk, 32, progress_cb, progress_ctx);
}

kdbx_err kdbx_argon2_bench(uint32_t mem_kib)
{
    static const uint8_t salt[32], pw[32];
    uint8_t out[32];
    kdbx_argon2_params a = {KDBX_ARGON2_ID, 0x13, 2, 1, mem_kib, salt, NULL, NULL, sizeof salt, 0, 0};
    if (progress_cb) progress_cb(progress_ctx, 0);
    kdbx_err e = kdbx_argon2(&a, pw, sizeof pw, out, sizeof out, progress_cb, progress_ctx);
    mbedtls_platform_zeroize(out, sizeof out);
    return e;
}

void kdbx_aes_kdf(const uint8_t seed[32], uint64_t rounds, const uint8_t in[32], uint8_t out[32])
{
    uint8_t b[32];
    memcpy(b, in, 32);
    uint64_t chunk = rounds / 50 ? rounds / 50 : 1;
    if (chunk > KDF_MAX_CHUNK) chunk = KDF_MAX_CHUNK;
    if (progress_cb) progress_cb(progress_ctx, 0);
    for (uint64_t done = 0; done < rounds;) {
        uint64_t n = rounds - done < chunk ? rounds - done : chunk;
        if (!kdf_accel || !kdf_accel(seed, b, n)) soft_rounds(seed, b, n);
        done += n;
        if (progress_cb) progress_cb(progress_ctx, (int)(done * 100 / rounds));
    }
    if (progress_cb) progress_cb(progress_ctx, 100);
    mbedtls_sha256(b, 32, out, 0);
    mbedtls_platform_zeroize(b, sizeof b);
}

/* ---------------- payload pipeline ---------------- */

typedef struct {
    kdbx_sink *sink;
    int cipher;
    bool gzip;
    mbedtls_aes_context aes;
    mbedtls_chacha20_context chacha;
    uint8_t iv[16];
    uint8_t cbuf[CHUNK + 16];
    size_t clen;
    uint8_t out[CHUNK + 16];
    /* gzip */
    uint8_t gzh[10];
    int gzhave;
    bool inf_done;
    size_t dict_ofs;
    tinfl_decompressor inf;
    uint8_t *dict;              /* TINFL_LZ_DICT_SIZE: see dict_get() */
    /* inner header */
    uint8_t ih[5], val[64];
    int ihave;
    uint32_t remain, vlen;
    bool in_xml, have_id, have_key;
} pipeline;

/* The 32 KB inflate window is the biggest block an unlock or a save needs in one piece. After the first unlock the heap can
 * be fragmented so that no such hole is left, and every later save failed with "out of memory" although plenty was free. So
 * one window is kept (wiped) while the database is unlocked and handed to the next unlock / save / verify; app_lock gives it
 * back through kdbx_release_buffers(). */
static uint8_t *dict_spare;

static uint8_t *dict_get(void)
{
    uint8_t *d = dict_spare;
    dict_spare = NULL;
    return d ? d : malloc(TINFL_LZ_DICT_SIZE);
}

static void dict_put(uint8_t *d)
{
    if (!d) return;
    mbedtls_platform_zeroize(d, TINFL_LZ_DICT_SIZE);      /* decompressed XML passed through it */
    if (dict_spare) free(d);
    else dict_spare = d;
}

void kdbx_release_buffers(void)
{
    free(dict_spare);
    dict_spare = NULL;
}

static pipeline *pipeline_new(void)
{
    pipeline *p = calloc(1, sizeof *p);
    if (p && !(p->dict = dict_get())) {
        free(p);
        p = NULL;
    }
    return p;
}

static void pipeline_free(pipeline *p)
{
    if (!p) return;
    dict_put(p->dict);
    p->dict = NULL;
    mbedtls_platform_zeroize(p, sizeof *p);
    free(p);
}

static kdbx_err inner_field_done(pipeline *p)
{
    switch (p->ih[0]) {
    case 0:
        if (!p->have_id || !p->have_key) return KDBX_ERR_FORMAT;
        p->in_xml = true;
        break;
    case 1:
        if (p->vlen != 4) return KDBX_ERR_FORMAT;
        if (le32(p->val) != 3) return KDBX_ERR_CIPHER; /* only ChaCha20 inner stream (KDBX 4 default) */
        p->have_id = true;
        break;
    case 2: {
        uint8_t h[64];
        mbedtls_sha512(p->val, p->vlen, h, 0);
        memcpy(p->sink->stream_key, h, 32);
        memcpy(p->sink->stream_nonce, h + 32, 12);
        mbedtls_platform_zeroize(h, sizeof h);
        p->have_key = true;
        break;
    }
    default: break; /* 3 = attachment: skipped, never decoded */
    }
    p->ihave = 0;
    return KDBX_OK;
}

static kdbx_err inner_feed(pipeline *p, const uint8_t *d, size_t n)
{
    while (n) {
        if (p->in_xml) return p->sink->xml(p->sink->ctx, d, n);
        if (p->ihave < 5) {
            p->ih[p->ihave++] = *d++;
            n--;
            if (p->ihave == 5) {
                p->remain = le32(p->ih + 1);
                p->vlen = 0;
                if ((p->ih[0] == 1 || p->ih[0] == 2) && p->remain > sizeof p->val) return KDBX_ERR_FORMAT;
                if (p->ih[0] == 3 && p->sink->bin) {
                    kdbx_err e = p->sink->bin(p->sink->ctx, p->ih, 5);
                    if (e) return e;
                }
                if (!p->remain) { kdbx_err e = inner_field_done(p); if (e) return e; }
            }
            continue;
        }
        size_t take = n < p->remain ? n : p->remain;
        if (p->ih[0] == 1 || p->ih[0] == 2) {
            memcpy(p->val + p->vlen, d, take);
            p->vlen += (uint32_t)take;
        } else if (p->ih[0] == 3 && p->sink->bin) {
            kdbx_err e = p->sink->bin(p->sink->ctx, d, take);
            if (e) return e;
        }
        d += take;
        n -= take;
        if (!(p->remain -= (uint32_t)take)) { kdbx_err e = inner_field_done(p); if (e) return e; }
    }
    return KDBX_OK;
}

static kdbx_err inflate_feed(pipeline *p, const uint8_t *d, size_t n)
{
    if (!p->gzip) return inner_feed(p, d, n);
    for (; p->gzhave < 10 && n; n--) p->gzh[p->gzhave++] = *d++;
    if (p->gzhave < 10 || !n) return KDBX_OK;
    /* ponytail: no optional gzip fields (KeePass/KeePassXC never write them) */
    if (p->gzh[0] != 0x1f || p->gzh[1] != 0x8b || p->gzh[2] != 8 || p->gzh[3]) return KDBX_ERR_FORMAT;

    while (n && !p->inf_done) {
        size_t in_sz = n, out_sz = TINFL_LZ_DICT_SIZE - p->dict_ofs;
        tinfl_status st = tinfl_decompress(&p->inf, d, &in_sz, p->dict, p->dict + p->dict_ofs, &out_sz,
                                           TINFL_FLAG_HAS_MORE_INPUT);
        d += in_sz;
        n -= in_sz;
        if (out_sz) {
            kdbx_err e = inner_feed(p, p->dict + p->dict_ofs, out_sz);
            if (e) return e;
            p->dict_ofs = (p->dict_ofs + out_sz) & (TINFL_LZ_DICT_SIZE - 1);
        }
        if (st < 0) return KDBX_ERR_CORRUPT;
        if (st == TINFL_STATUS_DONE) p->inf_done = true;
    }
    return KDBX_OK; /* bytes after the deflate stream = gzip trailer, covered by the HMAC */
}

static kdbx_err outer_feed(pipeline *p, const uint8_t *d, size_t n)
{
    kdbx_err e;
    if (p->cipher == CIPHER_CHACHA20) {
        mbedtls_chacha20_update(&p->chacha, n, d, p->out);
        return inflate_feed(p, p->out, n);
    }
    /* AES-CBC: always hold back the last block (PKCS#7 padding is only known at the end) */
    memcpy(p->cbuf + p->clen, d, n);
    p->clen += n;
    size_t m = p->clen ? (p->clen - 1) / 16 * 16 : 0;
    if (!m) return KDBX_OK;
    mbedtls_aes_crypt_cbc(&p->aes, MBEDTLS_AES_DECRYPT, m, p->iv, p->cbuf, p->out);
    memmove(p->cbuf, p->cbuf + m, p->clen - m);
    p->clen -= m;
    e = inflate_feed(p, p->out, m);
    return e;
}

static kdbx_err outer_finish(pipeline *p)
{
    if (p->cipher == CIPHER_AES256) {
        if (p->clen != 16) return KDBX_ERR_CORRUPT;
        mbedtls_aes_crypt_cbc(&p->aes, MBEDTLS_AES_DECRYPT, 16, p->iv, p->cbuf, p->out);
        uint8_t pad = p->out[15];
        if (pad < 1 || pad > 16) return KDBX_ERR_CORRUPT;
        for (int i = 16 - pad; i < 16; i++)
            if (p->out[i] != pad) return KDBX_ERR_CORRUPT;
        kdbx_err e = inflate_feed(p, p->out, 16 - pad);
        if (e) return e;
    }
    if (p->gzip && !p->inf_done) return KDBX_ERR_CORRUPT;
    return p->in_xml ? KDBX_OK : KDBX_ERR_CORRUPT;
}

void kdbx_block_key(const uint8_t hmac_base[64], uint64_t idx, uint8_t out[64])
{
    uint8_t b[72];
    put_le64(b, idx);
    memcpy(b + 8, hmac_base, 64);
    mbedtls_sha512(b, sizeof b, out, 0);
    mbedtls_platform_zeroize(b, sizeof b);
}

static kdbx_err read_blocks(FILE *f, pipeline *p, mbedtls_md_context_t *md, const uint8_t hmac_base[64])
{
    uint8_t stored[32], mac[32], key[64], hdr[12], buf[CHUNK];
    kdbx_err err = KDBX_OK;

    for (uint64_t idx = 0;; idx++) {
        if (!rd(f, stored, 32) || !rd(f, hdr + 8, 4)) { err = KDBX_ERR_IO; break; }
        uint32_t len = le32(hdr + 8);
        put_le64(hdr, idx);
        kdbx_block_key(hmac_base, idx, key);
        mbedtls_md_hmac_starts(md, key, 64);
        mbedtls_md_hmac_update(md, hdr, 12);
        for (uint32_t left = len; left;) {
            size_t n = left < CHUNK ? left : CHUNK;
            if (!rd(f, buf, n)) { err = KDBX_ERR_IO; goto out; }
            mbedtls_md_hmac_update(md, buf, n);
            if ((err = outer_feed(p, buf, n)) != KDBX_OK) goto out;
            left -= (uint32_t)n;
        }
        mbedtls_md_hmac_finish(md, mac);
        if (mbedtls_ct_memcmp(mac, stored, 32)) { err = KDBX_ERR_CORRUPT; break; }
        if (!len) { err = outer_finish(p); break; }
    }
out:
    mbedtls_platform_zeroize(key, sizeof key);
    mbedtls_platform_zeroize(buf, sizeof buf);
    return err;
}

void kdbx_derive(const kdbx_header *h, const uint8_t tk[32], uint8_t master[32], uint8_t hmac_base[64])
{
    uint8_t buf[65];
    memcpy(buf, h->master_seed, 32);
    memcpy(buf + 32, tk, 32);
    mbedtls_sha256(buf, 64, master, 0);
    buf[64] = 1;
    mbedtls_sha512(buf, 65, hmac_base, 0);
    mbedtls_platform_zeroize(buf, sizeof buf);
}

void kdbx_header_hmac(const kdbx_header *h, const uint8_t hmac_base[64], uint8_t mac[32])
{
    uint8_t hk[64];
    kdbx_block_key(hmac_base, UINT64_MAX, hk);
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), hk, 64, h->raw, h->rawlen, mac);
    mbedtls_platform_zeroize(hk, sizeof hk);
}

static kdbx_err index_xml(void *ctx, const uint8_t *d, size_t n);
static kdbx_err index_bin(void *ctx, const uint8_t *d, size_t n);

/* Test hook (fuzzing): decrypted payload bytes -> gzip -> inner header -> index,
 * fed in chunks of `chunk` bytes as the real pipeline would. */
kdbx_err kdbx_index_payload(const uint8_t *d, size_t n, bool gzip, size_t chunk, kdbx_db **out)
{
    pipeline *p = pipeline_new();
    kdbx_db *db = calloc(1, sizeof *db);
    xml_index *xi = malloc(sizeof *xi);
    kdbx_sink s = {index_xml, index_bin, xi, {0}, {0}};
    kdbx_err err = KDBX_ERR_NOMEM;
    *out = NULL;
    if (p && db && xi) {
        xml_index_init(xi, db);
        p->sink = &s;
        p->cipher = CIPHER_CHACHA20; /* no padding stage */
        p->gzip = gzip;
        tinfl_init(&p->inf);
        err = KDBX_OK;
        for (size_t i = 0; i < n && !err; i += chunk)
            err = inflate_feed(p, d + i, n - i < chunk ? n - i : chunk);
        if (!err) err = outer_finish(p);
        if (!err) err = xml_index_finish(xi);
        xml_index_wipe(xi);
    }
    free(xi);
    pipeline_free(p);
    if (err) kdbx_close(db);
    else *out = db;
    return err;
}

/* Does this key open the file? Runs the KDF and checks the header HMAC only: no payload, no index. */
kdbx_err kdbx_check_key(FILE *f, const kdbx_key *key)
{
    kdbx_header *h = malloc(sizeof *h);
    uint8_t sums[64], mac[32], tk[32], master[32], base[64];
    kdbx_err err = KDBX_ERR_NOMEM;
    if (!h) return err;
    if ((err = kdbx_read_header(f, h)) != KDBX_OK) goto done;
    if (fread(sums, 1, 64, f) != 64) { err = KDBX_ERR_IO; goto done; }
    if ((err = kdbx_kdf(h, key->composite, tk)) != KDBX_OK) goto done;
    kdbx_derive(h, tk, master, base);
    kdbx_header_hmac(h, base, mac);
    err = mbedtls_ct_memcmp(mac, sums + 32, 32) ? KDBX_ERR_KEY : KDBX_OK;
done:
    mbedtls_platform_zeroize(tk, sizeof tk);
    mbedtls_platform_zeroize(master, sizeof master);
    mbedtls_platform_zeroize(base, sizeof base);
    free(h);
    return err;
}

kdbx_err kdbx_read_file(FILE *f, const uint8_t *composite, uint8_t tk[32], kdbx_header *h, kdbx_sink *s)
{
    pipeline *p = pipeline_new();
    uint8_t sums[64], mac[32], hmac_base[64], master[32];
    mbedtls_md_context_t md;
    kdbx_err err;

    mbedtls_md_init(&md);
    if (!p) return KDBX_ERR_NOMEM;
    mbedtls_aes_init(&p->aes);
    mbedtls_chacha20_init(&p->chacha);
    if ((err = kdbx_read_header(f, h)) != KDBX_OK) goto done;
    if (!rd(f, sums, 64)) { err = KDBX_ERR_IO; goto done; }
    mbedtls_sha256(h->raw, h->rawlen, mac, 0);
    if (memcmp(mac, sums, 32)) { err = KDBX_ERR_CORRUPT; goto done; }

    if (composite && (err = kdbx_kdf(h, composite, tk)) != KDBX_OK) goto done;
    kdbx_derive(h, tk, master, hmac_base);
    kdbx_header_hmac(h, hmac_base, mac);
    if (mbedtls_ct_memcmp(mac, sums + 32, 32)) { err = KDBX_ERR_KEY; goto done; }

    if (mbedtls_md_setup(&md, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1)) { err = KDBX_ERR_NOMEM; goto done; }
    p->sink = s;
    p->cipher = h->cipher;
    p->gzip = h->gzip;
    memcpy(p->iv, h->iv, h->ivlen);
    if (h->cipher == CIPHER_AES256) {
        mbedtls_aes_setkey_dec(&p->aes, master, 256);
    } else {
        mbedtls_chacha20_setkey(&p->chacha, master);
        mbedtls_chacha20_starts(&p->chacha, h->iv, 0);
    }
    tinfl_init(&p->inf);
    err = read_blocks(f, p, &md, hmac_base);

done:
    mbedtls_md_free(&md);
    mbedtls_platform_zeroize(hmac_base, sizeof hmac_base);
    mbedtls_platform_zeroize(master, sizeof master);
    mbedtls_aes_free(&p->aes);
    mbedtls_chacha20_free(&p->chacha);
    pipeline_free(p);
    return err;
}

static kdbx_err index_xml(void *ctx, const uint8_t *d, size_t n) { return xml_index_feed(ctx, d, n); }

/* Attachment sizes only (content skipped). The first call per field is its 5-byte header. */
static kdbx_err index_bin(void *ctx, const uint8_t *d, size_t n)
{
    kdbx_db *db = ((xml_index *)ctx)->db;
    if (db->bin_left) {
        db->bin_left -= (uint32_t)n;
        return KDBX_OK;
    }
    db->bin_left = le32(d + 1);
    if (db->nbins < 64) db->bin_size[db->nbins] = db->bin_left ? db->bin_left - 1 : 0; /* minus flags byte */
    db->nbins++;
    return KDBX_OK;
}

typedef struct {
    uint32_t want, idx, left;
    bool in_field, flags_done;
    uint8_t *buf;
    size_t max, got, total;
} att_reader;

static kdbx_err att_bin(void *ctx, const uint8_t *d, size_t n)
{
    att_reader *r = ctx;
    if (!r->left) { /* field header */
        r->left = le32(d + 1);
        r->in_field = r->idx++ == r->want;
        r->flags_done = false;
        return KDBX_OK;
    }
    r->left -= (uint32_t)n;
    if (!r->in_field) return KDBX_OK;
    if (!r->flags_done) { d++; n--; r->flags_done = true; }
    size_t take = r->max - r->got < n ? r->max - r->got : n;
    memcpy(r->buf + r->got, d, take);
    r->got += take;
    r->total += n;
    return KDBX_OK;
}

static kdbx_err ignore_xml(void *ctx, const uint8_t *d, size_t n) { (void)ctx; (void)d; (void)n; return KDBX_OK; }

kdbx_err kdbx_attachment_read(const kdbx_db *db, const char *path, const kdbx_attachment *a, uint8_t *buf,
                              size_t max, size_t *got)
{
    att_reader r = {.want = a->ref, .buf = buf, .max = max};
    kdbx_sink s = {ignore_xml, att_bin, &r, {0}, {0}};
    kdbx_header *h = malloc(sizeof *h);
    uint8_t tk[32];
    FILE *f = fopen(path, "rb");
    kdbx_err err = !h ? KDBX_ERR_NOMEM : !f ? KDBX_ERR_IO : KDBX_OK;
    *got = 0;
    if (!err) {
        memcpy(tk, db->transformed, 32);
        err = kdbx_read_file(f, NULL, tk, h, &s); /* whole file: every block HMAC is checked */
        mbedtls_platform_zeroize(tk, sizeof tk);
    }
    if (!err && r.idx <= a->ref) err = KDBX_ERR_CORRUPT;
    if (err) mbedtls_platform_zeroize(buf, max);
    else *got = r.got;
    mbedtls_platform_zeroize(&s, sizeof s);
    if (f) fclose(f);
    free(h);
    return err;
}

bool kdbx_is_text(const uint8_t *d, size_t n, bool truncated)
{
    for (size_t i = 0; i < n;) {
        uint8_t c = d[i];
        int len = c < 0x80 ? 1 : (c & 0xE0) == 0xC0 ? 2 : (c & 0xF0) == 0xE0 ? 3 : (c & 0xF8) == 0xF0 ? 4 : 0;
        if (!len || (len == 1 && c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7F) return false;
        if (i + (size_t)len > n) return truncated;
        for (int k = 1; k < len; k++)
            if ((d[i + k] & 0xC0) != 0x80) return false;
        i += (size_t)len;
    }
    return true;
}

kdbx_err kdbx_open_tk(FILE *f, const uint8_t *composite, const uint8_t tk_in[32], kdbx_db **out)
{
    kdbx_header *h = malloc(sizeof *h);
    kdbx_db *db = calloc(1, sizeof *db);
    xml_index *xi = malloc(sizeof *xi);
    kdbx_sink s = {index_xml, index_bin, xi, {0}, {0}};
    kdbx_err err = KDBX_ERR_NOMEM;

    *out = NULL;
    if (h && db && xi) {
        xml_index_init(xi, db);
        if (tk_in) memcpy(db->transformed, tk_in, 32);
        err = kdbx_read_file(f, composite, db->transformed, h, &s);
        if (!err) err = xml_index_finish(xi);
        memcpy(db->stream_key, s.stream_key, 32);
        memcpy(db->stream_nonce, s.stream_nonce, 12);
        mbedtls_platform_zeroize(&s, sizeof s);
        xml_index_wipe(xi);
    }
    free(xi);
    free(h);
    if (err) kdbx_close(db);
    else *out = db;
    return err;
}

kdbx_err kdbx_open(FILE *f, const kdbx_key *key, kdbx_db **out)
{
    return kdbx_open_tk(f, key->composite, NULL, out);
}

void kdbx_close(kdbx_db *db)
{
    if (!db) return;
    arena_free(&db->a);
    mbedtls_platform_zeroize(db, sizeof *db);
    free(db);
}

const kdbx_entry *kdbx_entries(const kdbx_db *db) { return db->entries; }
const kdbx_group *kdbx_groups(const kdbx_db *db) { return db->groups; }

const kdbx_field *kdbx_field_get(const kdbx_entry *e, const char *key)
{
    for (size_t i = 0; i < e->nfields; i++)
        if (!strcmp(e->fields[i].key, key)) return &e->fields[i];
    return NULL;
}

void kdbx_stream_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t off, const uint8_t *in, uint8_t *out, size_t n)
{
    mbedtls_chacha20_context c;
    uint8_t skip[64] = {0};
    mbedtls_chacha20_init(&c);
    mbedtls_chacha20_setkey(&c, key);
    mbedtls_chacha20_starts(&c, nonce, off / 64);
    mbedtls_chacha20_update(&c, off % 64, skip, skip);
    mbedtls_chacha20_update(&c, n, in, out);
    mbedtls_chacha20_free(&c);
    mbedtls_platform_zeroize(skip, sizeof skip);
}

const char *kdbx_autotype(const kdbx_entry *e, const char *fallback)
{
    if (*e->autotype) return e->autotype;
    for (const kdbx_group *g = e->group; g; g = g->parent)
        if (*g->autotype) return g->autotype;
    return fallback;
}

kdbx_err kdbx_reveal(const kdbx_db *db, const kdbx_field *f, char *out, size_t outsz)
{
    if (f->len >= outsz) return KDBX_ERR_NOMEM;
    if (f->stream_off == KDBX_PLAIN) memcpy(out, f->value, f->len);
    else kdbx_stream_xor(db->stream_key, db->stream_nonce, f->stream_off, f->value, (uint8_t *)out, f->len);
    out[f->len] = 0;
    return KDBX_OK;
}
