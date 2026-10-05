/* Argon2 (RFC 9106: Argon2d / Argon2i / Argon2id, versions 0x10 and 0x13) and BLAKE2b (RFC 7693), for KDBX 4
 * databases that use Argon2 as their key derivation.
 *
 * Memory. Argon2 needs `m` KiB (KeePass default: 64 MiB), the Cardputer has ~300 KB of RAM. The blocks live
 *   - in RAM when the whole memory fits under the limit set with kdbx_set_argon2_memory(), else
 *   - in a swap file on the SD card, ENCRYPTED with AES-256-CTR under a random key made for this one run and wiped
 *     at the end (counter = pass + block index: every write uses fresh keystream). What is on the card is useless
 *     once the run is over, and the file is deleted.
 * Swap layout: block (lane, column) is stored at ((slice * lanes + lane) * segment + index). That is exactly the
 * order Argon2 computes blocks in, so pass 0 only appends, every later pass rewrites the file front to back, and
 * whether a block was already rewritten in the current pass is just "index < current index".
 * Argon2 picks reference blocks with a bias towards recent ones (P(within the last f of the area) = sqrt(f)), so a
 * cache of the most recently written blocks saves real reads; writes are batched into runs; the old contents at the
 * write position (passes > 0) are read ahead sequentially.
 *
 * Blocks are used as uint64 arrays straight from bytes: little-endian CPUs only (x86, Xtensa). */
#include <stdlib.h>
#include <string.h>
#include "kdbx_priv.h"
#include "mbedtls/aes.h"
#include "mbedtls/platform_util.h"

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "argon2.c assumes a little-endian CPU"
#endif

/* ======================= BLAKE2b ======================= */

typedef struct { uint64_t h[8], t[2]; uint8_t b[128]; size_t c, outlen; } b2b;

static const uint64_t B2B_IV[8] = {0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL, 0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
                                   0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL, 0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL};
static const uint8_t SIGMA[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}, {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}};

static inline uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

static void b2b_compress(b2b *s, bool last)
{
    uint64_t v[16], m[16];
    for (int i = 0; i < 8; i++) v[i] = s->h[i], v[i + 8] = B2B_IV[i];
    v[12] ^= s->t[0];
    v[13] ^= s->t[1];
    if (last) v[14] = ~v[14];
    memcpy(m, s->b, 128);
#define B2G(a, b, c, d, x, y)                                                                                       \
    do {                                                                                                            \
        v[a] += v[b] + (x); v[d] = rotr64(v[d] ^ v[a], 32); v[c] += v[d]; v[b] = rotr64(v[b] ^ v[c], 24);           \
        v[a] += v[b] + (y); v[d] = rotr64(v[d] ^ v[a], 16); v[c] += v[d]; v[b] = rotr64(v[b] ^ v[c], 63);           \
    } while (0)
    for (int r = 0; r < 12; r++) {
        const uint8_t *z = SIGMA[r];
        B2G(0, 4, 8, 12, m[z[0]], m[z[1]]);
        B2G(1, 5, 9, 13, m[z[2]], m[z[3]]);
        B2G(2, 6, 10, 14, m[z[4]], m[z[5]]);
        B2G(3, 7, 11, 15, m[z[6]], m[z[7]]);
        B2G(0, 5, 10, 15, m[z[8]], m[z[9]]);
        B2G(1, 6, 11, 12, m[z[10]], m[z[11]]);
        B2G(2, 7, 8, 13, m[z[12]], m[z[13]]);
        B2G(3, 4, 9, 14, m[z[14]], m[z[15]]);
    }
#undef B2G
    for (int i = 0; i < 8; i++) s->h[i] ^= v[i] ^ v[i + 8];
    mbedtls_platform_zeroize(v, sizeof v);
    mbedtls_platform_zeroize(m, sizeof m);
}

static void b2b_init(b2b *s, size_t outlen)
{
    memset(s, 0, sizeof *s);
    memcpy(s->h, B2B_IV, sizeof s->h);
    s->h[0] ^= 0x01010000ULL ^ outlen;
    s->outlen = outlen;
}

static void b2b_update(b2b *s, const void *in, size_t n)
{
    const uint8_t *p = in;
    while (n--) {
        if (s->c == 128) {
            s->t[0] += 128;
            if (s->t[0] < 128) s->t[1]++;
            b2b_compress(s, false);
            s->c = 0;
        }
        s->b[s->c++] = *p++;
    }
}

static void b2b_final(b2b *s, uint8_t *out)
{
    s->t[0] += s->c;
    if (s->t[0] < s->c) s->t[1]++;
    memset(s->b + s->c, 0, 128 - s->c);
    b2b_compress(s, true);
    memcpy(out, s->h, s->outlen);                  /* little-endian words */
    mbedtls_platform_zeroize(s, sizeof *s);
}

void kdbx_blake2b(uint8_t *out, size_t outlen, const void *in, size_t inlen)
{
    b2b s;
    b2b_init(&s, outlen);
    b2b_update(&s, in, inlen);
    b2b_final(&s, out);
}

static void le32(uint8_t p[4], uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> 8 * i); }

/* H' (variable-length hash, RFC 9106 3.3) of a || b */
static void hprime(uint8_t *out, uint32_t outlen, const void *a, size_t alen, const void *b, size_t blen)
{
    uint8_t l[4], v[64];
    b2b s;
    le32(l, outlen);
    b2b_init(&s, outlen <= 64 ? outlen : 64);
    b2b_update(&s, l, 4);
    b2b_update(&s, a, alen);
    b2b_update(&s, b, blen);
    if (outlen <= 64) { b2b_final(&s, out); return; }
    b2b_final(&s, v);
    memcpy(out, v, 32);
    out += 32;
    uint32_t rem = outlen - 32;
    while (rem > 64) {
        kdbx_blake2b(v, 64, v, 64);
        memcpy(out, v, 32);
        out += 32;
        rem -= 32;
    }
    kdbx_blake2b(out, rem, v, 64);
    mbedtls_platform_zeroize(v, sizeof v);
}

/* ======================= Argon2 compression ======================= */

#define QW 128                                     /* 64-bit words per 1 KiB block */
typedef struct { uint64_t v[QW]; } blk;

static inline uint64_t fBlaMka(uint64_t x, uint64_t y) { return x + y + 2 * (uint64_t)(uint32_t)x * (uint32_t)y; }

#define GB(a, b, c, d)                                                                                              \
    do {                                                                                                            \
        a = fBlaMka(a, b); d = rotr64(d ^ a, 32); c = fBlaMka(c, d); b = rotr64(b ^ c, 24);                         \
        a = fBlaMka(a, b); d = rotr64(d ^ a, 16); c = fBlaMka(c, d); b = rotr64(b ^ c, 63);                         \
    } while (0)
#define PERM(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15)                                  \
    do {                                                                                                            \
        GB(v0, v4, v8, v12); GB(v1, v5, v9, v13); GB(v2, v6, v10, v14); GB(v3, v7, v11, v15);                       \
        GB(v0, v5, v10, v15); GB(v1, v6, v11, v12); GB(v2, v7, v8, v13); GB(v3, v4, v9, v14);                       \
    } while (0)

/* next = G(prev, ref), or next ^= G(prev, ref) (version 0x13, passes > 0) */
static void fill_block(const blk *prev, const blk *ref, blk *next, bool with_xor)
{
    static blk R, Z;                               /* static: 2 KiB off the stack (single-threaded use), wiped below */
    for (int i = 0; i < QW; i++) R.v[i] = prev->v[i] ^ ref->v[i];
    Z = R;
    uint64_t *z = Z.v;
    for (int i = 0; i < 8; i++) {
        uint64_t *r = z + 16 * i;
        PERM(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]);
    }
    for (int i = 0; i < 8; i++) {
        uint64_t *c = z + 2 * i;
        PERM(c[0], c[1], c[16], c[17], c[32], c[33], c[48], c[49], c[64], c[65], c[80], c[81], c[96], c[97], c[112], c[113]);
    }
    if (with_xor)
        for (int i = 0; i < QW; i++) next->v[i] ^= R.v[i] ^ Z.v[i];
    else
        for (int i = 0; i < QW; i++) next->v[i] = R.v[i] ^ Z.v[i];
}

static void wipe_fill_scratch(void)
{
    blk zero = {{0}}, out;
    fill_block(&zero, &zero, &out, false);         /* overwrites the static R/Z with values derived from zeros */
    mbedtls_platform_zeroize(&out, sizeof out);
}

static void next_addresses(blk *addr, blk *in, const blk *zero)
{
    in->v[6]++;
    fill_block(zero, in, addr, false);
    fill_block(zero, addr, addr, false);
}

/* ======================= memory: RAM or encrypted swap ======================= */

static size_t mem_ram_max = (size_t)-1;            /* host default: always RAM */
static char mem_swap_path[160];
static size_t mem_cache_bytes = 32 * 1024;

void kdbx_set_argon2_memory(size_t ram_max, const char *swap_path, size_t cache_bytes)
{
    mem_ram_max = ram_max;
    snprintf(mem_swap_path, sizeof mem_swap_path, "%s", swap_path ? swap_path : "");
    mem_cache_bytes = cache_bytes;
}

#define PEND_MAX 16                                /* blocks per batched write */
#define RA_MAX 16                                  /* blocks per sequential read-ahead */

typedef struct {
    uint32_t type, version, lanes, passes, lane_len, seg_len, mblocks;
    blk *ram;                                      /* whole memory (RAM mode) */
    /* swap mode */
    FILE *f;
    mbedtls_aes_context aes;
    uint8_t nonce[4];
    blk *cache;
    uint32_t *cidx, ncache, chead;
    uint32_t pend_start, pend_len, pend_slot[PEND_MAX];
    blk *io;                                       /* PEND_MAX blocks: write batches and read-ahead decryption */
    blk *ra;
    uint32_t ra_start, ra_len;
    uint32_t pass, cur;                            /* blocks with file index < cur were written in this pass */
    kdbx_err err;
    /* work blocks */
    blk pbuf, rbuf, cbuf, in, addr, zero;
    uint64_t done, total;
    void (*prog)(void *, int);
    void *pctx;
} a2;

static uint32_t fidx(const a2 *c, uint32_t lane, uint32_t col)
{
    return ((col / c->seg_len) * c->lanes + lane) * c->seg_len + col % c->seg_len;
}

static void ctr(a2 *c, uint32_t pass, uint32_t idx, const blk *in, blk *out, uint32_t n)
{
    uint8_t nc[16] = {0}, stream[16];
    size_t off = 0;
    uint64_t ctrv = (uint64_t)idx * (sizeof(blk) / 16);
    memcpy(nc, c->nonce, 4);
    for (int i = 0; i < 4; i++) nc[4 + i] = (uint8_t)(pass >> (24 - 8 * i));
    for (int i = 0; i < 8; i++) nc[8 + i] = (uint8_t)(ctrv >> (56 - 8 * i));
    mbedtls_aes_crypt_ctr(&c->aes, (size_t)n * sizeof(blk), &off, nc, stream, (const uint8_t *)in, (uint8_t *)out);
    mbedtls_platform_zeroize(stream, sizeof stream);
}

static void flush(a2 *c)
{
    if (!c->pend_len || c->err) return;
    for (uint32_t i = 0; i < c->pend_len; i++) c->io[i] = c->cache[c->pend_slot[i]];
    ctr(c, c->pass, c->pend_start, c->io, c->io, c->pend_len);
    if (fseek(c->f, (long)c->pend_start * (long)sizeof(blk), SEEK_SET) ||
        fwrite(c->io, sizeof(blk), c->pend_len, c->f) != c->pend_len)
        c->err = KDBX_ERR_SWAP;
    mbedtls_platform_zeroize(c->io, sizeof(blk) * c->pend_len);
    c->pend_len = 0;
}

static void disk_read(a2 *c, uint32_t idx, blk *out, uint32_t n, uint32_t pass)
{
    if (c->err) { memset(out, 0, sizeof(blk) * n); return; }
    if (fseek(c->f, (long)idx * (long)sizeof(blk), SEEK_SET) || fread(out, sizeof(blk), n, c->f) != n) {
        c->err = KDBX_ERR_SWAP;
        memset(out, 0, sizeof(blk) * n);
        return;
    }
    ctr(c, pass, idx, out, out, n);
}

/* Contents of block `idx` (newest version) into out. sequential: the old contents at the write position. */
static void swap_read(a2 *c, uint32_t idx, blk *out, bool sequential)
{
    for (uint32_t s = 0; s < c->ncache; s++)
        if (c->cidx[s] == idx) { *out = c->cache[s]; return; }
    if (idx >= c->ra_start && idx < c->ra_start + c->ra_len) { *out = c->ra[idx - c->ra_start]; return; }
    if (sequential) {                              /* idx == cur: this and the next blocks are all from the last pass */
        uint32_t n = c->mblocks - idx < RA_MAX ? c->mblocks - idx : RA_MAX;
        disk_read(c, idx, c->ra, n, c->pass - 1);
        c->ra_start = idx;
        c->ra_len = n;
        *out = c->ra[0];
        return;
    }
    disk_read(c, idx, out, 1, idx < c->cur || c->pass == 0 ? c->pass : c->pass - 1);
}

static void swap_write(a2 *c, uint32_t idx, const blk *b)
{
    if (c->pend_len && (idx != c->pend_start + c->pend_len || c->pend_len == PEND_MAX)) flush(c);
    for (uint32_t s = 0; s < c->ncache; s++)       /* an older version of this block (earlier pass) must go */
        if (c->cidx[s] == idx) c->cidx[s] = UINT32_MAX;
    uint32_t slot = c->chead;                      /* FIFO: the oldest slot is never pending (ncache > PEND_MAX) */
    c->chead = (c->chead + 1) % c->ncache;
    c->cidx[slot] = idx;
    c->cache[slot] = *b;
    if (!c->pend_len) c->pend_start = idx;
    c->pend_slot[c->pend_len++] = slot;
    if (idx >= c->ra_start && idx < c->ra_start + c->ra_len) c->ra[idx - c->ra_start] = *b;
}

static const blk *get(a2 *c, uint32_t lane, uint32_t col, blk *buf)
{
    if (c->ram) return &c->ram[(size_t)lane * c->lane_len + col];
    swap_read(c, fidx(c, lane, col), buf, false);
    return buf;
}

/* ======================= Argon2 ======================= */

static uint32_t index_alpha(const a2 *c, uint32_t pass, uint32_t slice, uint32_t index, uint32_t rnd, bool same_lane)
{
    uint64_t area;
    if (pass == 0) {
        if (slice == 0) area = index - 1;
        else if (same_lane) area = (uint64_t)slice * c->seg_len + index - 1;
        else area = (uint64_t)slice * c->seg_len - (index == 0 ? 1 : 0);
    } else {
        if (same_lane) area = c->lane_len - c->seg_len + index - 1;
        else area = c->lane_len - c->seg_len - (index == 0 ? 1 : 0);
    }
    uint64_t x = (uint64_t)rnd * rnd >> 32;
    uint64_t rel = area - 1 - (area * x >> 32);
    uint64_t start = 0;
    if (pass != 0) start = slice == 3 ? 0 : (uint64_t)(slice + 1) * c->seg_len;
    return (uint32_t)((start + rel) % c->lane_len);
}

static void (*idle_hook)(void);
void kdbx_set_idle_hook(void (*fn)(void)) { idle_hook = fn; }

static void progress(a2 *c)
{
    if ((++c->done & 255) == 0) {
        if (c->prog) c->prog(c->pctx, (int)(c->done * 100 / c->total));
        if (idle_hook) idle_hook();
    }
}

static void fill_segment(a2 *c, uint32_t pass, uint32_t slice, uint32_t lane)
{
    bool di = c->type == KDBX_ARGON2_I || (c->type == KDBX_ARGON2_ID && pass == 0 && slice < 2);
    bool xor_old = pass > 0 && c->version != 0x10;
    uint32_t start = pass == 0 && slice == 0 ? 2 : 0;
    if (di) {
        memset(&c->in, 0, sizeof c->in);
        memset(&c->zero, 0, sizeof c->zero);
        c->in.v[0] = pass; c->in.v[1] = lane; c->in.v[2] = slice;
        c->in.v[3] = c->mblocks; c->in.v[4] = c->passes; c->in.v[5] = c->type;
        if (start == 2) next_addresses(&c->addr, &c->in, &c->zero);
    }
    uint32_t col = slice * c->seg_len + start;
    if (!c->ram) c->cur = fidx(c, lane, col);
    const blk *prev = get(c, lane, col == 0 ? c->lane_len - 1 : col - 1, &c->pbuf);
    for (uint32_t i = start; i < c->seg_len && !c->err; i++, col++) {
        uint64_t rnd;
        if (di) {
            if (i % QW == 0) next_addresses(&c->addr, &c->in, &c->zero);
            rnd = c->addr.v[i % QW];
        } else {
            rnd = prev->v[0];
        }
        uint32_t ref_lane = pass == 0 && slice == 0 ? lane : (uint32_t)((rnd >> 32) % c->lanes);
        uint32_t ref_col = index_alpha(c, pass, slice, i, (uint32_t)rnd, ref_lane == lane);
        if (c->ram) {
            blk *cur = &c->ram[(size_t)lane * c->lane_len + col];
            fill_block(prev, get(c, ref_lane, ref_col, NULL), cur, xor_old);
            prev = cur;
        } else {
            c->cur = fidx(c, lane, col);
            const blk *ref = get(c, ref_lane, ref_col, &c->rbuf);
            if (xor_old) swap_read(c, c->cur, &c->cbuf, true);
            fill_block(prev, ref, &c->cbuf, xor_old);
            swap_write(c, c->cur, &c->cbuf);
            c->pbuf = c->cbuf;
            prev = &c->pbuf;
        }
        progress(c);
    }
}

static bool swap_open(a2 *c)
{
    if (!mem_swap_path[0]) return false;
    size_t nc = mem_cache_bytes / sizeof(blk);
    if (nc < PEND_MAX + 2) nc = PEND_MAX + 2;
    c->ncache = (uint32_t)nc;
    c->cache = calloc(nc, sizeof(blk));
    c->cidx = malloc(nc * sizeof *c->cidx);
    c->io = calloc(PEND_MAX, sizeof(blk));
    c->ra = calloc(RA_MAX, sizeof(blk));
    if (!c->cache || !c->cidx || !c->io || !c->ra) return false;
    for (size_t i = 0; i < nc; i++) c->cidx[i] = UINT32_MAX;
    c->ra_start = UINT32_MAX;
    uint8_t key[32];
    cp_random(key, sizeof key);
    cp_random(c->nonce, sizeof c->nonce);
    mbedtls_aes_init(&c->aes);
    mbedtls_aes_setkey_enc(&c->aes, key, 256);
    mbedtls_platform_zeroize(key, sizeof key);
    remove(mem_swap_path);
    c->f = fopen(mem_swap_path, "w+b");
    return c->f != NULL;
}

static void swap_close(a2 *c)
{
    if (c->f) { fclose(c->f); remove(mem_swap_path); }     /* contents are unreadable without the wiped key */
    if (c->cache) mbedtls_platform_zeroize(c->cache, sizeof(blk) * c->ncache);
    if (c->io) mbedtls_platform_zeroize(c->io, sizeof(blk) * PEND_MAX);
    if (c->ra) mbedtls_platform_zeroize(c->ra, sizeof(blk) * RA_MAX);
    free(c->cache); free(c->cidx); free(c->io); free(c->ra);
    mbedtls_aes_free(&c->aes);
}

#ifdef KDBX_TESTING
void (*kdbx_argon2_test_fin)(const uint8_t blk[1024]);
#endif

kdbx_err kdbx_argon2(const kdbx_argon2_params *a, const uint8_t *pw, size_t pwlen, uint8_t *out, uint32_t outlen,
                     void (*prog)(void *ctx, int pct), void *pctx)
{
    if (a->type > KDBX_ARGON2_ID || (a->version != 0x10 && a->version != 0x13) || !a->lanes || a->lanes > 0xFFFFFF ||
        !a->passes || a->mem_kib < 8u * a->lanes || a->mem_kib > KDBX_ARGON2_MAX_KIB || outlen < 4 || outlen > 64)
        return KDBX_ERR_KDF;
    a2 *c = calloc(1, sizeof *c);
    if (!c) return KDBX_ERR_NOMEM;
    c->type = a->type;
    c->version = a->version;
    c->lanes = a->lanes;
    c->passes = a->passes;
    c->seg_len = a->mem_kib / (4 * a->lanes);
    c->lane_len = c->seg_len * 4;
    c->mblocks = c->lane_len * a->lanes;
    c->total = (uint64_t)c->passes * c->mblocks;
    c->prog = prog;
    c->pctx = pctx;
    kdbx_err err = KDBX_OK;

    if ((size_t)c->mblocks * sizeof(blk) <= mem_ram_max) c->ram = calloc(c->mblocks, sizeof(blk));
    if (!c->ram && !swap_open(c)) { err = mem_swap_path[0] ? KDBX_ERR_SWAP : KDBX_ERR_NOMEM; goto done; }

    /* H0 and the first two blocks of every lane */
    uint8_t h0[72], t[4];
    b2b s;
    b2b_init(&s, 64);
    le32(t, a->lanes); b2b_update(&s, t, 4);
    le32(t, outlen); b2b_update(&s, t, 4);
    le32(t, a->mem_kib); b2b_update(&s, t, 4);
    le32(t, a->passes); b2b_update(&s, t, 4);
    le32(t, a->version); b2b_update(&s, t, 4);
    le32(t, a->type); b2b_update(&s, t, 4);
    le32(t, (uint32_t)pwlen); b2b_update(&s, t, 4); b2b_update(&s, pw, pwlen);
    le32(t, (uint32_t)a->saltlen); b2b_update(&s, t, 4); b2b_update(&s, a->salt, a->saltlen);
    le32(t, (uint32_t)a->secretlen); b2b_update(&s, t, 4); if (a->secretlen) b2b_update(&s, a->secret, a->secretlen);
    le32(t, (uint32_t)a->adlen); b2b_update(&s, t, 4); if (a->adlen) b2b_update(&s, a->ad, a->adlen);
    b2b_final(&s, h0);
    for (uint32_t l = 0; l < c->lanes; l++)
        for (uint32_t k = 0; k < 2; k++) {
            le32(h0 + 64, k);
            le32(h0 + 68, l);
            blk *b = c->ram ? &c->ram[(size_t)l * c->lane_len + k] : &c->cbuf;
            hprime((uint8_t *)b->v, sizeof(blk), h0, 72, NULL, 0);
            if (!c->ram) { c->cur = fidx(c, l, k); swap_write(c, c->cur, b); }
        }
    mbedtls_platform_zeroize(h0, sizeof h0);

    for (uint32_t pass = 0; pass < c->passes && !c->err; pass++) {
        if (!c->ram) { flush(c); c->pass = pass; c->ra_start = UINT32_MAX; c->ra_len = 0; }
        for (uint32_t slice = 0; slice < 4; slice++)
            for (uint32_t l = 0; l < c->lanes; l++) fill_segment(c, pass, slice, l);
    }
    if (!c->ram) { flush(c); c->cur = c->mblocks; }

    /* final block = XOR of the last block of every lane; tag = H'(final) */
    blk fin;
    fin = *get(c, 0, c->lane_len - 1, &c->rbuf);
    for (uint32_t l = 1; l < c->lanes; l++) {
        const blk *b = get(c, l, c->lane_len - 1, &c->rbuf);
        for (int i = 0; i < QW; i++) fin.v[i] ^= b->v[i];
    }
#ifdef KDBX_TESTING
    if (kdbx_argon2_test_fin && !c->err) kdbx_argon2_test_fin((const uint8_t *)fin.v);   /* memscan only: a pattern to look for */
#endif
    if (!c->err) hprime(out, outlen, fin.v, sizeof fin, NULL, 0);
    mbedtls_platform_zeroize(&fin, sizeof fin);
    err = c->err;
    if (prog && !err) prog(pctx, 100);

done:
    if (c->ram) { mbedtls_platform_zeroize(c->ram, (size_t)c->mblocks * sizeof(blk)); free(c->ram); }
    swap_close(c);
    wipe_fill_scratch();
    mbedtls_platform_zeroize(c, sizeof *c);
    free(c);
    if (err) mbedtls_platform_zeroize(out, outlen);
    return err;
}
