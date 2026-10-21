/* Streaming save (KDBX 4.x rewrite).
 *
 * The original file is decrypted again and its XML turned into events
 * (START with attributes, TEXT, PTEXT = decrypted protected text, END). The
 * rewriter copies everything it doesn't understand, applies the edits, and
 * writes: XML -> gzip (stored blocks) -> AES-CBC / ChaCha20 -> HMAC blocks.
 * Protected values are re-encrypted with a fresh inner stream key.
 *
 * Moves need the moved subtree before its new parent may appear in the
 * document, so a first pass captures moved subtrees (as events) when any
 * move is present. Edited entries are buffered as events until their end
 * (old version -> History). Buffers are wiped after use. */
#include <stdlib.h>
#include <string.h>
#include "mbedtls/aes.h"
#include "mbedtls/base64.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "kdbx_priv.h"
#ifdef ESP_PLATFORM
#include <unistd.h>
#endif

#define BLOCK (8 * 1024)    /* HMAC block size written (KeePass accepts any) */
#define STORED 8192         /* deflate chunk (positions must fit uint16) */
#define MAXD XML_MAX_DEPTH
#define TICKS_TO_UNIX 62135596800LL
#define DEFAULT_HISTORY_MAX 10

static const uint8_t UUID_AESKDF[16] = {0xc9,0xd9,0xf3,0x9a,0x62,0x8a,0x44,0x60,0xbf,0x74,0x0d,0x08,0xc1,0x8a,0x4f,0xea};

static void put_le32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> 8 * i); }
static void put_le64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> 8 * i); }
static uint32_t le32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }

/* ======================= output pipeline ======================= */

typedef struct {
    FILE *f;
    kdbx_err err;
    mbedtls_md_context_t md;
    uint8_t hmac_base[64];
    uint64_t idx;
    uint8_t *block;             /* BLOCK bytes; the three big buffers are separate allocations (8 KB each) so a fragmented heap can serve them */
    size_t blen;
    int cipher;
    mbedtls_aes_context aes;
    mbedtls_chacha20_context chacha, inner;
    uint8_t iv[16], pend[16], tmp[512];
    size_t plen;
    uint8_t *stored;            /* STORED bytes */
    size_t slen;
    uint16_t *head;             /* 4096 entries */
    uint8_t zbuf[256];
    size_t zlen;
    uint32_t bitbuf;
    int bitcnt;
    bool counting;
    size_t count;
    uint32_t crc, isize;
    bool open;  /* start tag written, '>' not yet */
} out_t;

static void blk_emit(out_t *o)
{
    uint8_t key[64], hdr[12], mac[32];
    put_le64(hdr, o->idx);
    put_le32(hdr + 8, (uint32_t)o->blen);
    kdbx_block_key(o->hmac_base, o->idx++, key);
    mbedtls_md_hmac_starts(&o->md, key, 64);
    mbedtls_md_hmac_update(&o->md, hdr, 12);
    mbedtls_md_hmac_update(&o->md, o->block, o->blen);
    mbedtls_md_hmac_finish(&o->md, mac);
    mbedtls_platform_zeroize(key, sizeof key);
    if (fwrite(mac, 1, 32, o->f) != 32 || fwrite(hdr + 8, 1, 4, o->f) != 4 ||
        fwrite(o->block, 1, o->blen, o->f) != o->blen)
        o->err = KDBX_ERR_IO;
    o->blen = 0;
}

static void blk_put(out_t *o, const uint8_t *d, size_t n)
{
    while (n) {
        size_t take = BLOCK - o->blen < n ? BLOCK - o->blen : n;
        memcpy(o->block + o->blen, d, take);
        o->blen += take;
        d += take;
        n -= take;
        if (o->blen == BLOCK) blk_emit(o);
    }
}

static void enc_put(out_t *o, const uint8_t *d, size_t n)
{
    while (n) {
        size_t k;
        if (o->cipher == CIPHER_CHACHA20) {
            k = n < sizeof o->tmp ? n : sizeof o->tmp;
            mbedtls_chacha20_update(&o->chacha, k, d, o->tmp);
        } else if (o->plen || n < 16) {
            k = 16 - o->plen < n ? 16 - o->plen : n;
            memcpy(o->pend + o->plen, d, k);
            d += k;
            n -= k;
            if ((o->plen += k) == 16) {
                mbedtls_aes_crypt_cbc(&o->aes, MBEDTLS_AES_ENCRYPT, 16, o->iv, o->pend, o->tmp);
                blk_put(o, o->tmp, 16);
                o->plen = 0;
            }
            continue;
        } else {
            k = n / 16 * 16 < sizeof o->tmp ? n / 16 * 16 : sizeof o->tmp;
            mbedtls_aes_crypt_cbc(&o->aes, MBEDTLS_AES_ENCRYPT, k, o->iv, d, o->tmp);
        }
        blk_put(o, o->tmp, k);
        d += k;
        n -= k;
    }
}

static void enc_final(out_t *o)
{
    if (o->cipher != CIPHER_AES256) return;
    uint8_t pad = (uint8_t)(16 - o->plen);  /* PKCS#7, full block when aligned */
    memset(o->pend + o->plen, pad, pad);
    mbedtls_aes_crypt_cbc(&o->aes, MBEDTLS_AES_ENCRYPT, 16, o->iv, o->pend, o->tmp);
    blk_put(o, o->tmp, 16);
}

static uint32_t crc32_update(uint32_t crc, const uint8_t *d, size_t n)
{
    crc = ~crc;
    while (n--) {
        crc ^= *d++;
        for (int k = 0; k < 8; k++) crc = crc >> 1 ^ (0xEDB88320u & (0u - (crc & 1)));
    }
    return ~crc;
}

/* ---- tiny deflate: greedy LZ77 (one hash candidate) + fixed Huffman ----
 * ponytail: matches only inside each 16 KB chunk, ~16 KB RAM total (miniz's
 * tdefl needs ~300 KB). Ratio is a bit worse than zlib; KeePassXC recompresses
 * on its next save anyway. */
static const uint16_t LBASE[29] = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
static const uint8_t LEXT[29] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
static const uint16_t DBASE[30] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,
                                   4097,6145,8193,12289,16385,24577};
static const uint8_t DEXT[30] = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};

static void z_flush(out_t *o)
{
    enc_put(o, o->zbuf, o->zlen);
    o->zlen = 0;
}

static void bits(out_t *o, uint32_t v, int n)
{
    if (o->counting) {
        o->count += (size_t)n;
        return;
    }
    o->bitbuf |= v << o->bitcnt;
    for (o->bitcnt += n; o->bitcnt >= 8; o->bitcnt -= 8, o->bitbuf >>= 8) {
        o->zbuf[o->zlen++] = (uint8_t)o->bitbuf;
        if (o->zlen == sizeof o->zbuf) z_flush(o);
    }
}

static void huff(out_t *o, unsigned code, int len) /* Huffman codes go MSB first */
{
    unsigned r = 0;
    for (int i = 0; i < len; i++, code >>= 1) r = r << 1 | (code & 1);
    bits(o, r, len);
}

static void sym(out_t *o, unsigned s)
{
    if (s < 144) huff(o, 0x30 + s, 8);
    else if (s < 256) huff(o, 0x190 + s - 144, 9);
    else if (s < 280) huff(o, s - 256, 7);
    else huff(o, 0xC0 + s - 280, 8);
}

static unsigned zhash(const uint8_t *p) { return ((p[0] << 16 | p[1] << 8 | p[2]) * 2654435761u) >> 20; }

static void lz(out_t *o)
{
    const uint8_t *b = o->stored;
    size_t n = o->slen, i = 0;
    memset(o->head, 0xff, 4096 * sizeof *o->head);
    while (i < n) {
        size_t len = 0, dist = 0;
        if (i + 3 <= n) {
            unsigned h = zhash(b + i), c = o->head[h];
            o->head[h] = (uint16_t)i;
            if (c != 0xFFFF) {
                size_t max = n - i < 258 ? n - i : 258;
                while (len < max && b[c + len] == b[i + len]) len++;
                dist = i - c;
            }
        }
        if (len < 3) {
            sym(o, b[i++]);
            continue;
        }
        int li = 28, di = 29;
        while (LBASE[li] > len) li--;
        while (DBASE[di] > dist) di--;
        sym(o, 257 + li);
        bits(o, (uint32_t)(len - LBASE[li]), LEXT[li]);
        huff(o, di, 5);
        bits(o, (uint32_t)(dist - DBASE[di]), DEXT[di]);
        for (size_t k = 1; k < len && i + k + 3 <= n; k++) o->head[zhash(b + i + k)] = (uint16_t)(i + k);
        i += len;
    }
    sym(o, 256);
}

/* One deflate block per chunk: fixed Huffman, or stored if that would be smaller. */
static void gz_block(out_t *o, bool final)
{
    o->counting = true;
    o->count = 0;
    lz(o);
    o->counting = false;
    bits(o, final, 1);
    if (o->count / 8 < o->slen + 4) {
        bits(o, 1, 2);
        lz(o);
    } else {
        bits(o, 0, 2);
        if (o->bitcnt) bits(o, 0, 8 - o->bitcnt);
        bits(o, (uint32_t)o->slen, 16);
        bits(o, (uint32_t)~o->slen & 0xFFFF, 16);
        z_flush(o);
        enc_put(o, o->stored, o->slen);
    }
    o->slen = 0;
    if (final) {
        if (o->bitcnt) bits(o, 0, 8 - o->bitcnt);
        z_flush(o);
    }
}

static void gz_put(out_t *o, const void *data, size_t n)
{
    const uint8_t *d = data;
    o->crc = crc32_update(o->crc, d, n);
    o->isize += (uint32_t)n;
    while (n) {
        size_t take = STORED - o->slen < n ? STORED - o->slen : n;
        memcpy(o->stored + o->slen, d, take);
        o->slen += take;
        d += take;
        n -= take;
        if (o->slen == STORED) gz_block(o, false);
    }
}

static void out_finish(out_t *o)
{
    uint8_t t[8];
    gz_block(o, true);
    put_le32(t, o->crc);
    put_le32(t + 4, o->isize);
    enc_put(o, t, 8);
    enc_final(o);
    if (o->blen) blk_emit(o);
    blk_emit(o); /* empty terminating block */
}

/* ---- XML writer ---- */

static void xw_raw(out_t *o, const char *s) { gz_put(o, s, strlen(s)); }

static void xw_close(out_t *o)
{
    if (o->open) xw_raw(o, ">");
    o->open = false;
}

static void xw_esc(out_t *o, const uint8_t *d, size_t n, bool attr)
{
    size_t run = 0;
    for (size_t i = 0; i < n; i++) {
        const char *rep = NULL;
        uint8_t c = d[i];
        switch (c) {
        case '&': rep = "&amp;"; break;
        case '<': rep = "&lt;"; break;
        case '>': rep = "&gt;"; break;
        case '"': rep = attr ? "&quot;" : NULL; break;
        case '\r': rep = "&#13;"; break;
        default: if (c < 0x20 && c != '\t' && c != '\n') rep = ""; /* not allowed in XML 1.0 */
        }
        if (!rep) continue;
        gz_put(o, d + run, i - run);
        xw_raw(o, rep);
        run = i + 1;
    }
    gz_put(o, d + run, n - run);
}

static void xw_start(out_t *o, const char *name, const uint8_t *attrs, size_t alen)
{
    xw_close(o);
    xw_raw(o, "<");
    xw_raw(o, name);
    for (size_t i = 0; i < alen;) {
        const char *k = (const char *)attrs + i, *v = k + strlen(k) + 1;
        xw_raw(o, " ");
        xw_raw(o, k);
        xw_raw(o, "=\"");
        xw_esc(o, (const uint8_t *)v, strlen(v), true);
        xw_raw(o, "\"");
        i = (size_t)(v - (const char *)attrs) + strlen(v) + 1;
    }
    o->open = true;
}

static void xw_end(out_t *o, const char *name)
{
    if (o->open) {
        xw_raw(o, "/>");
        o->open = false;
        return;
    }
    xw_raw(o, "</");
    xw_raw(o, name);
    xw_raw(o, ">");
}

static void xw_text(out_t *o, const uint8_t *d, size_t n)
{
    if (!n) return;
    xw_close(o);
    xw_esc(o, d, n, false);
}

/* Protected value: encrypt with the new inner stream (sequential), base64. */
static void xw_ptext(out_t *o, const uint8_t *d, size_t n)
{
    uint8_t c[48];
    unsigned char b[65];
    size_t olen;
    if (!n) return;
    xw_close(o);
    while (n) {
        size_t k = n < 48 ? n : 48;
        mbedtls_chacha20_update(&o->inner, k, d, c);
        mbedtls_base64_encode(b, sizeof b, &olen, c, k);
        gz_put(o, b, olen);
        d += k;
        n -= k;
    }
    mbedtls_platform_zeroize(c, sizeof c);
}

static void xw_el(out_t *o, const char *name, const char *text)
{
    xw_start(o, name, NULL, 0);
    xw_text(o, (const uint8_t *)text, strlen(text));
    xw_end(o, name);
}

/* ======================= events ======================= */

enum { EV_START = 1, EV_TEXT, EV_PTEXT, EV_END };

typedef struct {
    int type;
    const char *name;     /* START / END */
    const uint8_t *data;  /* TEXT / PTEXT data, START attributes ("k\0v\0...") */
    size_t len;
} ev_t;

static bool ev_save(tbuf *b, const ev_t *e)
{
    uint8_t h[5];
    size_t al = e->name ? strlen(e->name) + 1 : 0;
    h[0] = (uint8_t)e->type;
    put_le32(h + 1, (uint32_t)al);
    uint8_t l[4];
    put_le32(l, (uint32_t)e->len);
    return tbuf_put(b, h, 5) && tbuf_put(b, e->name ? e->name : "", al) && tbuf_put(b, l, 4) &&
           tbuf_put(b, e->data ? e->data : (const uint8_t *)"", e->len);
}

static bool ev_next(const tbuf *b, size_t *off, ev_t *e)
{
    if (*off >= b->len) return false;
    const uint8_t *p = b->p + *off;
    uint32_t al = le32(p + 1), dl = le32(p + 5 + al);
    e->type = p[0];
    e->name = al ? (const char *)p + 5 : NULL;
    e->data = p + 9 + al;
    e->len = dl;
    *off += 9 + al + dl;
    return true;
}

static void ev_write(out_t *o, const ev_t *e)
{
    switch (e->type) {
    case EV_START: xw_start(o, e->name, e->data, e->len); break;
    case EV_TEXT: xw_text(o, e->data, e->len); break;
    case EV_PTEXT: xw_ptext(o, e->data, e->len); break;
    case EV_END: xw_end(o, e->name); break;
    }
}

/* ======================= rewriter ======================= */

enum { K_OTHER, K_FILE, K_META, K_ROOT, K_GROUP, K_ENTRY, K_HISTORY, K_HENTRY, K_UUID, K_GNAME, K_DELOBJS,
       K_RBUUID, K_RBCHANGED, K_HISTMAX };

static int classify(const char *n, int parent)
{
    switch (parent) {
    case K_OTHER: return !strcmp(n, "KeePassFile") ? K_FILE : K_OTHER;
    case K_FILE: return !strcmp(n, "Meta") ? K_META : !strcmp(n, "Root") ? K_ROOT : K_OTHER;
    case K_META:
        return !strcmp(n, "RecycleBinUUID") ? K_RBUUID : !strcmp(n, "RecycleBinChanged") ? K_RBCHANGED
             : !strcmp(n, "HistoryMaxItems") ? K_HISTMAX : K_OTHER;
    case K_ROOT: return !strcmp(n, "Group") ? K_GROUP : !strcmp(n, "DeletedObjects") ? K_DELOBJS : K_OTHER;
    case K_GROUP:
        return !strcmp(n, "Group") ? K_GROUP : !strcmp(n, "Entry") ? K_ENTRY : !strcmp(n, "UUID") ? K_UUID
             : !strcmp(n, "Name") ? K_GNAME : K_OTHER;
    case K_ENTRY: return !strcmp(n, "UUID") ? K_UUID : !strcmp(n, "History") ? K_HISTORY : K_OTHER;
    case K_HISTORY: return !strcmp(n, "Entry") ? K_HENTRY : K_OTHER;
    default: return K_OTHER;
    }
}

typedef struct saver saver;
typedef kdbx_err (*proc_fn)(saver *s, const ev_t *e);

struct saver {
    const kdbx_db *db;
    const kdbx_edit *ed;
    size_t n;
    bool *applied;
    int64_t now;
    char now_b64[16];
    out_t *o;
    bool pass2, xml_started;

    /* XML source */
    yxml_t x;
    uint8_t ystack[2048];
    char names[MAXD][48];
    bool prot[MAXD];
    int sdepth;
    bool pstart;
    tbuf attrs, text, plain;
    uint8_t okey[32], ononce[12];
    kdbx_sink *sink;
    uint32_t opos;
    proc_fn proc;

    /* tree */
    int depth;
    uint8_t kind[MAXD];
    uint8_t guuid[MAXD][16];
    const kdbx_edit *rename[MAXD];
    int history_max;
    const kdbx_edit *new_bin;

    /* modes */
    int skip_depth, pend_depth, ebuf_depth, replace_depth;
    bool skip_record;
    const char *replace;
    char replace_buf[32];
    tbuf pend, ebuf, uuid_text, deleted;
    const kdbx_edit *ebuf_edit;
    bool deleted_written;
    const uint8_t *placing;

    /* pass 1 captures, per edit */
    tbuf *cap;
    int *cap_depth;
};

static void time_b64(int64_t unix_s, char out[16])
{
    uint8_t b[8];
    size_t olen;
    put_le64(b, (uint64_t)(unix_s + TICKS_TO_UNIX));
    mbedtls_base64_encode((unsigned char *)out, 16, &olen, b, 8);
}

static void uuid_b64(const uint8_t u[16], char out[32])
{
    size_t olen;
    mbedtls_base64_encode((unsigned char *)out, 32, &olen, u, 16);
}

static const kdbx_edit *find(saver *s, int op, const uint8_t uuid[16], int create)
{
    for (size_t i = 0; i < s->n; i++)
        if ((int)s->ed[i].op == op && !memcmp(s->ed[i].uuid, uuid, 16) && (create < 0 || s->ed[i].create == create))
            return &s->ed[i];
    return NULL;
}

static void applied(saver *s, const kdbx_edit *e) { s->applied[e - s->ed] = true; }

static bool uuid_from_text(saver *s, uint8_t out[16])
{
    size_t olen;
    return !mbedtls_base64_decode(out, 16, &olen, s->uuid_text.p, s->uuid_text.len) && olen == 16;
}

/* ---- new content ---- */

static void write_times(saver *s, bool expires, int64_t expiry)
{
    out_t *o = s->o;
    char t[16];
    xw_start(o, "Times", NULL, 0);
    xw_el(o, "LastModificationTime", s->now_b64);
    xw_el(o, "CreationTime", s->now_b64);
    xw_el(o, "LastAccessTime", s->now_b64);
    time_b64(expires ? expiry : s->now, t);
    xw_el(o, "ExpiryTime", t);
    xw_el(o, "Expires", expires ? "True" : "False");
    xw_el(o, "UsageCount", "0");
    xw_el(o, "LocationChanged", s->now_b64);
    xw_end(o, "Times");
}

static void write_strings(saver *s, const kdbx_edit *e)
{
    out_t *o = s->o;
    static const uint8_t prot[] = "Protected\0True";
    for (size_t i = 0; i < e->nfields; i++) {
        const kdbx_edit_field *f = &e->fields[i];
        xw_start(o, "String", NULL, 0);
        xw_el(o, "Key", f->key);
        xw_start(o, "Value", f->protect ? prot : NULL, f->protect ? sizeof prot : 0);
        if (f->protect) xw_ptext(o, (const uint8_t *)f->value, strlen(f->value));
        else xw_text(o, (const uint8_t *)f->value, strlen(f->value));
        xw_end(o, "Value");
        xw_end(o, "String");
    }
}

static void write_new_entry(saver *s, const kdbx_edit *e)
{
    out_t *o = s->o;
    char u[32];
    uuid_b64(e->uuid, u);
    xw_start(o, "Entry", NULL, 0);
    xw_el(o, "UUID", u);
    xw_el(o, "IconID", "0");
    xw_el(o, "ForegroundColor", "");
    xw_el(o, "BackgroundColor", "");
    xw_el(o, "OverrideURL", "");
    xw_el(o, "Tags", e->tags ? e->tags : "");
    write_times(s, e->expires, e->expiry);
    write_strings(s, e);
    xw_start(o, "AutoType", NULL, 0);
    xw_el(o, "Enabled", "True");
    xw_el(o, "DataTransferObfuscation", "0");
    xw_end(o, "AutoType");
    xw_el(o, "History", "");
    xw_end(o, "Entry");
}

static void write_deleted(saver *s)
{
    char u[32];
    for (size_t i = 0; i + 16 <= s->deleted.len; i += 16) {
        uuid_b64(s->deleted.p + i, u);
        xw_start(s->o, "DeletedObject", NULL, 0);
        xw_el(s->o, "UUID", u);
        xw_el(s->o, "DeletionTime", s->now_b64);
        xw_end(s->o, "DeletedObject");
    }
}

static kdbx_err proc2(saver *s, const ev_t *e);

static kdbx_err pe(saver *s, int type, const char *name, const char *text)
{
    ev_t e = {type, name, (const uint8_t *)text, text ? strlen(text) : 0};
    return proc2(s, &e);
}

static kdbx_err pel(saver *s, const char *name, const char *text)
{
    kdbx_err err = pe(s, EV_START, name, NULL);
    if (!err && *text) err = pe(s, EV_TEXT, NULL, text);
    return err ? err : pe(s, EV_END, name, NULL);
}

/* New group: generated as events so its own new/moved children get appended. */
static kdbx_err gen_group(saver *s, const kdbx_edit *e)
{
    char u[32], t[16];
    uuid_b64(e->uuid, u);
    time_b64(s->now, t);
    kdbx_err err = pe(s, EV_START, "Group", NULL);
    if (!err) err = pel(s, "UUID", u);
    if (!err) err = pel(s, "Name", e->name ? e->name : "");
    if (!err) err = pel(s, "Notes", "");
    if (!err) err = pel(s, "IconID", e->recycle_bin ? "43" : "48");
    if (!err) {
        err = pe(s, EV_START, "Times", NULL);
        const char *tn[] = {"LastModificationTime", "CreationTime", "LastAccessTime", "ExpiryTime"};
        for (int i = 0; i < 4 && !err; i++) err = pel(s, tn[i], t);
        if (!err) err = pel(s, "Expires", "False");
        if (!err) err = pel(s, "UsageCount", "0");
        if (!err) err = pel(s, "LocationChanged", t);
        if (!err) err = pe(s, EV_END, "Times", NULL);
    }
    if (!err) err = pel(s, "IsExpanded", "True");
    if (!err) err = pel(s, "DefaultAutoTypeSequence", "");
    if (!err) err = pel(s, "EnableAutoType", e->recycle_bin ? "false" : "null");
    if (!err) err = pel(s, "EnableSearching", e->recycle_bin ? "false" : "null");
    if (!err) err = pel(s, "LastTopVisibleEntry", "AAAAAAAAAAAAAAAAAAAAAA==");
    return err ? err : pe(s, EV_END, "Group", NULL);
}

/* Before </Group>: new groups, new entries and moved items that belong here. */
static kdbx_err append_children(saver *s, const uint8_t uuid[16])
{
    kdbx_err err = KDBX_OK;
    for (size_t i = 0; i < s->n && !err; i++) {
        const kdbx_edit *e = &s->ed[i];
        if (memcmp(e->parent, uuid, 16) || s->applied[i]) continue;
        if (e->op == KDBX_EDIT_GROUP && e->create) {
            applied(s, e);
            err = gen_group(s, e);
        } else if (e->op == KDBX_EDIT_ENTRY && e->create) {
            applied(s, e);
            write_new_entry(s, e);
        } else if ((e->op == KDBX_EDIT_ENTRY_MOVE || e->op == KDBX_EDIT_GROUP_MOVE) && s->cap[i].len) {
            applied(s, e);
            const uint8_t *prev = s->placing;
            s->placing = e->uuid;
            ev_t ev;
            for (size_t off = 0; !err && ev_next(&s->cap[i], &off, &ev);) err = proc2(s, &ev);
            s->placing = prev;
        }
    }
    return err;
}

/* Edited entry: new strings/tags/times, old version appended to History. */
static void transform_entry(saver *s)
{
    const kdbx_edit *ed = s->ebuf_edit;
    out_t *o = s->o;
    ev_t e;
    size_t off;
    int rel = 0, nhist = 0;

    bool ih = false;
    for (off = 0; ev_next(&s->ebuf, &off, &e);) {
        if (e.type == EV_START) {
            if (++rel == 2) ih = !strcmp(e.name, "History");
            else if (rel == 3 && ih) nhist++;
        } else if (e.type == EV_END) {
            if (rel-- == 2) ih = false;
        }
    }
    int hmax = s->history_max;
    int drop = hmax < 0 ? 0 : nhist + 1 - hmax > 0 ? nhist + 1 - hmax : 0;
    bool tags_done = false, strings_done = false, hist_done = false, in_hist = false, in_times = false;
    int skip = 0, hist_i = 0, repl = 0;
    char rbuf[16];
    const char *rtext = NULL;

    rel = 0;
    for (off = 0; ev_next(&s->ebuf, &off, &e);) {
        if (e.type == EV_START) {
            rel++;
            if (skip) continue;
            if (rel == 2 && !strcmp(e.name, "String")) {
                if (!strings_done) write_strings(s, ed);
                strings_done = true;
                skip = rel;
                continue;
            }
            if (rel == 2 && !strcmp(e.name, "Tags")) {
                xw_el(o, "Tags", ed->tags ? ed->tags : "");
                tags_done = true;
                skip = rel;
                continue;
            }
            if (rel == 2) {
                in_hist = !strcmp(e.name, "History");
                in_times = !strcmp(e.name, "Times");
            }
            if (in_hist && rel == 3 && hist_i++ < drop) { skip = rel; continue; }
            if (in_times && rel == 3) {
                rtext = NULL;
                if (!strcmp(e.name, "LastModificationTime")) rtext = s->now_b64;
                else if (!strcmp(e.name, "ExpiryTime")) { time_b64(ed->expires ? ed->expiry : 0, rbuf); rtext = ed->expires ? rbuf : NULL; }
                else if (!strcmp(e.name, "Expires")) rtext = ed->expires ? "True" : "False";
                if (rtext) repl = rel;
            }
            ev_write(o, &e);
        } else if (e.type == EV_END) {
            if (skip) {
                if (rel-- == skip) skip = 0;
                continue;
            }
            if (repl == rel) {
                xw_text(o, (const uint8_t *)rtext, strlen(rtext));
                repl = 0;
                rtext = NULL;
            }
            if (rel == 2 && in_hist) {
                /* snapshot = old entry without its History */
                if (hmax != 0) {
                    ev_t se;
                    int r = 0, sk = 0;
                    for (size_t so = 0; ev_next(&s->ebuf, &so, &se);) {
                        if (se.type == EV_START && ++r == 2 && !strcmp(se.name, "History")) sk = 2;
                        if (!sk) ev_write(o, &se);
                        if (se.type == EV_END && r-- == sk) sk = 0;
                    }
                }
                hist_done = true;
                in_hist = false;
            }
            if (rel == 2) in_times = false;
            if (rel == 1) {
                if (!tags_done) xw_el(o, "Tags", ed->tags ? ed->tags : "");
                if (!strings_done) write_strings(s, ed);
                if (!hist_done && hmax != 0) {
                    xw_start(o, "History", NULL, 0);
                    ev_t se;
                    int r = 0, sk = 0;
                    for (size_t so = 0; ev_next(&s->ebuf, &so, &se);) {
                        if (se.type == EV_START && ++r == 2 && !strcmp(se.name, "History")) sk = 2;
                        if (!sk) ev_write(o, &se);
                        if (se.type == EV_END && r-- == sk) sk = 0;
                    }
                    xw_end(o, "History");
                }
            }
            ev_write(o, &e);
            rel--;
        } else if (!skip && repl != rel) {
            ev_write(o, &e);
        }
    }
}

static bool in_moves(saver *s, const uint8_t uuid[16])
{
    return find(s, KDBX_EDIT_ENTRY_MOVE, uuid, -1) || find(s, KDBX_EDIT_GROUP_MOVE, uuid, -1);
}

/* Entry/Group identity known (its UUID child ended): decide what to do with it. */
static kdbx_err decide(saver *s)
{
    uint8_t u[16];
    int d = s->pend_depth, k = s->kind[d];
    if (!uuid_from_text(s, u)) return KDBX_ERR_FORMAT;
    bool placing = s->placing && !memcmp(s->placing, u, 16);
    if (placing) s->placing = NULL;
    s->pend_depth = 0;

    const kdbx_edit *del = find(s, k == K_ENTRY ? KDBX_EDIT_ENTRY_DELETE : KDBX_EDIT_GROUP_DELETE, u, -1);
    const kdbx_edit *mv = find(s, k == K_ENTRY ? KDBX_EDIT_ENTRY_MOVE : KDBX_EDIT_GROUP_MOVE, u, -1);
    const kdbx_edit *upd = find(s, k == K_ENTRY ? KDBX_EDIT_ENTRY : KDBX_EDIT_GROUP, u, 0);

    if (del || (mv && !placing)) {
        if (del) {
            applied(s, del);
            if (!tbuf_put(&s->deleted, u, 16)) return KDBX_ERR_NOMEM;
        }
        s->skip_depth = d;
        s->skip_record = del && k == K_GROUP;
        tbuf_clear(&s->pend);
        tbuf_clear(&s->uuid_text);
        return KDBX_OK;
    }
    if (k == K_ENTRY && upd) {
        applied(s, upd);
        tbuf t = s->ebuf;
        s->ebuf = s->pend;  /* keep buffering the whole entry */
        s->pend = t;
        s->ebuf_depth = d;
        s->ebuf_edit = upd;
        return KDBX_OK;
    }
    if (k == K_GROUP) {
        memcpy(s->guuid[d], u, 16);
        s->rename[d] = upd;
        if (upd) applied(s, upd);
    }
    ev_t e;
    for (size_t off = 0; ev_next(&s->pend, &off, &e);) ev_write(s->o, &e);
    tbuf_clear(&s->pend);
    return KDBX_OK;
}

static kdbx_err proc2(saver *s, const ev_t *e)
{
    kdbx_err err = KDBX_OK;
    if (e->type == EV_START) {
        if (++s->depth >= MAXD) return KDBX_ERR_FORMAT;
        s->kind[s->depth] = (uint8_t)classify(e->name, s->kind[s->depth - 1]);
        s->rename[s->depth] = NULL;
    }
    int d = s->depth, k = s->kind[d], parent = s->kind[d - 1];

    if (s->skip_depth) {
        if (s->skip_record && k == K_UUID && (parent == K_ENTRY || parent == K_GROUP)) {
            if (e->type == EV_TEXT && !tbuf_put(&s->uuid_text, e->data, e->len)) err = KDBX_ERR_NOMEM;
            if (e->type == EV_END) {
                uint8_t u[16];
                if (uuid_from_text(s, u) && !in_moves(s, u) && !tbuf_put(&s->deleted, u, 16)) err = KDBX_ERR_NOMEM;
                tbuf_clear(&s->uuid_text);
            }
        }
        if (e->type == EV_END && d == s->skip_depth) s->skip_depth = 0;
    } else if (s->pend_depth) {
        if (!ev_save(&s->pend, e)) err = KDBX_ERR_NOMEM;
        else if (d == s->pend_depth + 1 && k == K_UUID && e->type == EV_TEXT) {
            if (!tbuf_put(&s->uuid_text, e->data, e->len)) err = KDBX_ERR_NOMEM;
        } else if (d == s->pend_depth + 1 && k == K_UUID && e->type == EV_END) {
            err = decide(s);
        } else if (d == s->pend_depth && e->type == EV_END) {
            err = KDBX_ERR_FORMAT; /* Entry/Group without UUID as first child */
        }
    } else if (s->ebuf_depth) {
        if (!ev_save(&s->ebuf, e)) err = KDBX_ERR_NOMEM;
        else if (e->type == EV_END && d == s->ebuf_depth) {
            transform_entry(s);
            s->ebuf_depth = 0;
            tbuf_clear(&s->ebuf);
        }
    } else if (e->type == EV_START) {
        if ((k == K_ENTRY || k == K_GROUP)) {
            s->pend_depth = d;
            tbuf_clear(&s->uuid_text);
            if (!ev_save(&s->pend, e)) err = KDBX_ERR_NOMEM;
        } else {
            if (k == K_GNAME && s->rename[d - 1]) s->replace = s->rename[d - 1]->name ? s->rename[d - 1]->name : "";
            else if (k == K_RBUUID && s->new_bin) { uuid_b64(s->new_bin->uuid, s->replace_buf); s->replace = s->replace_buf; }
            else if (k == K_RBCHANGED && s->new_bin) s->replace = s->now_b64;
            if (s->replace) s->replace_depth = d;
            ev_write(s->o, e);
        }
    } else if (e->type == EV_END) {
        if (s->replace_depth == d) {
            xw_text(s->o, (const uint8_t *)s->replace, strlen(s->replace));
            s->replace_depth = 0;
            s->replace = NULL;
        }
        if (k == K_GROUP) err = append_children(s, s->guuid[d]);
        if (k == K_DELOBJS) {
            write_deleted(s);
            s->deleted_written = true;
        }
        if (k == K_ROOT && !s->deleted_written && s->deleted.len) {
            xw_start(s->o, "DeletedObjects", NULL, 0);
            write_deleted(s);
            xw_end(s->o, "DeletedObjects");
        }
        ev_write(s->o, e);
    } else if (s->replace_depth != d) {
        if (k == K_HISTMAX && e->type == EV_TEXT) {
            char b[16] = {0};
            memcpy(b, e->data, e->len < 15 ? e->len : 15);
            s->history_max = atoi(b);
        }
        ev_write(s->o, e);
    }
    if (e->type == EV_END) s->depth--;
    return err;
}

/* Pass 1: capture the subtrees of moved items. */
static kdbx_err proc1(saver *s, const ev_t *e)
{
    if (e->type == EV_START) {
        if (++s->depth >= MAXD) return KDBX_ERR_FORMAT;
        s->kind[s->depth] = (uint8_t)classify(e->name, s->kind[s->depth - 1]);
    }
    int d = s->depth, k = s->kind[d];
    for (size_t i = 0; i < s->n; i++)
        if (s->cap_depth[i] > 0 && !ev_save(&s->cap[i], e)) return KDBX_ERR_NOMEM;

    if (s->pend_depth) {
        if (!ev_save(&s->pend, e)) return KDBX_ERR_NOMEM;
        if (d == s->pend_depth + 1 && k == K_UUID && e->type == EV_TEXT && !tbuf_put(&s->uuid_text, e->data, e->len))
            return KDBX_ERR_NOMEM;
        if (d == s->pend_depth + 1 && k == K_UUID && e->type == EV_END) {
            uint8_t u[16];
            if (!uuid_from_text(s, u)) return KDBX_ERR_FORMAT;
            for (size_t i = 0; i < s->n; i++) {
                const kdbx_edit *x = &s->ed[i];
                bool mv = (x->op == KDBX_EDIT_ENTRY_MOVE && s->kind[s->pend_depth] == K_ENTRY) ||
                          (x->op == KDBX_EDIT_GROUP_MOVE && s->kind[s->pend_depth] == K_GROUP);
                if (mv && !memcmp(x->uuid, u, 16) && !s->cap[i].len) {
                    if (!tbuf_put(&s->cap[i], s->pend.p, s->pend.len)) return KDBX_ERR_NOMEM;
                    s->cap_depth[i] = s->pend_depth;
                }
            }
            s->pend_depth = 0;
            tbuf_clear(&s->pend);
        }
    } else if (e->type == EV_START && (k == K_ENTRY || k == K_GROUP)) {
        s->pend_depth = d;
        tbuf_clear(&s->uuid_text);
        if (!ev_save(&s->pend, e)) return KDBX_ERR_NOMEM;
    }
    if (e->type == EV_END) {
        for (size_t i = 0; i < s->n; i++)
            if (s->cap_depth[i] == d) s->cap_depth[i] = 0;
        s->depth--;
    }
    return KDBX_OK;
}

/* ---- XML source: yxml -> events (protected text decrypted with the old stream) ---- */

static kdbx_err src_flush_start(saver *s)
{
    if (!s->pstart) return KDBX_OK;
    s->pstart = false;
    ev_t e = {EV_START, s->names[s->sdepth], s->attrs.p, s->attrs.len};
    return s->proc(s, &e);
}

static kdbx_err src_flush_text(saver *s)
{
    if (!s->text.len) return KDBX_OK;
    kdbx_err err;
    if (s->prot[s->sdepth]) {
        size_t n;
        int r = mbedtls_base64_decode(NULL, 0, &n, s->text.p, s->text.len);
        if (r && r != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) return KDBX_ERR_FORMAT;
        tbuf_clear(&s->plain);
        uint8_t zero[64] = {0};
        for (size_t i = 0; i < n; i += sizeof zero)
            if (!tbuf_put(&s->plain, zero, n - i < sizeof zero ? n - i : sizeof zero)) return KDBX_ERR_NOMEM;
        if (mbedtls_base64_decode(s->plain.p, n, &n, s->text.p, s->text.len)) return KDBX_ERR_FORMAT;
        kdbx_stream_xor(s->okey, s->ononce, s->opos, s->plain.p, s->plain.p, n);
        s->opos += (uint32_t)n;
        ev_t e = {EV_PTEXT, NULL, s->plain.p, n};
        err = s->proc(s, &e);
        tbuf_clear(&s->plain);
    } else {
        ev_t e = {EV_TEXT, NULL, s->text.p, s->text.len};
        err = s->proc(s, &e);
    }
    tbuf_clear(&s->text);
    return err;
}

static kdbx_err src_xml(void *ctx, const uint8_t *d, size_t n)
{
    saver *s = ctx;
    if (!s->xml_started) {
        /* inner header done: its stream key is in the sink now */
        memcpy(s->okey, s->sink->stream_key, 32);
        memcpy(s->ononce, s->sink->stream_nonce, 12);
        if (s->pass2) {
            static const uint8_t end_field[5] = {0};
            gz_put(s->o, end_field, 5);
            xw_raw(s->o, "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");
        }
        s->xml_started = true;
    }
    for (size_t i = 0; i < n; i++) {
        kdbx_err err = KDBX_OK;
        switch (yxml_parse(&s->x, d[i])) {
        case YXML_OK: break;
        case YXML_ELEMSTART:
            if (!(err = src_flush_start(s)) && !(err = src_flush_text(s))) {
                if (++s->sdepth >= MAXD || strlen(s->x.elem) >= sizeof s->names[0]) return KDBX_ERR_FORMAT;
                strcpy(s->names[s->sdepth], s->x.elem);
                s->prot[s->sdepth] = false;
                s->pstart = true;
                tbuf_clear(&s->attrs);
            }
            break;
        case YXML_ATTRSTART:
            if (!tbuf_put(&s->attrs, s->x.attr, strlen(s->x.attr) + 1)) err = KDBX_ERR_NOMEM;
            break;
        case YXML_ATTRVAL:
            if (!tbuf_put(&s->attrs, s->x.data, strlen(s->x.data))) err = KDBX_ERR_NOMEM;
            break;
        case YXML_ATTREND: {
            if (!tbuf_put(&s->attrs, "", 1)) { err = KDBX_ERR_NOMEM; break; }
            /* last pair is "Protected\0True\0"? */
            static const char pt[] = "Protected\0True";
            if (s->attrs.len >= sizeof pt && !memcmp(s->attrs.p + s->attrs.len - sizeof pt, pt, sizeof pt) &&
                (s->attrs.len == sizeof pt || s->attrs.p[s->attrs.len - sizeof pt - 1] == 0))
                s->prot[s->sdepth] = true;
            break;
        }
        case YXML_CONTENT:
            if (!(err = src_flush_start(s)) && !tbuf_put(&s->text, s->x.data, strlen(s->x.data))) err = KDBX_ERR_NOMEM;
            break;
        case YXML_ELEMEND:
            if (!(err = src_flush_start(s)) && !(err = src_flush_text(s))) {
                ev_t e = {EV_END, s->names[s->sdepth], NULL, 0};
                err = s->proc(s, &e);
                s->sdepth--;
            }
            break;
        case YXML_PISTART: case YXML_PICONTENT: case YXML_PIEND: break;
        default: err = KDBX_ERR_FORMAT;
        }
        if (err) return err;
    }
    return KDBX_OK;
}

static kdbx_err bin_copy(void *ctx, const uint8_t *d, size_t n)
{
    saver *s = ctx;
    if (s->pass2) gz_put(s->o, d, n);
    return KDBX_OK;
}

static void src_reset(saver *s, proc_fn proc)
{
    yxml_init(&s->x, s->ystack, sizeof s->ystack);
    s->proc = proc;
    s->sdepth = s->depth = 0;
    s->pstart = s->xml_started = false;
    s->pend_depth = s->skip_depth = s->ebuf_depth = s->replace_depth = 0;
    s->opos = 0;
}

/* Runs one pass over the original file. */
static kdbx_err run_pass(saver *s, FILE *in, uint8_t tk[32], kdbx_header *h, proc_fn proc)
{
    kdbx_sink sink = {src_xml, bin_copy, s, {0}, {0}};
    src_reset(s, proc);
    s->sink = &sink;
    kdbx_err err = kdbx_read_file(in, NULL, tk, h, &sink);
    s->sink = NULL;
    if (!err && (s->sdepth || yxml_eof(&s->x) != YXML_OK)) err = KDBX_ERR_CORRUPT;
    mbedtls_platform_zeroize(&sink, sizeof sink);
    return err;
}

/* ======================= file output ======================= */

static bool out_init(out_t *o)
{
    mbedtls_md_init(&o->md);
    mbedtls_aes_init(&o->aes);
    mbedtls_chacha20_init(&o->chacha);
    mbedtls_chacha20_init(&o->inner);
    o->block = calloc(1, BLOCK);
    o->stored = calloc(1, STORED);
    o->head = calloc(4096, sizeof *o->head);
    return o->block && o->stored && o->head;            /* on false the caller still calls out_free */
}

static void out_free(out_t *o)
{
    mbedtls_md_free(&o->md);
    mbedtls_aes_free(&o->aes);
    mbedtls_chacha20_free(&o->chacha);
    mbedtls_chacha20_free(&o->inner);
    if (o->block) mbedtls_platform_zeroize(o->block, BLOCK);
    if (o->stored) mbedtls_platform_zeroize(o->stored, STORED);
    free(o->block);
    free(o->stored);
    free(o->head);
    mbedtls_platform_zeroize(o, sizeof *o);
}

/* Header, HMACs, cipher setup, gzip header and inner header (new stream key).
 * Attachments and XML follow through gz_put(). */
static kdbx_err out_begin(out_t *o, FILE *f, const kdbx_header *nh, const uint8_t tk[32])
{
    uint8_t master[32], sums[64], ik[64], h512[64];
    kdbx_derive(nh, tk, master, o->hmac_base);
    mbedtls_sha256(nh->raw, nh->rawlen, sums, 0);
    kdbx_header_hmac(nh, o->hmac_base, sums + 32);
    o->f = f;
    o->cipher = nh->cipher;
    memcpy(o->iv, nh->iv, nh->ivlen);
    if (o->cipher == CIPHER_AES256) {
        mbedtls_aes_setkey_enc(&o->aes, master, 256);
    } else {
        mbedtls_chacha20_setkey(&o->chacha, master);
        mbedtls_chacha20_starts(&o->chacha, nh->iv, 0);
    }
    mbedtls_platform_zeroize(master, sizeof master);
    if (mbedtls_md_setup(&o->md, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1)) return KDBX_ERR_NOMEM;
    if (fwrite(nh->raw, 1, nh->rawlen, f) != nh->rawlen || fwrite(sums, 1, 64, f) != 64) return KDBX_ERR_IO;

    static const uint8_t gzh[10] = {0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff};
    static const uint8_t f1[9] = {1, 4, 0, 0, 0, 3, 0, 0, 0}, f2[5] = {2, 64, 0, 0, 0};
    enc_put(o, gzh, 10);
    cp_random(ik, 64);
    mbedtls_sha512(ik, 64, h512, 0);
    mbedtls_chacha20_setkey(&o->inner, h512);
    mbedtls_chacha20_starts(&o->inner, h512 + 32, 0);
    gz_put(o, f1, 9);
    gz_put(o, f2, 5);
    gz_put(o, ik, 64);
    mbedtls_platform_zeroize(h512, sizeof h512);
    mbedtls_platform_zeroize(ik, sizeof ik);
    return o->err;
}

/* Finish the payload and close the file (always closed). */
static kdbx_err out_end(out_t *o)
{
    out_finish(o);
    kdbx_err err = o->err;
    if (!err && (fflush(o->f) || ferror(o->f))) err = KDBX_ERR_IO;
#ifdef ESP_PLATFORM
    if (!err) fsync(fileno(o->f));
#endif
    if (fclose(o->f) && !err) err = KDBX_ERR_IO;
    o->f = NULL;
    return err;
}

/* ======================= header ======================= */

/* New header from the original: fresh master seed and IV (and KDF seed when
 * rekeying), gzip on; other fields (cipher, custom data) copied. */
/* VariantDictionary items */
static size_t vd_bytes(uint8_t *b, size_t t, const char *k, const uint8_t *v, size_t vl)
{
    size_t kl = strlen(k);
    b[t] = 0x42;
    put_le32(b + t + 1, (uint32_t)kl);
    memcpy(b + t + 5, k, kl);
    put_le32(b + t + 5 + kl, (uint32_t)vl);
    memcpy(b + t + 9 + kl, v, vl);
    return t + 9 + kl + vl;
}
static size_t vd_num(uint8_t *b, size_t t, uint8_t type, const char *k, uint64_t v)
{
    size_t kl = strlen(k), vl = type == 0x05 ? 8 : 4;
    b[t] = type;
    put_le32(b + t + 1, (uint32_t)kl);
    memcpy(b + t + 5, k, kl);
    put_le32(b + t + 5 + kl, (uint32_t)vl);
    if (vl == 8) put_le64(b + t + 9 + kl, v);
    else put_le32(b + t + 9 + kl, (uint32_t)v);
    return t + 9 + kl + vl;
}

static kdbx_err build_header(const kdbx_header *old, kdbx_header *nh, bool new_kdf, uint64_t rounds)
{
    *nh = *old;
    cp_random(nh->master_seed, 32);
    cp_random(nh->iv, nh->ivlen);
    if (new_kdf) {                                     /* rekey: fresh salt; a round count switches to AES-KDF */
        if (rounds) nh->kdf = KDF_AES, nh->rounds = rounds;
        cp_random(nh->kdf_seed, 32);
        if (nh->kdf == KDF_ARGON2) cp_random(nh->a2_salt, nh->a2_saltlen);
    }
    nh->gzip = true;

    size_t pos = 12, np = 12;
    while (pos + 5 <= old->rawlen) {
        uint8_t id = old->raw[pos], tmp[400];
        uint32_t len = le32(old->raw + pos + 1);
        const uint8_t *src = old->raw + pos + 5;
        pos += 5 + len;
        if (id == 3) {
            put_le32(tmp, 1);
            src = tmp;
            len = 4;
        } else if (id == 4) {
            src = nh->master_seed;
            len = 32;
        } else if (id == 7) {
            src = nh->iv;
            len = (uint32_t)nh->ivlen;
        } else if (id == 11 && nh->kdf == KDF_ARGON2) {
            size_t t = 0;
            tmp[t++] = 0; tmp[t++] = 1;
            t = vd_bytes(tmp, t, "$UUID", nh->a2_type == KDBX_ARGON2_D ? KDBX_UUID_ARGON2D : KDBX_UUID_ARGON2ID, 16);
            t = vd_bytes(tmp, t, "S", nh->a2_salt, nh->a2_saltlen);
            t = vd_num(tmp, t, 0x04, "P", nh->a2_lanes);
            t = vd_num(tmp, t, 0x05, "M", nh->a2_mem);
            t = vd_num(tmp, t, 0x05, "I", nh->a2_iter);
            t = vd_num(tmp, t, 0x04, "V", nh->a2_version);
            if (nh->a2_secretlen) t = vd_bytes(tmp, t, "K", nh->a2_secret, nh->a2_secretlen);
            if (nh->a2_adlen) t = vd_bytes(tmp, t, "A", nh->a2_ad, nh->a2_adlen);
            tmp[t++] = 0;
            src = tmp;
            len = (uint32_t)t;
        } else if (id == 11) {
            size_t t = 0;
            tmp[t++] = 0; tmp[t++] = 1;
            tmp[t++] = 0x42; put_le32(tmp + t, 5); memcpy(tmp + t + 4, "$UUID", 5); t += 9;
            put_le32(tmp + t, 16); memcpy(tmp + t + 4, UUID_AESKDF, 16); t += 20;
            tmp[t++] = 0x05; put_le32(tmp + t, 1); tmp[t + 4] = 'R'; t += 5;
            put_le32(tmp + t, 8); put_le64(tmp + t + 4, nh->rounds); t += 12;
            tmp[t++] = 0x42; put_le32(tmp + t, 1); tmp[t + 4] = 'S'; t += 5;
            put_le32(tmp + t, 32); memcpy(tmp + t + 4, nh->kdf_seed, 32); t += 36;
            tmp[t++] = 0;
            src = tmp;
            len = (uint32_t)t;
        }
        if (np + 5 + len > sizeof nh->raw) return KDBX_ERR_FORMAT;
        nh->raw[np] = id;
        put_le32(nh->raw + np + 1, len);
        memcpy(nh->raw + np + 5, src, len);
        np += 5 + len;
        if (id == 0) break;
    }
    nh->rawlen = np;
    return KDBX_OK;
}

/* ======================= public ======================= */

void kdbx_new_uuid(uint8_t uuid[16]) { cp_random(uuid, 16); }

const kdbx_group *kdbx_root_group(const kdbx_db *db)
{
    for (const kdbx_group *g = db->groups; g; g = g->next)
        if (!g->parent) return g;
    return NULL;
}

static const kdbx_group *find_group(const kdbx_db *db, const uint8_t uuid[16])
{
    for (const kdbx_group *g = db->groups; g; g = g->next)
        if (!memcmp(g->uuid, uuid, 16)) return g;
    return NULL;
}

const kdbx_group *kdbx_recycle_bin(const kdbx_db *db)
{
    static const uint8_t zero[16];
    return memcmp(db->recycle_uuid, zero, 16) ? find_group(db, db->recycle_uuid) : NULL;
}

static bool inside(const kdbx_group *g, const kdbx_group *ancestor)
{
    for (; g && ancestor; g = g->parent)
        if (g == ancestor) return true;
    return false;
}

/* Recycle bin target (existing, or a new group edit in *out). Returns edits used. */
static size_t bin_target(const kdbx_db *db, kdbx_edit *out, const uint8_t **bin_uuid)
{
    const kdbx_group *bin = kdbx_recycle_bin(db), *root = kdbx_root_group(db);
    if (bin) {
        *bin_uuid = bin->uuid;
        return 0;
    }
    out->op = KDBX_EDIT_GROUP;
    out->create = true;
    out->recycle_bin = true;
    out->name = "Recycle Bin";
    kdbx_new_uuid(out->uuid);
    if (root) memcpy(out->parent, root->uuid, 16);
    *bin_uuid = out->uuid;
    return 1;
}

size_t kdbx_delete_entry(const kdbx_db *db, const kdbx_entry *e, kdbx_edit out[2])
{
    const uint8_t *bin;
    memset(out, 0, 2 * sizeof *out);
    if (!db->recycle_enabled || inside(e->group, kdbx_recycle_bin(db))) {
        out[0].op = KDBX_EDIT_ENTRY_DELETE;
        memcpy(out[0].uuid, e->uuid, 16);
        return 1;
    }
    size_t n = bin_target(db, out, &bin);
    out[n].op = KDBX_EDIT_ENTRY_MOVE;
    memcpy(out[n].uuid, e->uuid, 16);
    memcpy(out[n].parent, bin, 16);
    return n + 1;
}

size_t kdbx_delete_group(const kdbx_db *db, const kdbx_group *g, kdbx_edit out[2])
{
    const uint8_t *bin;
    memset(out, 0, 2 * sizeof *out);
    if (!db->recycle_enabled || inside(g, kdbx_recycle_bin(db))) {
        out[0].op = KDBX_EDIT_GROUP_DELETE;
        memcpy(out[0].uuid, g->uuid, 16);
        return 1;
    }
    size_t n = bin_target(db, out, &bin);
    out[n].op = KDBX_EDIT_GROUP_MOVE;
    memcpy(out[n].uuid, g->uuid, 16);
    memcpy(out[n].parent, bin, 16);
    return n + 1;
}

void kdbx_recover(const char *path)
{
    char tmp[512];
    FILE *f = fopen(path, "rb");
    if (f) { fclose(f); return; }
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    if ((f = fopen(tmp, "rb"))) {
        fclose(f);
        rename(tmp, path); /* .tmp was verified before the original was moved away */
    }
}

static bool valid_edits(const kdbx_db *db, const kdbx_edit *ed, size_t n, uint64_t rounds, const kdbx_key *newkey)
{
    if (rounds && !newkey) return false;
    for (size_t i = 0; i < n; i++) {
        if (ed[i].op != KDBX_EDIT_GROUP_MOVE) continue;
        const kdbx_group *g = find_group(db, ed[i].uuid), *dst = find_group(db, ed[i].parent);
        if (!memcmp(ed[i].uuid, ed[i].parent, 16) || (g && dst && inside(dst, g))) return false;
    }
    return true;
}

static kdbx_err check_xml(void *ctx, const uint8_t *d, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (yxml_parse(ctx, d[i]) < 0) return KDBX_ERR_CORRUPT;
    return KDBX_OK;
}

/* Full read of a written file without building an index: HMACs, decryption,
 * inflate, inner header, well-formed XML. */
static kdbx_err verify_file(const char *path, const uint8_t tk[32])
{
    struct { yxml_t x; uint8_t stack[2048]; kdbx_header h; } *v = malloc(sizeof *v);
    FILE *f = fopen(path, "rb");
    uint8_t t2[32];
    kdbx_err err = !v ? KDBX_ERR_NOMEM : !f ? KDBX_ERR_IO : KDBX_OK;
    if (!err) {
        kdbx_sink s = {check_xml, NULL, &v->x, {0}, {0}};
        yxml_init(&v->x, v->stack, sizeof v->stack);
        memcpy(t2, tk, 32);
        err = kdbx_read_file(f, NULL, t2, &v->h, &s);
        if (!err && yxml_eof(&v->x) != YXML_OK) err = KDBX_ERR_CORRUPT;
        mbedtls_platform_zeroize(&s, sizeof s);
        mbedtls_platform_zeroize(t2, sizeof t2);
    }
    if (f) fclose(f);
    free(v);
    return err;
}

/* The index is freed before saving and edit strings (field names, tags) may point into it, so the save works on
 * its own copy, wiped when done (it holds plaintext values). */
static kdbx_edit *edits_dup(const kdbx_edit *in, size_t n, size_t *size)
{
    size_t total = n * sizeof *in, nf = 0;
    for (size_t i = 0; i < n; i++) {
        nf += in[i].nfields;
        total += in[i].nfields * sizeof(kdbx_edit_field) + (in[i].tags ? strlen(in[i].tags) + 1 : 0) + (in[i].name ? strlen(in[i].name) + 1 : 0);
        for (size_t k = 0; k < in[i].nfields; k++)
            total += (in[i].fields[k].key ? strlen(in[i].fields[k].key) + 1 : 0) + (in[i].fields[k].value ? strlen(in[i].fields[k].value) + 1 : 0);
    }
    uint8_t *b = malloc(total ? total : 1);
    if (!b) return NULL;
    kdbx_edit *ed = (kdbx_edit *)b;
    kdbx_edit_field *fa = (kdbx_edit_field *)(b + n * sizeof *in);
    char *p = (char *)(fa + nf);
    if (n) memcpy(ed, in, n * sizeof *in);                 /* in may be NULL when there are no edits */
#define DUP(dst, src) do { if (src) { size_t l_ = strlen(src) + 1; memcpy(p, src, l_); dst = p; p += l_; } } while (0)
    for (size_t i = 0; i < n; i++) {
        DUP(ed[i].tags, in[i].tags);
        DUP(ed[i].name, in[i].name);
        ed[i].fields = in[i].nfields ? fa : NULL;
        for (size_t k = 0; k < in[i].nfields; k++) {
            fa[k] = in[i].fields[k];
            DUP(fa[k].key, in[i].fields[k].key);
            DUP(fa[k].value, in[i].fields[k].value);
        }
        fa += in[i].nfields;
    }
#undef DUP
    *size = total;
    return ed;
}

kdbx_err kdbx_save(kdbx_db **dbp, const char *path, const kdbx_edit *edits_in, size_t nedits, int64_t now,
                   const kdbx_key *newkey, uint64_t rounds)
{
    const kdbx_db *db = dbp ? *dbp : NULL;
    if (!db || !path) return KDBX_ERR_EDIT;
    kdbx_edit *edits = NULL;
    size_t esz = 0;
    bool freed = false, committed = false;
    size_t pl = strlen(path);
    char *tmp = malloc(pl + 5), *bak = malloc(pl + 5);
    saver *s = NULL;            /* the big buffers are allocated after the index is freed: they never coexist with it */
    out_t *o = NULL;
    kdbx_header *h = NULL, *nh = NULL;
    bool *appl = calloc(nedits + 1, sizeof *appl);
    tbuf *cap = calloc(nedits + 1, sizeof *cap);
    int *capd = calloc(nedits + 1, sizeof *capd);
    uint8_t tk[32], tk_new[32];
    FILE *in = NULL, *out = NULL;
    bool renaming = false;
    kdbx_err err = KDBX_ERR_NOMEM;

    if (!tmp || !bak || !appl || !cap || !capd) goto done;
    if (!valid_edits(db, edits_in, nedits, rounds, newkey)) { err = KDBX_ERR_EDIT; goto done; }
    if (!(edits = edits_dup(edits_in, nedits, &esz))) goto done;
    memcpy(tk, db->transformed, 32);
    kdbx_close(*dbp);            /* the save needs no index: free it so the size of the database does not matter */
    *dbp = NULL;
    db = NULL;
    freed = true;
    s = calloc(1, sizeof *s);
    o = calloc(1, sizeof *o);
    h = malloc(sizeof *h);
    nh = malloc(sizeof *nh);
    if (!s || !o || !h || !nh) goto done;
    if (!out_init(o)) goto done;
    snprintf(tmp, pl + 5, "%s.tmp", path);
    snprintf(bak, pl + 5, "%s.bak", path);

    s->db = NULL;
    s->ed = edits;
    s->n = nedits;
    s->applied = appl;
    s->now = now;
    time_b64(now, s->now_b64);
    s->o = o;
    s->history_max = DEFAULT_HISTORY_MAX;
    s->cap = cap;
    s->cap_depth = capd;
    bool moves = false;
    for (size_t i = 0; i < nedits; i++) {
        if (edits[i].op == KDBX_EDIT_GROUP && edits[i].create && edits[i].recycle_bin) s->new_bin = &edits[i];
        moves |= edits[i].op == KDBX_EDIT_ENTRY_MOVE || edits[i].op == KDBX_EDIT_GROUP_MOVE;
    }

    if (!(in = fopen(path, "rb"))) { err = KDBX_ERR_IO; goto done; }
    if ((err = kdbx_read_header(in, h)) != KDBX_OK) goto done;
    rewind(in);
    if (moves) {
        if ((err = run_pass(s, in, tk, h, proc1)) != KDBX_OK) goto done;
        rewind(in);
    }

    /* new header + keys */
    if ((err = build_header(h, nh, newkey != NULL, rounds)) != KDBX_OK) goto done;
    if (newkey) {
        if ((err = kdbx_kdf(nh, newkey->composite, tk_new)) != KDBX_OK) goto done;
    } else {
        memcpy(tk_new, tk, 32);
    }
    if (!(out = fopen(tmp, "wb"))) { err = KDBX_ERR_IO; goto done; }
    if ((err = out_begin(o, out, nh, tk_new)) != KDBX_OK) goto done;
    s->pass2 = true;
    if ((err = run_pass(s, in, tk, h, proc2)) != KDBX_OK) goto done;
    for (size_t i = 0; i < nedits; i++)
        if (!appl[i]) { err = KDBX_ERR_EDIT; goto done; }
    err = out_end(o);
    out = NULL;
    if (err) goto done;
    fclose(in);
    in = NULL;

    /* verify, swap files, then swap indexes (old freed before the new one is built) */
    if ((err = verify_file(tmp, tk_new)) != KDBX_OK) goto done;
    remove(bak);
    if (rename(path, bak)) { err = KDBX_ERR_IO; goto done; }
    renaming = true;
    if (rename(tmp, path)) { err = KDBX_ERR_IO; goto done; } /* kdbx_recover() finishes this */
    committed = true;                                      /* reopened below, once the save's own buffers are freed */

done:
    if (out) fclose(out);
    if (in) fclose(in);
    if (err && !renaming && tmp) remove(tmp);
    if (edits) { mbedtls_platform_zeroize(edits, esz); free(edits); }
    if (s) {
        tbuf *bufs[] = {&s->attrs, &s->text, &s->plain, &s->pend, &s->ebuf, &s->uuid_text, &s->deleted};
        for (size_t i = 0; i < sizeof bufs / sizeof *bufs; i++) tbuf_free(bufs[i]);
        mbedtls_platform_zeroize(s, sizeof *s);
    }
    if (cap)
        for (size_t i = 0; i < nedits; i++) tbuf_free(&cap[i]);
    if (o) out_free(o);
    free(tmp); free(bak); free(s); free(o); free(h); free(nh); free(appl); free(cap); free(capd);
    /* Everything the save needed is released: only now reopen (the new file, or the old one if nothing was saved),
     * so the peak is one unlock and not an unlock on top of the save buffers. */
    if (freed && !*dbp && (committed || !renaming)) {
        FILE *rt = fopen(path, "rb");
        kdbx_err re = rt ? kdbx_open_tk(rt, NULL, committed ? tk_new : tk, dbp) : KDBX_ERR_IO;
        if (rt) fclose(rt);
        if (committed && re) err = KDBX_ERR_REINDEX;       /* saved, but the file did not fit in memory */
    }
    mbedtls_platform_zeroize(tk, sizeof tk);
    mbedtls_platform_zeroize(tk_new, sizeof tk_new);
    return err;
}

/* ======================= create ======================= */

static void write_group_open(out_t *o, const uint8_t uuid[16], const char *name, const char *now_b64)
{
    char u[32];
    uuid_b64(uuid, u);
    xw_start(o, "Group", NULL, 0);
    xw_el(o, "UUID", u);
    xw_el(o, "Name", name);
    xw_el(o, "Notes", "");
    xw_el(o, "IconID", "48");
    xw_start(o, "Times", NULL, 0);
    const char *tn[] = {"LastModificationTime", "CreationTime", "LastAccessTime", "ExpiryTime"};
    for (int i = 0; i < 4; i++) xw_el(o, tn[i], now_b64);
    xw_el(o, "Expires", "False");
    xw_el(o, "UsageCount", "0");
    xw_el(o, "LocationChanged", now_b64);
    xw_end(o, "Times");
    xw_el(o, "IsExpanded", "True");
    xw_el(o, "DefaultAutoTypeSequence", "");
    xw_el(o, "EnableAutoType", "null");
    xw_el(o, "EnableSearching", "null");
    xw_el(o, "LastTopVisibleEntry", "AAAAAAAAAAAAAAAAAAAAAA==");
}

static kdbx_err create_impl(const char *path, int cipher, uint64_t rounds, uint32_t a2_mem_kib, uint32_t a2_iter, const kdbx_key *key,
                            const char *name, int64_t now, kdbx_db **db);

kdbx_err kdbx_create(const char *path, int cipher, uint64_t rounds, const kdbx_key *key, const char *name,
                     int64_t now, kdbx_db **db)
{
    return create_impl(path, cipher, rounds, 0, 0, key, name, now, db);
}

kdbx_err kdbx_create_argon2(const char *path, int cipher, uint32_t mem_kib, uint32_t iter, const kdbx_key *key, const char *name,
                            int64_t now, kdbx_db **db)
{
    *db = NULL;
    if (!mem_kib || mem_kib > KDBX_ARGON2_MAX_KIB || !iter) return KDBX_ERR_EDIT;
    return create_impl(path, cipher, 0, mem_kib, iter, key, name, now, db);
}

static kdbx_err create_impl(const char *path, int cipher, uint64_t rounds, uint32_t a2_mem_kib, uint32_t a2_iter, const kdbx_key *key,
                            const char *name, int64_t now, kdbx_db **db)
{
    static const char ZERO_UUID[] = "AAAAAAAAAAAAAAAAAAAAAA==";
    size_t pl = strlen(path);
    char *tmp = malloc(pl + 5), nb[16];
    out_t *o = calloc(1, sizeof *o);
    kdbx_header *tpl = calloc(1, sizeof *tpl), *nh = malloc(sizeof *nh);
    uint8_t tk[32], root[16];
    FILE *f = NULL;
    kdbx_err err = KDBX_ERR_NOMEM;

    *db = NULL;
    if (!tmp || !o || !tpl || !nh || !out_init(o)) goto done;
    if ((!rounds && !a2_iter) || (cipher != KDBX_AES256 && cipher != KDBX_CHACHA20)) { err = KDBX_ERR_EDIT; goto done; }
    if ((f = fopen(path, "rb"))) { fclose(f); f = NULL; err = KDBX_ERR_IO; goto done; } /* never overwrite */
    snprintf(tmp, pl + 5, "%s.tmp", path);

    /* template header; build_header() fills seeds, IV and KDF parameters */
    uint8_t *r = tpl->raw;
    size_t n = 0;
    const uint8_t sig[12] = {0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 0, 0, 4, 0};
    memcpy(r, sig, 12);
    n = 12;
    size_t ivlen = cipher == KDBX_AES256 ? 16 : 12;
    const struct { uint8_t id; uint32_t len; const void *d; } fl[] = {
        {2, 16, cipher == KDBX_AES256 ? KDBX_UUID_AES256 : KDBX_UUID_CHACHA20}, {3, 4, NULL}, {4, 32, NULL},
        {7, (uint32_t)ivlen, NULL}, {11, 0, NULL}, {0, 4, "\r\n\r\n"}};
    for (size_t i = 0; i < sizeof fl / sizeof *fl; i++) {
        r[n] = fl[i].id;
        put_le32(r + n + 1, fl[i].len);
        if (fl[i].d) memcpy(r + n + 5, fl[i].d, fl[i].len);
        n += 5 + fl[i].len;
    }
    tpl->rawlen = n;
    tpl->cipher = cipher;
    tpl->ivlen = ivlen;
    if (a2_iter) {                                     /* Argon2id; build_header() adds the salt and writes the parameters */
        tpl->kdf = KDF_ARGON2;
        tpl->a2_type = KDBX_ARGON2_ID;
        tpl->a2_lanes = 2;
        tpl->a2_version = 0x13;
        tpl->a2_mem = (uint64_t)a2_mem_kib * 1024;
        tpl->a2_iter = a2_iter;
        tpl->a2_saltlen = 32;
    }
    if ((err = build_header(tpl, nh, true, rounds)) != KDBX_OK) goto done;
    if ((err = kdbx_kdf(nh, key->composite, tk)) != KDBX_OK) goto done;

    if (!(f = fopen(tmp, "wb"))) { err = KDBX_ERR_IO; goto done; }
    if ((err = out_begin(o, f, nh, tk)) != KDBX_OK) goto done;
    f = NULL; /* owned by o now */
    static const uint8_t end_field[5] = {0};
    gz_put(o, end_field, 5);
    xw_raw(o, "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");
    time_b64(now, nb);
    xw_start(o, "KeePassFile", NULL, 0);
    xw_start(o, "Meta", NULL, 0);
    xw_el(o, "Generator", "CardPass");
    xw_el(o, "DatabaseName", name);
    xw_el(o, "DatabaseNameChanged", nb);
    xw_el(o, "DatabaseDescription", "");
    xw_el(o, "DatabaseDescriptionChanged", nb);
    xw_el(o, "DefaultUserName", "");
    xw_el(o, "DefaultUserNameChanged", nb);
    xw_el(o, "MaintenanceHistoryDays", "365");
    xw_el(o, "Color", "");
    xw_el(o, "MasterKeyChanged", nb);
    xw_el(o, "MasterKeyChangeRec", "-1");
    xw_el(o, "MasterKeyChangeForce", "-1");
    xw_start(o, "MemoryProtection", NULL, 0);
    xw_el(o, "ProtectTitle", "False");
    xw_el(o, "ProtectUserName", "False");
    xw_el(o, "ProtectPassword", "True");
    xw_el(o, "ProtectURL", "False");
    xw_el(o, "ProtectNotes", "False");
    xw_end(o, "MemoryProtection");
    xw_el(o, "CustomIcons", "");
    xw_el(o, "RecycleBinEnabled", "True");
    xw_el(o, "RecycleBinUUID", ZERO_UUID);
    xw_el(o, "RecycleBinChanged", nb);
    xw_el(o, "EntryTemplatesGroup", ZERO_UUID);
    xw_el(o, "EntryTemplatesGroupChanged", nb);
    xw_el(o, "LastSelectedGroup", ZERO_UUID);
    xw_el(o, "LastTopVisibleGroup", ZERO_UUID);
    xw_el(o, "HistoryMaxItems", "10");
    xw_el(o, "HistoryMaxSize", "6291456");
    xw_el(o, "SettingsChanged", nb);
    xw_el(o, "CustomData", "");
    xw_end(o, "Meta");
    xw_start(o, "Root", NULL, 0);
    kdbx_new_uuid(root);
    write_group_open(o, root, name, nb);
    xw_end(o, "Group");
    xw_el(o, "DeletedObjects", "");
    xw_end(o, "Root");
    xw_end(o, "KeePassFile");
    if ((err = out_end(o)) != KDBX_OK) goto done;

    if (!(f = fopen(tmp, "rb"))) { err = KDBX_ERR_IO; goto done; }
    err = kdbx_open_tk(f, NULL, tk, db);
    fclose(f);
    f = NULL;
    if (!err && rename(tmp, path)) err = KDBX_ERR_IO;

done:
    if (f) fclose(f);
    if (err) {
        if (tmp && o && !o->f) remove(tmp);
        kdbx_close(*db);
        *db = NULL;
    }
    if (o) {
        if (o->f) { fclose(o->f); if (tmp) remove(tmp); }
        out_free(o);
    }
    mbedtls_platform_zeroize(tk, sizeof tk);
    free(tmp); free(o); free(tpl); free(nh);
    return err;
}
