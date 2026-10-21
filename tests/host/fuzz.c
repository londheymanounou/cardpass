/* Mutation fuzzer for every parser that sees untrusted or unauthenticated input.
 * Run under ASan/UBSan (tests/host/asan.sh); any memory error aborts the run.
 * Linux only (fmemopen).
 *   fuzz <testdata dir> [iterations per target]
 *
 * Targets: outer header, whole files with the right key (payload is parsed
 * before its block HMAC is checked), decrypted payloads (gzip -> inner header
 * -> XML index), key files, otpauth:// / TimeOtp-*, auto-type sequences,
 * search queries, strength estimator. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kdbx_priv.h"
#include "miniz.h"
#include "search.h"
#include "strength.h"
#include "totp.h"
#include "typing.h"
#include "fido.h"
#include "../../components/fido/cbor.h"

static uint64_t rs = 0x9E3779B97F4A7C15ULL;
static uint32_t rnd(void)
{
    rs ^= rs << 13;
    rs ^= rs >> 7;
    rs ^= rs << 17;
    return (uint32_t)(rs >> 16);
}
static uint32_t below(uint32_t n) { return n ? rnd() % n : 0; }

typedef struct { uint8_t *p; size_t n; } blob;

static blob load(const char *dir, const char *name)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    blob b = {0};
    if (!f) { fprintf(stderr, "missing %s\n", path); exit(2); }
    fseek(f, 0, SEEK_END);
    b.n = (size_t)ftell(f);
    rewind(f);
    b.p = malloc(b.n + 1);
    if (fread(b.p, 1, b.n, f) != b.n) exit(2);
    b.p[b.n] = 0;
    fclose(f);
    return b;
}

/* Mutated copy of seed (NUL-terminated too, for string targets). */
static blob mutate(const blob *seeds, size_t nseeds, size_t max)
{
    const blob *s = &seeds[below((uint32_t)nseeds)];
    blob m = {malloc(max + 1), s->n < max ? s->n : max};
    memcpy(m.p, s->p, m.n);
    static const uint8_t interesting[] = {0, 1, 0x7F, 0x80, 0xFF, '<', '>', '&', '{', '}', '=', '%', 0xC3, 0xE2};
    for (int k = 1 + (int)below(8); k--;) {
        size_t at = below((uint32_t)m.n + 1);
        switch (below(7)) {
        case 0: if (m.n) m.p[below((uint32_t)m.n)] ^= (uint8_t)(1u << below(8)); break;
        case 1: if (m.n) m.p[below((uint32_t)m.n)] = (uint8_t)rnd(); break;
        case 2: if (m.n) m.p[below((uint32_t)m.n)] = interesting[below(sizeof interesting)]; break;
        case 3: if (m.n < max) { memmove(m.p + at + 1, m.p + at, m.n - at); m.p[at] = (uint8_t)rnd(); m.n++; } break;
        case 4: if (m.n) { size_t len = 1 + below(16); if (at + len > m.n) len = m.n - at; memmove(m.p + at, m.p + at + len, m.n - at - len); m.n -= len; } break;
        case 5: if (m.n && m.n < max) { size_t src = below((uint32_t)m.n), len = 1 + below(32);
                    if (src + len > m.n) len = m.n - src; if (m.n + len > max) len = max - m.n;
                    memmove(m.p + at + len, m.p + at, m.n - at); memmove(m.p + at, m.p + src + (src >= at ? len : 0), len); m.n += len; } break;
        case 6: if (m.n > 1) m.n = below((uint32_t)m.n); break; /* truncate */
        }
    }
    m.p[m.n] = 0;
    return m;
}

/* Touch everything in an index so ASan sees any bad pointer. */
static void walk(const kdbx_db *db)
{
    volatile size_t sum = 0;
    char buf[4096];
    for (const kdbx_group *g = kdbx_groups(db); g; g = g->next) sum += strlen(g->name) + strlen(g->autotype);
    for (const kdbx_entry *e = kdbx_entries(db); e; e = e->next) {
        sum += strlen(e->title) + strlen(e->username) + strlen(e->url) + strlen(e->tags) + strlen(kdbx_autotype(e, ""));
        for (size_t i = 0; i < e->nfields; i++)
            if (kdbx_reveal(db, &e->fields[i], buf, sizeof buf) == KDBX_OK) sum += strlen(buf);
        for (const kdbx_attachment *a = e->attachments; a; a = a->next) sum += strlen(a->name) + a->size;
    }
    search_hit hits[64];
    search_run(db, "a", NULL, 0, hits, 64);
    (void)sum;
}

/* ---- payload seeds: inner header + XML, raw and gzip'd ---- */
typedef struct { tbuf bin, xml; } capture;
static kdbx_err cap_xml(void *c, const uint8_t *d, size_t n) { return tbuf_put(&((capture *)c)->xml, d, n) ? KDBX_OK : KDBX_ERR_NOMEM; }
static kdbx_err cap_bin(void *c, const uint8_t *d, size_t n) { return tbuf_put(&((capture *)c)->bin, d, n) ? KDBX_OK : KDBX_ERR_NOMEM; }

static void payload_seeds(const char *dir, const char *name, blob *raw, blob *gz)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    kdbx_key k;
    kdbx_header h;
    uint8_t tk[32];
    capture c = {0};
    kdbx_sink s = {cap_xml, cap_bin, &c, {0}, {0}};
    kdbx_key_init(&k, "test", 4, NULL);
    if (kdbx_read_file(f, k.composite, tk, &h, &s)) { fprintf(stderr, "seed %s failed\n", name); exit(2); }
    fclose(f);
    tbuf p = {0};
    uint8_t f1[9] = {1, 4, 0, 0, 0, 3, 0, 0, 0}, f2[5] = {2, 64, 0, 0, 0}, key[64] = {1}, end[5] = {0};
    tbuf_put(&p, f1, 9); tbuf_put(&p, f2, 5); tbuf_put(&p, key, 64);
    tbuf_put(&p, c.bin.p, c.bin.len); tbuf_put(&p, end, 5); tbuf_put(&p, c.xml.p, c.xml.len);
    raw->p = p.p;
    raw->n = p.len;
    /* gzip: header + raw deflate + crc32 + size */
    size_t dl;
    void *def = tdefl_compress_mem_to_heap(p.p, p.len, &dl, 0x100);
    gz->n = 10 + dl + 8;
    gz->p = malloc(gz->n);
    static const uint8_t gzh[10] = {0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3};
    memcpy(gz->p, gzh, 10);
    memcpy(gz->p + 10, def, dl);
    uint32_t crc = (uint32_t)mz_crc32(MZ_CRC32_INIT, p.p, p.len), sz = (uint32_t)p.len;
    memcpy(gz->p + 10 + dl, &crc, 4);
    memcpy(gz->p + 14 + dl, &sz, 4);
    mz_free(def);
    tbuf_free(&c.xml);
    tbuf_free(&c.bin);
}

/* ---- auto-type mock ---- */
static bool at_field(void *c, const char *n, char *b, size_t sz) { (void)c; if (n[0] == 'Z') return false; snprintf(b, sz, "v%sé€", n); return true; }
static bool at_totp(void *c, char *b, size_t sz) { (void)c; snprintf(b, sz, "123456"); return true; }
static void at_stroke(void *c, uint8_t k, uint8_t m) { (void)c; (void)k; (void)m; }
static void at_delay(void *c, int ms) { (void)c; (void)ms; }

static int fz_store(void *c, const fido_new *n) { (void)c; (void)n; return (int)below(3); }
static int fz_choose(void *c, const char *rp, const fido_cred *cr, size_t n) { (void)c; (void)rp; (void)cr; return (int)below((uint32_t)n + 1) - 1; }
static void fz_send(void *c, const uint8_t r[64]) { (void)c; (void)r; }

void cp_random(void *buf, size_t n) { for (uint8_t *p = buf; n--;) *p++ = (uint8_t)rnd(); }

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : "testdata";
    long iters = argc > 2 ? atol(argv[2]) : 2000;
    kdbx_key key;
    kdbx_key_init(&key, "test", 4, NULL);

    blob files[] = {load(dir, "aes.kdbx"), load(dir, "chacha_kpxc.kdbx"), load(dir, "keyfile_xml2.kdbx")};
    blob headers[3];
    for (int i = 0; i < 3; i++) headers[i] = (blob){files[i].p, files[i].n < 400 ? files[i].n : 400};
    blob keyfiles[] = {load(dir, "key_xml2.keyx"), load(dir, "key_xml1.keyx"), load(dir, "key_hex64.keyx"),
                       load(dir, "key_raw32.keyx")};
    blob raw[2], gz[2];
    payload_seeds(dir, "aes_kpxc.kdbx", &raw[0], &gz[0]);
    payload_seeds(dir, "aes.kdbx", &raw[1], &gz[1]);

    const char *uri_s[] = {"otpauth://totp/Google:alice?secret=JBSWY3DPEHPK3PXP&issuer=Google&period=30&digits=8&algorithm=SHA256",
                           "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ%3D%3D&encoder=steam"};
    const char *seq_s[] = {"{USERNAME}{TAB}{PASSWORD}{ENTER}", "{S:PIN}{DELAY 5}{DELAY=1}^a+{TAB 3}~{+}{{}{}}{TOTP}{URL}"};
    const char *txt_s[] = {"Café Crème gml", "P@ssw0rd2024! correct-horse qwerty 12345 ŁÓDŹ ✓"};
    blob uris[2], seqs[2], txts[2];
    for (int i = 0; i < 2; i++) {
        uris[i] = (blob){(uint8_t *)uri_s[i], strlen(uri_s[i])};
        seqs[i] = (blob){(uint8_t *)seq_s[i], strlen(seq_s[i])};
        txts[i] = (blob){(uint8_t *)txt_s[i], strlen(txt_s[i])};
    }
    at_ops ops = {at_field, at_totp, at_stroke, at_delay, NULL};

    /* FIDO: passkeys db, CTAP2 request seeds, CTAPHID report seeds */
    kdbx_db *pdb;
    {
        char p[512];
        snprintf(p, sizeof p, "%s/passkeys.kdbx", dir);
        FILE *pf = fopen(p, "rb");
        if (!pf || kdbx_open(pf, &key, &pdb)) { fprintf(stderr, "passkeys.kdbx\n"); return 2; }
        fclose(pf);
    }
    fido_env fenv = {pdb, fz_choose, NULL, fz_store};
    fido_cred pc[4];
    fido_find(pdb, "webauthn.io", pc, 4);
    static uint8_t reqbuf[3][512];
    blob reqs[3];
    {
        cbor_w w = {reqbuf[0] + 1, 0, 511, false};
        reqbuf[0][0] = 0x02;
        uint8_t h[32] = {7};
        cbor_map(&w, 4);
        cbor_uint(&w, 1); cbor_text(&w, "webauthn.io");
        cbor_uint(&w, 2); cbor_bytes(&w, h, 32);
        cbor_uint(&w, 3); cbor_array(&w, 1); cbor_map(&w, 2);
        cbor_text(&w, "id"); cbor_bytes(&w, pc[0].cred_id, pc[0].cred_len);
        cbor_text(&w, "type"); cbor_text(&w, "public-key");
        cbor_uint(&w, 5); cbor_map(&w, 2); cbor_text(&w, "up"); cbor_bool(&w, true); cbor_text(&w, "uv"); cbor_bool(&w, true);
        reqs[0] = (blob){reqbuf[0], 1 + w.n};
        reqbuf[1][0] = 0x04;
        reqs[1] = (blob){reqbuf[1], 1};
        cbor_w mw = {reqbuf[2] + 1, 0, 511, false};                 /* makeCredential */
        reqbuf[2][0] = 0x01;
        uint8_t uid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        cbor_map(&mw, 5);
        cbor_uint(&mw, 1); cbor_bytes(&mw, h, 32);
        cbor_uint(&mw, 2); cbor_map(&mw, 2); cbor_text(&mw, "id"); cbor_text(&mw, "example.org"); cbor_text(&mw, "name"); cbor_text(&mw, "Example");
        cbor_uint(&mw, 3); cbor_map(&mw, 3); cbor_text(&mw, "id"); cbor_bytes(&mw, uid, 8); cbor_text(&mw, "name"); cbor_text(&mw, "zoe");
        cbor_text(&mw, "displayName"); cbor_text(&mw, "Zoe");
        cbor_uint(&mw, 4); cbor_array(&mw, 2); cbor_map(&mw, 2); cbor_text(&mw, "alg"); cbor_int(&mw, -7); cbor_text(&mw, "type"); cbor_text(&mw, "public-key");
        cbor_map(&mw, 2); cbor_text(&mw, "alg"); cbor_int(&mw, -257); cbor_text(&mw, "type"); cbor_text(&mw, "public-key");
        cbor_uint(&mw, 7); cbor_map(&mw, 1); cbor_text(&mw, "rk"); cbor_bool(&mw, true);
        reqs[2] = (blob){reqbuf[2], 1 + mw.n};
    }
    static uint8_t repbuf[2][64] = {{0xFF, 0xFF, 0xFF, 0xFF, 0x86, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8},
                                    {0, 0, 0, 1, 0x90, 0, 1, 0x04}};
    blob reps[2] = {{repbuf[0], 64}, {repbuf[1], 64}};
    static ctaphid hid;
    ctaphid_init(&hid);
    static uint8_t resp[4096];
    long ok_payload = 0, ok_open = 0;

    for (long it = 0; it < iters; it++) {
        blob m;
        kdbx_db *db;

        m = mutate(headers, 3, 600); /* outer header */
        FILE *f = fmemopen(m.p, m.n ? m.n : 1, "rb");
        kdbx_header h;
        kdbx_read_header(f, &h);
        fclose(f);
        free(m.p);

        m = mutate(files, 3, 8192); /* whole file, right key */
        f = fmemopen(m.p, m.n ? m.n : 1, "rb");
        if (kdbx_open(f, &key, &db) == KDBX_OK) { walk(db); kdbx_close(db); ok_open++; }
        fclose(f);
        free(m.p);

        bool gzip = below(2);
        m = mutate(gzip ? gz : raw, 2, 16384); /* decrypted payload */
        if (kdbx_index_payload(m.p, m.n, gzip, 1 + below(4096), &db) == KDBX_OK) { walk(db); kdbx_close(db); ok_payload++; }
        free(m.p);

        m = mutate(keyfiles, 4, 5000); /* key files */
        f = fmemopen(m.p, m.n ? m.n : 1, "rb");
        kdbx_key k2;
        kdbx_key_init(&k2, NULL, 0, f);
        fclose(f);
        free(m.p);

        m = mutate(uris, 2, 512); /* TOTP */
        totp t;
        char code[16];
        if (totp_from_uri(&t, (char *)m.p)) totp_code(&t, 1234567890, code);
        totp_init(&t);
        if (totp_set_keepass(&t, below(2) ? "TimeOtp-Secret-Base64" : "TimeOtp-Secret-Base32", (char *)m.p) &&
            totp_set_keepass(&t, "TimeOtp-Algorithm", (char *)m.p) && totp_valid(&t))
            totp_code(&t, 42, code);
        free(m.p);

        m = mutate(seqs, 2, 512); /* auto-type */
        at_error ae;
        at_type((char *)m.p, kbd_layout_get((int)below((uint32_t)kbd_layout_count())), &ops, 0, &ae);
        free(m.p);

        m = mutate(reqs, 3, 600); /* CTAP2 requests */
        ctap2_handle(&fenv, m.p, m.n, resp, sizeof resp);
        free(m.p);
        for (int r = 0; r < 4; r++) { /* CTAPHID reports */
            m = mutate(reps, 2, 64);
            uint8_t rep[64] = {0};
            memcpy(rep, m.p, m.n);
            ctaphid_report(&hid, rep, &fenv, fz_send, NULL);
            free(m.p);
        }

        m = mutate(txts, 2, 256); /* strength + search folding */
        strength_bits((char *)m.p);
        search_score((char *)m.p, "Gmail Café");
        search_score("gml", (char *)m.p);
        free(m.p);
    }
    kdbx_close(pdb);
    for (int i = 0; i < 3; i++) free(files[i].p);
    for (int i = 0; i < 4; i++) free(keyfiles[i].p);
    for (int i = 0; i < 2; i++) free(raw[i].p), free(gz[i].p);
    printf("fuzz: %ld iterations x 10 targets, no memory errors (valid mutants: %ld files, %ld payloads)\n", iters,
           ok_open, ok_payload);
    return 0;
}
