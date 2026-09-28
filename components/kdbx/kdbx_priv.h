/* Internals shared by the kdbx sources and the host tests. */
#pragma once
#include "kdbx.h"
#include "yxml/yxml.h"

/* ---- arena: chunked, never realloc'd (no unwiped copies), wiped on free ---- */
typedef struct arena_chunk {
    struct arena_chunk *next;
    size_t cap, used;
    _Alignas(8) uint8_t data[];
} arena_chunk;

typedef struct { arena_chunk *head; } arena;

void *arena_alloc(arena *a, size_t n); /* zeroed, 8-byte aligned */
void arena_free(arena *a);

/* ---- growable text buffer (wiped on grow and free) ---- */
typedef struct { uint8_t *p; size_t len, cap; } tbuf;
bool tbuf_put(tbuf *t, const void *d, size_t n);
void tbuf_clear(tbuf *t); /* wipes contents, keeps capacity */
void tbuf_free(tbuf *t);

/* ---- outer header ---- */
enum { CIPHER_AES256, CIPHER_CHACHA20 };

typedef struct {
    uint8_t raw[4096];        /* header bytes, for SHA-256 + HMAC */
    size_t rawlen;
    int cipher;
    bool gzip;
    uint8_t master_seed[32];
    uint8_t iv[16];
    size_t ivlen;
    uint8_t kdf_seed[32];
    uint64_t rounds;
} kdbx_header;

kdbx_err kdbx_read_header(FILE *f, kdbx_header *h);
void kdbx_aes_kdf(const uint8_t seed[32], uint64_t rounds, const uint8_t in[32], uint8_t out[32]);
void kdbx_derive(const kdbx_header *h, const uint8_t tk[32], uint8_t master[32], uint8_t hmac_base[64]);
void kdbx_block_key(const uint8_t hmac_base[64], uint64_t idx, uint8_t out[64]);
void kdbx_header_hmac(const kdbx_header *h, const uint8_t hmac_base[64], uint8_t mac[32]);

/* ---- decrypted payload consumer ---- */
typedef struct {
    kdbx_err (*xml)(void *ctx, const uint8_t *d, size_t n);
    kdbx_err (*bin)(void *ctx, const uint8_t *d, size_t n); /* raw inner-header attachment fields, NULL = skip */
    void *ctx;
    uint8_t stream_key[32], stream_nonce[12];              /* set before the first xml() call */
} kdbx_sink;

/* Verify + decrypt f into s. composite != NULL: run the KDF, tk is output;
 * composite == NULL: tk is the cached transformed key (input). */
kdbx_err kdbx_read_file(FILE *f, const uint8_t *composite, uint8_t tk[32], kdbx_header *h, kdbx_sink *s);
kdbx_err kdbx_open_tk(FILE *f, const uint8_t *composite, const uint8_t tk[32], kdbx_db **out);
void kdbx_stream_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t off, const uint8_t *in, uint8_t *out, size_t n);

/* ---- XML -> index ---- */
#define XML_MAX_DEPTH 64

struct kdbx_db {
    arena a;
    kdbx_entry *entries, *entries_tail;
    kdbx_group *groups, *groups_tail;
    uint8_t stream_key[32], stream_nonce[12]; /* inner ChaCha20 */
    uint8_t transformed[32];                  /* cached for saving without re-running the KDF */
    bool recycle_enabled;
    uint8_t recycle_uuid[16];
};

typedef struct {
    kdbx_db *db;
    yxml_t x;
    uint8_t stack[2048];        /* yxml name stack */
    uint8_t tags[XML_MAX_DEPTH];/* our tag ids per depth */
    int depth, history;         /* history > 0: inside <History> */
    kdbx_group *group;          /* current group */
    kdbx_entry *entry;          /* current (non-history) entry */
    kdbx_field *field, *fields_tail;
    bool protected_attr, in_attr;
    tbuf text, attr;
    uint32_t stream_pos;        /* bytes of inner keystream consumed so far */
    bool done;
} xml_index;

void xml_index_init(xml_index *xi, kdbx_db *db);
kdbx_err xml_index_feed(xml_index *xi, const uint8_t *d, size_t n);
kdbx_err xml_index_finish(xml_index *xi);
void xml_index_wipe(xml_index *xi);
