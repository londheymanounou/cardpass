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

/* ---- XML -> index ---- */
#define XML_MAX_DEPTH 64

struct kdbx_db {
    arena a;
    kdbx_entry *entries, *entries_tail;
    kdbx_group *groups, *groups_tail;
    uint8_t stream_key[32], stream_nonce[12]; /* inner ChaCha20 */
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
