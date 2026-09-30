/* Minimal CBOR (RFC 8949) for CTAP2: unsigned/negative ints, byte/text strings,
 * arrays, maps, booleans. Definite lengths only (CTAP2 canonical form). */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *p;
    size_t n, cap;
    bool overflow;
} cbor_w;

void cbor_uint(cbor_w *w, uint64_t v);
void cbor_int(cbor_w *w, int64_t v);
void cbor_bytes(cbor_w *w, const void *d, size_t n);
void cbor_text(cbor_w *w, const char *s);
void cbor_array(cbor_w *w, size_t n);
void cbor_map(cbor_w *w, size_t n);
void cbor_bool(cbor_w *w, bool v);

enum { CBOR_UINT, CBOR_NINT, CBOR_BYTES, CBOR_TEXT, CBOR_ARRAY, CBOR_MAP, CBOR_TAG, CBOR_SIMPLE };

typedef struct {
    const uint8_t *p, *end;
    bool err;
} cbor_r;

typedef struct {
    int type;
    uint64_t val;          /* int value, length, or count */
    const uint8_t *data;   /* bytes/text payload */
} cbor_item;

bool cbor_next(cbor_r *r, cbor_item *it);   /* reads one item header (+ string payload) */
bool cbor_skip(cbor_r *r);                   /* skips one whole item (nested), depth-limited */
bool cbor_int_value(const cbor_item *it, int64_t *v);
