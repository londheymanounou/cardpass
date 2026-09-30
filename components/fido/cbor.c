#include <string.h>
#include "cbor.h"

static void put(cbor_w *w, const void *d, size_t n)
{
    if (w->overflow || n > w->cap - w->n) { w->overflow = true; return; }
    memcpy(w->p + w->n, d, n);
    w->n += n;
}

static void head(cbor_w *w, int major, uint64_t v)
{
    uint8_t b[9];
    size_t n;
    b[0] = (uint8_t)(major << 5);
    if (v < 24) { b[0] |= (uint8_t)v; n = 1; }
    else if (v <= 0xFF) { b[0] |= 24; b[1] = (uint8_t)v; n = 2; }
    else if (v <= 0xFFFF) { b[0] |= 25; b[1] = (uint8_t)(v >> 8); b[2] = (uint8_t)v; n = 3; }
    else if (v <= 0xFFFFFFFF) { b[0] |= 26; for (int i = 0; i < 4; i++) b[1 + i] = (uint8_t)(v >> (24 - 8 * i)); n = 5; }
    else { b[0] |= 27; for (int i = 0; i < 8; i++) b[1 + i] = (uint8_t)(v >> (56 - 8 * i)); n = 9; }
    put(w, b, n);
}

void cbor_uint(cbor_w *w, uint64_t v) { head(w, 0, v); }
void cbor_int(cbor_w *w, int64_t v) { if (v >= 0) head(w, 0, (uint64_t)v); else head(w, 1, (uint64_t)(-1 - v)); }
void cbor_bytes(cbor_w *w, const void *d, size_t n) { head(w, 2, n); put(w, d, n); }
void cbor_text(cbor_w *w, const char *s) { size_t n = strlen(s); head(w, 3, n); put(w, s, n); }
void cbor_array(cbor_w *w, size_t n) { head(w, 4, n); }
void cbor_map(cbor_w *w, size_t n) { head(w, 5, n); }
void cbor_bool(cbor_w *w, bool v) { uint8_t b = v ? 0xF5 : 0xF4; put(w, &b, 1); }

bool cbor_next(cbor_r *r, cbor_item *it)
{
    if (r->err || r->p >= r->end) return !(r->err = true);
    uint8_t b = *r->p++;
    int major = b >> 5, info = b & 31;
    uint64_t v = (uint64_t)info;
    if (info >= 24 && info <= 27) {
        size_t n = (size_t)1 << (info - 24);
        if ((size_t)(r->end - r->p) < n) return !(r->err = true);
        v = 0;
        for (size_t i = 0; i < n; i++) v = v << 8 | *r->p++;
    } else if (info > 27) {
        return !(r->err = true); /* indefinite lengths / reserved: not CTAP2 canonical */
    }
    it->type = major;
    it->val = v;
    it->data = NULL;
    if (major == CBOR_BYTES || major == CBOR_TEXT) {
        if (v > (uint64_t)(r->end - r->p)) return !(r->err = true);
        it->data = r->p;
        r->p += v;
    }
    return true;
}

static bool skip_depth(cbor_r *r, int depth)
{
    cbor_item it;
    if (depth > 16 || !cbor_next(r, &it)) return !(r->err = true);
    uint64_t n = it.type == CBOR_ARRAY ? it.val : it.type == CBOR_MAP ? it.val * 2 : it.type == CBOR_TAG ? 1 : 0;
    if (n > (uint64_t)(r->end - r->p)) return !(r->err = true); /* each item needs >= 1 byte */
    for (uint64_t i = 0; i < n; i++)
        if (!skip_depth(r, depth + 1)) return false;
    return true;
}

bool cbor_skip(cbor_r *r) { return skip_depth(r, 0); }

bool cbor_int_value(const cbor_item *it, int64_t *v)
{
    if (it->val > INT64_MAX) return false;
    if (it->type == CBOR_UINT) *v = (int64_t)it->val;
    else if (it->type == CBOR_NINT) *v = -1 - (int64_t)it->val;
    else return false;
    return true;
}
