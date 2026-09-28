/* Streaming KeePass XML -> compact index. Protected values keep their
 * ciphertext + inner keystream offset; history is only counted (keystream). */
#include <stdlib.h>
#include <string.h>
#include "mbedtls/base64.h"
#include "mbedtls/platform_util.h"
#include "kdbx_priv.h"

#define ARENA_CHUNK 16384
#define TICKS_TO_UNIX 62135596800LL /* seconds from 0001-01-01 to 1970-01-01 */

/* ---------------- arena / tbuf ---------------- */

void *arena_alloc(arena *a, size_t n)
{
    n = (n + 7) & ~(size_t)7;
    arena_chunk *c = a->head;
    if (!c || c->cap - c->used < n) {
        size_t cap = n > ARENA_CHUNK ? n : ARENA_CHUNK;
        if (!(c = calloc(1, sizeof *c + cap))) return NULL;
        c->cap = cap;
        c->next = a->head;
        a->head = c;
    }
    void *p = c->data + c->used;
    c->used += n;
    return p;
}

void arena_free(arena *a)
{
    for (arena_chunk *c = a->head, *next; c; c = next) {
        next = c->next;
        mbedtls_platform_zeroize(c->data, c->used);
        free(c);
    }
    a->head = NULL;
}

bool tbuf_put(tbuf *t, const void *d, size_t n)
{
    if (t->len + n > t->cap) {
        size_t cap = t->cap ? t->cap : 256;
        while (cap < t->len + n) cap *= 2;
        uint8_t *p = malloc(cap);
        if (!p) return false;
        if (t->p) {
            memcpy(p, t->p, t->len);
            mbedtls_platform_zeroize(t->p, t->cap);
            free(t->p);
        }
        t->p = p;
        t->cap = cap;
    }
    memcpy(t->p + t->len, d, n);
    t->len += n;
    return true;
}

void tbuf_clear(tbuf *t)
{
    if (t->p) mbedtls_platform_zeroize(t->p, t->len);
    t->len = 0;
}

void tbuf_free(tbuf *t)
{
    if (t->p) mbedtls_platform_zeroize(t->p, t->cap);
    free(t->p);
    memset(t, 0, sizeof *t);
}

/* ---------------- XML ---------------- */

enum { T_OTHER, T_GROUP, T_ENTRY, T_HISTORY, T_STRING, T_KEY, T_VALUE, T_UUID, T_NAME, T_TAGS,
       T_TIMES, T_EXPIRY, T_EXPIRES, T_ROOT, T_META, T_RB_ENABLED, T_RB_UUID };

static const char *const tag_names[] = {
    [T_GROUP] = "Group", [T_ENTRY] = "Entry", [T_HISTORY] = "History", [T_STRING] = "String",
    [T_KEY] = "Key", [T_VALUE] = "Value", [T_UUID] = "UUID", [T_NAME] = "Name", [T_TAGS] = "Tags",
    [T_TIMES] = "Times", [T_EXPIRY] = "ExpiryTime", [T_EXPIRES] = "Expires", [T_ROOT] = "Root",
    [T_META] = "Meta", [T_RB_ENABLED] = "RecycleBinEnabled", [T_RB_UUID] = "RecycleBinUUID",
};

static int tag_id(const char *name)
{
    for (int i = 1; i < (int)(sizeof tag_names / sizeof *tag_names); i++)
        if (!strcmp(name, tag_names[i])) return i;
    return T_OTHER;
}

void xml_index_init(xml_index *xi, kdbx_db *db)
{
    memset(xi, 0, sizeof *xi);
    xi->db = db;
    yxml_init(&xi->x, xi->stack, sizeof xi->stack);
}

void xml_index_wipe(xml_index *xi)
{
    tbuf_free(&xi->text);
    tbuf_free(&xi->attr);
    mbedtls_platform_zeroize(xi, sizeof *xi);
}

static const char *text_dup(xml_index *xi)
{
    char *s = arena_alloc(&xi->db->a, xi->text.len + 1);
    if (s && xi->text.len) memcpy(s, xi->text.p, xi->text.len);
    return s;
}

/* Exactly `want` decoded bytes (0 = any length, returns length). -1 on error. */
static long b64(xml_index *xi, uint8_t *out, size_t want)
{
    size_t olen;
    if (mbedtls_base64_decode(out, want, &olen, xi->text.p, xi->text.len) || (want && olen != want)) return -1;
    return (long)olen;
}

static kdbx_err elem_start(xml_index *xi)
{
    if (++xi->depth >= XML_MAX_DEPTH) return KDBX_ERR_FORMAT;
    int t = tag_id(xi->x.elem), parent = xi->tags[xi->depth - 1];
    xi->tags[xi->depth] = (uint8_t)t;
    xi->protected_attr = false;
    tbuf_clear(&xi->text);
    kdbx_db *db = xi->db;

    if (t == T_HISTORY) xi->history++;
    if (xi->history) return KDBX_OK;

    if (t == T_GROUP && (parent == T_ROOT || parent == T_GROUP)) {
        kdbx_group *g = arena_alloc(&db->a, sizeof *g);
        if (!g) return KDBX_ERR_NOMEM;
        g->name = "";
        g->parent = xi->group;
        *(db->groups ? &db->groups_tail->next : &db->groups) = g;
        db->groups_tail = xi->group = g;
    } else if (t == T_ENTRY && parent == T_GROUP) {
        kdbx_entry *e = arena_alloc(&db->a, sizeof *e);
        if (!e) return KDBX_ERR_NOMEM;
        e->group = xi->group;
        e->title = e->username = e->url = e->tags = "";
        xi->entry = e;
        xi->fields_tail = NULL;
    } else if (t == T_STRING && parent == T_ENTRY && xi->entry) {
        if (!(xi->field = arena_alloc(&db->a, sizeof *xi->field))) return KDBX_ERR_NOMEM;
        xi->field->key = "";
        xi->field->value = (const uint8_t *)"";
        xi->field->stream_off = KDBX_PLAIN;
    }
    return KDBX_OK;
}

static kdbx_err elem_end(xml_index *xi)
{
    int t = xi->tags[xi->depth], parent = xi->tags[xi->depth - 1];
    int grand = xi->depth >= 2 ? xi->tags[xi->depth - 2] : T_OTHER;
    kdbx_db *db = xi->db;
    kdbx_entry *e = xi->entry;
    kdbx_field *f = xi->field;
    kdbx_err err = KDBX_OK;
    bool prot = xi->protected_attr;
    xi->protected_attr = false; /* must not leak to the parent's end tag */
    xi->depth--;

    if (prot) {
        /* Every protected value consumes keystream, in document order. */
        size_t n;
        int r = mbedtls_base64_decode(NULL, 0, &n, xi->text.p, xi->text.len);
        if (r && r != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) return KDBX_ERR_FORMAT;
        if (!xi->history && t == T_VALUE && parent == T_STRING && f) {
            uint8_t *c = arena_alloc(&db->a, n + 1);
            if (!c) return KDBX_ERR_NOMEM;
            if (n && b64(xi, c, n) < 0) return KDBX_ERR_FORMAT;
            f->value = c;
            f->len = (uint32_t)n;
            f->stream_off = xi->stream_pos;
        }
        if (xi->stream_pos + n < xi->stream_pos) return KDBX_ERR_FORMAT;
        xi->stream_pos += (uint32_t)n;
        tbuf_clear(&xi->text);
        return KDBX_OK;
    }

    if (t == T_HISTORY) { xi->history--; goto out; }
    if (xi->history) goto out;

    if (parent == T_META && t == T_RB_ENABLED) {
        db->recycle_enabled = xi->text.len == 4 && !memcmp(xi->text.p, "True", 4);
    } else if (parent == T_META && t == T_RB_UUID) {
        if (b64(xi, db->recycle_uuid, 16) < 0) memset(db->recycle_uuid, 0, 16);
    } else if (parent == T_GROUP && xi->group && (t == T_NAME || t == T_UUID)) {
        if (t == T_NAME) {
            if (!(xi->group->name = text_dup(xi))) err = KDBX_ERR_NOMEM;
        } else if (b64(xi, xi->group->uuid, 16) < 0) err = KDBX_ERR_FORMAT;
    } else if (t == T_GROUP && xi->group && (parent == T_ROOT || parent == T_GROUP)) {
        xi->group = xi->group->parent;
    } else if (e && parent == T_ENTRY) {
        if (t == T_UUID) {
            if (b64(xi, e->uuid, 16) < 0) err = KDBX_ERR_FORMAT;
        } else if (t == T_TAGS) {
            if (!(e->tags = text_dup(xi))) err = KDBX_ERR_NOMEM;
        } else if (t == T_STRING && f) {
            *(xi->fields_tail ? &xi->fields_tail->next : &e->fields) = f;
            xi->fields_tail = f;
            xi->field = NULL;
            if (f->stream_off == KDBX_PLAIN) {
                const char *v = (const char *)f->value;
                if (!strcmp(f->key, "Title")) e->title = v;
                else if (!strcmp(f->key, "UserName")) e->username = v;
                else if (!strcmp(f->key, "URL")) e->url = v;
            }
        }
    } else if (t == T_ENTRY && e && parent == T_GROUP) {
        *(db->entries ? &db->entries_tail->next : &db->entries) = e;
        db->entries_tail = e;
        xi->entry = NULL;
    } else if (f && parent == T_STRING && (t == T_KEY || t == T_VALUE)) {
        const char *s = text_dup(xi);
        if (!s) err = KDBX_ERR_NOMEM;
        else if (t == T_KEY) f->key = s;
        else { f->value = (const uint8_t *)s; f->len = (uint32_t)xi->text.len; }
    } else if (e && parent == T_TIMES && grand == T_ENTRY) {
        if (t == T_EXPIRES) {
            e->expires = xi->text.len == 4 && !memcmp(xi->text.p, "True", 4);
        } else if (t == T_EXPIRY) {
            uint8_t b[8];
            if (b64(xi, b, 8) == 8) {
                int64_t v = 0;
                for (int i = 7; i >= 0; i--) v = v << 8 | b[i];
                e->expiry = v - TICKS_TO_UNIX;
            }
        }
    }
out:
    tbuf_clear(&xi->text);
    return err;
}

kdbx_err xml_index_feed(xml_index *xi, const uint8_t *d, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        kdbx_err err = KDBX_OK;
        switch (yxml_parse(&xi->x, d[i])) {
        case YXML_OK: break;
        case YXML_ELEMSTART: err = elem_start(xi); break;
        case YXML_ELEMEND:
            err = elem_end(xi);
            if (xi->depth == 0) xi->done = true;
            break;
        case YXML_CONTENT:
            if (!tbuf_put(&xi->text, xi->x.data, strlen(xi->x.data))) err = KDBX_ERR_NOMEM;
            break;
        case YXML_ATTRSTART: tbuf_clear(&xi->attr); break;
        case YXML_ATTRVAL:
            if (!tbuf_put(&xi->attr, xi->x.data, strlen(xi->x.data))) err = KDBX_ERR_NOMEM;
            break;
        case YXML_ATTREND:
            if (!strcmp(xi->x.attr, "Protected") && xi->attr.len == 4 && !memcmp(xi->attr.p, "True", 4))
                xi->protected_attr = true;
            break;
        case YXML_PISTART: case YXML_PICONTENT: case YXML_PIEND: break;
        default: err = KDBX_ERR_FORMAT;
        }
        if (err) return err;
    }
    return KDBX_OK;
}

kdbx_err xml_index_finish(xml_index *xi)
{
    return xi->done && yxml_eof(&xi->x) == YXML_OK ? KDBX_OK : KDBX_ERR_CORRUPT;
}
