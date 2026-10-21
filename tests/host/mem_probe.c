/* RAM budget: peak heap during unlock / save / attachment read, and index size,
 * with a 32-bit estimate for the ESP32-S3 (struct sizes from xtensa-esp32s3-elf-gcc).
 * Linked with -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free.
 *   mem_probe <testdata dir> <work dir> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kdbx_priv.h"

/* ---- counting allocator ---- */
void *__real_malloc(size_t n);
void *__real_calloc(size_t a, size_t b);
void *__real_realloc(void *p, size_t n);
void __real_free(void *p);
static size_t cur, peak, biggest, big_calls[16], nbig;
#define HDR 16

void *__wrap_malloc(size_t n)
{
    unsigned char *p = __real_malloc(n + HDR);
    if (!p) return NULL;
    memcpy(p, &n, sizeof n);
    if ((cur += n) > peak) peak = cur;
    if (n > biggest) biggest = n;
    if (n >= 3000 && nbig < 16) big_calls[nbig++] = n;
    return p + HDR;
}
void *__wrap_calloc(size_t a, size_t b)
{
    void *p = __wrap_malloc(a * b);
    if (p) memset(p, 0, a * b);
    return p;
}
void __wrap_free(void *q)
{
    if (!q) return;
    unsigned char *p = (unsigned char *)q - HDR;
    size_t n;
    memcpy(&n, p, sizeof n);
    cur -= n;
    __real_free(p);
}
void *__wrap_realloc(void *q, size_t n)
{
    void *p = __wrap_malloc(n);
    if (p && q) {
        size_t old;
        memcpy(&old, (unsigned char *)q - HDR, sizeof old);
        memcpy(p, q, old < n ? old : n);
        __wrap_free(q);
    }
    return p;
}

/* ESP32-S3 sizes (xtensa-esp32s3-elf-gcc) */
enum { ESP_ENTRY = 80, ESP_GROUP = 32, ESP_FIELD = 16, ESP_ATT = 16 };

static size_t arena_total(const kdbx_db *db)
{
    size_t n = 0;
    for (const arena_chunk *c = db->a.head; c; c = c->next) n += sizeof *c + c->cap;
    return n;
}

static void probe(const char *dir, const char *work, const char *name)
{
    char path[512], dst[512];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    snprintf(dst, sizeof dst, "%s/mem_%s", work, name);
    FILE *a = fopen(path, "rb"), *b = fopen(dst, "wb");
    int c;
    while ((c = fgetc(a)) != EOF) fputc(c, b);
    fclose(a);
    fclose(b);

    kdbx_key k;
    kdbx_key_init(&k, "test", 4, NULL);
    FILE *f = fopen(dst, "rb");
    kdbx_db *db;
    size_t base = cur;
    peak = cur;
    kdbx_err e = kdbx_open(f, &k, &db);
    fclose(f);
    if (e) { printf("%s: %s\n", name, kdbx_strerror(e)); return; }
    size_t open_peak = peak - base, resident = cur - base;

    /* index contents: host struct bytes -> ESP32 struct bytes */
    size_t ne = 0, ng = 0, nf = 0, na = 0, used = 0;
    for (const kdbx_entry *x = kdbx_entries(db); x; x = x->next, ne++) {
        nf += x->nfields;
        for (const kdbx_attachment *z = x->attachments; z; z = z->next) na++;
    }
    for (const kdbx_group *g = kdbx_groups(db); g; g = g->next) ng++;
    for (const arena_chunk *ch = db->a.head; ch; ch = ch->next) used += ch->used;
    size_t host_structs = ne * ((sizeof(kdbx_entry) + 7) & ~7u) + ng * ((sizeof(kdbx_group) + 7) & ~7u) +
                          nf * sizeof(kdbx_field) + na * ((sizeof(kdbx_attachment) + 7) & ~7u);
    size_t esp_structs = ne * ESP_ENTRY + ng * ESP_GROUP + nf * ESP_FIELD + na * ESP_ATT;
    size_t esp_used = used - host_structs + esp_structs;

    peak = cur;
    size_t before = cur;
    biggest = 0;
    nbig = 0;
    e = kdbx_save(&db, dst, NULL, 0, 1790000000, NULL, 0);
    size_t save_peak = peak - before;
    printf("  save: largest single allocation %zu B; allocations >= 3000 B:", biggest);
    for (size_t i = 0; i < nbig; i++) printf(" %zu", big_calls[i]);
    printf("\n");
    if (e) { printf("%s: save %s\n", name, kdbx_strerror(e)); return; }

    {   /* an update of an existing entry (all fields carried over + one more) against a new entry */
        const kdbx_entry *x = kdbx_entries(db);
        static char vals[40][2048];
        kdbx_edit_field f[41];
        size_t nfl = 0;
        for (size_t i = 0; x && i < x->nfields && nfl < 40; i++) {
            if (kdbx_reveal(db, &x->fields[i], vals[nfl], sizeof vals[nfl])) continue;
            f[nfl] = (kdbx_edit_field){strdup(x->fields[i].key), vals[nfl], x->fields[i].stream_off != KDBX_PLAIN};
            nfl++;
        }
        f[nfl++] = (kdbx_edit_field){"KPEX_PASSKEY_USERNAME", "zoe", false};
        kdbx_edit up = {.op = KDBX_EDIT_ENTRY, .fields = f, .nfields = nfl};
        if (x) memcpy(up.uuid, x->uuid, 16);
        peak = cur;
        before = cur;
        biggest = 0;
        e = kdbx_save(&db, dst, &up, 1, 1790000001, NULL, 0);
        printf("  update of an entry: %s, peak +%zu B, largest single allocation %zu B\n", e ? kdbx_strerror(e) : "ok", peak - before, biggest);
        kdbx_edit_field nf[1] = {{"Title", "n", false}};
        kdbx_edit cr = {.op = KDBX_EDIT_ENTRY, .create = true, .fields = nf, .nfields = 1};
        kdbx_new_uuid(cr.uuid);
        if (db) memcpy(cr.parent, kdbx_root_group(db)->uuid, 16);
        peak = cur;
        before = cur;
        biggest = 0;
        e = db ? kdbx_save(&db, dst, &cr, 1, 1790000002, NULL, 0) : KDBX_ERR_EDIT;
        printf("  new entry:          %s, peak +%zu B, largest single allocation %zu B\n", e ? kdbx_strerror(e) : "ok", peak - before, biggest);
        if (!db) return;
    }

    size_t att_peak = 0;
    for (const kdbx_entry *x = kdbx_entries(db); x && !att_peak; x = x->next)
        if (x->attachments) {
            static uint8_t buf[65536];
            size_t got;
            peak = cur;
            before = cur;
            kdbx_attachment_read(db, dst, x->attachments, buf, sizeof buf, &got);
            att_peak = peak - before + sizeof buf;
        }

    printf("%-14s %4zu entries %4zu fields | index %7zu B used (ESP32 ~%7zu), arena %7zu B | "
           "unlock peak %7zu B | save peak +%7zu B | attachment view +%zu B\n",
           name, ne, nf, used, esp_used, arena_total(db), open_peak, save_peak, att_peak);
    (void)resident;
    kdbx_close(db);
    kdbx_key_wipe(&k);
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : "testdata", *work = argc > 2 ? argv[2] : ".";
    printf("host sizeof: entry %zu group %zu field %zu attachment %zu (ESP32-S3: 80 32 16 16)\n",
           sizeof(kdbx_entry), sizeof(kdbx_group), sizeof(kdbx_field), sizeof(kdbx_attachment));
    probe(dir, work, "aes_kpxc.kdbx");
    probe(dir, work, "big1000.kdbx");
    probe(dir, work, "multiblock.kdbx");
    return 0;
}
