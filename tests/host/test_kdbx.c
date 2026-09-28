/* Stage 0 acceptance test: every case in testdata/manifest.txt opens (or fails)
 * as expected, and intermediates + entries match tools/ref_dump.py output.
 *   test_kdbx <testdata dir> */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "kdbx_priv.h"

static int failures;
#define CHECK(c, ...) do { if (!(c)) { failures++; printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static char dir[512];

static FILE *open_in(const char *name, const char *mode)
{
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    return fopen(path, mode);
}

static size_t unhex(const char *s, uint8_t *out)
{
    size_t n = 0;
    for (; isxdigit((unsigned char)s[0]) && isxdigit((unsigned char)s[1]); s += 2) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (uint8_t)v;
    }
    return n;
}

static void hexs(const uint8_t *b, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]);
}

static const kdbx_entry *find_entry(const kdbx_db *db, const uint8_t uuid[16])
{
    for (const kdbx_entry *e = kdbx_entries(db); e; e = e->next)
        if (!memcmp(e->uuid, uuid, 16)) return e;
    return NULL;
}

/* Group path as pykeepass prints it: names below the root group, joined by '/'. */
static void group_path(const kdbx_group *g, char *out)
{
    const kdbx_group *chain[64];
    int n = 0;
    for (; g && g->parent && n < 64; g = g->parent) chain[n++] = g;
    out[0] = 0;
    while (n--) {
        strcat(out, chain[n]->name);
        if (n) strcat(out, "/");
    }
}

static void check_expected(const char *name, const kdbx_key *key, const kdbx_db *db)
{
    static char line[1 << 17];
    static uint8_t want[1 << 16], got[1 << 16];
    char fname[300];
    snprintf(fname, sizeof fname, "%s.expected", name);
    FILE *f = open_in(fname, "r");
    CHECK(f, "missing %s", fname);
    if (!f) return;

    /* intermediates */
    kdbx_header h;
    uint8_t tk[32], buf[65], master[32], hmac_base[64];
    FILE *db_f = open_in(name, "rb");
    CHECK(kdbx_read_header(db_f, &h) == KDBX_OK, "header");
    fclose(db_f);
    kdbx_aes_kdf(h.kdf_seed, h.rounds, key->composite, tk);
    memcpy(buf, h.master_seed, 32);
    memcpy(buf + 32, tk, 32);
    buf[64] = 1;
    mbedtls_sha256(buf, 64, master, 0);
    mbedtls_sha512(buf, 65, hmac_base, 0);

    int entries = 0, fields = 0;
    while (fgets(line, sizeof line, f)) {
        char kind[16], a[128];
        uint8_t uuid[16];
        sscanf(line, "%15s %127s", kind, a);
        const char *rest = strchr(strchr(line, '\t') + 1, '\t');
        rest = rest ? rest + 1 : "";
        if (!strcmp(kind, "key")) {
            size_t n = unhex(rest, want);
            const uint8_t *v = !strcmp(a, "composite") ? key->composite : !strcmp(a, "transformed") ? tk
                             : !strcmp(a, "master") ? master : !strcmp(a, "hmac_base") ? hmac_base : NULL;
            if (v) CHECK(!memcmp(v, want, n), "%s: %s mismatch", name, a);
            continue;
        }
        unhex(a, uuid);
        const kdbx_entry *e = find_entry(db, uuid);
        CHECK(e, "%s: entry %s missing", name, a);
        if (!e) continue;
        if (!strcmp(kind, "entry")) {
            entries++;
            char path[1024], wpath[1024];
            size_t n = unhex(rest, (uint8_t *)wpath);
            wpath[n] = 0;
            group_path(e->group, path);
            CHECK(!strcmp(path, wpath), "%s: group '%s' != '%s'", name, path, wpath);
        } else if (!strcmp(kind, "field")) {
            fields++;
            char k[256];
            size_t kl = unhex(rest, (uint8_t *)k);
            k[kl] = 0;
            rest = strchr(rest, '\t') + 1;
            char prot = rest[0];
            size_t n = unhex(rest + 2, want);
            want[n] = 0;
            const kdbx_field *fl = kdbx_field_get(e, k);
            CHECK(fl, "%s: field %s missing", name, k);
            if (!fl) continue;
            CHECK((fl->stream_off != KDBX_PLAIN) == (prot == 'P'), "%s: field %s protection", name, k);
            CHECK(kdbx_reveal(db, fl, (char *)got, sizeof got) == KDBX_OK, "reveal");
            CHECK(!strcmp((char *)got, (char *)want), "%s: field %s = '%s', want '%s'", name, k, got, want);
            if (!strcmp(k, "Title") && prot == 'U') CHECK(!strcmp(e->title, (char *)want), "title ptr");
            if (!strcmp(k, "UserName") && prot == 'U') CHECK(!strcmp(e->username, (char *)want), "username ptr");
        } else if (!strcmp(kind, "tags")) {
            size_t n = unhex(rest, want);
            want[n] = 0;
            char t[1024];
            snprintf(t, sizeof t, "%s", e->tags);
            for (char *c = t; *c; c++) if (*c == ',') *c = ';';
            CHECK(!strcmp(t, (char *)want), "%s: tags '%s' != '%s'", name, t, want);
        } else if (!strcmp(kind, "expiry")) {
            CHECK(e->expires && e->expiry == atoll(rest), "%s: expiry %lld", name, (long long)e->expiry);
        }
    }
    fclose(f);

    int n_entries = 0, n_fields = 0;
    for (const kdbx_entry *e = kdbx_entries(db); e; e = e->next, n_entries++)
        for (const kdbx_field *fl = e->fields; fl; fl = fl->next) n_fields++;
    CHECK(n_entries == entries, "%s: %d entries, want %d", name, n_entries, entries);
    CHECK(n_fields == fields, "%s: %d fields, want %d", name, n_fields, fields);
}

static kdbx_err expect_code(const char *s)
{
    if (!strcmp(s, "ok")) return KDBX_OK;
    if (!strcmp(s, "bad_key")) return KDBX_ERR_KEY;
    if (!strcmp(s, "argon2")) return KDBX_ERR_KDF;
    if (!strcmp(s, "version")) return KDBX_ERR_VERSION;
    return -1;
}

static kdbx_err open_with(const char *name, const kdbx_key *key, kdbx_db **db)
{
    FILE *f = open_in(name, "rb");
    if (!f) return KDBX_ERR_IO;
    kdbx_err e = kdbx_open(f, key, db);
    fclose(f);
    return e;
}

/* Flip one byte at `off` in a copy of `name`; opening must fail with `want`. */
static void tamper(const char *name, long off, kdbx_err want)
{
    static uint8_t data[1 << 16];
    FILE *f = open_in(name, "rb");
    size_t n = fread(data, 1, sizeof data, f);
    fclose(f);
    if (off < 0) off += (long)n;
    data[off] ^= 0x01;
    f = open_in("tampered.tmp", "wb");
    fwrite(data, 1, n, f);
    fclose(f);

    kdbx_key key;
    kdbx_db *db;
    kdbx_key_init(&key, "test", 4, NULL);
    kdbx_err e = open_with("tampered.tmp", &key, &db);
    CHECK(e == want, "tamper %s@%ld: got '%s', want '%s'", name, off, kdbx_strerror(e), kdbx_strerror(want));
    CHECK(!db, "db returned on failure");
    kdbx_close(db);
    kdbx_key_wipe(&key);
    char path[1024];
    snprintf(path, sizeof path, "%s/tampered.tmp", dir);
    remove(path);
}

int main(int argc, char **argv)
{
    snprintf(dir, sizeof dir, "%s", argc > 1 ? argv[1] : "testdata");
    FILE *m = open_in("manifest.txt", "r");
    if (!m) { printf("no manifest in %s\n", dir); return 1; }

    char line[1024];
    int cases = 0;
    while (fgets(line, sizeof line, m)) {
        char name[256], pwhex[256], kf[256], expect[32];
        if (sscanf(line, "%255s %255s %255s %31s", name, pwhex, kf, expect) != 4) continue;
        cases++;
        char pw[128];
        size_t pwlen = strcmp(pwhex, "-") ? unhex(pwhex, (uint8_t *)pw) : 0;
        FILE *kff = strcmp(kf, "-") ? open_in(kf, "rb") : NULL;

        kdbx_key key;
        kdbx_err e = kdbx_key_init(&key, strcmp(pwhex, "-") ? pw : NULL, pwlen, kff);
        if (kff) fclose(kff);
        CHECK(e == KDBX_OK, "%s: key init: %s", name, kdbx_strerror(e));

        kdbx_db *db;
        e = open_with(name, &key, &db);
        printf("%-20s %-8s -> %s\n", name, expect, kdbx_strerror(e));
        CHECK(e == expect_code(expect), "%s: got '%s'", name, kdbx_strerror(e));
        if (e == KDBX_OK) check_expected(name, &key, db);
        kdbx_close(db);
        kdbx_key_wipe(&key);
    }
    fclose(m);

    /* Damage detection */
    tamper("aes.kdbx", 60, KDBX_ERR_CORRUPT);    /* master seed -> header SHA-256 mismatch */
    tamper("aes.kdbx", -40, KDBX_ERR_CORRUPT);   /* payload -> block HMAC mismatch */
    tamper("chacha.kdbx", -40, KDBX_ERR_CORRUPT);

    /* Bad XML v2 key file hash */
    {
        const char *bad = "<?xml version=\"1.0\"?><KeyFile><Meta><Version>2.0</Version></Meta><Key>"
                          "<Data Hash=\"00000000\">000102030405060708090A0B0C0D0E0F"
                          "101112131415161718191A1B1C1D1E1F</Data></Key></KeyFile>";
        FILE *f = open_in("badkey.tmp", "wb");
        fputs(bad, f);
        fclose(f);
        f = open_in("badkey.tmp", "rb");
        kdbx_key key;
        CHECK(kdbx_key_init(&key, NULL, 0, f) == KDBX_ERR_KEYFILE, "bad key file hash accepted");
        fclose(f);
        char path[1024];
        snprintf(path, sizeof path, "%s/badkey.tmp", dir);
        remove(path);
    }

    printf("%d cases, %d failures\n", cases, failures);
    return failures ? 1 : 0;
}
