/* Stage 5: streaming save. No-op round trips must keep every entry/field; each
 * edit type is applied and checked through our own reader. tools/check_saved.py
 * then checks the output files with pykeepass + keepassxc-cli.
 *   test_save <testdata dir> <work dir> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kdbx_priv.h"
#include "mbedtls/platform_util.h"
#ifdef _WIN32
#include <direct.h>
#define MKDIR(d) _mkdir(d)
#else
#include <sys/stat.h>
#define MKDIR(d) mkdir(d, 0755)
#endif

static int failures;
#define CHECK(c, ...) do { if (!(c)) { failures++; printf("  FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static const char *tdir, *wdir;
static const int64_t NOW = 1790000000;

static void path_in(char *out, const char *dir, const char *name) { sprintf(out, "%s/%s", dir, name); }

static bool copy_file(const char *src, const char *dst)
{
    FILE *a = fopen(src, "rb"), *b = fopen(dst, "wb");
    char buf[8192];
    size_t n;
    bool ok = a && b;
    while (ok && (n = fread(buf, 1, sizeof buf, a)) > 0) ok = fwrite(buf, 1, n, b) == n;
    if (a) fclose(a);
    if (b) fclose(b);
    return ok;
}

static long file_size(const char *p)
{
    FILE *f = fopen(p, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fclose(f);
    return n;
}

static bool same_bytes(const char *a, const char *b)
{
    FILE *x = fopen(a, "rb"), *y = fopen(b, "rb");
    bool same = x && y;
    int c1, c2;
    while (same && ((c1 = fgetc(x)) != EOF || (c2 = fgetc(y)) != EOF)) same = c1 == fgetc(y);
    if (x) fclose(x);
    if (y) fclose(y);
    return same && (c2 = 0, 1);
}

static kdbx_err open_key(const char *path, const char *pw, const char *keyfile, kdbx_db **db)
{
    kdbx_key k;
    FILE *kf = keyfile ? fopen(keyfile, "rb") : NULL;
    kdbx_err e = kdbx_key_init(&k, pw, pw ? strlen(pw) : 0, kf);
    if (kf) fclose(kf);
    FILE *f = fopen(path, "rb");
    *db = NULL;
    if (!e) e = f ? kdbx_open(f, &k, db) : KDBX_ERR_IO;
    if (f) fclose(f);
    kdbx_key_wipe(&k);
    return e;
}

static const kdbx_entry *by_title(const kdbx_db *db, const char *t)
{
    for (const kdbx_entry *e = kdbx_entries(db); e; e = e->next)
        if (!strcmp(e->title, t)) return e;
    return NULL;
}

static const kdbx_group *by_name(const kdbx_db *db, const char *n)
{
    for (const kdbx_group *g = kdbx_groups(db); g; g = g->next)
        if (!strcmp(g->name, n)) return g;
    return NULL;
}

static bool field_is(const kdbx_db *db, const kdbx_entry *e, const char *key, const char *want, int prot)
{
    static char buf[1 << 16];
    const kdbx_field *f = e ? kdbx_field_get(e, key) : NULL;
    if (!f || kdbx_reveal(db, f, buf, sizeof buf)) return false;
    bool ok = !strcmp(buf, want) && (prot < 0 || (f->stream_off != KDBX_PLAIN) == prot);
    mbedtls_platform_zeroize(buf, sizeof buf);
    return ok;
}

/* Same entries, groups, fields (plaintext + protection), tags, expiry. */
static bool same_index(const kdbx_db *a, const kdbx_db *b)
{
    static char va[1 << 16], vb[1 << 16];
    int na = 0, nb = 0;
    for (const kdbx_entry *e = kdbx_entries(b); e; e = e->next) nb++;
    for (const kdbx_group *g = kdbx_groups(b); g; g = g->next) nb += 1000000;
    for (const kdbx_group *g = kdbx_groups(a); g; g = g->next) {
        na += 1000000;
        const kdbx_group *h = kdbx_groups(b);
        while (h && memcmp(h->uuid, g->uuid, 16)) h = h->next;
        if (!h || strcmp(h->name, g->name)) return false;
    }
    for (const kdbx_entry *e = kdbx_entries(a); e; e = e->next, na++) {
        const kdbx_entry *f = kdbx_entries(b);
        while (f && memcmp(f->uuid, e->uuid, 16)) f = f->next;
        if (!f || strcmp(e->tags, f->tags) || e->expires != f->expires || (e->expires && e->expiry != f->expiry) ||
            memcmp(e->group->uuid, f->group->uuid, 16))
            return false;
        int fa = 0, fb = 0;
        for (const kdbx_field *x = f->fields; x; x = x->next) fb++;
        for (const kdbx_field *x = e->fields; x; x = x->next, fa++) {
            const kdbx_field *y = kdbx_field_get(f, x->key);
            if (!y || (x->stream_off == KDBX_PLAIN) != (y->stream_off == KDBX_PLAIN)) return false;
            kdbx_reveal(a, x, va, sizeof va);
            kdbx_reveal(b, y, vb, sizeof vb);
            if (strcmp(va, vb)) return false;
        }
        if (fa != fb) return false;
    }
    return na == nb;
}

static kdbx_err save(kdbx_db **db, const char *path, const kdbx_edit *ed, size_t n)
{
    kdbx_db *nd;
    kdbx_err e = kdbx_save(*db, path, ed, n, NOW, NULL, 0, &nd);
    if (!e) {
        kdbx_close(*db);
        *db = nd;
    }
    return e;
}

static void noop(const char *name, const char *pw, const char *keyfile)
{
    char src[512], dst[512], out[512], kf[512];
    path_in(src, tdir, name);
    snprintf(out, sizeof out, "noop_%s", name);
    path_in(dst, wdir, out);
    if (keyfile) path_in(kf, tdir, keyfile);
    CHECK(copy_file(src, dst), "copy %s", name);
    kdbx_db *orig, *saved, *reread;
    CHECK(open_key(dst, pw, keyfile ? kf : NULL, &orig) == KDBX_OK, "open %s", name);
    if (!orig) return;
    kdbx_err e = kdbx_save(orig, dst, NULL, 0, NOW, NULL, 0, &saved);
    CHECK(e == KDBX_OK, "noop save %s: %s", name, kdbx_strerror(e));
    if (!e) {
        CHECK(same_index(orig, saved), "%s: returned db differs", name);
        CHECK(open_key(dst, pw, keyfile ? kf : NULL, &reread) == KDBX_OK, "%s: reopen", name);
        if (reread) CHECK(same_index(orig, reread), "%s: reopened db differs", name);
        char bak[600];
        snprintf(bak, sizeof bak, "%s.bak", dst);
        CHECK(same_bytes(bak, src), "%s: .bak is not the original", name);
        kdbx_close(reread);
    }
    printf("noop %-20s %ld -> %ld bytes\n", name, file_size(src), file_size(dst));
    kdbx_close(orig);
    kdbx_close(saved);
}

int main(int argc, char **argv)
{
    tdir = argc > 1 ? argv[1] : "testdata";
    wdir = argc > 2 ? argv[2] : "save_work";
    MKDIR(wdir);
    char path[512], src[512], tmp[600];

    /* ---- 0. attachments: listed, readable as text, binary detected ---- */
    {
        static const char line[] = "Line 1 é à\nLine 2\tend\n";
        static uint8_t buf[1 << 16];
        char want[2048] = "";
        for (int i = 0; i < 40; i++) strcat(want, line);
        size_t got;
        path_in(path, tdir, "aes_kpxc.kdbx");
        kdbx_db *adb;
        CHECK(open_key(path, "test", NULL, &adb) == KDBX_OK, "open for attachments");
        const kdbx_entry *b = adb ? by_title(adb, "Bank") : NULL;
        const kdbx_attachment *bin = NULL, *txt = NULL;
        int count = 0;
        for (const kdbx_attachment *a = b ? b->attachments : NULL; a; a = a->next, count++) {
            if (!strcmp(a->name, "scan.bin")) bin = a;
            if (!strcmp(a->name, "notes.txt")) txt = a;
        }
        CHECK(bin && txt && count == 2, "names");
        CHECK(bin && txt && bin->size == 4096 && txt->size == strlen(want), "sizes");
        if (txt) {
            CHECK(kdbx_attachment_read(adb, path, txt, buf, sizeof buf, &got) == KDBX_OK && got == strlen(want) &&
                  !memcmp(buf, want, got) && kdbx_is_text(buf, got, false), "text attachment");
            CHECK(kdbx_attachment_read(adb, path, txt, buf, 8, &got) == KDBX_OK && got == 8 &&
                  kdbx_is_text(buf, got, true) && !kdbx_is_text(buf, got, false), "truncated mid-é");
            CHECK(kdbx_attachment_read(adb, path, bin, buf, sizeof buf, &got) == KDBX_OK && got == 4096 &&
                  !kdbx_is_text(buf, got, false), "binary attachment");
            path_in(src, tdir, "aes.kdbx"); /* different file: header HMAC with cached key fails */
            CHECK(kdbx_attachment_read(adb, src, txt, buf, sizeof buf, &got) == KDBX_ERR_KEY && !got, "wrong file");
        }
        kdbx_close(adb);
        path_in(path, tdir, "multiblock.kdbx");
        CHECK(open_key(path, "test", NULL, &adb) == KDBX_OK, "open multiblock");
        const kdbx_attachment *big = adb ? kdbx_entries(adb)->attachments : NULL;
        CHECK(big && big->size == 1500000 && kdbx_attachment_read(adb, path, big, buf, sizeof buf, &got) == KDBX_OK &&
              got == sizeof buf, "multiblock attachment");
        kdbx_close(adb);
        mbedtls_platform_zeroize(buf, sizeof buf);
    }

    /* ---- 1. no-op saves keep everything ---- */
    noop("aes.kdbx", "test", NULL);
    noop("chacha.kdbx", "test", NULL);
    noop("aes_kpxc.kdbx", "test", NULL);
    noop("chacha_kpxc.kdbx", "test", NULL);
    noop("utf8pw.kdbx", "pässwörd€", NULL);
    noop("keyfile_xml2.kdbx", "test", "key_xml2.keyx");
    noop("keyfile_only.kdbx", NULL, "key_xml2.keyx");
    noop("big1000.kdbx", "test", NULL);
    noop("multiblock.kdbx", "test", NULL);

    /* ---- 2. edits, one save per operation (like the device) ---- */
    path_in(src, tdir, "aes_kpxc.kdbx");
    path_in(path, wdir, "edit.kdbx");
    copy_file(src, path);
    kdbx_db *db;
    CHECK(open_key(path, "test", NULL, &db) == KDBX_OK, "open edit");
    if (!db) return 1;
    kdbx_err e;

    /* a. edit an entry (new password, new protected field, tags) */
    const kdbx_entry *g = by_title(db, "Gmail");
    kdbx_edit ed = {.op = KDBX_EDIT_ENTRY, .tags = "email"};
    memcpy(ed.uuid, g->uuid, 16);
    kdbx_edit_field fa[] = {
        {"Title", "Gmail", false}, {"UserName", "alice@gmail.com", false}, {"Password", "new-pw! <&>\"", true},
        {"URL", "https://mail.google.com", false}, {"Notes", "edited notes\nline 2 é", false},
        {"otp", "otpauth://totp/Google:alice?secret=JBSWY3DPEHPK3PXP&issuer=Google", true},
        {"Security Q", "s3cret", true},
    };
    ed.fields = fa;
    ed.nfields = sizeof fa / sizeof *fa;
    CHECK((e = save(&db, path, &ed, 1)) == KDBX_OK, "edit entry: %s", kdbx_strerror(e));
    g = by_title(db, "Gmail");
    CHECK(field_is(db, g, "Password", "new-pw! <&>\"", 1), "new password");
    CHECK(field_is(db, g, "Security Q", "s3cret", 1), "new protected field");
    CHECK(field_is(db, g, "Notes", "edited notes\nline 2 é", 0), "notes");
    CHECK(g && !kdbx_field_get(g, "PIN"), "removed field still there");
    CHECK(g && !strcmp(g->tags, "email") && !g->expires, "tags/expiry");

    /* b. new entry */
    kdbx_edit ne = {.op = KDBX_EDIT_ENTRY, .create = true, .tags = "favorite", .expires = true, .expiry = 1900000000};
    kdbx_new_uuid(ne.uuid);
    memcpy(ne.parent, by_name(db, "Email")->uuid, 16);
    kdbx_edit_field fb[] = {{"Title", "Proton", false}, {"UserName", "bob", false}, {"Password", "pr0ton", true},
                            {"URL", "", false}, {"Notes", "", false}};
    ne.fields = fb;
    ne.nfields = 5;
    CHECK((e = save(&db, path, &ne, 1)) == KDBX_OK, "new entry: %s", kdbx_strerror(e));
    const kdbx_entry *p = by_title(db, "Proton");
    CHECK(p && field_is(db, p, "Password", "pr0ton", 1) && !strcmp(p->group->name, "Email") && p->expires &&
          p->expiry == 1900000000, "new entry content");

    /* c. delete -> recycle bin (created), delete again -> permanent */
    CHECK(db->recycle_enabled, "aes_kpxc has the recycle bin enabled");
    kdbx_edit del[2];
    size_t nd = kdbx_delete_entry(db, by_title(db, "Visa"), del);
    CHECK(nd == 2 && del[0].op == KDBX_EDIT_GROUP && del[1].op == KDBX_EDIT_ENTRY_MOVE, "delete -> create bin + move");
    CHECK((e = save(&db, path, del, nd)) == KDBX_OK, "recycle: %s", kdbx_strerror(e));
    const kdbx_entry *v = by_title(db, "Visa");
    CHECK(v && !strcmp(v->group->name, "Recycle Bin") && !memcmp(v->group->uuid, db->recycle_uuid, 16), "in bin");
    nd = kdbx_delete_entry(db, v, del);
    CHECK(nd == 1 && del[0].op == KDBX_EDIT_ENTRY_DELETE, "second delete is permanent");
    CHECK((e = save(&db, path, del, nd)) == KDBX_OK, "permanent delete: %s", kdbx_strerror(e));
    CHECK(!by_title(db, "Visa"), "Visa gone");

    /* d. groups: create, rename, move group, move entry into it, delete group */
    kdbx_edit gc = {.op = KDBX_EDIT_GROUP, .create = true, .name = "Work"};
    kdbx_new_uuid(gc.uuid);
    memcpy(gc.parent, kdbx_root_group(db)->uuid, 16);
    CHECK((e = save(&db, path, &gc, 1)) == KDBX_OK, "create group: %s", kdbx_strerror(e));
    kdbx_edit gr = {.op = KDBX_EDIT_GROUP, .name = "Travail & Co"};
    memcpy(gr.uuid, gc.uuid, 16);
    CHECK((e = save(&db, path, &gr, 1)) == KDBX_OK, "rename group: %s", kdbx_strerror(e));
    CHECK(by_name(db, "Travail & Co") && !by_name(db, "Work"), "renamed");

    kdbx_edit mv[2] = {{.op = KDBX_EDIT_GROUP_MOVE}, {.op = KDBX_EDIT_ENTRY_MOVE}};
    memcpy(mv[0].uuid, by_name(db, "Cards")->uuid, 16);   /* Banking/Cards -> Email/Cards */
    memcpy(mv[0].parent, by_name(db, "Email")->uuid, 16);
    memcpy(mv[1].uuid, by_title(db, "Bank")->uuid, 16);   /* Bank -> Travail & Co (later in document) */
    memcpy(mv[1].parent, gc.uuid, 16);
    CHECK((e = save(&db, path, mv, 2)) == KDBX_OK, "moves: %s", kdbx_strerror(e));
    CHECK(by_name(db, "Cards") && by_name(db, "Cards")->parent == by_name(db, "Email"), "group moved");
    CHECK(by_title(db, "Bank") && by_title(db, "Bank")->group == by_name(db, "Travail & Co"), "entry moved");
    CHECK(field_is(db, by_title(db, "Bank"), "Password", "B4nk!pw", 1), "moved entry keeps protected value");
    {
        const kdbx_entry *b = by_title(db, "Bank");
        const kdbx_attachment *t = b ? b->attachments : NULL;
        while (t && strcmp(t->name, "notes.txt")) t = t->next;
        uint8_t buf[16];
        size_t got;
        CHECK(t && !strcmp(t->name, "notes.txt") && kdbx_attachment_read(db, path, t, buf, 6, &got) == KDBX_OK &&
              got == 6 && !memcmp(buf, "Line 1", 6), "attachment readable after edits");
    }

    kdbx_edit bad = {.op = KDBX_EDIT_GROUP_MOVE};           /* into its own child: refused */
    memcpy(bad.uuid, by_name(db, "Email")->uuid, 16);
    memcpy(bad.parent, by_name(db, "Cards")->uuid, 16);
    CHECK(save(&db, path, &bad, 1) == KDBX_ERR_EDIT, "cycle move refused");

    nd = kdbx_delete_group(db, by_name(db, "Café & Bar"), del);
    CHECK((e = save(&db, path, del, nd)) == KDBX_OK, "delete group: %s", kdbx_strerror(e));
    const kdbx_group *cb = by_name(db, "Café & Bar");
    CHECK(cb && cb->parent && !strcmp(cb->parent->name, "Recycle Bin"), "group in bin");
    CHECK(field_is(db, by_title(db, "Café Crème"), "Password", "p€ss wörd ✓", 1), "entry inside moved group intact");
    nd = kdbx_delete_group(db, cb, del);
    CHECK(nd == 1 && (e = save(&db, path, del, nd)) == KDBX_OK, "permanent group delete: %s", kdbx_strerror(e));
    CHECK(!by_name(db, "Café & Bar") && !by_title(db, "Café Crème"), "group + entry gone");

    /* e. failure leaves the file untouched and no .tmp behind */
    copy_file(path, tmp);
    snprintf(tmp, sizeof tmp, "%s.before", path);
    copy_file(path, tmp);
    kdbx_edit ghost = {.op = KDBX_EDIT_ENTRY_DELETE};
    kdbx_new_uuid(ghost.uuid);
    CHECK(save(&db, path, &ghost, 1) == KDBX_ERR_EDIT, "missing target refused");
    CHECK(same_bytes(path, tmp), "file changed by a failed save");
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    CHECK(file_size(tmp) < 0, ".tmp left behind");

    /* f. change master key + rounds */
    kdbx_key nk;
    kdbx_key_init(&nk, "n3w pässword", strlen("n3w pässword"), NULL);
    kdbx_db *nd2;
    CHECK((e = kdbx_save(db, path, NULL, 0, NOW, &nk, 2000, &nd2)) == KDBX_OK, "rekey: %s", kdbx_strerror(e));
    kdbx_key_wipe(&nk);
    kdbx_close(db);
    db = nd2;
    kdbx_db *x;
    CHECK(open_key(path, "test", NULL, &x) == KDBX_ERR_KEY, "old password still works");
    CHECK(open_key(path, "n3w pässword", NULL, &x) == KDBX_OK, "new password fails");
    if (x) {
        kdbx_header h;
        FILE *f = fopen(path, "rb");
        kdbx_read_header(f, &h);
        fclose(f);
        CHECK(h.rounds == 2000, "rounds %llu", (unsigned long long)h.rounds);
        CHECK(same_index(db, x), "rekeyed content");
        kdbx_close(x);
    }

    /* g. crash between the two renames: kdbx_recover() restores the new file */
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    rename(path, tmp);
    kdbx_recover(path);
    CHECK(open_key(path, "n3w pässword", NULL, &x) == KDBX_OK, "recover");
    kdbx_close(x);
    kdbx_close(db);

    /* h. ChaCha20 + attachments across many blocks, with an edit */
    path_in(src, tdir, "multiblock.kdbx");
    path_in(path, wdir, "edit_multiblock.kdbx");
    copy_file(src, path);
    CHECK(open_key(path, "test", NULL, &db) == KDBX_OK, "open multiblock");
    if (db) {
        kdbx_edit_field fm[] = {{"Title", "Big attachment", false}, {"Password", "changed", true}};
        kdbx_edit em = {.op = KDBX_EDIT_ENTRY, .fields = fm, .nfields = 2};
        memcpy(em.uuid, kdbx_entries(db)->uuid, 16);
        CHECK((e = save(&db, path, &em, 1)) == KDBX_OK, "multiblock edit: %s", kdbx_strerror(e));
        CHECK(field_is(db, kdbx_entries(db), "Password", "changed", 1), "multiblock password");
        kdbx_close(db);
    }
    path_in(src, tdir, "chacha.kdbx");
    path_in(path, wdir, "edit_chacha.kdbx");
    copy_file(src, path);
    CHECK(open_key(path, "test", NULL, &db) == KDBX_OK, "open chacha");
    if (db) {
        nd = kdbx_delete_entry(db, by_title(db, "Root entry"), del);
        CHECK((e = save(&db, path, del, nd)) == KDBX_OK, "chacha delete: %s", kdbx_strerror(e));
        kdbx_close(db);
    }

    /* ---- 3. create databases (Stage 6) ---- */
    char kfp[512];
    path_in(kfp, wdir, "created.keyx");
    remove(kfp);
    FILE *kf = fopen(kfp, "wb");
    CHECK(kf && kdbx_keyfile_create(kf) == KDBX_OK, "keyfile create");
    if (kf) fclose(kf);
    const struct { const char *name; int cipher; const char *pw; bool keyfile; } cr[] = {
        {"created_aes.kdbx", KDBX_AES256, "créé", false},
        {"created_chacha_kf.kdbx", KDBX_CHACHA20, "test", true},
        {"created_kf_only.kdbx", KDBX_AES256, NULL, true},
    };
    for (size_t i = 0; i < sizeof cr / sizeof *cr; i++) {
        path_in(path, wdir, cr[i].name);
        remove(path);
        kdbx_key k;
        FILE *kff = cr[i].keyfile ? fopen(kfp, "rb") : NULL;
        CHECK(kdbx_key_init(&k, cr[i].pw, cr[i].pw ? strlen(cr[i].pw) : 0, kff) == KDBX_OK, "key");
        if (kff) fclose(kff);
        CHECK((e = kdbx_create(path, cr[i].cipher, 1500, &k, "My Vault", NOW, &db)) == KDBX_OK, "create %s: %s",
              cr[i].name, kdbx_strerror(e));
        kdbx_db *dup;
        CHECK(kdbx_create(path, cr[i].cipher, 1500, &k, "x", NOW, &dup) == KDBX_ERR_IO, "create overwrote a file");
        kdbx_key_wipe(&k);
        if (!db) continue;
        CHECK(!kdbx_entries(db) && kdbx_root_group(db) && !strcmp(kdbx_root_group(db)->name, "My Vault") &&
              db->recycle_enabled, "empty new db");
        kdbx_edit_field fc[] = {{"Title", "First", false}, {"UserName", "me", false}, {"Password", "pw1", true},
                                {"URL", "", false}, {"Notes", "", false}};
        kdbx_edit ce = {.op = KDBX_EDIT_ENTRY, .create = true, .fields = fc, .nfields = 5};
        kdbx_new_uuid(ce.uuid);
        memcpy(ce.parent, kdbx_root_group(db)->uuid, 16);
        CHECK((e = save(&db, path, &ce, 1)) == KDBX_OK, "add to created: %s", kdbx_strerror(e));
        CHECK(field_is(db, by_title(db, "First"), "Password", "pw1", 1), "created db entry");
        kdbx_close(db);
        CHECK(open_key(path, cr[i].pw, cr[i].keyfile ? kfp : NULL, &db) == KDBX_OK, "reopen created %s", cr[i].name);
        kdbx_close(db);
    }

    printf("save: %d failures\n", failures);
    return failures != 0;
}
