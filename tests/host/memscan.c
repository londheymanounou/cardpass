/* Secret-residue and leak test (Linux only: reads /proc/self/maps).
 *
 * Drives the real app through a full session on a database with unique secrets: unlock, reveal, type, QR code,
 * edit + save, change the master password, a wrong-password attempt, lock. Then it scans the process's own
 * writable memory (heap, freed heap, stack incl. dead stack, libc data, .bss) for every secret, in every form the
 * code could have left behind: master passwords, entry passwords, protected fields, TOTP secret, the composite
 * key, the AES-KDF chain value and the transformed key. After locking nothing may be found.
 * Positive control: the transformed key MUST be found while the database is unlocked (it is cached for saving),
 * otherwise the scanner itself is broken.
 * Last, a leak check: many unlock/lock cycles must not grow the heap.
 *
 * The secrets are never copied into this program's memory: typed from string literals (read-only memory,
 * not scanned), binary patterns come from a child process through a pipe, XOR-masked at once. */
#define _GNU_SOURCE
#ifndef __linux__
#error "memscan needs Linux (/proc/self/maps)"
#endif
#include <dirent.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../../components/ui/app_priv.h"
#include "kdbx_priv.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"

/* ---- the secrets (string literals: read-only memory) ---- */
static const char *const MP = "Mq7#unique-MASTER-pass-5519";      /* master password */
static const char *const NMP = "Nw2$unique-NEWMASTER-8864!";      /* after the change */
static const char *const WRONG = "Wr0ng-unique-attempt-4412";     /* a failed unlock */
static const char *const EP1 = "EntryPw-unique-1-71829";          /* entry password */
static const char *const EP2 = "EntryPw-unique-2-93057";          /* entry password after the edit */
static const char *const PIN1 = "PIN-unique-445566";              /* custom protected field */
static const char *const OTPS = "ZQXWVUTSRQPONMLK";               /* TOTP secret (base32) */
#define NOTE1 "Note-unique-text-3391"                             /* unprotected, but still must not linger */

#define MASK 0x5A
typedef struct { const char *name; const uint8_t *lit; uint8_t masked[32]; size_t len; } pat;
static pat pats[40];
static int npats;
static int failures;
#define CHECK(c, ...) do { if (!(c)) { failures++; printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } } while (0)

static void add_str(const char *name, const char *s) { pats[npats++] = (pat){name, (const uint8_t *)s, {0}, strlen(s)}; }

/* ---- platform ---- */
static app A;
static char wdir[256];
static uint16_t panel[UI_W * UI_H];
static int list_files(void *c, const char *ext, char names[][64], int max)
{
    (void)c;
    DIR *d = opendir(wdir);
    int n = 0;
    struct dirent *e;
    size_t el = strlen(ext);
    while (d && (e = readdir(d)) && n < max) {
        size_t l = strlen(e->d_name);
        if (l > el && l < 64 && !strcmp(e->d_name + l - el, ext)) snprintf(names[n++], 64, "%s", e->d_name);
    }
    if (d) closedir(d);
    return n;
}
static void path_fn(void *c, const char *name, char *out, size_t n) { (void)c; snprintf(out, n, "%s/%s", wdir, name); }
static int64_t now_fn(void *c, bool *valid) { (void)c; *valid = true; return 1790000000; }
static uint32_t ms;
static uint32_t millis_fn(void *c) { (void)c; return ms += 40; }
static int battery(void *c) { (void)c; return 80; }
static bool hid_ready(void *c) { (void)c; return true; }
static void stroke(void *c, uint8_t k, uint8_t m) { (void)c; (void)k; (void)m; }     /* typed text is discarded */
static void delay_fn(void *c, int d) { (void)c; (void)d; }
static void save_settings(void *c, const char *t) { (void)c; (void)t; }
static void present(void *c)
{
    (void)c;
    static uint16_t buf[UI_W * 16];
    int y0, y1;
    while (app_dirty(&A, &y0, &y1))
        for (int y = y0; y < y1; y += 16) {
            ui_strip s = {buf, y, y1 - y < 16 ? y1 - y : 16};
            app_draw(&A, &s);                                   /* the drawing code sees revealed secrets too */
            memcpy(panel + y * UI_W, buf, sizeof(uint16_t) * UI_W * (size_t)s.h);
        }
}
static void pump_fn(void *c) { (void)c; }
static bool usb_drive(void *c, bool e) { (void)c; (void)e; return true; }
static void backlight_fn(void *c, int s) { (void)c; (void)s; }
static void shutdown_fn(void *c) { (void)c; }
static void set_time_fn(void *c, int64_t t) { (void)c; (void)t; }
static int wifi_scan_fn(void *c, app_ap *o, int m) { (void)c; (void)o; (void)m; return 0; }
static int ntp_sync_fn(void *c, const char *a, const char *b, int64_t *t) { (void)c; (void)a; (void)b; (void)t; return NTP_ERR_CONNECT; }
static bool bt_start_fn(void *c) { (void)c; return false; }
static void bt_stop_fn(void *c) { (void)c; }
static int bt_state_fn(void *c, uint32_t *code) { (void)c; if (code) *code = 0; return BT_OFF; }
static void bt_answer_fn(void *c, bool ok) { (void)c; (void)ok; }
static void bt_forget_fn(void *c) { (void)c; }
static int list_dir_fn(void *c, const char *rel, app_dirent *out, int max) { (void)c; (void)rel; (void)out; (void)max; return 0; }
static void root_path_fn(void *c, const char *rel, char *out, size_t n) { (void)c; snprintf(out, n, rel[0] ? "%s/%s" : "%s%.0s", wdir, rel); }
static void start_dir_fn(void *c, char *out, size_t n) { (void)c; if (n) out[0] = 0; }
static const app_platform PLAT = {list_files, path_fn, now_fn, millis_fn, battery, hid_ready, stroke, delay_fn, save_settings, present,
                                  pump_fn, usb_drive, backlight_fn, shutdown_fn, set_time_fn, wifi_scan_fn, ntp_sync_fn, bt_start_fn,
                                  bt_stop_fn, bt_state_fn, bt_answer_fn, bt_forget_fn, list_dir_fn, root_path_fn, start_dir_fn, NULL, NULL, NULL};

static void key(uint32_t k) { app_key(&A, k, true); app_key(&A, k, false); present(NULL); }
static void feed(const char *s) { while (*s) key(ui_utf8_next(&s)); }
static void tick(void) { ms += 100; app_tick(&A, ms); present(NULL); }

/* ---- binary secrets come from a child process: composite key, KDF chain value, transformed key ---- */
static void derive(const char *pw, const char *path, uint8_t out[3][32])
{
    kdbx_key k;
    kdbx_key_init(&k, pw, strlen(pw), NULL);
    FILE *f = fopen(path, "rb");
    kdbx_header h;
    kdbx_read_header(f, &h);
    fclose(f);
    uint8_t b[32];
    memcpy(b, k.composite, 32);
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, h.kdf_seed, 256);
    for (uint64_t i = 0; i < h.rounds; i++) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, b, b);
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, b + 16, b + 16);
    }
    memcpy(out[0], k.composite, 32);
    memcpy(out[1], b, 32);
    mbedtls_sha256(b, 32, out[2], 0);
}

static void child_create(const char *path, int fd)
{
    kdbx_key k;
    kdbx_key_init(&k, MP, strlen(MP), NULL);
    kdbx_db *db;
    if (kdbx_create(path, KDBX_AES256, 3000, &k, "Vault", 1790000000, &db)) _exit(2);
    char otp[128];
    snprintf(otp, sizeof otp, "otpauth://totp/x?secret=%s&digits=6&period=30", OTPS);
    kdbx_edit_field fc[] = {{"Title", "Bank", false}, {"UserName", "alice", false}, {"Password", EP1, true},
                            {"URL", "https://bank.example", false}, {"Notes", NOTE1, false},
                            {"PIN", PIN1, true}, {"otp", otp, true}};
    kdbx_edit ce = {.op = KDBX_EDIT_ENTRY, .create = true, .fields = fc, .nfields = 7};
    kdbx_new_uuid(ce.uuid);
    memcpy(ce.parent, kdbx_root_group(db)->uuid, 16);
    if (kdbx_save(&db, path, &ce, 1, 1790000000, NULL, 0)) _exit(3);
    kdbx_close(db);
    uint8_t d[3][32];
    derive(MP, path, d);
    for (int i = 0; i < 3; i++) for (int j = 0; j < 32; j++) d[i][j] ^= MASK;
    if (write(fd, d, sizeof d) != (ssize_t)sizeof d) _exit(4);
    _exit(0);
}

static void child_derive(const char *pw, const char *path, int fd)
{
    uint8_t d[3][32];
    derive(pw, path, d);
    for (int i = 0; i < 3; i++) for (int j = 0; j < 32; j++) d[i][j] ^= MASK;
    if (write(fd, d, sizeof d) != (ssize_t)sizeof d) _exit(4);
    _exit(0);
}

/* any KDF (AES or Argon2) through the library: composite key, transformed key, and (Argon2) the tail of the final
 * memory block: Argon2's working memory is secret-equivalent (it gives the key without the password) */
extern void (*kdbx_argon2_test_fin)(const uint8_t blk[1024]);
static uint8_t fin_tail[32];
static void grab_fin(const uint8_t blk[1024]) { memcpy(fin_tail, blk + 1024 - 32, 32); }
static void child_kdf(const char *pw, const char *path, int fd)
{
    uint8_t d[3][32];
    kdbx_argon2_test_fin = grab_fin;
    kdbx_key k;
    kdbx_key_init(&k, pw, strlen(pw), NULL);
    FILE *f = fopen(path, "rb");
    kdbx_header h;
    kdbx_read_header(f, &h);
    fclose(f);
    memcpy(d[0], k.composite, 32);
    if (kdbx_kdf(&h, k.composite, d[1])) _exit(5);
    memcpy(d[2], fin_tail, 32);
    for (int i = 0; i < 3; i++) for (int j = 0; j < 32; j++) d[i][j] ^= MASK;
    if (write(fd, d, sizeof d) != (ssize_t)sizeof d) _exit(4);
    _exit(0);
}

static uint8_t pipe_buf[3][32];                        /* receives masked bytes only */
static bool run_child(int which, const char *pw, const char *path)
{
    int fds[2];
    if (pipe(fds)) return false;
    pid_t pid = fork();
    if (pid == 0) {
        close(fds[0]);
        if (which == 0) child_create(path, fds[1]);
        else if (which == 2) child_kdf(pw, path, fds[1]);
        else child_derive(pw, path, fds[1]);
        _exit(9);
    }
    close(fds[1]);
    ssize_t got = read(fds[0], pipe_buf, sizeof pipe_buf);
    close(fds[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    return got == (ssize_t)sizeof pipe_buf && WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

static void add_bin(const char *name, const uint8_t masked[32])
{
    pat *p = &pats[npats++];
    p->name = name;
    p->lit = NULL;
    memcpy(p->masked, masked, 32);
    p->len = 32;
}

/* ---- the scanner ---- */
static inline uint8_t pb(const pat *p, size_t i) { return p->lit ? p->lit[i] : (uint8_t)(p->masked[i] ^ MASK); }

typedef struct { int hits; char where[160]; } found;

static int scan(const pat *p, found *f)
{
    FILE *m = fopen("/proc/self/maps", "r");
    char line[512];
    int total = 0;
    f->where[0] = 0;
    while (m && fgets(line, sizeof line, m)) {
        unsigned long lo, hi;
        char perms[8], path[256] = "";
        if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %255[^\n]", &lo, &hi, perms, path) < 3) continue;
        if (perms[0] != 'r' || perms[1] != 'w') continue;                    /* read-only memory cannot hold runtime secrets */
        if (strstr(path, "[vvar") || strstr(path, "[vsyscall") || strstr(path, "[vdso")) continue;
        const uint8_t *base = (const uint8_t *)lo;
        size_t n = hi - lo;
        /* Search the TAIL of the secret (last 12 bytes): the allocator overwrites the first 16 bytes of a freed block
         * with its own bookkeeping, so a freed copy no longer matches as a whole. 12 bytes are still unique. */
        size_t sl = p->len > 16 ? 12 : p->len, off = p->len - sl;
        for (size_t i = 0; i + sl <= n; i++) {
            if (base[i] != pb(p, off)) continue;
            size_t j = 1;
            while (j < sl && base[i + j] == pb(p, off + j)) j++;
            if (j < sl) continue;
            total++;
            if (strlen(f->where) < sizeof f->where - 40)
                snprintf(f->where + strlen(f->where), sizeof f->where - strlen(f->where), " %s+0x%zx", path[0] ? path : "[anon]", i);
        }
    }
    if (m) fclose(m);
    f->hits = total;
    return total;
}

static int report(const char *when, int expect_found_name_idx)
{
    int bad = 0;
    printf("-- %s\n", when);
    for (int i = 0; i < npats; i++) {
        found f;
        scan(&pats[i], &f);
        if (i == expect_found_name_idx) continue;                              /* checked by the caller */
        printf("   %-26s %d match%s%s\n", pats[i].name, f.hits, f.hits == 1 ? "" : "es", f.hits ? f.where : "");
        bad += f.hits;
    }
    return bad;
}

/* ---- scanner self-test: plant a secret in freed heap and in dead stack, the scanner must see both ---- */
static const char *const PLANT = "SELFTEST-unique-planted-90871";
static void plant_stack(void)
{
    volatile char big[4096];                               /* written, never wiped, then the frame is gone */
    for (size_t i = 0; i + 1 < sizeof big; i++) big[i] = PLANT[i % strlen(PLANT)];
    big[sizeof big - 1] = 0;
}
static void scanner_selftest(void)
{
    pat p = {"planted secret", (const uint8_t *)PLANT, {0}, strlen(PLANT)};
    found f;
    volatile char *h = malloc(256);                        /* volatile: the compiler must not drop the dead stores */
    for (size_t i = 0; i <= strlen(PLANT); i++) h[i] = PLANT[i];
    free((void *)h);                                               /* freed without wiping: what a leak of this kind looks like */
    scan(&p, &f);
    printf("-- scanner self-test: freed heap block found %d time(s):%s\n", f.hits, f.where);
    CHECK(f.hits >= 1 && strstr(f.where, "[heap]"), "the scanner missed a secret in freed heap");
    plant_stack();
    scan(&p, &f);
    printf("-- scanner self-test: dead stack found, %d hits in total\n", f.hits);
    CHECK(f.hits >= 2 && strstr(f.where, "[stack]"), "the scanner missed a secret in dead stack");
}

/* ---- the session ---- */
static void select_kind(int kind)
{
    for (int i = 0; i < 40 && !(A.nrows && A.rows[A.sel].kind == kind); i++) key(K_DOWN);
}

static void open_vault(const char *pw)
{
    app_lock(&A);
    key(K_ENTER);                                          /* the only database */
    feed(pw);
    key(K_ENTER);
}

static void open_entry(void)
{
    for (int i = 0; i < 4 && (A.scr == SCR_ENTRY || A.scr == SCR_SEARCH); i++) key(A.scr == SCR_SEARCH ? K_ESC : '`');   /* back to the list */
    feed("Bank");
    key(K_ENTER);
}

int main(int argc, char **argv)
{
    const char *tdir = argc > 1 ? argv[1] : "../../testdata";
    /* Behave like the ESP32 heap: no mmap for big blocks and no returning memory to the OS, otherwise an
     * unwiped big buffer (Argon2's memory) would vanish on free() here and the test could not see it. */
    mallopt(M_MMAP_THRESHOLD, 1 << 30);
    mallopt(M_TRIM_THRESHOLD, 1 << 30);
    char tmpl[] = "/tmp/memscan_XXXXXX";
    if (!mkdtemp(tmpl)) return 2;
    snprintf(wdir, sizeof wdir, "%s", tmpl);
    char dbpath[300];
    snprintf(dbpath, sizeof dbpath, "%s/vault.kdbx", wdir);

    if (!run_child(0, NULL, dbpath)) { printf("FAIL: creating the test database\n"); return 2; }
    add_bin("MP composite key", pipe_buf[0]);
    add_bin("MP KDF chain value", pipe_buf[1]);
    add_bin("MP transformed key", pipe_buf[2]);
    int tk_idx = npats - 1;
    add_str("master password", MP);
    add_str("new master password", NMP);
    add_str("wrong password", WRONG);
    add_str("entry password", EP1);
    add_str("entry password (edited)", EP2);
    add_str("protected field PIN", PIN1);
    add_str("TOTP secret", OTPS);
    add_str("notes", NOTE1);

    scanner_selftest();
    cp_settings cfg;
    cp_settings_default(&cfg);
    cfg.animations = false;
    cfg.splash = false;
    app_init(&A, &PLAT, &cfg);
    present(NULL);

    /* 1. unlock; the transformed key is cached for saving, so it has to be visible to the scanner */
    open_vault(MP);
    CHECK(A.db && A.scr == SCR_HOME, "unlock: %s", A.msg);
    {
        found f;
        scan(&pats[tk_idx], &f);
        printf("-- unlocked: positive control, MP transformed key found %d time(s)\n", f.hits);
        CHECK(f.hits >= 1, "scanner is broken: the cached transformed key was not found while unlocked");
    }

    /* 2. use everything: reveal, hide, type, auto-type, TOTP, QR code, protected custom field */
    open_entry();
    CHECK(A.scr == SCR_ENTRY, "entry open");
    select_kind(R_PASS);
    key('r');
    CHECK(A.revealed, "revealed");
    tick();
    key('r');
    key(K_ENTER);                                          /* type the password */
    key('a');                                              /* auto-type the whole login */
    key('q');                                              /* QR code of the password */
    tick();
    key(' ');                                              /* close it */
    for (int i = 0; i < A.nrows; i++) {
        A.sel = i;                                         /* walk every row: reveal each protected one */
        ap_mark_all(&A);
        key('r');
        tick();
        key('r');
    }
    select_kind(R_TOTP);
    key(K_ENTER);
    key('`');

    /* 3. edit the password and save (decrypts and rewrites the whole database) */
    open_entry();
    CHECK(A.scr == SCR_ENTRY, "entry open before the edit (screen %d)", (int)A.scr);
    key('e');
    CHECK(A.scr == SCR_EDIT, "editor open (screen %d)", (int)A.scr);
    key(K_DOWN);
    key(K_DOWN);
    key(K_ENTER);
    for (int i = 0; i < 40; i++) key(K_BACKSPACE);
    feed(EP2);
    key(K_ENTER);
    key('s' | K_FN);
    CHECK(strstr(A.msg, "Saved"), "edit saved: '%s' (screen %d)", A.msg, (int)A.scr);
    key('`');

    /* 4. change the master password (re-runs the KDF, rewrites the file with a new seed) */
    ap_account_open(&A);
    key(K_ENTER); feed(MP); key(K_ENTER);
    key(K_ENTER); feed(NMP); key(K_ENTER);
    key(K_ENTER); feed(NMP); key(K_ENTER);
    key(K_DOWN); key(K_DOWN);
    key(K_ENTER);
    CHECK(A.db && strstr(A.msg, "changed"), "master password changed: %s", A.msg);

    /* 5. a wrong password, then the right new one */
    open_vault(WRONG);
    CHECK(!A.db && strstr(A.msg, "Wrong"), "wrong password refused: %s", A.msg);
    key(K_ESC);
    open_vault(NMP);
    CHECK(A.db, "unlock with the new password: %s", A.msg);
    open_entry();
    select_kind(R_PASS);
    key('r');
    tick();

    /* 6. lock, then look for anything left */
    app_lock(&A);
    present(NULL);
    if (!run_child(1, NMP, dbpath)) { printf("FAIL: deriving the new keys\n"); return 2; }
    add_bin("NMP composite key", pipe_buf[0]);
    add_bin("NMP KDF chain value", pipe_buf[1]);
    add_bin("NMP transformed key", pipe_buf[2]);

    int bad = report("after lock: every secret must be gone", -1);
    CHECK(bad == 0, "%d secret(s) left in memory after locking", bad);

    /* 7. leak check: lock/unlock cycles must not grow the heap */
    size_t base = 0, last = 0;
    const int cycles = 40;
    for (int i = 0; i < cycles; i++) {
        open_vault(NMP);
        open_entry();
        select_kind(R_PASS);
        key('r');
        tick();
        key('r');
        key('`');
        key('e');
        key('`');
        app_lock(&A);
        present(NULL);
        if (i == 4) base = mallinfo2().uordblks;
        last = mallinfo2().uordblks;
    }
    printf("-- heap in use after cycle 5: %zu B, after cycle %d: %zu B\n", base, cycles, last);
    CHECK(last <= base + 64, "heap grows by %zd bytes over %d lock/unlock cycles", (ssize_t)(last - base), cycles - 5);

    bad = report("after the cycles: still nothing", -1);
    CHECK(bad == 0, "%d secret(s) in memory after the cycles", bad);

    /* 8. Argon2: the same session on an Argon2id database, memory in RAM and then in the encrypted swap file */
    {
        char src[600], dst[600], swp[600];
        snprintf(src, sizeof src, "%s/argon2id_small.kdbx", tdir);
        snprintf(dst, sizeof dst, "%s/zz_argon2.kdbx", wdir);           /* sorts after vault.kdbx in the picker */
        snprintf(swp, sizeof swp, "%s/.argon2.swp", wdir);
        FILE *a = fopen(src, "rb"), *b = fopen(dst, "wb");
        char cp[4096];
        size_t n;
        while (a && b && (n = fread(cp, 1, sizeof cp, a)) > 0) fwrite(cp, 1, n, b);
        if (a) fclose(a);
        if (b) fclose(b);
        if (!run_child(2, "test", dst)) { printf("FAIL: deriving the Argon2 keys\n"); return 2; }
        add_bin("Argon2 composite key", pipe_buf[0]);
        add_bin("Argon2 transformed key", pipe_buf[1]);
        int a2tk = npats - 1;
        add_bin("Argon2 final memory block", pipe_buf[2]);       /* 1 lane: the final block IS the last memory block */
        add_str("Argon2 db entry password", "Gm@il-p4ss!-v2");
        for (int mode = 0; mode < 2; mode++) {
            if (mode == 0) kdbx_set_argon2_memory((size_t)-1, NULL, 0);
            else kdbx_set_argon2_memory(0, swp, 32 * 1024);
            app_lock(&A);
            for (int i = 0; i < 8 && strcmp(A.dbs[A.sel], "zz_argon2.kdbx"); i++) key(K_DOWN);
            key(K_ENTER);
            feed("test");
            key(K_ENTER);
            CHECK(A.db, "Argon2 unlock (%s): %s", mode ? "swap" : "RAM", A.msg);
            found f;
            scan(&pats[a2tk], &f);
            printf("-- Argon2 (%s) unlocked: positive control, transformed key found %d time(s)\n", mode ? "swap" : "RAM", f.hits);
            CHECK(f.hits >= 1, "scanner did not see the Argon2 key while unlocked");
            for (int i = 0; i < 4 && (A.scr == SCR_ENTRY || A.scr == SCR_SEARCH); i++) key(A.scr == SCR_SEARCH ? K_ESC : '`');
            feed("Gmail");
            key(K_ENTER);
            select_kind(R_PASS);
            key('r');
            tick();
            key('r');
            app_lock(&A);
            present(NULL);
        }
        kdbx_set_argon2_memory((size_t)-1, NULL, 0);
        FILE *sw = fopen(swp, "rb");
        CHECK(!sw, "swap file left behind");
        if (sw) fclose(sw);
        bad = report("after Argon2 (RAM and swap) and lock: still nothing", -1);
        CHECK(bad == 0, "%d secret(s) in memory after the Argon2 sessions", bad);
    }

    printf("memscan: %d failures\n", failures);
    return failures != 0;
}
