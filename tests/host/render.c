/* Host render harness: drives the real app with scripted keys on copies of the
 * test databases, simulates the panel (only dirty strips are redrawn, like the
 * device), checks that equals a full redraw, and writes PNGs (1x and 3x).
 *   render <testdata dir> <out dir>
 * tools/check_qr.py and tools/check_ui_files.py check the results. */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../components/ui/app_priv.h"
#include "miniz.h"
#ifdef _WIN32
#include <direct.h>
#define MKDIR(d) _mkdir(d)
#else
#include <sys/stat.h>
#define MKDIR(d) mkdir(d, 0755)
#endif

#define STRIP 16
static const char *tdir, *odir;
static char wdir[512];
static uint16_t panel[UI_W * UI_H];
static int failures, shots;
static app A;

#define CHECK(c, ...) do { if (!(c)) { failures++; printf("FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

/* ---- platform stubs ---- */
static int cmp(const void *x, const void *y) { return strcmp(x, y); }
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
    qsort(names, (size_t)n, 64, cmp);
    return n;
}
static void path_fn(void *c, const char *name, char *out, size_t n) { (void)c; snprintf(out, n, "%s/%s", wdir, name); }
static bool time_valid = true;
static int64_t now_s = 1790000000;
static int64_t now_fn(void *c, bool *valid) { (void)c; *valid = time_valid; return now_s; }
static uint32_t ms;
static uint32_t millis_fn(void *c) { (void)c; return ms += 40; }
static int battery(void *c) { (void)c; return 76; }
static bool hid_ready(void *c) { (void)c; return true; }
static char typed[4096];
static void stroke(void *c, uint8_t k, uint8_t m) { (void)c; size_t l = strlen(typed); if (l < sizeof typed - 8) sprintf(typed + l, "%02x%s ", k, m ? "*" : ""); }
static void delay_fn(void *c, int d) { (void)c; (void)d; }
static char saved_settings[512];
static void save_settings(void *c, const char *t) { (void)c; snprintf(saved_settings, sizeof saved_settings, "%s", t); }
static void present(void *c);
static const app_platform PLAT = {list_files, path_fn, now_fn, millis_fn, battery, hid_ready, stroke, delay_fn,
                                  save_settings, present, NULL};

static void draw_band(uint16_t *dst, int y0, int y1)
{
    static uint16_t buf[UI_W * STRIP];
    for (int y = y0; y < y1; y += STRIP) {
        ui_strip s = {buf, y, y1 - y < STRIP ? y1 - y : STRIP};
        app_draw(&A, &s);
        memcpy(dst + y * UI_W, buf, sizeof(uint16_t) * UI_W * (size_t)s.h);
    }
}
static int presents;
static void present(void *c)
{
    (void)c;
    int y0, y1;
    presents++;
    while (app_dirty(&A, &y0, &y1)) draw_band(panel, y0, y1);
}

static void write_png(const char *name, const uint16_t *px, int scale)
{
    int w = UI_W * scale, h = UI_H * scale;
    uint8_t *rgb = malloc((size_t)w * h * 3);
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++) {
            uint16_t c = px[(y / scale) * UI_W + x / scale];
            uint8_t *p = rgb + (y * w + x) * 3;
            p[0] = (uint8_t)((c >> 11) << 3 | (c >> 13));
            p[1] = (uint8_t)(((c >> 5) & 63) << 2 | ((c >> 9) & 3));
            p[2] = (uint8_t)((c & 31) << 3 | ((c >> 2) & 7));
        }
    size_t len;
    void *png = tdefl_write_image_to_png_file_in_memory(rgb, w, h, 3, &len);
    char path[512];
    snprintf(path, sizeof path, "%s/%s%s.png", odir, name, scale > 1 ? "@3x" : "");
    FILE *f = fopen(path, "wb");
    fwrite(png, 1, len, f);
    fclose(f);
    mz_free(png);
    free(rgb);
}

static void snap(const char *name)
{
    present(NULL);
    static uint16_t full[UI_W * UI_H];
    draw_band(full, 0, UI_H);
    if (memcmp(full, panel, sizeof full)) {
        failures++;
        printf("FAIL %s: partial redraw differs from a full redraw\n", name);
        write_png("MISMATCH_full", full, 3);
    }
    write_png(name, panel, 1);
    write_png(name, panel, 3);
    shots++;
}

static void key(uint32_t k) { app_key(&A, k, true); app_key(&A, k, false); }
static void type(const char *s) { while (*s) key(ui_utf8_next(&s)); }
static void keys(uint32_t k, int n) { while (n--) key(k); }

static void copy(const char *name)
{
    char s[512], d[512];
    snprintf(s, sizeof s, "%s/%s", tdir, name);
    snprintf(d, sizeof d, "%s/%s", wdir, name);
    FILE *a = fopen(s, "rb"), *b = fopen(d, "wb");
    char buf[8192];
    size_t n;
    while (a && b && (n = fread(buf, 1, sizeof buf, a)) > 0) fwrite(buf, 1, n, b);
    if (a) fclose(a);
    if (b) fclose(b);
}

/* From the picker: choose a database by name, type the password, unlock. */
static void open_db(const char *name, const char *pw)
{
    if (A.db) app_lock(&A);
    int i = 0;
    while (i < A.ndbs && strcmp(A.dbs[i], name)) i++;
    CHECK(i < A.ndbs, "%s not listed", name);
    keys(K_UP, A.sel);
    keys(K_DOWN, i);
    key(K_ENTER);
    type(pw);
    key(K_ENTER);
}

/* Select the list row whose entry title is t. */
static void select_title(const char *t)
{
    for (int i = 0; i < A.nhits; i++) {
        const list_item *it = &((list_item *)A.hits)[i];
        const kdbx_entry *e = it->p;
        if (it->type != LI_GROUP && it->type != LI_ALERT && e && !strcmp(e->title, t)) { keys(K_DOWN, (i - A.sel + A.nhits) % A.nhits); return; }
    }
    CHECK(0, "no row %s", t);
}

static void select_row_kind(int kind)
{
    for (int i = 0; i < A.nrows; i++)
        if (A.rows[i].kind == kind) { keys(K_DOWN, (i - A.sel + A.nrows) % A.nrows); return; }
    CHECK(0, "no row kind %d", kind);
}

int main(int argc, char **argv)
{
    tdir = argc > 1 ? argv[1] : "testdata";
    odir = argc > 2 ? argv[2] : "renders";
    snprintf(wdir, sizeof wdir, "%s/db", odir);
    MKDIR(odir);
    MKDIR(wdir);
    char p[600];
    const char *dbs[] = {"aes_kpxc.kdbx", "argon2.kdbx", "big1000.kdbx", "passkeys.kdbx", "keyfile_xml2.kdbx", "key_xml2.keyx"};
    for (size_t i = 0; i < sizeof dbs / sizeof *dbs; i++) copy(dbs[i]);
    snprintf(p, sizeof p, "%s/newdb.kdbx", wdir);
    remove(p);
    snprintf(p, sizeof p, "%s/newdb.keyx", wdir);
    remove(p);
    cp_settings cfg;
    cp_settings_default(&cfg);
    cfg.tz_minutes = 120;

    app_init(&A, &PLAT, &cfg);
    snap("01_picker");
    open_db("aes_kpxc.kdbx", "wrong`pw");
    snap("02_wrong_password");
    CHECK(presents > 3, "KDF progress was presented (%d)", presents);
    key(K_ESC);
    open_db("aes_kpxc.kdbx", "test");
    snap("03_home");
    select_title("Gmail");
    key(K_ENTER);
    snap("04_entry");
    select_row_kind(1 /* R_PASS */);
    app_key(&A, 'r', true);
    snap("05_entry_revealed");
    app_key(&A, 'r', false);

    /* typing */
    select_row_kind(0 /* R_USER */);
    typed[0] = 0;
    key(K_ENTER);
    CHECK(!strncmp(typed, "04 0f 0c 06 08 1f* ", 19), "typed alice@...: %s", typed); /* a l i c e @ */
    snap("06_typed");
    typed[0] = 0;
    key('a');
    CHECK(strstr(typed, "2b ") && strstr(typed, "28 "), "auto-type has tab and enter: %.60s", typed);
    select_row_kind(3 /* R_TOTP */);
    key('q');
    snap("qr_totp");
    key(' ');
    select_row_kind(1);
    key('q');
    snap("qr_password");
    key(' ');
    select_row_kind(2 /* R_URL */);
    key('q');
    snap("qr_url");
    app_tick(&A, 21000);
    snap("07_qr_timed_out");

    /* favorite off and on again (saved to the file) */
    key('f');
    snap("08_unfavorited");
    CHECK(strstr(A.msg, "Removed"), "msg %s", A.msg);
    key('f');

    /* help */
    key('?');
    snap("09_help_entry");
    key(' ');

    /* edit the URL, save */
    key('e');
    snap("10_edit");
    keys(K_DOWN, 3);
    key(K_ENTER);
    type("/mail");
    snap("11_edit_typing");
    key(K_ENTER);
    key('s' | K_FN);
    snap("12_saved");
    CHECK(A.scr == SCR_ENTRY && strstr(A.msg, "Saved"), "saved: %s", A.msg);
    key('`');

    /* new entry with a generated password, from the menu */
    key(K_TAB);
    snap("13_menu");
    key(K_ENTER); /* New entry */
    key(K_ENTER);
    type("Proton");
    key(K_ENTER);
    key(K_DOWN);
    key(K_ENTER);
    type("bob@proton.me");
    key(K_ENTER);
    key(K_DOWN);
    key('g');
    snap("14_generator");
    keys(K_RIGHT, 4);
    snap("15_generator_longer");
    key(K_TAB);
    snap("16_passphrase");
    key(K_ENTER);
    keys(K_DOWN, 3); /* past URL and Notes to Tags */
    key(K_ENTER);
    type("mail");
    key(K_ENTER);
    key(K_DOWN); /* Add field */
    key(K_ENTER);
    type("PIN");
    key(K_ENTER);
    type("4321");
    key(K_ENTER);
    key('p');
    snap("17_new_entry_edit");
    key('`');
    snap("18_confirm_save");
    key(K_ENTER);
    snap("19_new_entry_saved");
    CHECK(A.scr == SCR_ENTRY && A.entry && !strcmp(A.entry->title, "Proton"), "new entry shown");

    /* delete it (recycle bin) */
    key(K_BACKSPACE | K_FN);
    snap("20_confirm_delete");
    key(K_ENTER);
    snap("21_deleted");
    CHECK(strstr(A.msg, "recycle"), "msg %s", A.msg);

    /* untypeable: zoë on US QWERTY types nothing */
    type("caf");
    key(K_ENTER);
    select_row_kind(0);
    typed[0] = 0;
    key(K_ENTER);
    CHECK(!typed[0] && strstr(A.msg, "not on US"), "untypeable: %s / %s", A.msg, typed);
    snap("22_untypeable");
    key('`');
    key(K_ESC);

    /* settings */
    key(K_TAB);
    keys(K_DOWN, 4);
    key(K_ENTER);
    snap("23_settings");
    key(K_RIGHT); /* light */
    keys(K_DOWN, 4);
    key(K_RIGHT); /* layout -> UK */
    snap("24_settings_light");
    key('`');
    CHECK(strstr(saved_settings, "theme=light") && strstr(saved_settings, "layout=UK QWERTY"), "settings saved: %s", saved_settings);
    snap("25_home_light");
    key(K_TAB);
    keys(K_DOWN, 4);
    key(K_ENTER);
    key(K_RIGHT); /* back to dark */
    key('`');

    /* audit + expiry */
    key(K_TAB);
    keys(K_DOWN, 2);
    key(K_ENTER);
    snap("26_audit");
    key('w');
    snap("27_audit_weak");
    key('`');
    now_s = 1893553445 + 86400; /* Gmail expired yesterday */
    open_db("aes_kpxc.kdbx", "test");
    snap("28_home_expiry_alert");
    key(K_ENTER);
    snap("29_expiry");
    now_s = 1790000000;

    /* big database: scrolling and search */
    open_db("big1000.kdbx", "test");
    keys(K_DOWN, 25);
    snap("30_big_scrolled");
    type("ste 42");
    snap("31_big_search");

    /* passkey entry */
    open_db("passkeys.kdbx", "test");
    type("alice");
    key(K_ENTER);
    snap("32_passkey_entry");

    /* key file: tab cycles */
    app_lock(&A);
    int i = 0;
    while (i < A.ndbs && strcmp(A.dbs[i], "keyfile_xml2.kdbx")) i++;
    keys(K_UP, A.sel);
    keys(K_DOWN, i);
    key(K_ENTER);
    key(K_TAB);
    type("test");
    snap("33_unlock_keyfile");
    key(K_ENTER);
    CHECK(A.db && A.scr == SCR_HOME, "key file unlock: %s", A.msg);

    /* new database from the picker menu */
    app_lock(&A);
    key(K_TAB);
    snap("34_picker_menu");
    key(K_ENTER);
    key(K_ENTER);
    keys(K_BACKSPACE, 9);
    type("newdb");
    key(K_ENTER);
    type("créé 1");
    key(K_ENTER);
    type("créé 1");
    key(K_ENTER);
    key(K_RIGHT); /* ChaCha20 */
    key(K_DOWN);
    key(K_DOWN);
    key(K_ENTER); /* generate key file */
    snap("35_create");
    key(K_DOWN);
    key(K_ENTER);
    snap("36_created_home");
    CHECK(A.db && !strcmp(A.dbname, "newdb.kdbx"), "created: %s", A.msg);

    /* large font, time not set, auto-lock */
    cfg.large_font = true;
    app_lock(&A); /* app_init starts from scratch: close the database first */
    app_init(&A, &PLAT, &cfg);
    open_db("aes_kpxc.kdbx", "test");
    snap("37_large_home");
    select_title("Gmail");
    key(K_ENTER);
    time_valid = false;
    select_row_kind(3);
    snap("38_large_entry_no_time");
    time_valid = true;
    app_tick(&A, 21000 + 6 * 60 * 1000);
    snap("39_autolocked");
    CHECK(!A.db, "auto-lock");
    app_lock(&A);

    if (ui_overflow) printf("FAIL: %d pixels drawn past the panel edge\n", ui_overflow), failures++;
    printf("render: %d screens -> %s/, %d failures\n", shots, odir, failures);
    return failures != 0;
}
