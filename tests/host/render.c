/* Host render harness: drives the real app with scripted keys on copies of the
 * test databases, simulates the panel (only dirty strips are redrawn, like the
 * device), checks that equals a full redraw, and writes PNGs (1x and 3x).
 *   render <testdata dir> <out dir>
 * tools/check_qr.py and tools/check_ui_files.py check the results. */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "../../components/ui/app_priv.h"
#include "../../components/ui/motion_br.h"
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
/* file browser: the working folder is the "SD root" */
static int list_dir_fn(void *c, const char *rel, app_dirent *out, int max)
{
    (void)c;
    char dir[600];
    snprintf(dir, sizeof dir, rel[0] ? "%s/%s" : "%s%.0s", wdir, rel);
    DIR *d = opendir(dir);
    int n = 0;
    struct dirent *e;
    while (d && (e = readdir(d)) && n < max) {
        size_t l = strlen(e->d_name);
        if (e->d_name[0] == '.' || l >= 64) continue;
        char full[700];
        snprintf(full, sizeof full, "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(full, &st)) continue;
        snprintf(out[n].name, 64, "%s", e->d_name);
        out[n].dir = S_ISDIR(st.st_mode);
        out[n].size = out[n].dir ? 0 : (uint32_t)st.st_size;
        n++;
    }
    if (d) closedir(d);
    return n;
}
static void root_path_fn(void *c, const char *rel, char *out, size_t n) { (void)c; snprintf(out, n, rel[0] ? "%s/%s" : "%s%.0s", wdir, rel); }
static void start_dir_fn(void *c, char *out, size_t n) { (void)c; if (n) out[0] = 0; }
static bool time_valid = true;
static int64_t now_s = 1790000000;
static int64_t now_fn(void *c, bool *valid) { (void)c; *valid = time_valid; return now_s; }
static uint32_t ms;
static uint32_t millis_fn(void *c) { (void)c; return ms += 40; }
static int battery_level_now(void);
static int battery(void *c) { (void)c; return battery_level_now(); }
static bool hid_ready(void *c) { (void)c; return true; }
static char typed[4096];
static void stroke(void *c, uint8_t k, uint8_t m) { (void)c; size_t l = strlen(typed); if (l < sizeof typed - 8) sprintf(typed + l, "%02x%s ", k, m ? "*" : ""); }
static void delay_fn(void *c, int d) { (void)c; (void)d; }
static char saved_settings[512];
static void save_settings(void *c, const char *t) { (void)c; snprintf(saved_settings, sizeof saved_settings, "%s", t); }
static void present(void *c);
static void pump_fn(void *c);
static int bt_st, bt_starts, bt_stops, bt_answers, bt_forgets, bt_accept = -1;
static uint32_t bt_code_v;
static bool bt_start_fn(void *c) { (void)c; bt_starts++; bt_st = BT_ADVERTISING; return true; }
static void bt_stop_fn(void *c) { (void)c; bt_stops++; bt_st = BT_OFF; }
static int bt_state_fn(void *c, uint32_t *code) { (void)c; if (code) *code = bt_code_v; return bt_st; }
static void bt_answer_fn(void *c, bool ok) { (void)c; bt_answers++; bt_accept = ok; bt_st = ok ? BT_CONNECTED : BT_ADVERTISING; bt_code_v = 0; }
static void bt_forget_fn(void *c) { (void)c; bt_forgets++; }
static bool drive_on;
static bool usb_drive(void *c, bool enter) { (void)c; drive_on = enter; return true; }
static void set_time_fn(void *c, int64_t t) { (void)c; now_s = t; time_valid = true; }
static int backlight_state, backlight_calls, shutdowns, battery_level = 76;
static void backlight_fn(void *c, int s) { (void)c; backlight_state = s; backlight_calls++; }
static void shutdown_fn(void *c) { (void)c; shutdowns++; }
static int scans, ntp_calls;
static char ntp_ssid[40], ntp_pass[64];
static int64_t ntp_time;
static int wifi_scan_fn(void *c, app_ap *out, int max)
{
    (void)c; (void)max;
    scans++;
    snprintf(out[0].ssid, 33, "HomeWiFi"); out[0].secure = true; out[0].rssi = -40;
    snprintf(out[1].ssid, 33, "Caf\xC3\xA9 Guest"); out[1].secure = false; out[1].rssi = -55;
    snprintf(out[2].ssid, 33, "Neighbour"); out[2].secure = true; out[2].rssi = -70;
    return 3;
}
static int ntp_sync_fn(void *c, const char *ssid, const char *pass, int64_t *t)
{
    (void)c;
    ntp_calls++;
    snprintf(ntp_ssid, sizeof ntp_ssid, "%s", ssid);
    snprintf(ntp_pass, sizeof ntp_pass, "%s", pass);
    if (!strcmp(pass, "wrong")) return NTP_ERR_PASSWORD;
    *t = ntp_time;
    return NTP_OK;
}
static const app_platform PLAT = {list_files, path_fn, now_fn, millis_fn, battery, hid_ready, stroke, delay_fn,
                                  save_settings, present, pump_fn, usb_drive, backlight_fn, shutdown_fn, set_time_fn, wifi_scan_fn, ntp_sync_fn,
                                  bt_start_fn, bt_stop_fn, bt_state_fn, bt_answer_fn, bt_forget_fn,
                                  list_dir_fn, root_path_fn, start_dir_fn, NULL};
static int battery_level_now(void) { return battery_level; }

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

static void snap(const char *name);
static void key(uint32_t k);
static int pump_script, pump_n;
/* stands in for the device loop while a passkey confirmation is showing */
static void pump_fn(void *c)
{
    (void)c;
    pump_n++;
    app_tick(&A, A.now_ms + 500);
    if (pump_script == 1 && pump_n == 2) { snap("40_passkey_confirm"); key(K_DOWN); }
    if (pump_script == 1 && pump_n == 3) key(K_ENTER);
    if (pump_script == 2 && pump_n == 2) key('`');
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

static void select_group(const char *name)
{
    for (int i = 0; i < A.nhits; i++) {
        const list_item *it = &((list_item *)A.hits)[i];
        if (it->type == LI_GROUP && !strcmp(((const kdbx_group *)it->p)->name, name)) { keys(K_DOWN, (i - A.sel + A.nhits) % A.nhits); return; }
    }
    CHECK(0, "no group row %s", name);
}

static const kdbx_group *group_named(const char *n)
{
    for (const kdbx_group *g = kdbx_groups(A.db); g; g = g->next)
        if (!strcmp(g->name, n)) return g;
    return NULL;
}

static void copy_as(const char *name, const char *as)
{
    char s[512], d[512];
    snprintf(s, sizeof s, "%s/%s", tdir, name);
    snprintf(d, sizeof d, "%s/%s", wdir, as);
    FILE *a = fopen(s, "rb"), *b = fopen(d, "wb");
    char buf[8192];
    size_t n;
    while (a && b && (n = fread(buf, 1, sizeof buf, a)) > 0) fwrite(buf, 1, n, b);
    if (a) fclose(a);
    if (b) fclose(b);
}

static void select_row_kind(int kind)
{
    for (int i = 0; i < A.nrows; i++)
        if (A.rows[i].kind == kind) { keys(K_DOWN, (i - A.sel + A.nrows) % A.nrows); return; }
    CHECK(0, "no row kind %d", kind);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0); /* keep FAIL lines if a later step crashes */
    tdir = argc > 1 ? argv[1] : "testdata";
    odir = argc > 2 ? argv[2] : "renders";
    snprintf(wdir, sizeof wdir, "%s/db", odir);
    MKDIR(odir);
    MKDIR(wdir);
    char p[600];
    const char *dbs[] = {"aes_kpxc.kdbx", "argon2.kdbx", "big1000.kdbx", "passkeys.kdbx", "keyfile_xml2.kdbx", "key_xml2.keyx", "argon2id_small.kdbx"};
    for (size_t i = 0; i < sizeof dbs / sizeof *dbs; i++) copy(dbs[i]);
    copy_as("chacha_kpxc.kdbx", "chg.kdbx");
    snprintf(p, sizeof p, "%s/chg.keyx", wdir);
    remove(p);
    snprintf(p, sizeof p, "%s/newdb.kdbx", wdir);
    remove(p);
    snprintf(p, sizeof p, "%s/newdb.keyx", wdir);
    remove(p);
    cp_settings cfg;
    cp_settings_default(&cfg);
    cfg.tz_minutes = 120;
    cfg.splash = false;                 /* the splash has its own test */
    cfg.animations = false;             /* all screenshots show the settled state; the animation test enables it */

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
    key(K_RIGHT); /* Deep night: its contrast trade is disclosed */
    CHECK(strstr(A.msg, "Deep night"), "deep-night disclosure: %s", A.msg);
    snap("23b_settings_deep_night");
    key(K_RIGHT); /* Daylight */
    keys(K_DOWN, 6);
    key(K_RIGHT); /* layout -> UK */
    snap("24_settings_light");
    key('`');
    CHECK(strstr(saved_settings, "theme=daylight") && strstr(saved_settings, "layout=UK QWERTY"), "settings saved: %s", saved_settings);
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

    /* passkey confirmation (what a browser triggers over USB) */
    {
        fido_cred creds[4];
        size_t nc = fido_find(A.db, "webauthn.io", creds, 4);
        CHECK(nc == 2, "two webauthn.io passkeys");
        int scr = A.scr;
        pump_script = 1, pump_n = 0;
        int r = app_ask_passkey(&A, "webauthn.io", creds, nc);
        CHECK(r == 1 && A.scr == scr && !A.fido_active, "approved second account: %d", r);
        pump_script = 2, pump_n = 0;
        r = app_ask_passkey(&A, "webauthn.io", creds, nc);
        CHECK(r == -1 && A.scr == scr, "denied: %d", r);
        pump_script = 0;
        r = app_ask_passkey(&A, "webauthn.io", creds, nc);
        CHECK(r == -1 && pump_n > 50 && A.db, "times out after 30 s: %d after %d passes", r, pump_n);
        key('l' | K_FN);
        CHECK(A.db == NULL || A.scr != SCR_FIDO, "not stuck in the modal");
    }

    /* animations: cross-fade, slide-in, toast; off switch, key skips, battery/power guards */
    {
        open_db("aes_kpxc.kdbx", "test");
        A.cfg.animations = false;
        uint32_t t0 = A.now_ms + 1000;
        app_tick(&A, t0);
        CHECK(!A.anim_on, "animations off");
        key(K_DOWN);
        CHECK(ap_row_weight(&A, A.sel) == 256 && ap_row_weight(&A, A.sel_prev) == 0, "no cross-fade when off");

        A.cfg.animations = true;
        app_tick(&A, t0 + 100);
        CHECK(A.anim_on, "animations on");
        int old = A.sel;
        key(K_DOWN);
        CHECK(A.sel_prev == old && ap_row_weight(&A, A.sel) == 0 && ap_row_weight(&A, old) == 256, "cross-fade starts: old row lit, new row not yet");
        app_tick(&A, A.now_ms + BR_MS_FEEDBACK / 2);      /* half of the token's feedback duration */
        int w = ap_row_weight(&A, A.sel);
        CHECK(w > 100 && w < 160 && ap_row_weight(&A, old) == 256 - w, "halfway: %d", w);
        snap("73_crossfade_half");
        app_tick(&A, A.now_ms + 200);
        CHECK(ap_row_weight(&A, A.sel) == 256 && ap_row_weight(&A, old) == 0, "cross-fade done");

        /* slide-in: entering an entry starts with rows pushed to the right, ends identical to the static screen */
        select_title("Gmail");
        key(K_ENTER);
        static uint16_t settled[UI_W * UI_H], moving[UI_W * UI_H];
        int y0, y1;
        while (app_dirty(&A, &y0, &y1)) draw_band(panel, y0, y1);
        draw_band(moving, 0, UI_H);                    /* time = just entered */
        CHECK(memcmp(moving, panel, sizeof moving) == 0, "partial redraw equals full redraw mid-slide");
        snap("74_slide_start");
        app_tick(&A, A.now_ms + 60);
        snap("75_slide_mid");
        app_tick(&A, A.now_ms + 500);                  /* one stalled pass past the end (busy loop after unlock) */
        while (app_dirty(&A, &y0, &y1)) draw_band(panel, y0, y1);
        draw_band(settled, 0, UI_H);
        CHECK(memcmp(panel, settled, sizeof panel) == 0, "a slide whose last frame was missed still ends settled");
        A.cfg.animations = false;
        app_tick(&A, A.now_ms + 10);
        draw_band(moving, 0, UI_H);                    /* the same screen with animations off */
        CHECK(memcmp(moving, settled, sizeof moving) == 0, "slide ends exactly on the static screen");
        A.cfg.animations = true;
        app_tick(&A, A.now_ms + 10);

        /* a key press skips a running slide */
        key('`');
        CHECK(A.scr == SCR_HOME, "back home");
        while (app_dirty(&A, &y0, &y1)) draw_band(panel, y0, y1);
        app_tick(&A, A.now_ms + 20);
        CHECK(A.now_ms - A.scr_ms < 100, "slide is running");
        key(K_DOWN);
        CHECK(A.now_ms - A.scr_ms > 1000u, "a key press ends the slide at once");

        /* toast slides up from behind the footer */
        snprintf(A.msg, sizeof A.msg, "Hello toast");
        app_tick(&A, A.now_ms + 500);
        CHECK(ap_toast_offset(&A) == TOAST_H, "toast starts below: %d", ap_toast_offset(&A));
        app_tick(&A, A.now_ms + 200);
        CHECK(ap_toast_offset(&A) == 0, "toast settled");
        A.msg[0] = 0;

        /* guards: low battery, dimmed screen, passkey prompt switch animations off */
        battery_level = 10;
        app_tick(&A, A.now_ms + 6000);
        CHECK(!A.anim_on, "off below 15 %% battery");
        battery_level = 76;
        app_tick(&A, A.now_ms + 6000);
        CHECK(A.anim_on, "back on");
        A.fido_active = true;
        app_tick(&A, A.now_ms + 10);
        CHECK(!A.anim_on, "off during a passkey prompt");
        A.fido_active = false;
        app_tick(&A, A.now_ms + 10);
        A.cfg.animations = false;
        app_lock(&A);
    }

    /* frames for tools/make_anim_gif.py: what the animations look like, straight from the app's drawing code */
    {
        open_db("aes_kpxc.kdbx", "test");
        A.cfg.animations = true;
        app_tick(&A, A.now_ms + 500);
        char name[64];
        int f = 0;
        select_title("Gmail");
        A.cfg.animations = false;
        app_tick(&A, A.now_ms + 500);
        A.cfg.animations = true;
        app_tick(&A, A.now_ms + 500);
        while (f < 12) { present(NULL); snprintf(name, sizeof name, "anim_00_home_%02d", f++); write_png(name, panel, 3); app_tick(&A, A.now_ms + 33); }
        key(K_ENTER);                                      /* entering the entry: rows slide in */
        for (f = 0; f < 14; f++) { present(NULL); snprintf(name, sizeof name, "anim_01_slide_%02d", f); write_png(name, panel, 3); app_tick(&A, A.now_ms + 33); }
        for (int d = 0; d < 3; d++) {                      /* moving the selection: the highlight fades over */
            key(K_DOWN);
            for (f = 0; f < 5; f++) { present(NULL); snprintf(name, sizeof name, "anim_02_fade_%d_%02d", d, f); write_png(name, panel, 3); app_tick(&A, A.now_ms + 33); }
        }
        snprintf(A.msg, sizeof A.msg, "Copied to the screen");         /* toast slides up */
        app_tick(&A, A.now_ms + 33);
        for (f = 0; f < 8; f++) { present(NULL); snprintf(name, sizeof name, "anim_03_toast_%02d", f); write_png(name, panel, 3); app_tick(&A, A.now_ms + 33); }
        A.msg[0] = 0;
        A.cfg.animations = false;
        app_lock(&A);
    }

    /* Bluetooth: on only when switched on, pairing needs the code confirmed, idle/lock switch it off */
    {
        open_db("aes_kpxc.kdbx", "test");
        key(K_TAB);
        keys(K_DOWN, 10);
        key(K_ENTER);
        CHECK(A.scr == SCR_BT && !A.bt_on && bt_starts == 0, "Bluetooth screen, radio off");
        snap("95_bt_off");
        key(K_ENTER);
        CHECK(A.bt_on && bt_starts == 1 && bt_st == BT_ADVERTISING, "switched on");
        app_tick(&A, A.now_ms + 20);
        snap("96_bt_advertising");
        key('`');
        CHECK(A.scr == SCR_HOME && A.bt_on, "radio stays on after leaving the screen");
        snap("97_bt_icon_in_bar");
        bt_st = BT_PAIR_CONFIRM;                     /* a host starts pairing while we are on the home screen */
        bt_code_v = 123456;
        app_tick(&A, A.now_ms + 20);
        CHECK(A.scr == SCR_BT && A.bt_state == BT_PAIR_CONFIRM, "pairing request shows the code");
        snap("98_bt_pair_confirm");
        key('`');                                    /* refuse */
        CHECK(bt_answers == 1 && bt_accept == 0 && A.scr == SCR_HOME, "refused, back where we were");
        bt_st = BT_PAIR_CONFIRM;
        bt_code_v = 654321;
        app_tick(&A, A.now_ms + 20);
        key(K_ENTER);                                /* accept */
        CHECK(bt_answers == 2 && bt_accept == 1 && A.scr == SCR_HOME, "accepted");
        app_tick(&A, A.now_ms + 20);
        CHECK(A.bt_state == BT_CONNECTED, "connected");
        app_tick(&A, A.now_ms + 119000);
        CHECK(A.bt_on, "still on at 119 s");
        app_tick(&A, A.now_ms + 2000);
        CHECK(!A.bt_on && bt_stops == 1 && strstr(A.msg, "Bluetooth off"), "off after 2 min idle");
        key(K_UP);                                   /* the screen went dark meanwhile: this key only wakes it */
        key(K_TAB);
        keys(K_DOWN, 10);
        key(K_ENTER);
        key('f');
        CHECK(bt_forgets == 1, "forget pairings");
        key(K_ENTER);
        CHECK(A.bt_on, "on again");
        app_lock(&A);
        CHECK(!A.bt_on && bt_stops == 2, "locking switches Bluetooth off");
    }

    /* power: dim, screen off, wake without side effects, no dimming while a browser waits */
    {
        open_db("aes_kpxc.kdbx", "test");
        select_title("Gmail");
        key(K_ENTER);
        uint32_t t0 = A.now_ms;
        app_tick(&A, t0 + 19000);
        CHECK(A.power == 0 && backlight_state == 0, "still bright at 19 s");
        app_tick(&A, t0 + 21000);
        CHECK(A.power == 1 && backlight_state == 1, "dimmed after 20 s");
        snap("70_dimmed");
        app_tick(&A, t0 + 46000);
        CHECK(A.power == 2 && backlight_state == 2, "screen off after 45 s");
        int y0, y1;
        CHECK(!app_dirty(&A, &y0, &y1), "nothing is drawn while dark");
        int scr = A.scr, sel = A.sel;
        key(K_DOWN);            /* wakes the screen, does nothing else */
        CHECK(A.power == 0 && backlight_state == 0 && A.scr == scr && A.sel == sel, "wake key is swallowed");
        snap("71_woken");
        key(K_DOWN);
        CHECK(A.sel != sel, "next key works");
        uint32_t t1 = A.now_ms;
        app_tick(&A, t1 + 21000);           /* dim again, but a passkey request keeps the screen on */
        CHECK(A.power == 1, "dimmed again");
        A.fido_active = true;
        app_tick(&A, t1 + 22000);
        CHECK(A.power == 0, "bright while a browser waits");
        A.fido_active = false;
        key(K_DOWN);
        app_tick(&A, A.now_ms + 1000);
        CHECK(A.power == 0, "any key restores brightness");

        /* critical battery: three low readings in a row lock, wipe and shut down */
        battery_level = 2;
        uint32_t tb = A.now_ms + 6000;
        app_tick(&A, tb);
        app_tick(&A, tb + 5000);
        CHECK(A.db && shutdowns == 0, "two low readings are not enough");
        battery_level = 50;
        app_tick(&A, tb + 10000);           /* sag recovered: counter resets */
        battery_level = 2;
        app_tick(&A, tb + 15000);
        app_tick(&A, tb + 20000);
        CHECK(A.db && shutdowns == 0, "counter was reset");
        app_tick(&A, tb + 25000);
        CHECK(!A.db && shutdowns == 1 && A.scr == SCR_PICKER, "locked and shut down");
        snap("72_battery_empty");
        battery_level = 76;
        app_lock(&A);
    }

    /* change password + key file, groups, moving an entry, attachment viewer (scratch copy chg.kdbx) */
    {
        char path[700];
        snprintf(path, sizeof path, "%s/chg.kdbx", wdir);
        open_db("chg.kdbx", "test");
        key(K_TAB);
        keys(K_DOWN, 9);
        key(K_ENTER);
        CHECK(A.scr == SCR_ACCOUNT, "change password screen");
        snap("80_account");
        type("bad"); key(K_ENTER);
        type("n3w pw"); key(K_ENTER);
        type("n3w pw"); key(K_ENTER);
        keys(K_DOWN, 2);
        key(K_ENTER);
        CHECK(A.scr == SCR_ACCOUNT && strstr(A.msg, "wrong"), "wrong current password refused: %s", A.msg);
        snap("81_account_wrong");
        keys(K_UP, 5);
        key(K_ENTER);                      /* edit "bad" */
        keys(K_BACKSPACE, 3);
        type("test");
        key(K_ENTER);
        keys(K_DOWN, 4);
        key(K_ENTER);
        CHECK(A.scr == SCR_HOME && A.db && strstr(A.msg, "changed"), "password changed: %s", A.msg);
        {
            char bak[720];
            snprintf(bak, sizeof bak, "%s.bak", path);
            FILE *f = fopen(bak, "rb");
            CHECK(!f, ".bak with the old password removed");
            if (f) fclose(f);
            kdbx_key k;
            f = fopen(path, "rb");
            kdbx_key_init(&k, "n3w pw", 6, NULL);
            CHECK(f && kdbx_check_key(f, &k) == KDBX_OK, "new password opens the file");
            fclose(f);
            kdbx_key_init(&k, "test", 4, NULL);
            f = fopen(path, "rb");
            CHECK(f && kdbx_check_key(f, &k) == KDBX_ERR_KEY, "old password no longer works");
            fclose(f);
        }
        snap("82_account_done");
        key(K_TAB);                       /* second change: new password + generated key file + ~1 s KDF */
        keys(K_DOWN, 9);
        key(K_ENTER);
        type("n3w pw"); key(K_ENTER);
        type("kf pw"); key(K_ENTER);
        type("kf pw"); key(K_ENTER);
        key(K_ENTER);                      /* key file: Generate new */
        key(K_DOWN);
        key(K_ENTER);                      /* unlock in ~1 s */
        snap("83_account_keyfile");
        key(K_DOWN);
        key(K_ENTER);
        CHECK(A.scr == SCR_HOME && strstr(A.msg, "changed") && A.keyrel[0], "key file added: %s", A.msg);
        {
            char kp[720];
            snprintf(kp, sizeof kp, "%s/chg.keyx", wdir);
            FILE *kf = fopen(kp, "rb"), *f = fopen(path, "rb");
            kdbx_key k;
            CHECK(kf && f && kdbx_key_init(&k, "kf pw", 5, kf) == KDBX_OK && kdbx_check_key(f, &k) == KDBX_OK, "password + key file open the file");
            if (kf) fclose(kf);
            if (f) fclose(f);
        }

        /* groups */
        key(K_TAB);
        keys(K_DOWN, 8);
        key(K_ENTER);
        CHECK(A.scr == SCR_GROUPS, "groups screen");
        snap("84_groups");
        key(K_ENTER);
        type("Work");
        snap("85_group_name");
        key(K_ENTER);
        CHECK(A.scr == SCR_HOME && group_named("Work"), "group created");
        select_group("Work");
        key(K_ENTER);
        key(K_TAB);
        keys(K_DOWN, 8);
        key(K_ENTER);
        key(K_DOWN);
        key(K_ENTER);                      /* rename */
        keys(K_BACKSPACE, 4);
        type("Job");
        key(K_ENTER);
        CHECK(group_named("Job") && !group_named("Work"), "group renamed");
        select_group("Job");
        key(K_ENTER);
        key(K_TAB);
        keys(K_DOWN, 8);
        key(K_ENTER);
        keys(K_DOWN, 2);
        key(K_ENTER);                      /* move: choose the destination */
        snap("86_group_move");
        key(K_DOWN);                       /* Email, [Banking], ... */
        key(K_ENTER);
        CHECK(group_named("Job") && group_named("Job")->parent == group_named("Banking"), "group moved into Banking");
        select_group("Banking");
        key(K_ENTER);
        select_group("Job");
        key(K_ENTER);
        key(K_TAB);
        keys(K_DOWN, 8);
        key(K_ENTER);
        keys(K_DOWN, 3);
        key(K_ENTER);
        snap("87_group_delete_confirm");
        key(K_ENTER);
        CHECK(group_named("Job") && group_named("Job")->parent && !strcmp(group_named("Job")->parent->name, "Recycle Bin"),
              "group moved to the recycle bin");
        ap_go_home(&A);

        /* moving an entry */
        type("gmail");
        key(K_ENTER);
        key('m');
        snap("88_entry_move");
        keys(K_DOWN, 3);
        key(K_ENTER);
        CHECK(A.scr == SCR_ENTRY && A.entry && !strcmp(A.entry->group->name, "Caf\xC3\xA9 & Bar"), "entry moved: %s", A.entry ? A.entry->group->name : "-");
        key(96);
        key(K_ESC);

        /* attachment viewer */
        type("bank");
        key(K_ENTER);
        select_row_kind(7);
        key(K_ENTER);
        CHECK(A.scr == SCR_VIEW, "viewer opens a text attachment");
        snap("89_view_text");
        keys(K_DOWN, 3);
        snap("90_view_scrolled");
        key(96);
        CHECK(A.scr == SCR_ENTRY, "back to the entry");
        key(K_DOWN);
        key(K_ENTER);
        CHECK(A.scr == SCR_VIEW, "viewer opens the binary attachment");
        snap("91_view_binary");
        key(96);
        app_lock(&A);
        CHECK(A.view == NULL && A.acct == NULL && A.grp == NULL, "everything wiped on lock");
    }

    /* setting the time (cfg.tz_minutes = 120): by hand, then over Wi-Fi */
    {
        if (A.db) app_lock(&A);
        time_valid = false;
        key(K_TAB);
        keys(K_DOWN, 3);
        key(K_ENTER);
        CHECK(A.scr == SCR_TIME, "time screen");
        snap("50_time_not_set");
        key(K_ENTER);
        snap("51_time_manual_prefilled");
        type("2026");
        type("01");
        type("15");
        type("09");
        type("30");
        type("00");
        key(K_ENTER);
        CHECK(strstr(A.msg, "Before the firmware build"), "date before the build is refused: %s", A.msg);
        snap("52_time_before_build");
        keys(K_LEFT, 4);        /* seconds -> month */
        type("13");
        key(K_ENTER);
        CHECK(strstr(A.msg, "valid"), "month 13 is refused: %s", A.msg);
        snap("53_time_invalid");
        key(K_LEFT);            /* typing 13 moved on to the day */
        type("10");             /* month, moves on to the day */
        type("15");             /* day, moves on to the hour */
        snap("54_time_manual");
        key(K_ENTER);
        int64_t want = cp_unix_from_civil(2026, 10, 15, 9, 30, 0) - 120 * 60;
        CHECK(time_valid && now_s == want && A.time_src == 1, "manual time set: %lld want %lld", (long long)now_s, (long long)want);
        snap("55_time_set");

        /* Wi-Fi: password once, saved afterwards */
        ntp_time = cp_build_time() + 86400 * 30;
        key(K_DOWN);
        key(K_ENTER);
        CHECK(scans == 1, "scan");
        snap("56_wifi_list");
        key(K_ENTER);           /* HomeWiFi: secured, unknown */
        type("secret");
        snap("57_wifi_password");
        key(K_ENTER);
        CHECK(ntp_calls == 1 && !strcmp(ntp_ssid, "HomeWiFi") && !strcmp(ntp_pass, "secret") && now_s == ntp_time && A.time_src == 2,
              "synced over Wi-Fi");
        CHECK(strstr(saved_settings, "wifi="), "network saved");
        snap("58_wifi_done");
        key(' ');
        key(K_DOWN);
        key(K_ENTER);
        key(K_ENTER);           /* saved: no password asked */
        CHECK(ntp_calls == 2 && !strcmp(ntp_pass, "secret") && A.tm != NULL, "saved network used");
        key(' ');
        key(K_DOWN);
        key(K_ENTER);
        keys(K_DOWN, 2);
        key(K_ENTER);           /* Neighbour */
        type("wrong");
        key(K_ENTER);
        snap("59_wifi_wrong_password");
        key(K_ENTER);           /* retype */
        CHECK(!strstr(A.msg, "x") && ntp_calls == 3, "wrong password reported");
        key(K_ESC);
        key(K_DOWN);            /* open network, server time is nonsense */
        ntp_time = 1000;
        key(K_ENTER);
        CHECK(ntp_calls == 4 && now_s != 1000, "bad server time not applied");
        snap("60_wifi_bad_time");
        key(' ');
        key(96);
        CHECK(A.scr == SCR_PICKER, "left the time screen");

        /* with a database open: manual only, Wi-Fi refused */
        open_db("aes_kpxc.kdbx", "test");
        key(K_TAB);
        keys(K_DOWN, 7);
        key(K_ENTER);
        CHECK(A.scr == SCR_TIME, "time screen while unlocked");
        key(K_DOWN);
        key(K_ENTER);
        CHECK(scans == 3 && strstr(A.msg, "Lock"), "no Wi-Fi with a database open: %s", A.msg);
        snap("61_time_unlocked");
        key(96);
        CHECK(A.scr == SCR_HOME, "back home");

        /* the TOTP row offers a shortcut when the clock is not set */
        time_valid = false;
        select_title("Gmail");
        key(K_ENTER);
        select_row_kind(3);
        snap("62_totp_no_time_hint");
        key('t');
        CHECK(A.scr == SCR_TIME, "T opens the time screen");
        key(96);
        CHECK(A.scr == SCR_ENTRY, "and returns to the entry");
        time_valid = true;
        now_s = 1790000000;
    }

    /* USB drive mode: locks first, a file copied on the PC shows up afterwards */
    {
        open_db("aes_kpxc.kdbx", "test");
        key(K_TAB);
        keys(K_DOWN, 6);
        key(K_ENTER);
        snap("41_drive_confirm");
        key(K_ENTER);
        snap("42_drive_mode");
        CHECK(A.scr == SCR_DRIVE && drive_on && !A.db, "drive mode locked the database");
        key('x');
        key(K_TAB);
        CHECK(A.scr == SCR_DRIVE, "no other screen reachable");
        copy("chacha.kdbx");                       /* "the PC copied a file" */
        key(96);
        CHECK(!drive_on && A.scr == SCR_PICKER && !A.db, "left drive mode");
        int seen = 0;
        for (int i = 0; i < A.ndbs; i++) seen |= !strcmp(A.dbs[i], "chacha.kdbx");
        CHECK(seen, "new file listed after leaving");
    }

    /* key file: Tab opens a file browser (folders first, any file can be chosen, ".." goes up) */
    {
        char kd[600];
        snprintf(kd, sizeof kd, "%s/keys", wdir);
        MKDIR(kd);
        copy_as("key_xml2.keyx", "keys/key_xml2.keyx");
    }
    app_lock(&A);
    int i = 0;
    while (i < A.ndbs && strcmp(A.dbs[i], "keyfile_xml2.kdbx")) i++;
    keys(K_UP, A.sel);
    keys(K_DOWN, i);
    key(K_ENTER);
    CHECK(A.scr == SCR_UNLOCK && !A.keyrel[0], "unlock screen, no key file yet");
    type("test");
    snap("33a_unlock_masked");
    key('e' | K_FN);                                       /* the eye: show what was typed */
    CHECK(A.pw_show, "eye on");
    snap("33b_unlock_visible");
    key('e' | K_FN);
    CHECK(!A.pw_show, "eye off again");
    key('e' | K_FN);
    key(K_TAB);
    CHECK(A.scr == SCR_BROWSE && A.br_n > 5, "browser open (%d entries)", A.br_n);
    snap("33c_browser_root");
    CHECK(A.br_ents[0].dir && !strcmp(A.br_ents[0].name, "keys"), "folders first");
    key(K_ENTER);                                          /* into keys/ */
    CHECK(!strcmp(A.br_dir, "keys") && A.br_n == 1, "inside keys/ (%s, %d)", A.br_dir, A.br_n);
    snap("33d_browser_keys_dir");
    key(K_LEFT);                                           /* back up: lands on the folder we left */
    CHECK(!A.br_dir[0] && A.sel == 0, "up again, folder selected");
    key('`');                                              /* cancel */
    CHECK(A.scr == SCR_UNLOCK && !A.keyrel[0] && !A.pw_show, "cancel keeps no key file, eye reset on the new screen");
    key(K_TAB);
    key(K_ENTER);                                          /* keys/ */
    key(K_DOWN);
    key(K_ENTER);                                          /* ".." is row 0: row 1 is key_xml2.keyx */
    CHECK(A.scr == SCR_UNLOCK && !strcmp(A.keyrel, "keys/key_xml2.keyx"), "key file in a folder chosen: '%s'", A.keyrel);
    key(K_TAB);                                            /* reopens where the key file is, with it selected */
    CHECK(!strcmp(A.br_dir, "keys") && A.sel == 1, "browser starts at the chosen file");
    key('`');
    key(K_BACKSPACE | K_FN);                               /* fn+Backspace: no key file */
    CHECK(!A.keyrel[0], "key file cleared");
    key(K_TAB);
    while (A.sel < A.br_n && strcmp(A.br_ents[A.sel].name, "key_xml2.keyx")) key(K_DOWN);
    key(K_ENTER);
    CHECK(!strcmp(A.keyrel, "key_xml2.keyx"), "key file chosen from the root: '%s'", A.keyrel);
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
    app_tick(&A, 21000 + 6 * 60 * 1000);       /* long idle: the screen went dark and the app locked */
    CHECK(A.power == 2 && !A.db, "dark and locked");
    key(K_UP);                                  /* wakes the screen; nothing sensitive is left to show */
    snap("39_autolocked");
    CHECK(!A.db, "auto-lock");
    app_lock(&A);

    /* a revealed password is shown in full: in the row when it fits, else wrapped over the whole content area */
    {
        static const char *const pws[] = {"Sm4ll-pw-16chars",
                                          "correct-horse-battery-staple-Xk9-2024!",
                                          "zQ7$mW2#pL9@vN4&rT6*yB1^hJ8%cF3!kD5(xG0)aS7+eU2=iO9-nM4_wR6~tY1`uH8|jK3;lZ5:bV0?qP7/xC2.dE9,fA4"
                                          "zQ7$mW2#pL9@vN4&rT6*yB1^hJ8%cF3!kD5(xG0)aS7+eU2=iO9-nM4_wR6~tY1"};
        cfg.large_font = false;
        for (int i = 0; i < 3; i++) {
            app_lock(&A);
            app_init(&A, &PLAT, &cfg);
            open_db("aes_kpxc.kdbx", "test");
            select_title("Gmail");
            key(K_ENTER);
            key('e');
            keys(K_DOWN, 2);
            key(K_ENTER);
            keys(K_BACKSPACE, 200);
            type(pws[i]);
            key(K_ENTER);
            key('s' | K_FN);
            CHECK(strstr(A.msg, "Saved"), "long password saved: %s", A.msg);
            key('`');
            select_title("Gmail");
            key(K_ENTER);
            select_row_kind(1 /* R_PASS */);
            key('r');
            CHECK(A.revealed, "revealed with one press (toggle is the default)");
            char nm[32];
            snprintf(nm, sizeof nm, "10%d_reveal_len%d", 2 + i, (int)strlen(pws[i]));
            snap(nm);
            key('r');
            CHECK(!A.revealed, "second press hides it again");
        }
        app_lock(&A);
    }

    /* Argon2id through the UI, memory in the encrypted swap file (as on the device): progress shown, unlocks */
    {
        char swp[600];
        snprintf(swp, sizeof swp, "%s/.argon2.swp", wdir);
        kdbx_set_argon2_memory(0, swp, 32 * 1024);
        app_lock(&A);
        int before = presents;
        open_db("argon2id_small.kdbx", "test");
        CHECK(A.db && A.scr == SCR_HOME, "Argon2id unlock through swap: %s", A.msg);
        CHECK(presents - before > 3, "Argon2 progress was shown (%d frames)", presents - before);
        snap("106_argon2_home");
        FILE *sw = fopen(swp, "rb");
        CHECK(!sw, "swap file deleted after unlocking");
        if (sw) fclose(sw);
        app_lock(&A);
        open_db("argon2id_small.kdbx", "wrong");
        CHECK(!A.db && strstr(A.msg, "Wrong"), "Argon2 wrong password: %s", A.msg);
        kdbx_set_argon2_memory((size_t)-1, NULL, 0);
        app_lock(&A);
    }

    /* the shared progress screen: percentage, bar, elapsed time, estimate */
    {
        app_lock(&A);
        app_init(&A, &PLAT, &cfg);
        key(K_ENTER);
        CHECK(A.scr == SCR_UNLOCK, "unlock screen for the progress screen test");
        A.progress_t0 = 1000;
        const int steps[] = {1, 37, 100};
        for (int i = 0; i < 3; i++) {
            A.progress = steps[i];
            A.progress_ms = 1000 + (steps[i] == 37 ? 12000 : steps[i] == 100 ? 31000 : 600);
            ap_mark_all(&A);
            char nm[32];
            snprintf(nm, sizeof nm, "105_progress_%d", steps[i]);
            snap(nm);
        }
        ap_progress_end(&A);
        CHECK(A.progress == -1 && A.progress_t0 == 0, "progress reset");
        app_lock(&A);
    }

    /* splash: shown first when on, leaves by timer or any key, never when off, survives a settings round trip */
    {
        cp_settings sc;
        cp_settings_default(&sc);
        sc.animations = false;
        CHECK(sc.splash, "splash is on by default");
        char txt[1024];
        CHECK(cp_settings_format(&sc, txt, sizeof txt) > 0 && strstr(txt, "splash=on"), "splash saved");
        sc.splash = false;
        cp_settings_format(&sc, txt, sizeof txt);
        cp_settings back;
        cp_settings_parse(&back, txt);
        CHECK(!back.splash, "splash=off round trip");
        sc.splash = true;
        app_init(&A, &PLAT, &sc);
        CHECK(A.scr == SCR_SPLASH, "starts on the splash");
        snap("99_splash");
        app_tick(&A, 1000);
        app_tick(&A, 3500);
        CHECK(A.scr == SCR_SPLASH, "still showing after 2.5 s");
        app_tick(&A, 4100);
        CHECK(A.scr == SCR_PICKER, "timer leaves the splash");
        snap("100_after_splash");
        app_init(&A, &PLAT, &sc);
        key('x');
        CHECK(A.scr == SCR_PICKER, "a key skips the splash (and is not typed anywhere)");
        sc.splash = false;
        sc.theme = UI_THEME_DAYLIGHT;
        app_init(&A, &PLAT, &sc);
        CHECK(A.scr == SCR_PICKER, "no splash when off");
        sc.splash = true;
        app_init(&A, &PLAT, &sc);
        snap("101_splash_light");
        app_lock(&A);
    }

    if (ui_overflow) printf("FAIL: %d pixels drawn past the panel edge\n", ui_overflow), failures++;
    printf("render: %d screens -> %s/, %d failures\n", shots, odir, failures);
    return failures != 0;
}
