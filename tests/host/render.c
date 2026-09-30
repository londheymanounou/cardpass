/* Host render harness: drives the real app with scripted keys, simulates the
 * panel (only dirty strips are redrawn, like the device), checks the result
 * equals a full redraw, and writes PNGs (1x and 3x) to <out>/.
 *   render <testdata dir> <out dir> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "app.h"
#include "miniz.h"

#define STRIP 16
static const char *tdir, *odir;
static uint16_t panel[UI_W * UI_H];
static int failures, shots;

/* ---- platform stubs ---- */
static int list_dbs(void *c, char names[][64], int max)
{
    (void)c;
    static const char *n[] = {"aes_kpxc.kdbx", "argon2.kdbx", "big1000.kdbx", "passkeys.kdbx", "chacha.kdbx"};
    int k = 0;
    for (; k < 5 && k < max; k++) snprintf(names[k], 64, "%s", n[k]);
    return k;
}
static void db_path(void *c, const char *name, char *out, size_t n) { (void)c; snprintf(out, n, "%s/%s", tdir, name); }
static bool time_valid = true;
static int64_t now_s = 1790000000;
static int64_t now_fn(void *c, bool *valid) { (void)c; *valid = time_valid; return now_s; }
static int battery(void *c) { (void)c; return 76; }
static const app_platform PLAT = {list_dbs, db_path, now_fn, battery, NULL};

static void draw_band(app *a, uint16_t *dst, int y0, int y1)
{
    static uint16_t buf[UI_W * STRIP];
    for (int y = y0; y < y1; y += STRIP) {
        ui_strip s = {buf, y, y1 - y < STRIP ? y1 - y : STRIP};
        app_draw(a, &s);
        memcpy(dst + y * UI_W, buf, sizeof(uint16_t) * UI_W * (size_t)s.h);
    }
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

static void snap(app *a, const char *name)
{
    int y0, y1;
    while (app_dirty(a, &y0, &y1)) draw_band(a, panel, y0, y1);
    static uint16_t full[UI_W * UI_H];
    draw_band(a, full, 0, UI_H);
    if (memcmp(full, panel, sizeof full)) {
        failures++;
        printf("FAIL %s: partial redraw differs from a full redraw\n", name);
        write_png("MISMATCH_full", full, 3);
    }
    write_png(name, panel, 1);
    write_png(name, panel, 3);
    shots++;
}

static void key(app *a, uint32_t k) { app_key(a, k, true); app_key(a, k, false); }
static void type(app *a, const char *s)
{
    while (*s) key(a, ui_utf8_next(&s));
}
static void keys(app *a, uint32_t k, int n) { while (n--) key(a, k); }

int main(int argc, char **argv)
{
    tdir = argc > 1 ? argv[1] : "testdata";
    odir = argc > 2 ? argv[2] : "renders";
    static app a;
    app_settings set = {&ui_dark, &ui_font_small, false, 5 * 60 * 1000, 120};

    app_init(&a, &PLAT, &set);
    snap(&a, "01_picker");
    key(&a, K_ENTER);
    snap(&a, "02_unlock");
    type(&a, "wrong`pw");
    snap(&a, "03_typing");
    key(&a, K_ENTER);
    snap(&a, "04_wrong_password");
    type(&a, "test");
    key(&a, K_ENTER);
    snap(&a, "05_home");
    keys(&a, K_DOWN, 3);
    snap(&a, "06_home_down3");
    keys(&a, K_UP, 2);
    key(&a, K_ENTER); /* second favorite: Gmail */
    snap(&a, "07_entry");
    key(&a, K_DOWN);
    app_key(&a, 'r', true);
    snap(&a, "08_entry_revealed");
    app_key(&a, 'r', false);
    keys(&a, K_DOWN, 2);
    snap(&a, "09_entry_totp");
    now_s += 25;
    app_tick(&a, 25000);
    snap(&a, "10_entry_totp_later");
    keys(&a, K_DOWN, 8);
    snap(&a, "11_entry_scrolled");
    /* QR codes: tools/check_qr.py decodes these PNGs with OpenCV */
    keys(&a, K_UP, 8);
    keys(&a, K_UP, 2); /* Password (TOTP was row 3) */
    key(&a, 'q');
    snap(&a, "qr_password");
    key(&a, ' ');
    snap(&a, "qr_closed");
    key(&a, K_DOWN);
    key(&a, 'q');
    snap(&a, "qr_url");
    app_tick(&a, 25000 + 21000); /* times out */
    snap(&a, "qr_timed_out");
    key(&a, K_DOWN);
    key(&a, 'q');
    snap(&a, "qr_totp");
    key(&a, ' ');
    keys(&a, K_UP, 2);
    key(&a, '`');
    type(&a, "caf");
    snap(&a, "12_search_caf");
    key(&a, K_ESC);
    type(&a, "bank");
    key(&a, K_ENTER);
    snap(&a, "13_entry_attachments");
    keys(&a, K_DOWN, 6);
    snap(&a, "14_entry_notes");
    keys(&a, K_UP, 8);
    snap(&a, "14b_entry_notes_end");
    key(&a, 'l' | K_FN);
    snap(&a, "15_locked");

    key(&a, K_DOWN);
    key(&a, K_ENTER);
    type(&a, "test");
    key(&a, K_ENTER);
    snap(&a, "16_argon2_rejected");
    key(&a, K_ESC);
    key(&a, K_DOWN);
    key(&a, K_ENTER);
    type(&a, "test");
    key(&a, K_ENTER);
    snap(&a, "17_big1000_home");
    keys(&a, K_DOWN, 25);
    snap(&a, "18_big1000_scrolled");
    type(&a, "ste 42");
    snap(&a, "19_big1000_search");
    key(&a, 'l' | K_FN);

    keys(&a, K_DOWN, 3);
    key(&a, K_ENTER);
    type(&a, "test");
    key(&a, K_ENTER);
    type(&a, "alice");
    key(&a, K_ENTER);
    snap(&a, "20_passkey_entry");
    key(&a, 'l' | K_FN);

    /* light theme, large font, time not set */
    set.theme = &ui_light;
    set.font = &ui_font_large;
    app_init(&a, &PLAT, &set);
    key(&a, K_ENTER);
    type(&a, "test");
    key(&a, K_ENTER);
    snap(&a, "21_light_large_home");
    key(&a, K_ENTER);
    time_valid = false;
    keys(&a, K_DOWN, 3);
    snap(&a, "22_light_large_entry_no_time");
    time_valid = true;

    /* auto-lock */
    app_tick(&a, 25000 + 6 * 60 * 1000);
    snap(&a, "23_autolocked");
    app_lock(&a);

    if (ui_overflow) printf("FAIL: %d pixels drawn past the panel edge\n", ui_overflow), failures++;
    printf("render: %d screens -> %s/, %d failures\n", shots, odir, failures);
    return failures != 0;
}
