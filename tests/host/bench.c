/* Rendering benchmark: full-frame redraws (all strips, 16 rows each, like the device) of real screens, averaged.
 * Build twice to see what the renderer's fast paths buy: normally, and with -DUI_NAIVE (gfx.c then uses a binary
 * search for every glyph, a full blend per anti-aliased pixel and per-pixel fills).
 *   bench <testdata dir> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../../components/ui/app_priv.h"

static app A;
static char wdir[512];
static uint32_t ms;
static int list_files(void *c, const char *ext, char names[][64], int max)
{
    (void)c; (void)ext; (void)max;
    snprintf(names[0], 64, "aes_kpxc.kdbx");
    return 1;
}
static void path_fn(void *c, const char *name, char *out, size_t n) { (void)c; snprintf(out, n, "%s/%s", wdir, name); }
static int64_t now_fn(void *c, bool *valid) { (void)c; *valid = true; return 1790000000; }
static uint32_t millis_fn(void *c) { (void)c; return ms; }
static int battery(void *c) { (void)c; return 76; }
static bool hid_ready(void *c) { (void)c; return true; }
static void stroke(void *c, uint8_t k, uint8_t m) { (void)c; (void)k; (void)m; }
static void delay_fn(void *c, int d) { (void)c; (void)d; }
static void save_settings(void *c, const char *t) { (void)c; (void)t; }
static void present(void *c) { (void)c; }
static void pump_fn(void *c) { (void)c; }
static bool usb_drive(void *c, bool e) { (void)c; (void)e; return true; }
static void backlight_fn(void *c, int s) { (void)c; (void)s; }
static void shutdown_fn(void *c) { (void)c; }
static void set_time_fn(void *c, int64_t t) { (void)c; (void)t; }
static int wifi_scan_fn(void *c, app_ap *o, int m) { (void)c; (void)o; (void)m; return 0; }
static int ntp_fn(void *c, const char *a, const char *b, int64_t *t) { (void)c; (void)a; (void)b; (void)t; return NTP_ERR_CONNECT; }
static bool bt_start_fn(void *c) { (void)c; return false; }
static void bt_stop_fn(void *c) { (void)c; }
static int bt_state_fn(void *c, uint32_t *code) { (void)c; if (code) *code = 0; return BT_OFF; }
static void bt_answer_fn(void *c, bool ok) { (void)c; (void)ok; }
static void bt_forget_fn(void *c) { (void)c; }
static int list_dir_fn(void *c, const char *r, app_dirent *o, int m) { (void)c; (void)r; (void)o; (void)m; return 0; }
static void root_path_fn(void *c, const char *r, char *o, size_t n) { (void)c; snprintf(o, n, "%s/%s", wdir, r); }
static void start_dir_fn(void *c, char *o, size_t n) { (void)c; if (n) o[0] = 0; }
static const app_platform PLAT = {list_files, path_fn, now_fn, millis_fn, battery, hid_ready, stroke, delay_fn, save_settings, present,
                                  pump_fn, usb_drive, backlight_fn, shutdown_fn, set_time_fn, wifi_scan_fn, ntp_fn, bt_start_fn,
                                  bt_stop_fn, bt_state_fn, bt_answer_fn, bt_forget_fn, list_dir_fn, root_path_fn, start_dir_fn, NULL};

static void key(uint32_t k) { app_key(&A, k, true); app_key(&A, k, false); }
static void type(const char *s) { while (*s) key(ui_utf8_next(&s)); }

static double frame_us(int frames)
{
    static uint16_t buf[UI_W * 16];
    unsigned sink = 0;
    clock_t t0 = clock();
    for (int f = 0; f < frames; f++)
        for (int y = 0; y < UI_H; y += 16) {
            ui_strip s = {buf, y, UI_H - y < 16 ? UI_H - y : 16};
            app_draw(&A, &s);
            sink += buf[UI_W + 7];
        }
    double us = (double)(clock() - t0) * 1e6 / CLOCKS_PER_SEC / frames;
    return sink == 12345 ? us + 1e-9 : us;          /* keep the work observable */
}

int main(int argc, char **argv)
{
    snprintf(wdir, sizeof wdir, "%s", argc > 1 ? argv[1] : "testdata");
    cp_settings cfg;
    cp_settings_default(&cfg);
    cfg.splash = cfg.animations = false;
    const int N = 4000;
    for (int large = 0; large < 2; large++) {
        cfg.large_font = large;
        app_init(&A, &PLAT, &cfg);
        printf("%s text\n", large ? "large" : "normal");
        printf("  %-10s %7.1f us/frame\n", "picker", frame_us(N));
        key(K_ENTER);
        type("test");
        printf("  %-10s %7.1f us/frame\n", "unlock", frame_us(N));
        key(K_ENTER);
        printf("  %-10s %7.1f us/frame\n", "home", frame_us(N));
        type("gm");
        key(K_ENTER);
        printf("  %-10s %7.1f us/frame\n", "entry", frame_us(N));
        key('`');
        key(K_ESC);
        key(K_TAB);
        for (int i = 0; i < 4; i++) key(K_DOWN);
        key(K_ENTER);
        printf("  %-10s %7.1f us/frame\n", "settings", frame_us(N));
        app_lock(&A);
    }
    cfg.large_font = false;
    cfg.splash = true;
    app_init(&A, &PLAT, &cfg);
    printf("  %-10s %7.1f us/frame (Plex 21 + superellipse + logo)\n", "splash", frame_us(N / 4));
    return 0;
}
