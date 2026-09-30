/* CardPass firmware entry: platform glue between the portable app (components/ui) and the
 * Cardputer ADV hardware. Everything the app needs comes through app_platform. */
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "app.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "hw.h"
#include "nvs_flash.h"

static app A;

/* ---- platform callbacks ---- */

static int by_name(const void *x, const void *y) { return strcmp(x, y); }

/* Database folder first (/sd/cardpass), then the card root, so a file dropped anywhere is found. */
static int scan(const char *dir, const char *ext, char names[][64], int n, int max)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    size_t el = strlen(ext);
    int start = n;
    while (d && (e = readdir(d)) && n < max) {
        size_t l = strlen(e->d_name);
        if (l <= el || l >= 64 || e->d_name[0] == '.' || strcasecmp(e->d_name + l - el, ext)) continue;
        bool dup = false;
        for (int i = 0; i < n; i++) dup |= !strcmp(names[i], e->d_name);
        if (!dup) memcpy(names[n], e->d_name, l + 1), n++;   /* l < 64 checked above */
    }
    if (d) closedir(d);
    qsort(names + start, (size_t)(n - start), 64, by_name);
    return n;
}

static int list_files(void *ctx, const char *ext, char names[][64], int max)
{
    if (!hw_sd_mount()) return 0;
    int n = scan(HW_DB_DIR, ext, names, 0, max);
    return scan(HW_SD_ROOT, ext, names, n, max);
}

static void path_fn(void *ctx, const char *name, char *out, size_t n)
{
    struct stat st;
    snprintf(out, n, "%s/%s", HW_DB_DIR, name);
    if (stat(out, &st) == 0) return;
    snprintf(out, n, "%s/%s", HW_SD_ROOT, name);
    if (stat(out, &st) != 0) snprintf(out, n, "%s/%s", HW_DB_DIR, name); /* new file: goes in the folder */
}

static int64_t now_fn(void *ctx, bool *valid)
{
    int64_t t;
    *valid = hw_time_get(&t);
    return t;
}

static uint32_t millis_fn(void *ctx) { return hw_millis(); }
static int battery_fn(void *ctx) { return hw_battery_percent(); }
static bool hid_ready(void *ctx) { return hw_usb_ready(); }               /* BLE HID: later */
static void stroke(void *ctx, uint8_t key, uint8_t mods) { hw_usb_stroke(key, mods); }
static void delay_ms(void *ctx, int ms) { vTaskDelay(pdMS_TO_TICKS(ms > 0 ? ms : 1)); }

static void save_settings(void *ctx, const char *text)
{
    hw_settings_save(text);
    cp_settings s;
    cp_settings_parse(&s, text);
    hw_display_brightness(s.brightness);
}

/* Draw and push whatever changed, band by band (no full framebuffer exists). */
static void present(void *ctx)
{
    int y0, y1;
    while (app_dirty(&A, &y0, &y1)) {
        for (int y = y0; y < y1; y += HW_STRIP_H) {
            ui_strip s = {hw_display_strip(), y, y1 - y < HW_STRIP_H ? y1 - y : HW_STRIP_H};
            app_draw(&A, &s);
            hw_display_push(y, s.h, s.px);
        }
    }
    vTaskDelay(1); /* let the idle task and watchdog run during long operations (KDF, save) */
}

static void on_key(uint32_t key, bool down) { app_key(&A, key, down); }

/* ---- passkeys over USB (CTAPHID): reports are queued by the USB task, handled here ---- */
static ctaphid HID;
static bool fido_modal;
static uint32_t keepalive_at;

static void usb_send(void *ctx, const uint8_t report[64]) { hw_usb_fido_send(report); }

static int fido_choose(void *ctx, const char *rp, const fido_cred *creds, size_t n)
{
    fido_modal = true;
    keepalive_at = 0;
    int r = app_ask_passkey(&A, rp, creds, n);
    fido_modal = false;
    return r;
}

/* One pass of the device loop; also what modal screens (passkey confirmation) run while they wait. */
static void pump(void *ctx)
{
    uint32_t now = hw_millis();
    hw_keys_poll(on_key, now);
    app_tick(&A, now);
    present(NULL);
    if (fido_modal && (int32_t)(now - keepalive_at) >= 0) {     /* tell the browser we are waiting for the user */
        ctaphid_keepalive(&HID, usb_send, NULL);
        keepalive_at = now + 100;
    }
    vTaskDelay(pdMS_TO_TICKS(10));
}

static const app_platform PLATFORM = {list_files, path_fn, now_fn, millis_fn, battery_fn, hid_ready, stroke, delay_ms,
                                      save_settings, present, pump, NULL};

void app_main(void)
{
    esp_err_t e = nvs_flash_init();
    if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) { /* launchers may wipe or share NVS */
        nvs_flash_erase();
        nvs_flash_init();
    }
    hw_display_init();
    hw_keys_init();
    hw_sd_mount();
    hw_usb_init();
    ctaphid_init(&HID);

    char text[512];
    cp_settings cfg;
    hw_settings_load(text, sizeof text);
    cp_settings_parse(&cfg, text);
    hw_display_brightness(cfg.brightness);

    app_init(&A, &PLATFORM, &cfg);
    present(NULL);
    for (;;) {
        pump(NULL);
        uint8_t report[64];
        while (hw_usb_fido_recv(report)) {
            fido_env env = {A.db, fido_choose, NULL};    /* db NULL while locked: requests are refused */
            ctaphid_report(&HID, report, &env, usb_send, NULL);
        }
    }
}
