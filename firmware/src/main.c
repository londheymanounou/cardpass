/* CardPass firmware entry: platform glue between the portable app (components/ui) and the
 * Cardputer ADV hardware. Everything the app needs comes through app_platform. */
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "app.h"
#include "esp_system.h"
#include "esp_timer.h"
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
/* Typing goes over Bluetooth when a host is connected (the user switched it on), else over USB. */
static bool hid_ready(void *ctx) { return hw_ble_ready() || hw_usb_ready(); }
static void stroke(void *ctx, uint8_t key, uint8_t mods)
{
    if (hw_ble_ready()) hw_ble_stroke(key, mods);
    else hw_usb_stroke(key, mods);
}
static bool bt_start_fn(void *ctx) { return hw_ble_start(); }
static void bt_stop_fn(void *ctx) { hw_ble_stop(); }
static int bt_state_fn(void *ctx, uint32_t *code) { return hw_ble_state(code); }
static void bt_answer_fn(void *ctx, bool ok) { hw_ble_answer(ok); }
static void bt_forget_fn(void *ctx) { hw_ble_forget(); }

/* "rel" is relative to the SD root, except VC_ROOT[/...]: that is the mounted VeraCrypt container */
static void real_path(const char *rel, char *out, size_t n)
{
    size_t l = strlen(VC_ROOT);
    if (!strncmp(rel, VC_ROOT, l) && (!rel[l] || rel[l] == '/')) snprintf(out, n, HW_VC_MOUNT "%s", rel + l);
    else snprintf(out, n, rel[0] ? HW_SD_ROOT "/%s" : HW_SD_ROOT "%.0s", rel);
}

/* file browser: folders relative to the SD root, no hidden entries */
static int list_dir(void *ctx, const char *rel, app_dirent *out, int max)
{
    char dir[160];
    real_path(rel, dir, sizeof dir);
    DIR *d = opendir(dir);
    int n = 0;
    struct dirent *e;
    while (d && (e = readdir(d)) && n < max) {
        size_t l = strlen(e->d_name);
        if (e->d_name[0] == '.' || l >= sizeof out[0].name || !strcmp(e->d_name, "System Volume Information")) continue;
        char full[sizeof dir + 1 + 256];                 /* d_name can be 255 bytes */
        struct stat st;
        snprintf(full, sizeof full, "%s/%s", dir, e->d_name);
        if (stat(full, &st)) continue;
        memcpy(out[n].name, e->d_name, l + 1);
        out[n].dir = S_ISDIR(st.st_mode);
        out[n].size = out[n].dir ? 0 : (uint32_t)st.st_size;
        n++;
    }
    if (d) closedir(d);
    return n;
}
static void root_path(void *ctx, const char *rel, char *out, size_t n) { real_path(rel, out, n); }
static int vc_mount(void *ctx, const char *rel, const uint8_t *pw, size_t pwlen, bool allow_outer_write, void (*progress)(void *, int), void *arg)
{
    char path[200];
    real_path(rel, path, sizeof path);
    return hw_vc_mount(path, pw, pwlen, allow_outer_write, progress, arg);
}
static void vc_unmount(void *ctx) { hw_vc_unmount(); }
static void start_dir(void *ctx, char *out, size_t n) { snprintf(out, n, "%s", HW_DB_DIR + strlen(HW_SD_ROOT) + 1); }
static void delay_ms(void *ctx, int ms) { vTaskDelay(pdMS_TO_TICKS(ms > 0 ? ms : 1)); }

static bool animations = true;   /* Settings -> Animations: fade the backlight */
static int brightness = 60;      /* settings value; the backlight state (normal/dim/off) scales it */

static void save_settings(void *ctx, const char *text)
{
    hw_settings_save(text);
    cp_settings s;
    cp_settings_parse(&s, text);
    brightness = s.brightness;
    animations = s.animations;
    hw_display_brightness(brightness);
}

/* Draw and push whatever changed, band by band (no full framebuffer exists). */
static void present(void *ctx)
{
    static bool was_open;
    if (was_open && !A.db) hw_display_forget();          /* locked: no fingerprint of unlocked screens survives */
    was_open = A.db != NULL;
    int y0, y1;
#ifdef CARDPASS_QEMU_UI
    int64_t frame_t0 = esp_timer_get_time();
    int frame_strips = 0;
#endif
    while (app_dirty(&A, &y0, &y1)) {
        for (int y = y0 / HW_STRIP_H * HW_STRIP_H; y < y1; y += HW_STRIP_H) {   /* whole grid strips: comparable */
            ui_strip s = {hw_display_strip(), y, UI_H - y < HW_STRIP_H ? UI_H - y : HW_STRIP_H};
            app_draw(&A, &s);
            hw_display_push(y, s.h, s.px);
#ifdef CARDPASS_QEMU_UI
            frame_strips++;
#endif
        }
    }
#ifdef CARDPASS_QEMU_UI
    if (frame_strips) printf("\x02" "FT %d %d\n", (int)(esp_timer_get_time() - frame_t0), frame_strips);   /* viewer: emulated frame time */
#endif
    vTaskDelay(1); /* 1 ms: let the idle task and watchdog run during long operations (KDF, save) */
}

static void on_key(uint32_t key, bool down) { app_key(&A, key, down); }
bool hw_keys_fn_arrows(void) { return A.cfg.fn_arrows; }

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
    hw_keys_poll(on_key, hw_millis());
    uint32_t now = hw_millis();   /* again: a key may have run for seconds (unlock, lock) */
    app_tick(&A, now);
    present(NULL);
    if (fido_modal && (int32_t)(now - keepalive_at) >= 0) {     /* tell the browser we are waiting for the user */
        ctaphid_keepalive(&HID, usb_send, NULL);
        keepalive_at = now + 100;
    }
    /* Paced loop: one pass per 16 ms frame (62.5 Hz: animations at 60 fps, keys read at that rate), 50 ms while the
     * screen is dark. vTaskDelayUntil keeps the rhythm whatever the frame cost (it never waits when a frame overran). */
    static TickType_t last;
    if (!last) last = xTaskGetTickCount();
    vTaskDelayUntil(&last, pdMS_TO_TICKS(A.power == 2 ? 50 : 16));
}

static bool usb_drive(void *ctx, bool enter) { return hw_usb_drive(enter); }
static void set_time_fn(void *ctx, int64_t t) { hw_time_set(t); }

static void backlight_fn(void *ctx, int state)
{
    int target = state == 1 ? (brightness < 8 ? brightness : 8) : brightness;
    if (state == 2) {                                            /* fade out, then switch the panel off */
        if (animations) { hw_display_fade(0, 250); vTaskDelay(pdMS_TO_TICKS(260)); }
        hw_display_sleep(true);
    } else {
        hw_display_sleep(false);                                 /* panel on; backlight ramps from where it was */
        if (animations) hw_display_fade(target, state == 0 ? 150 : 250);
        else hw_display_brightness(target);
    }
    hw_power_boost(state == 0);                                  /* full speed only while the user is active */
}
static void shutdown_fn(void *ctx) { hw_display_sleep(true); hw_deep_sleep(); }
/* Wi-Fi only while locked: enforced here as well as in the app (PLAN.md section 2). */
static int wifi_scan_fn(void *ctx, app_ap *out, int max) { return A.db ? 0 : hw_wifi_scan(out, max); }
static int ntp_sync_fn(void *ctx, const char *ssid, const char *pass, int64_t *t)
{
    return A.db ? NTP_ERR_CONNECT : hw_ntp_sync(ssid, pass, t);
}

static const app_platform PLATFORM = {list_files, path_fn, now_fn, millis_fn, battery_fn, hid_ready, stroke, delay_ms,
                                      save_settings, present, pump, usb_drive, backlight_fn, shutdown_fn, set_time_fn, wifi_scan_fn,
                                      ntp_sync_fn, bt_start_fn, bt_stop_fn, bt_state_fn, bt_answer_fn, bt_forget_fn, list_dir, root_path, start_dir, vc_mount, vc_unmount, NULL};

#ifdef CARDPASS_QEMU          /* QEMU debug build only (docs/qemu.md): progress + heap, no secrets */
#include "esp_rom_sys.h"
#include "esp_heap_caps.h"
void qemu_select_db(const char *name) { for (int i = 0; i < A.ndbs; i++) if (!strcmp(A.dbs[i], name)) A.sel = i; }
const char *qemu_state(int *scr, int *open) { *scr = A.scr; *open = A.db != NULL; return A.msg; }
#define MARK(n) esp_rom_printf("QEMU %s heap=%u min=%u\n", n, (unsigned)esp_get_free_heap_size(), (unsigned)esp_get_minimum_free_heap_size())
#else
#define MARK(n) ((void)0)
#endif

void app_main(void)
{
    MARK("start");
    bool aes_ok = hw_aes_selftest();                 /* accelerated AES-KDF only if it matches the portable loop */
    if (aes_ok) kdbx_set_kdf_accel(hw_aes_kdf_accel);
    /* Argon2: up to 128 KiB in RAM, anything bigger in an encrypted swap file on the card (one-time key) */
    kdbx_set_argon2_memory(128 * 1024, HW_DB_DIR "/.argon2.swp", 32 * 1024);
    kdbx_set_idle_hook(hw_yield_if_due);
#ifdef CARDPASS_QEMU
    {
        uint8_t sd[32] = {1, 2, 3}, in[32] = {9, 8, 7}, o1[32], o2[32];
        int64_t t0 = esp_timer_get_time();
        kdbx_set_kdf_accel(NULL);
        kdbx_aes_kdf(sd, 3000, in, o1);
        int64_t t1 = esp_timer_get_time();
        kdbx_set_kdf_accel(hw_aes_kdf_accel);
        kdbx_aes_kdf(sd, 3000, in, o2);
        int64_t t2 = esp_timer_get_time();
        esp_rom_printf("QEMU aes-kdf selftest=%d match=%d portable=%d us accelerated=%d us (3000 rounds)\n", aes_ok, !memcmp(o1, o2, 32), (int)(t1 - t0), (int)(t2 - t1));
        if (!aes_ok) kdbx_set_kdf_accel(NULL);
    }
#endif
    esp_err_t e = nvs_flash_init();
    if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) { /* launchers may wipe or share NVS */
        nvs_flash_erase();
        nvs_flash_init();
    }
    MARK("nvs");
    hw_display_init();
    MARK("display");
    hw_keys_init();
    MARK("keys");
    hw_sd_mount();
    remove(HW_DB_DIR "/.argon2.swp");              /* left by a power cut mid-unlock: unreadable (key gone), just space */
    MARK("sd");
    hw_usb_init();
    MARK("usb");
    ctaphid_init(&HID);

    char text[2048];
    cp_settings cfg;
    hw_settings_load(text, sizeof text);
    cp_settings_parse(&cfg, text);
#if defined(CARDPASS_QEMU) && !defined(CARDPASS_QEMU_UI)
    cfg.splash = false;                              /* the scripted keys start at the picker */
#endif
    brightness = cfg.brightness;
    animations = cfg.animations;
    hw_display_brightness(brightness);
    hw_power_init();
    MARK("power");

    app_init(&A, &PLATFORM, &cfg);
    MARK("app_init");
    present(NULL);
    MARK("present");
    for (;;) {
        pump(NULL);
        uint8_t report[64];
        while (hw_usb_fido_recv(report)) {
            fido_env env = {A.db, fido_choose, NULL};    /* db NULL while locked: requests are refused */
            ctaphid_report(&HID, report, &env, usb_send, NULL);
        }
    }
}
