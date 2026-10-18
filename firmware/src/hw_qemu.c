/* QEMU-only hardware stand-ins (docs/qemu.md). Espressif's QEMU has no SPI master, I2C keyboard, SD card,
 * USB or radio, so in the `qemu` PlatformIO env these replace hw_display/keys/sd/usb/ble/wifi. The app,
 * FreeRTOS, heap, mbedTLS and the KDBX code still run for real on the emulated ESP32-S3; a scripted key
 * sequence drives the UI and prints free/minimum heap at each step. Never part of a release build. */
#ifdef CARDPASS_QEMU
#include <stdio.h>
#include <string.h>
#include "esp_heap_caps.h"
#include "esp_rom_sys.h"
#include "esp_vfs_fat.h"
#include "wear_levelling.h"
#include "hw.h"

#ifdef CARDPASS_QEMU_UI
/* ---- display bridge (env qemu-ui, tools/qemu_view.py). QEMU's serial port runs at ~12 KB/s, far too slow for
 * pixels, so this build (and only this one: the device never has a frame buffer) keeps a copy of the screen in RAM;
 * the viewer reads it straight out of the emulator through QMP (memsave) ~60 times a second. Its address goes out
 * once over serial as "\x02FBADDR <hex>". Keys come back over serial as "k<8 hex digits>" lines. ---- */
#include "driver/uart.h"
static uint16_t strip[UI_W * HW_STRIP_H];
uint16_t qemu_fb[UI_W * UI_H];
void hw_display_init(void)
{
    printf("\x02" "FBADDR %08x\n", (unsigned)(uintptr_t)qemu_fb);
    fflush(stdout);
}
uint16_t *hw_display_strip(void) { return strip; }
void hw_display_push(int y0, int h, uint16_t *px) { memcpy(qemu_fb + y0 * UI_W, px, sizeof(uint16_t) * UI_W * (size_t)h); }
void hw_display_forget(void) {}
#else
/* ---- display: nothing to draw on ---- */
static uint16_t strip[UI_W * HW_STRIP_H];
void hw_display_init(void) {}
uint16_t *hw_display_strip(void) { return strip; }
void hw_display_push(int y0, int h, uint16_t *px) { (void)y0; (void)h; (void)px; }
void hw_display_forget(void) {}
#endif
void hw_display_brightness(int pct) { (void)pct; }
void hw_display_sleep(bool on) { (void)on; }
void hw_display_fade(int pct, int ms) { (void)pct; (void)ms; }

/* ---- keyboard: scripted; a step with key 0 only prints a heap marker ---- */
typedef struct { uint32_t key; const char *mark; } step;
enum { NFILES = 5, STRESS = 30, MAXSTEPS = NFILES * 40 + STRESS * 16 + 40 };
#define SEL_ARGON2 0xFFFFF001u                      /* pseudo key: select zz_argon2.kdbx in the picker */
void qemu_select_db(const char *name);
static step script[MAXSTEPS];
static unsigned nsteps;

static void add(uint32_t key, const char *mark) { script[nsteps].key = key; script[nsteps].mark = mark; nsteps++; }

/* per database: pick it, unlock with "test", search, open an entry, reveal, lock */
__attribute__((unused)) static void build_script(void)
{
    static const char *const names[NFILES] = {"q0200", "q0400", "q0600", "q0800", "q1000"};
    for (int f = 0; f < NFILES; f++) {
        if (f) add(K_DOWN, NULL);                          /* the picker preselects the database opened last */
        add(K_ENTER, NULL);
        add('t', NULL); add('e', NULL); add('s', NULL); add('t', NULL);
        add(K_ENTER, NULL);
        add(0, names[f]);                                 /* heap after opening this database */
        add('a', NULL); add(K_ENTER, NULL);
        add('r', NULL); add(0, "revealed");
        add('e', NULL); add(K_DOWN, NULL); add(K_DOWN, NULL); add(K_DOWN, NULL);   /* edit the URL, save */
        add(K_ENTER, NULL); add('x', NULL); add(K_ENTER, NULL);
        add('s' | K_FN, NULL);
        add(0, "saved");
        add(K_ESC, NULL); add(K_ESC, NULL); add(K_ESC, NULL);
        add('l' | K_FN, NULL);
        add(0, "locked");
    }
    /* leak stress on the real firmware: unlock, use, lock, 30 times; free heap must come back to the same number */
    for (int c = 0; c < STRESS; c++) {
        add(0, c == 0 ? "stress_start" : (c % 10 == 0 ? "stress_cycle_x10" : NULL));
        add(K_ENTER, NULL);
        add('t', NULL); add('e', NULL); add('s', NULL); add('t', NULL);
        add(K_ENTER, NULL);
        add('a', NULL); add(K_ENTER, NULL);
        add('r', NULL); add('r', NULL);
        add(K_ESC, NULL); add(K_ESC, NULL);
        add('l' | K_FN, NULL);
    }
    add(0, "stress_end");
    /* Argon2id, 512 KiB: over the 128 KiB RAM limit, so through the encrypted swap file on the FAT card */
    add(SEL_ARGON2, NULL);
    add(K_ENTER, NULL);
    add('t', NULL); add('e', NULL); add('s', NULL); add('t', NULL);
    add(K_ENTER, NULL);
    add(0, "argon2_unlocked");
    add('a', NULL); add(K_ENTER, NULL); add('r', NULL); add('r', NULL);
    add(K_ESC, NULL); add(K_ESC, NULL);
    add('l' | K_FN, NULL);
    add(0, "argon2_locked");
    add(0, "DONE");
}

const char *qemu_state(int *scr, int *open);
__attribute__((unused)) static void report(const char *what)
{
    int scr, open;
    const char *msg = qemu_state(&scr, &open);
    esp_rom_printf("QEMU   screen=%d db_open=%d msg=\"%s\"\n", scr, open, msg);
    esp_rom_printf("QEMU %s heap=%u min=%u largest=%u\n", what, (unsigned)esp_get_free_heap_size(),
                   (unsigned)esp_get_minimum_free_heap_size(), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    if (!strcmp(what, "stress_end"))
        esp_rom_printf("QEMU heap integrity: %s\n", heap_caps_check_integrity_all(true) ? "OK" : "CORRUPT");
}

#ifdef CARDPASS_QEMU_UI
void hw_keys_init(void) { uart_driver_install(UART_NUM_0, 1024, 0, 0, NULL, 0); }
void hw_keys_flush(void) {}
void hw_keys_poll(void (*on_key)(uint32_t, bool), uint32_t now_ms)
{
    static char line[16];
    static int n;
    uint8_t c;
    (void)now_ms;
    while (uart_read_bytes(UART_NUM_0, &c, 1, 0) == 1) {
        if (c == '\n' || c == '\r') {
            line[n] = 0;
            unsigned key = 0;
            if (n == 9 && line[0] == 'k' && sscanf(line + 1, "%8x", &key) == 1) { on_key(key, true); on_key(key, false); }
            n = 0;
        } else if (n < (int)sizeof line - 1) {
            line[n++] = (char)c;
        }
    }
}
#else
void hw_keys_init(void) {}
void hw_keys_flush(void) {}
void hw_keys_poll(void (*on_key)(uint32_t, bool), uint32_t now_ms)
{
    static unsigned i;
    static uint32_t next = 2000;
    if (!nsteps) build_script();
    if (i >= nsteps || now_ms < next) return;
    const step *s = &script[i++];
    next = now_ms + 150;
    if (!s->key) { if (s->mark) report(s->mark); return; }
    if (s->key == SEL_ARGON2) { qemu_select_db("zz_argon2.kdbx"); return; }
    on_key(s->key, true);
    on_key(s->key, false);
}
#endif

/* ---- SD card: the "storage" partition (FAT image built on the PC) mounted at /sd ---- */
static bool mounted;
bool hw_sd_mount(void)
{
    if (mounted) return true;
    esp_vfs_fat_mount_config_t mc = {.format_if_mount_failed = false, .max_files = 4, .allocation_unit_size = 4096};
    static wl_handle_t wl = WL_INVALID_HANDLE;
    mounted = esp_vfs_fat_spiflash_mount_rw_wl(HW_SD_ROOT, "storage", &mc, &wl) == ESP_OK;
    return mounted;
}
void hw_sd_unmount(void) { mounted = false; }
bool hw_sd_ok(void) { return mounted; }
sdmmc_card_t *hw_sd_raw_open(void) { return NULL; }
void hw_sd_raw_close(void) {}

/* ---- USB / Bluetooth / Wi-Fi: absent ---- */
bool hw_usb_init(void) { return true; }
bool hw_usb_drive(bool enter) { (void)enter; return false; }
bool hw_usb_ready(void) { return false; }
void hw_usb_stroke(uint8_t key, uint8_t mods) { (void)key; (void)mods; }
bool hw_usb_fido_recv(uint8_t report[64]) { (void)report; return false; }
void hw_usb_fido_send(const uint8_t report[64]) { (void)report; }
bool hw_ble_start(void) { return false; }
void hw_ble_stop(void) {}
int hw_ble_state(uint32_t *code) { if (code) *code = 0; return BT_OFF; }
void hw_ble_answer(bool accept) { (void)accept; }
void hw_ble_forget(void) {}
bool hw_ble_ready(void) { return false; }
void hw_ble_stroke(uint8_t key, uint8_t mods) { (void)key; (void)mods; }
int hw_vc_mount(const char *path, const uint8_t *pw, size_t pwlen, bool allow_outer_write, void (*progress)(void *, int), void *arg)
{
    (void)path; (void)pw; (void)pwlen; (void)allow_outer_write; (void)progress; (void)arg;
    return 2;
}
void hw_vc_unmount(void) {}
int hw_wifi_scan(app_ap *out, int max) { (void)out; (void)max; return 0; }
int hw_ntp_sync(const char *ssid, const char *pass, int64_t *unix_s) { (void)ssid; (void)pass; (void)unix_s; return NTP_ERR_CONNECT; }
#endif
