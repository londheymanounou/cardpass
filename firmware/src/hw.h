/* Cardputer ADV hardware layer (ESP-IDF). Pins are the ones verified in the sibling
 * firmware (SD) or taken from M5GFX / M5Unified for the ADV (display, keyboard, battery):
 * anything marked "unverified" in docs/first-hardware.md needs a first look on the device. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "app.h"
#include "sdmmc_cmd.h"

/* display: 240x135 landscape ST7789, pushed in strips */
void hw_display_init(void);
uint16_t *hw_display_strip(void);                        /* DMA-capable UI_W x STRIP_H buffer */
#define HW_STRIP_H 16
void hw_display_push(int y0, int h, uint16_t *px);        /* px is RGB565, byte-swapped in place */
void hw_display_brightness(int pct);
void hw_display_sleep(bool on);
void hw_display_fade(int pct, int ms);                   /* non-blocking backlight ramp */

/* power: CPU 240 MHz while the user is active (boost), 80 MHz when idle; deep sleep for a dead battery */
void hw_power_init(void);
void hw_power_boost(bool on);
void hw_deep_sleep(void);                                 /* does not return; woken by the keyboard */

/* keyboard (TCA8418): delivers app key codes (see app.h) */
void hw_keys_init(void);
void hw_keys_poll(void (*on_key)(uint32_t key, bool down), uint32_t now_ms);
void hw_keys_flush(void);                                 /* drop pending events, release INT (before deep sleep) */

/* SD card */
bool hw_sd_mount(void);
void hw_sd_unmount(void);
bool hw_sd_ok(void);
/* Raw card access for USB drive mode: only while FAT is unmounted (hw_sd_unmount first). */
sdmmc_card_t *hw_sd_raw_open(void);
void hw_sd_raw_close(void);
#define HW_SD_ROOT "/sd"
#define HW_DB_DIR "/sd/cardpass"

/* USB device: HID keyboard + FIDO HID */
bool hw_usb_init(void);
/* USB drive mode (PLAN.md stage 4): the SD card becomes a mass-storage drive for the PC and
 * nothing else is exposed. Enter: FAT unmounted first. Leave: FAT remounted (rescan the files). */
bool hw_usb_drive(bool enter);
bool hw_usb_ready(void);                                  /* enumerated and not suspended */
void hw_usb_stroke(uint8_t key, uint8_t mods);
bool hw_usb_fido_recv(uint8_t report[64]);                /* non-blocking */
void hw_usb_fido_send(const uint8_t report[64]);

/* Bluetooth LE keyboard: radio on only between start and stop; HID reports only over an authenticated link */
bool hw_ble_start(void);
void hw_ble_stop(void);
int hw_ble_state(uint32_t *code);                         /* BT_* from app.h + pairing code */
void hw_ble_answer(bool accept);                          /* numeric comparison */
void hw_ble_forget(void);
bool hw_ble_ready(void);
void hw_ble_stroke(uint8_t key, uint8_t mods);

/* Wi-Fi: ONLY to set the clock; radio fully off again on return. Never call with a database open. */
int hw_wifi_scan(app_ap *out, int max);                   /* number of networks */
int hw_ntp_sync(const char *ssid, const char *pass, int64_t *unix_s);   /* NTP_* code from app.h */

/* misc */
int hw_battery_percent(void);                             /* -1 unknown */
uint32_t hw_millis(void);
bool hw_time_get(int64_t *unix_s);                        /* false until the time was set */
void hw_time_set(int64_t unix_s);
void hw_settings_load(char *buf, size_t n);               /* "" if none */
void hw_settings_save(const char *text);
