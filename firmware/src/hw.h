/* Cardputer ADV hardware layer (ESP-IDF). Pins are the ones verified in the sibling
 * firmware (SD) or taken from M5GFX / M5Unified for the ADV (display, keyboard, battery):
 * anything marked "unverified" in docs/first-hardware.md needs a first look on the device. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* display: 240x135 landscape ST7789, pushed in strips */
void hw_display_init(void);
uint16_t *hw_display_strip(void);                        /* DMA-capable UI_W x STRIP_H buffer */
#define HW_STRIP_H 16
void hw_display_push(int y0, int h, uint16_t *px);        /* px is RGB565, byte-swapped in place */
void hw_display_brightness(int pct);
void hw_display_sleep(bool on);

/* keyboard (TCA8418): delivers app key codes (see app.h) */
void hw_keys_init(void);
void hw_keys_poll(void (*on_key)(uint32_t key, bool down), uint32_t now_ms);

/* SD card */
bool hw_sd_mount(void);
void hw_sd_unmount(void);
bool hw_sd_ok(void);
#define HW_SD_ROOT "/sd"
#define HW_DB_DIR "/sd/cardpass"

/* USB device: HID keyboard + FIDO HID */
bool hw_usb_init(void);
bool hw_usb_ready(void);                                  /* enumerated and not suspended */
void hw_usb_stroke(uint8_t key, uint8_t mods);
bool hw_usb_fido_recv(uint8_t report[64]);                /* non-blocking */
void hw_usb_fido_send(const uint8_t report[64]);

/* misc */
int hw_battery_percent(void);                             /* -1 unknown */
uint32_t hw_millis(void);
bool hw_time_get(int64_t *unix_s);                        /* false until the time was set */
void hw_time_set(int64_t unix_s);
void hw_settings_load(char *buf, size_t n);               /* "" if none */
void hw_settings_save(const char *text);
