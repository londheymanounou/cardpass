#ifndef CARDPASS_QEMU   /* replaced by hw_qemu.c in the qemu env */
/* USB device: composite HID keyboard (typing) + FIDO HID (passkeys) through esp_tinyusb.
 * The FIDO reports arrive in the TinyUSB task and are queued; the main task processes them
 * (user-presence UI must run there). Mass storage (SD as a drive) is a later step: entering it
 * locks the database and unmounts FAT (stage 4). */
#include <string.h>
#include "class/hid/hid_device.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "hw.h"
#include "tinyusb.h"
#include "tusb_msc_storage.h"

enum { ITF_KBD = 0, ITF_FIDO, ITF_COUNT };
enum { STR_LANG, STR_MANUF, STR_PRODUCT, STR_SERIAL, STR_KBD, STR_FIDO };

static const uint8_t kbd_report[] = {TUD_HID_REPORT_DESC_KEYBOARD()};
/* FIDO: usage page 0xF1D0, usage 1 (CTAPHID), 64-byte input and output reports */
static const uint8_t fido_report[] = {0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00,
                                      0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75,
                                      0x08, 0x95, 0x40, 0x91, 0x02, 0xC0};

#define CONFIG_LEN (TUD_CONFIG_DESC_LEN + TUD_HID_DESC_LEN + TUD_HID_INOUT_DESC_LEN)
static const uint8_t config_desc[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_COUNT, 0, CONFIG_LEN, TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, 100),
    TUD_HID_DESCRIPTOR(ITF_KBD, STR_KBD, HID_ITF_PROTOCOL_KEYBOARD, sizeof kbd_report, 0x81, 8, 10),
    TUD_HID_INOUT_DESCRIPTOR(ITF_FIDO, STR_FIDO, HID_ITF_PROTOCOL_NONE, sizeof fido_report, 0x02, 0x82, 64, 5),
};
/* wTotalLength must match: a short one cuts the FIDO interface off and Windows rejects the device (Code 10) */
_Static_assert(sizeof config_desc == CONFIG_LEN, "config descriptor length");

static const char *strings[] = {(const char[]){0x09, 0x04}, "CardPass", "CardPass", "000001", "CardPass keyboard", "CardPass security key"};
static QueueHandle_t fido_q;

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance) { return instance == ITF_FIDO ? fido_report : kbd_report; }

uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t type, uint8_t *buffer, uint16_t reqlen)
{
    return 0;
}

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t type, uint8_t const *buffer, uint16_t bufsize)
{
    if (instance != ITF_FIDO || bufsize != 64 || !fido_q) return;   /* keyboard LED reports are ignored */
    xQueueSend(fido_q, buffer, 0);
}

static bool install_hid(void)
{
    tinyusb_config_t cfg = {.device_descriptor = NULL, .string_descriptor = strings,
                            .string_descriptor_count = sizeof strings / sizeof *strings, .external_phy = false,
                            .configuration_descriptor = config_desc};
    return tinyusb_driver_install(&cfg) == ESP_OK;
}

bool hw_usb_init(void)
{
    if (!fido_q) fido_q = xQueueCreate(16, 64);
    return install_hid();
}

/* ---- drive mode: a mass-storage-only device; no keyboard, no security key ---- */
static const uint8_t msc_config_desc[] = {
    TUD_CONFIG_DESCRIPTOR(1, 1, 0, TUD_CONFIG_DESC_LEN + TUD_MSC_DESC_LEN, 0, 100),
    TUD_MSC_DESCRIPTOR(0, 4, 0x01, 0x81, 64),
};
_Static_assert(sizeof msc_config_desc == TUD_CONFIG_DESC_LEN + TUD_MSC_DESC_LEN, "drive config descriptor length");
/* A different product ID and serial than the keyboard/security-key mode: Windows remembers a device by VID/PID/serial, and
 * would keep the old composite (HID) interface list for a device whose descriptors changed. Espressif's VID, a PID next to
 * the esp_tinyusb default range. */
static const tusb_desc_device_t msc_device = {
    .bLength = sizeof(tusb_desc_device_t), .bDescriptorType = TUSB_DESC_DEVICE, .bcdUSB = 0x0200, .bDeviceClass = 0,
    .bDeviceSubClass = 0, .bDeviceProtocol = 0, .bMaxPacketSize0 = 64, .idVendor = 0x303A, .idProduct = 0x4F01,
    .bcdDevice = 0x0100, .iManufacturer = 1, .iProduct = 2, .iSerialNumber = 3, .bNumConfigurations = 1};
static const char *msc_strings[] = {(const char[]){0x09, 0x04}, "CardPass", "CardPass drive", "000002", "CardPass SD card"};
#define REENUM_MS 800   /* the port stays detached this long so the PC notices the old device is gone */

bool hw_usb_drive(bool enter)
{
    if (enter) {
        hw_sd_unmount();                              /* the app must not touch FAT while the PC owns the card */
        sdmmc_card_t *card = hw_sd_raw_open();
        if (!card) { hw_sd_mount(); return false; }
        tinyusb_driver_uninstall();
        vTaskDelay(pdMS_TO_TICKS(REENUM_MS));
        tinyusb_msc_sdmmc_config_t mc = {.card = card};
        if (tinyusb_msc_storage_init_sdmmc(&mc) != ESP_OK) goto fail;
        tinyusb_config_t cfg = {.device_descriptor = &msc_device, .string_descriptor = msc_strings,
                                .string_descriptor_count = sizeof msc_strings / sizeof *msc_strings, .external_phy = false,
                                .configuration_descriptor = msc_config_desc};
        if (tinyusb_driver_install(&cfg) != ESP_OK) { tinyusb_msc_storage_deinit(); goto fail; }
        return true;
    fail:
        hw_sd_raw_close();
        hw_sd_mount();
        install_hid();
        return false;
    }
    vTaskDelay(pdMS_TO_TICKS(300));                   /* let the last deferred write reach the card */
    tinyusb_driver_uninstall();
    tinyusb_msc_storage_deinit();
    hw_sd_raw_close();
    vTaskDelay(pdMS_TO_TICKS(REENUM_MS));
    bool ok = hw_sd_mount();
    install_hid();
    return ok;
}

bool hw_usb_ready(void) { return tud_mounted() && !tud_suspended(); }

static bool wait_ready(uint8_t itf)
{
    for (int i = 0; i < 200; i++) {                /* up to ~200 ms */
        if (tud_hid_n_ready(itf)) return true;
        vTaskDelay(1);
    }
    return false;
}

/* One key press + release. mods: HID modifier bits (LCTRL 1, LSHIFT 2, LALT 4, RALT/AltGr 0x40). */
void hw_usb_stroke(uint8_t key, uint8_t mods)
{
    uint8_t keys[6] = {key};
    if (wait_ready(ITF_KBD)) tud_hid_n_keyboard_report(ITF_KBD, 0, mods, keys);
    vTaskDelay(pdMS_TO_TICKS(4));
    if (wait_ready(ITF_KBD)) tud_hid_n_keyboard_report(ITF_KBD, 0, 0, NULL);
    vTaskDelay(pdMS_TO_TICKS(4));
}

bool hw_usb_fido_recv(uint8_t report[64]) { return fido_q && xQueueReceive(fido_q, report, 0) == pdTRUE; }

void hw_usb_fido_send(const uint8_t report[64])
{
    if (wait_ready(ITF_FIDO)) tud_hid_n_report(ITF_FIDO, 0, report, 64);
}
#endif
