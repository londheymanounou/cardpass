/* USB device: composite HID keyboard (typing) + FIDO HID (passkeys) through esp_tinyusb.
 * The FIDO reports arrive in the TinyUSB task and are queued; the main task processes them
 * (user-presence UI must run there). Mass storage (SD as a drive) is a later step: entering it
 * locks the database and unmounts FAT (PLAN.md stage 4). */
#include <string.h>
#include "class/hid/hid_device.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "hw.h"
#include "tinyusb.h"

enum { ITF_KBD = 0, ITF_FIDO, ITF_COUNT };
enum { STR_LANG, STR_MANUF, STR_PRODUCT, STR_SERIAL, STR_KBD, STR_FIDO };

static const uint8_t kbd_report[] = {TUD_HID_REPORT_DESC_KEYBOARD()};
/* FIDO: usage page 0xF1D0, usage 1 (CTAPHID), 64-byte input and output reports */
static const uint8_t fido_report[] = {0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00,
                                      0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75,
                                      0x08, 0x95, 0x40, 0x91, 0x02, 0xC0};

static const uint8_t config_desc[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_COUNT, 0, TUD_CONFIG_DESC_LEN + 2 * TUD_HID_DESC_LEN, TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, 100),
    TUD_HID_DESCRIPTOR(ITF_KBD, STR_KBD, HID_ITF_PROTOCOL_KEYBOARD, sizeof kbd_report, 0x81, 8, 10),
    TUD_HID_INOUT_DESCRIPTOR(ITF_FIDO, STR_FIDO, HID_ITF_PROTOCOL_NONE, sizeof fido_report, 0x02, 0x82, 64, 5),
};

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

bool hw_usb_init(void)
{
    fido_q = xQueueCreate(16, 64);
    tinyusb_config_t cfg = {.device_descriptor = NULL, .string_descriptor = strings,
                            .string_descriptor_count = sizeof strings / sizeof *strings, .external_phy = false,
                            .configuration_descriptor = config_desc};
    return tinyusb_driver_install(&cfg) == ESP_OK;
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
