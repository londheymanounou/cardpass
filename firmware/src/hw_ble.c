#ifndef CARDPASS_QEMU   /* replaced by hw_qemu.c in the qemu env */
/* Bluetooth LE keyboard (HID over GATT) for typing. The radio is only on while the user has switched
 * Bluetooth on (menu -> Bluetooth); starting it brings the whole stack up, stopping tears it down again
 * (PLAN.md section 2). Security: LE Secure Connections with NUMERIC COMPARISON (the Cardputer shows a
 * 6-digit code, the user confirms it matches the host's) and bonding; a HID report is sent ONLY over a
 * link that is encrypted AND authenticated, so a nearby stranger who connects can never receive typing. */
#include <string.h>
#include "esp_bt.h"
#include "esp_hidd.h"
#include "esp_hid_common.h"
#include "esp_nimble_hci.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "host/ble_hs.h"
#include "host/ble_store.h"
#include "host/util/util.h"
#include "hw.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"

void ble_store_config_init(void);

static const uint8_t kbd_map[] = {
    0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x85, 0x01,                                     /* keyboard, report id 1 */
    0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02,   /* modifiers */
    0x95, 0x01, 0x75, 0x08, 0x81, 0x01,                                                 /* reserved */
    0x95, 0x05, 0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02,             /* LEDs */
    0x95, 0x01, 0x75, 0x03, 0x91, 0x01,
    0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0xFF, 0x05, 0x07, 0x19, 0x00, 0x29, 0xFF, 0x81, 0x00, /* 6 keys */
    0xC0};
static esp_hid_raw_report_map_t maps[] = {{.data = kbd_map, .len = sizeof kbd_map}};
static esp_hid_device_config_t hid_cfg = {.vendor_id = 0x303A, .product_id = 0x4001, .version = 0x0100,
                                          .device_name = "CardPass", .manufacturer_name = "CardPass",
                                          .serial_number = "000001", .report_maps = maps, .report_maps_len = 1};

static esp_hidd_dev_t *hid;
static struct ble_hs_adv_fields adv_fields;
static volatile int state = BT_OFF;
static volatile uint32_t pair_code;
static volatile uint16_t conn = BLE_HS_CONN_HANDLE_NONE;
static bool controller_up, mem_released;

static bool link_secure(void)
{
    struct ble_gap_conn_desc d;
    return conn != BLE_HS_CONN_HANDLE_NONE && ble_gap_conn_find(conn, &d) == 0 && d.sec_state.encrypted && d.sec_state.authenticated;
}

static void advertise(void)
{
    struct ble_gap_adv_params p;
    extern int hw_ble_gap_event(struct ble_gap_event *event, void *arg);
    ble_gap_adv_set_fields(&adv_fields);
    memset(&p, 0, sizeof p);
    p.conn_mode = BLE_GAP_CONN_MODE_UND;
    p.disc_mode = BLE_GAP_DISC_MODE_GEN;
    p.itvl_min = BLE_GAP_ADV_ITVL_MS(30);
    p.itvl_max = BLE_GAP_ADV_ITVL_MS(50);
    if (ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER, &p, hw_ble_gap_event, NULL) == 0) state = BT_ADVERTISING;
}

int hw_ble_gap_event(struct ble_gap_event *e, void *arg)
{
    struct ble_gap_conn_desc d;
    switch (e->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (e->connect.status == 0) {
            conn = e->connect.conn_handle;
            ble_gap_security_initiate(conn);              /* we insist on pairing / encryption right away */
        } else {
            conn = BLE_HS_CONN_HANDLE_NONE;
            advertise();
        }
        return 0;
    case BLE_GAP_EVENT_DISCONNECT:
        conn = BLE_HS_CONN_HANDLE_NONE;
        pair_code = 0;
        if (state != BT_OFF) advertise();
        return 0;
    case BLE_GAP_EVENT_ENC_CHANGE:
        if (e->enc_change.status == 0 && link_secure()) state = BT_CONNECTED;
        else ble_gap_terminate(e->enc_change.conn_handle, BLE_ERR_REM_USER_CONN_TERM);   /* not secure: drop it */
        return 0;
    case BLE_GAP_EVENT_REPEAT_PAIRING:
        /* the host lost its bond: forget ours; the new pairing still needs the numeric comparison */
        if (ble_gap_conn_find(e->repeat_pairing.conn_handle, &d) == 0) ble_store_util_delete_peer(&d.peer_id_addr);
        return BLE_GAP_REPEAT_PAIRING_RETRY;
    case BLE_GAP_EVENT_PASSKEY_ACTION:
        if (e->passkey.params.action == BLE_SM_IOACT_NUMCMP) {
            pair_code = e->passkey.params.numcmp;
            state = BT_PAIR_CONFIRM;                      /* the app shows the code and asks the user */
        } else {
            ble_gap_terminate(e->passkey.conn_handle, BLE_ERR_REM_USER_CONN_TERM);   /* only numeric comparison is accepted */
        }
        return 0;
    default: return 0;
    }
}

static void hidd_event(void *args, esp_event_base_t base, int32_t id, void *data)
{
    if ((esp_hidd_event_t)id == ESP_HIDD_START_EVENT) advertise();
}

static void host_task(void *param)
{
    nimble_port_run();                                    /* returns when the stack is stopped */
    nimble_port_freertos_deinit();
}

bool hw_ble_start(void)
{
    if (state != BT_OFF) return true;
    if (!mem_released) { esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT); mem_released = true; }
    esp_bt_controller_config_t bc = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    if (esp_bt_controller_init(&bc) != ESP_OK) return false;
    if (esp_bt_controller_enable(ESP_BT_MODE_BLE) != ESP_OK) goto fail;
    controller_up = true;
    if (esp_nimble_init() != ESP_OK) goto fail;

    memset(&adv_fields, 0, sizeof adv_fields);
    static ble_uuid16_t hid_uuid = BLE_UUID16_INIT(0x1812);
    adv_fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    adv_fields.appearance = ESP_HID_APPEARANCE_KEYBOARD;
    adv_fields.appearance_is_present = 1;
    adv_fields.name = (uint8_t *)hid_cfg.device_name;
    adv_fields.name_len = (uint8_t)strlen(hid_cfg.device_name);
    adv_fields.name_is_complete = 1;
    adv_fields.uuids16 = &hid_uuid;
    adv_fields.num_uuids16 = 1;
    adv_fields.uuids16_is_complete = 1;

    ble_hs_cfg.sm_io_cap = BLE_SM_IO_CAP_DISP_YES_NO;     /* numeric comparison */
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_mitm = 1;
    ble_hs_cfg.sm_sc = 1;
    ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ID | BLE_SM_PAIR_KEY_DIST_ENC;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ID | BLE_SM_PAIR_KEY_DIST_ENC;
    ble_store_config_init();                              /* bonds live in NVS: pairing survives reboots */
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;

    state = BT_ADVERTISING;                               /* provisional: hidd START event starts advertising */
    if (esp_hidd_dev_init(&hid_cfg, ESP_HID_TRANSPORT_BLE, hidd_event, &hid) != ESP_OK) goto fail_nimble;
    if (esp_nimble_enable(host_task) != ESP_OK) goto fail_hid;
    return true;
fail_hid:
    esp_hidd_dev_deinit(hid);
    hid = NULL;
fail_nimble:
    esp_nimble_deinit();
fail:
    if (controller_up) esp_bt_controller_disable();
    esp_bt_controller_deinit();
    controller_up = false;
    state = BT_OFF;
    return false;
}

void hw_ble_stop(void)
{
    if (state == BT_OFF) return;
    state = BT_OFF;
    pair_code = 0;
    if (conn != BLE_HS_CONN_HANDLE_NONE) ble_gap_terminate(conn, BLE_ERR_REM_USER_CONN_TERM);
    ble_gap_adv_stop();
    if (hid) { esp_hidd_dev_deinit(hid); hid = NULL; }
    nimble_port_stop();
    esp_nimble_deinit();
    if (controller_up) { esp_bt_controller_disable(); controller_up = false; }
    esp_bt_controller_deinit();
    conn = BLE_HS_CONN_HANDLE_NONE;
}

int hw_ble_state(uint32_t *code)
{
    if (code) *code = pair_code;
    return state;
}

void hw_ble_answer(bool accept)
{
    if (state != BT_PAIR_CONFIRM || conn == BLE_HS_CONN_HANDLE_NONE) return;
    struct ble_sm_io io = {.action = BLE_SM_IOACT_NUMCMP, .numcmp_accept = accept};
    pair_code = 0;
    state = BT_ADVERTISING;                               /* becomes CONNECTED when encryption is up */
    if (ble_sm_inject_io(conn, &io) != 0 || !accept) ble_gap_terminate(conn, BLE_ERR_REM_USER_CONN_TERM);
}

void hw_ble_forget(void) { ble_store_clear(); }

bool hw_ble_ready(void) { return state == BT_CONNECTED && hid && link_secure(); }

/* One key press + release, only over an authenticated, encrypted link. */
void hw_ble_stroke(uint8_t key, uint8_t mods)
{
    if (!hw_ble_ready()) return;
    uint8_t r[8] = {mods, 0, key, 0, 0, 0, 0, 0};
    esp_hidd_dev_input_set(hid, 0, 1, r, sizeof r);
    vTaskDelay(pdMS_TO_TICKS(6));
    memset(r, 0, sizeof r);
    esp_hidd_dev_input_set(hid, 0, 1, r, sizeof r);
    vTaskDelay(pdMS_TO_TICKS(6));
}
#endif
