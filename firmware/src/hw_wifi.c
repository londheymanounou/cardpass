/* Wi-Fi is only ever used to set the clock (PLAN.md section 2): scan, or connect + NTP, and the
 * radio is fully shut down again before returning. The caller (main.c) refuses to call these while
 * a database is open. Credentials are never stored by IDF (RAM storage, no NVS wifi data). */
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "hw.h"
#include "mbedtls/platform_util.h"

#define GOT_IP BIT0
#define FAILED BIT1
#define CONNECT_MS 10000
#define NTP_MS 10000

static EventGroupHandle_t ev;
static esp_netif_t *sta;
static bool stack_ready;
static int fail_reason;

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        fail_reason = ((wifi_event_sta_disconnected_t *)data)->reason;
        xEventGroupSetBits(ev, FAILED);
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(ev, GOT_IP);
    }
}

static bool radio_on(void)
{
    if (!stack_ready) {
        esp_netif_init();
        esp_event_loop_create_default();                  /* already created: ESP_ERR_INVALID_STATE, fine */
        stack_ready = true;
    }
    ev = xEventGroupCreate();
    sta = esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    if (!ev || !sta || esp_wifi_init(&cfg) != ESP_OK) {
        if (sta) esp_netif_destroy_default_wifi(sta);
        if (ev) vEventGroupDelete(ev);
        sta = NULL;
        ev = NULL;
        return false;
    }
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, on_event, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_event, NULL);
    fail_reason = 0;
    return esp_wifi_start() == ESP_OK;
}

static void radio_off(void)
{
    esp_event_handler_unregister(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, on_event);
    esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, on_event);
    esp_wifi_disconnect();
    esp_wifi_stop();
    esp_wifi_deinit();
    if (sta) esp_netif_destroy_default_wifi(sta);
    if (ev) vEventGroupDelete(ev);
    sta = NULL;
    ev = NULL;
}

static int by_rssi(const void *a, const void *b) { return ((const wifi_ap_record_t *)b)->rssi - ((const wifi_ap_record_t *)a)->rssi; }

int hw_wifi_scan(app_ap *out, int max)
{
    wifi_ap_record_t rec[20];
    uint16_t n = 0;
    int count = 0;
    if (!radio_on()) { radio_off(); return 0; }
    if (esp_wifi_scan_start(NULL, true) == ESP_OK) {
        esp_wifi_scan_get_ap_num(&n);
        if (n > 20) n = 20;
        esp_wifi_scan_get_ap_records(&n, rec);
        qsort(rec, n, sizeof rec[0], by_rssi);
        for (int i = 0; i < n && count < max; i++) {
            const char *ssid = (const char *)rec[i].ssid;
            bool dup = !ssid[0];                          /* hidden networks can't be picked from a list */
            for (int k = 0; k < count && !dup; k++) dup = !strcmp(out[k].ssid, ssid);
            if (dup) continue;
            snprintf(out[count].ssid, sizeof out[count].ssid, "%s", ssid);
            out[count].secure = rec[i].authmode != WIFI_AUTH_OPEN;
            out[count].rssi = rec[i].rssi;
            count++;
        }
    }
    radio_off();
    return count;
}

static bool auth_failure(int r)
{
    return r == WIFI_REASON_AUTH_FAIL || r == WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT || r == WIFI_REASON_HANDSHAKE_TIMEOUT ||
           r == WIFI_REASON_MIC_FAILURE || r == WIFI_REASON_802_1X_AUTH_FAILED;
}

int hw_ntp_sync(const char *ssid, const char *pass, int64_t *unix_s)
{
    int code = NTP_ERR_CONNECT;
    wifi_config_t wc = {0};
    if (!radio_on()) goto out;
    snprintf((char *)wc.sta.ssid, sizeof wc.sta.ssid, "%s", ssid);
    snprintf((char *)wc.sta.password, sizeof wc.sta.password, "%s", pass);
    wc.sta.threshold.authmode = pass[0] ? WIFI_AUTH_WEP : WIFI_AUTH_OPEN;
    wc.sta.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;
    esp_wifi_set_config(WIFI_IF_STA, &wc);
    esp_wifi_connect();
    EventBits_t bits = xEventGroupWaitBits(ev, GOT_IP | FAILED, pdTRUE, pdFALSE, pdMS_TO_TICKS(CONNECT_MS));
    if (!(bits & GOT_IP)) {
        code = (bits & FAILED) && auth_failure(fail_reason) ? NTP_ERR_PASSWORD : NTP_ERR_CONNECT;
        goto out;
    }
    esp_sntp_config_t sc = ESP_NETIF_SNTP_DEFAULT_CONFIG_MULTIPLE(2, ESP_SNTP_SERVER_LIST("pool.ntp.org", "time.cloudflare.com"));
    if (esp_netif_sntp_init(&sc) == ESP_OK && esp_netif_sntp_sync_wait(pdMS_TO_TICKS(NTP_MS)) == ESP_OK) {
        time_t now;
        time(&now);
        *unix_s = now;
        code = NTP_OK;
    } else {
        code = NTP_ERR_SERVER;
    }
    esp_netif_sntp_deinit();
out:
    mbedtls_platform_zeroize(&wc, sizeof wc);
    radio_off();
    return code;
}
