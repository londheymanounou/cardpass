#include <string.h>
#include <sys/time.h>
#include "bootloader_random.h"
#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"
#include "esp_adc/adc_oneshot.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "hw.h"
#include "mbedtls/platform_util.h"
#include "nvs.h"

/* ---- randomness: hardware RNG with an entropy source active (Wi-Fi/BT are never on while unlocked) ----
 * Fresh bytes are drawn in small batches under bootloader_random_enable(); consumed bytes are wiped. */
void cp_random(void *buf, size_t n)
{
    static uint8_t pool[64];
    static size_t have;
    uint8_t *out = buf;
    while (n) {
        if (!have) {
            bootloader_random_enable();
            esp_fill_random(pool, sizeof pool);
            bootloader_random_disable();
            have = sizeof pool;
        }
        size_t k = n < have ? n : have;
        memcpy(out, pool + (have - k), k);
        mbedtls_platform_zeroize(pool + (have - k), k);
        have -= k;
        out += k;
        n -= k;
    }
}

uint32_t hw_millis(void) { return (uint32_t)(esp_timer_get_time() / 1000); }

/* ---- time: no RTC on the ADV; valid only after a manual set / NTP sync ---- */
#define TIME_MIN 1780000000 /* anything earlier than the firmware build is "not set" */
bool hw_time_get(int64_t *unix_s)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    *unix_s = tv.tv_sec;
    return tv.tv_sec >= TIME_MIN;
}
void hw_time_set(int64_t unix_s)
{
    struct timeval tv = {.tv_sec = (time_t)unix_s};
    settimeofday(&tv, NULL);
}

/* ---- battery: ADC divider on GPIO10; percent from (mV*2 - 3300) / (4150 - 3300) like M5Unified ---- */
int hw_battery_percent(void)
{
    static adc_oneshot_unit_handle_t adc;
    static adc_cali_handle_t cali;
    static adc_channel_t ch;
    static uint32_t last;
    static int cached = -1;
    uint32_t now = hw_millis();
    if (cached >= 0 && now - last < 5000) return cached;
    if (!adc) {
        adc_unit_t unit;
        if (adc_oneshot_io_to_channel(10, &unit, &ch) != ESP_OK) return -1;
        adc_oneshot_unit_init_cfg_t uc = {.unit_id = unit};
        if (adc_oneshot_new_unit(&uc, &adc) != ESP_OK) { adc = NULL; return -1; }
        adc_oneshot_chan_cfg_t cc = {.atten = ADC_ATTEN_DB_12, .bitwidth = ADC_BITWIDTH_DEFAULT};
        adc_oneshot_config_channel(adc, ch, &cc);
        adc_cali_curve_fitting_config_t cf = {.unit_id = unit, .chan = ch, .atten = ADC_ATTEN_DB_12, .bitwidth = ADC_BITWIDTH_DEFAULT};
        if (adc_cali_create_scheme_curve_fitting(&cf, &cali) != ESP_OK) cali = NULL;
    }
    int sum = 0, mv = 0;
    for (int i = 0; i < 8; i++) {
        int raw = 0;
        adc_oneshot_read(adc, ch, &raw);
        if (cali) adc_cali_raw_to_voltage(cali, raw, &mv);
        else mv = raw * 3100 / 4095;
        sum += mv;
    }
    int bat_mv = sum / 8 * 2, pct = (bat_mv - 3300) * 100 / (4150 - 3300);
    cached = pct < 0 ? 0 : pct > 100 ? 100 : pct;
    last = now;
    return cached;
}

/* ---- settings in NVS (a text blob; never anything from the database) ---- */
void hw_settings_load(char *buf, size_t n)
{
    nvs_handle_t h;
    buf[0] = 0;
    if (nvs_open("cardpass", NVS_READONLY, &h) != ESP_OK) return;
    size_t len = n;
    if (nvs_get_str(h, "cfg", buf, &len) != ESP_OK) buf[0] = 0;
    nvs_close(h);
}

void hw_settings_save(const char *text)
{
    nvs_handle_t h;
    if (nvs_open("cardpass", NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_str(h, "cfg", text);
    nvs_commit(h);
    nvs_close(h);
}
