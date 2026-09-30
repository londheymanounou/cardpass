/* Device settings (plan: stored in NVS or an SD file; never anything from the database). */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CP_WIFI_MAX 4
typedef struct {
    bool light, large_font, reveal_toggle, animations, splash;
    int autolock_s, brightness, typing_delay_ms, tz_minutes, weak_bits, expiry_days;
    int dim_s, off_s;      /* idle seconds until the backlight dims / the screen turns off (0 = never) */
    char layout[24];
    char autotype[96];     /* default auto-type sequence */
    char last_db[64];      /* file name only, to preselect in the picker */
    /* saved Wi-Fi networks (only ever used to sync the time while the database is locked) */
    int nwifi;
    char wifi_ssid[CP_WIFI_MAX][33];
    char wifi_pass[CP_WIFI_MAX][64];
} cp_settings;

/* Newest first; replaces a network with the same SSID, drops the oldest beyond CP_WIFI_MAX. */
void cp_settings_wifi_save(cp_settings *s, const char *ssid, const char *pass);
int cp_settings_wifi_find(const cp_settings *s, const char *ssid);   /* index or -1 */

/* Unix time of a civil UTC date/time (proleptic Gregorian). */
int64_t cp_unix_from_civil(int y, int mo, int d, int h, int mi, int sec);
int cp_days_in_month(int y, int mo);
/* When this firmware was built (from __DATE__/__TIME__): earlier clock values are rejected. */
int64_t cp_build_time(void);

void cp_settings_default(cp_settings *s);
void cp_settings_parse(cp_settings *s, const char *text);            /* defaults + whatever is valid */
size_t cp_settings_format(const cp_settings *s, char *out, size_t n); /* 0 if it does not fit */
