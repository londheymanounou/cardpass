/* Settings <-> "key=value\n" text (stored in NVS or on the SD card; never secrets).
 * Unknown keys and bad values are ignored, so a missing, old or wiped store
 * just gives the defaults. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "settings.h"

int cp_days_in_month(int y, int mo)
{
    static const int d[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return mo == 2 && (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)) ? 29 : d[mo - 1];
}

int64_t cp_unix_from_civil(int y, int mo, int d, int h, int mi, int sec)
{
    y -= mo <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400, yoe = y - era * 400;
    int64_t doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1, doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    int64_t days = era * 146097 + doe - 719468;
    return days * 86400 + h * 3600 + mi * 60 + sec;
}

int64_t cp_build_time(void)
{
    static const char *const M = "JanFebMarAprMayJunJulAugSepOctNovDec";
    const char *d = __DATE__, *t = __TIME__; /* "Sep 30 2026", "14:03:12" */
    int mo = 1, day = 1 + 0;
    for (int i = 0; i < 12; i++)
        if (!strncmp(d, M + 3 * i, 3)) mo = i + 1;
    day = (d[4] == ' ' ? 0 : d[4] - '0') * 10 + (d[5] - '0');
    int y = atoi(d + 7), h = atoi(t), mi = atoi(t + 3), s = atoi(t + 6);
    return cp_unix_from_civil(y, mo, day, h, mi, s);
}

static int hexval(int c) { return c >= '0' && c <= '9' ? c - '0' : (c | 32) >= 'a' && (c | 32) <= 'f' ? (c | 32) - 'a' + 10 : -1; }

static void hex_put(char *out, const char *s)
{
    for (; *s; s++) out += sprintf(out, "%02x", (unsigned char)*s);
    *out = 0;
}

static bool hex_get(const char *h, size_t n, char *out, size_t cap)
{
    size_t len = strlen(h);
    if (len % 2 || len / 2 >= cap || n < len) return false;
    for (size_t i = 0; i < len; i += 2) {
        int a = hexval(h[i]), b = hexval(h[i + 1]);
        if (a < 0 || b < 0) return false;
        out[i / 2] = (char)(a << 4 | b);
    }
    out[len / 2] = 0;
    return true;
}

int cp_settings_wifi_find(const cp_settings *s, const char *ssid)
{
    for (int i = 0; i < s->nwifi; i++)
        if (!strcmp(s->wifi_ssid[i], ssid)) return i;
    return -1;
}

void cp_settings_wifi_save(cp_settings *s, const char *ssid, const char *pass)
{
    int i = cp_settings_wifi_find(s, ssid);
    if (i < 0) i = s->nwifi < CP_WIFI_MAX ? s->nwifi++ : CP_WIFI_MAX - 1;
    for (; i > 0; i--) {                       /* move to the front */
        memcpy(s->wifi_ssid[i], s->wifi_ssid[i - 1], sizeof s->wifi_ssid[0]);
        memcpy(s->wifi_pass[i], s->wifi_pass[i - 1], sizeof s->wifi_pass[0]);
    }
    snprintf(s->wifi_ssid[0], sizeof s->wifi_ssid[0], "%s", ssid);
    snprintf(s->wifi_pass[0], sizeof s->wifi_pass[0], "%s", pass);
}

void cp_settings_default(cp_settings *s)
{
    memset(s, 0, sizeof *s);
    s->autolock_s = 300;
    s->brightness = 60;
    s->typing_delay_ms = 8;
    snprintf(s->layout, sizeof s->layout, "US QWERTY");
    snprintf(s->autotype, sizeof s->autotype, "{USERNAME}{TAB}{PASSWORD}{ENTER}");
    s->weak_bits = 64;
    s->expiry_days = 14;
}

static bool num(const char *v, int lo, int hi, int *out)
{
    char *end;
    long n = strtol(v, &end, 10);
    if (end == v || *end || n < lo || n > hi) return false;
    *out = (int)n;
    return true;
}

void cp_settings_parse(cp_settings *s, const char *text)
{
    cp_settings_default(s);
    char line[160];
    while (*text) {
        size_t n = strcspn(text, "\n");
        if (n < sizeof line) {
            memcpy(line, text, n);
            line[n] = 0;
            if (n && line[n - 1] == '\r') line[n - 1] = 0;
            char *eq = strchr(line, '=');
            if (eq) {
                *eq = 0;
                const char *k = line, *v = eq + 1;
                if (!strcmp(k, "theme")) s->light = !strcmp(v, "light");
                else if (!strcmp(k, "font")) s->large_font = !strcmp(v, "large");
                else if (!strcmp(k, "reveal")) s->reveal_toggle = !strcmp(v, "toggle");
                else if (!strcmp(k, "autolock")) num(v, 0, 86400, &s->autolock_s);
                else if (!strcmp(k, "brightness")) num(v, 5, 100, &s->brightness);
                else if (!strcmp(k, "typing_delay")) num(v, 0, 500, &s->typing_delay_ms);
                else if (!strcmp(k, "tz")) num(v, -14 * 60, 14 * 60, &s->tz_minutes);
                else if (!strcmp(k, "weak_bits")) num(v, 1, 256, &s->weak_bits);
                else if (!strcmp(k, "expiry_days")) num(v, 0, 365, &s->expiry_days);
                else if (!strcmp(k, "layout") && strlen(v) < sizeof s->layout) strcpy(s->layout, v);
                else if (!strcmp(k, "autotype") && *v && strlen(v) < sizeof s->autotype) strcpy(s->autotype, v);
                else if (!strcmp(k, "last_db") && strlen(v) < sizeof s->last_db) strcpy(s->last_db, v);
                else if (!strcmp(k, "wifi") && s->nwifi < CP_WIFI_MAX) { /* hex(ssid):hex(password) */
                    char *colon = strchr(v, ':');
                    int i = s->nwifi;
                    if (colon) {
                        *colon = 0;
                        if (hex_get(v, strlen(v), s->wifi_ssid[i], sizeof s->wifi_ssid[i]) &&
                            hex_get(colon + 1, strlen(colon + 1), s->wifi_pass[i], sizeof s->wifi_pass[i]))
                            s->nwifi++;
                    }
                }
            }
        }
        text += n;
        if (*text) text++;
    }
}

size_t cp_settings_format(const cp_settings *s, char *out, size_t n)
{
    int w = snprintf(out, n,
                     "theme=%s\nfont=%s\nreveal=%s\nautolock=%d\nbrightness=%d\ntyping_delay=%d\ntz=%d\n"
                     "weak_bits=%d\nexpiry_days=%d\nlayout=%s\nautotype=%s\nlast_db=%s\n",
                     s->light ? "light" : "dark", s->large_font ? "large" : "small", s->reveal_toggle ? "toggle" : "hold",
                     s->autolock_s, s->brightness, s->typing_delay_ms, s->tz_minutes, s->weak_bits, s->expiry_days,
                     s->layout, s->autotype, s->last_db);
    if (w < 0 || (size_t)w >= n) return 0;
    for (int i = 0; i < s->nwifi; i++) {
        char hs[2 * 33 + 1], hp[2 * 64 + 1];
        hex_put(hs, s->wifi_ssid[i]);
        hex_put(hp, s->wifi_pass[i]);
        int k = snprintf(out + w, n - (size_t)w, "wifi=%s:%s\n", hs, hp);
        if (k < 0 || (size_t)k >= n - (size_t)w) return 0;
        w += k;
    }
    return (size_t)w;
}
