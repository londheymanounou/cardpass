/* Settings <-> "key=value\n" text (stored in NVS or on the SD card; never secrets).
 * Unknown keys and bad values are ignored, so a missing, old or wiped store
 * just gives the defaults. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "settings.h"

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
    return w < 0 || (size_t)w >= n ? 0 : (size_t)w;
}
