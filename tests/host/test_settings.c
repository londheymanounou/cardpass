#include <stdio.h>
#include <string.h>
#include "settings.h"

static int failures;
#define CHECK(c, ...) do { if (!(c)) { failures++; printf("FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

int main(void)
{
    cp_settings s, t, d;
    char buf[1024];
    cp_settings_default(&d);

    cp_settings_parse(&s, ""); /* wiped NVS */
    CHECK(!memcmp(&s, &d, sizeof s), "empty -> defaults");

    s.theme = 3;
    s.large_font = s.reveal_toggle = s.fn_arrows = true;
    s.bar_clock = false;
    s.pw_lockout = true;
    s.autolock_s = 60;
    s.tz_minutes = -300;
    strcpy(s.layout, "FR AZERTY");
    strcpy(s.autotype, "{USERNAME}{TAB 2}{PASSWORD}{DELAY 200}{ENTER}");
    strcpy(s.last_db, "perso.kdbx");
    size_t n = cp_settings_format(&s, buf, sizeof buf);
    CHECK(n > 0, "format");
    cp_settings_parse(&t, buf);
    CHECK(!memcmp(&s, &t, sizeof s), "round trip");

    cp_settings_parse(&t, "autolock=-5\r\nbrightness=abc\ntz=99999\nfoo=bar\nlayout=DE QWERTZ\r\n=x\nnoequals\n");
    CHECK(t.autolock_s == d.autolock_s && t.brightness == d.brightness && t.tz_minutes == 0, "bad values ignored");
    CHECK(!strcmp(t.layout, "DE QWERTZ"), "CRLF tolerated");
    CHECK(!cp_settings_format(&s, buf, 20), "too small buffer");

    char big[400];
    memset(big, 'x', sizeof big - 1);
    big[sizeof big - 1] = 0;
    cp_settings_parse(&t, big); /* long garbage line */
    CHECK(!memcmp(&t, &d, sizeof t), "garbage -> defaults");

    /* Wi-Fi networks: round trip incl. odd characters, newest first, replace, cap */
    cp_settings_default(&s);
    cp_settings_wifi_save(&s, "Home", "pass:word\n=1");
    cp_settings_wifi_save(&s, "Café", "é€");
    cp_settings_wifi_save(&s, "Home", "new");
    CHECK(s.nwifi == 2 && !strcmp(s.wifi_ssid[0], "Home") && !strcmp(s.wifi_pass[0], "new") && !strcmp(s.wifi_ssid[1], "Café"), "wifi order");
    for (int i = 0; i < 6; i++) { char n2[8]; snprintf(n2, sizeof n2, "n%d", i); cp_settings_wifi_save(&s, n2, "p"); }
    CHECK(s.nwifi == CP_WIFI_MAX && !strcmp(s.wifi_ssid[0], "n5") && cp_settings_wifi_find(&s, "Home") < 0, "wifi cap drops the oldest");
    char wbuf[2048];
    CHECK(cp_settings_format(&s, wbuf, sizeof wbuf) > 0, "wifi format");
    cp_settings_parse(&t, wbuf);
    bool same = s.nwifi == t.nwifi;
    for (int i = 0; same && i < s.nwifi; i++) same = !strcmp(s.wifi_ssid[i], t.wifi_ssid[i]) && !strcmp(s.wifi_pass[i], t.wifi_pass[i]);
    CHECK(same, "wifi round trip");
    cp_settings_default(&s);
    cp_settings_wifi_save(&s, "Odd", "pass:word\n=1");
    cp_settings_format(&s, wbuf, sizeof wbuf);
    cp_settings_parse(&t, wbuf);
    CHECK(!strcmp(t.wifi_pass[0], "pass:word\n=1"), "wifi password with separators");
    cp_settings_parse(&t, "wifi=zz:00\nwifi=414:41\nwifi=41\n");
    CHECK(t.nwifi == 0, "bad wifi lines ignored");

    /* Wi-Fi password taken from a database entry: WPA shape check */
    CHECK(cp_wifi_valid("Home", "12345678") && cp_wifi_valid("Home", "a b~c d!") && cp_wifi_valid("12345678901234567890123456789012", "12345678"),
          "valid Wi-Fi");
    char p63[64], h64[65], x64[65];
    memset(p63, 'p', 63), p63[63] = 0;
    memset(h64, 'a', 64), h64[64] = 0;
    memset(x64, 'x', 64), x64[64] = 0;
    CHECK(cp_wifi_valid("Home", p63) && cp_wifi_valid("Home", h64), "63 chars, 64 hex");
    CHECK(!cp_wifi_valid("Home", "1234567") && !cp_wifi_valid("Home", x64) && !cp_wifi_valid("", "12345678") &&
          !cp_wifi_valid("123456789012345678901234567890123", "12345678") && !cp_wifi_valid("Home", "p\xC3\xA4sswort") &&
          !cp_wifi_valid("Home", "1234\n5678"), "invalid Wi-Fi refused");


    cp_settings_parse(&t, "dim=0\nscreen_off=30\n");
    CHECK(t.dim_s == 0 && t.off_s == 30, "dim/off parsed");
    cp_settings_parse(&t, "dim=-5\nscreen_off=abc\n");
    CHECK(t.dim_s == 20 && t.off_s == 45, "bad dim/off ignored");

    /* time math against independently computed values (python calendar.timegm) */
    CHECK(cp_unix_from_civil(1970, 1, 1, 0, 0, 0) == 0, "epoch");
    CHECK(cp_unix_from_civil(2026, 9, 30, 12, 0, 0) == 1790769600LL, "2026-09-30 12:00 = %lld", (long long)cp_unix_from_civil(2026, 9, 30, 12, 0, 0));
    CHECK(cp_unix_from_civil(2000, 2, 29, 23, 59, 59) == 951868799LL, "leap day 2000");
    CHECK(cp_unix_from_civil(2100, 3, 1, 0, 0, 0) == 4107542400LL, "2100 is not a leap year");
    CHECK(cp_days_in_month(2024, 2) == 29 && cp_days_in_month(2100, 2) == 28 && cp_days_in_month(2026, 4) == 30, "days in month");
    CHECK(cp_build_time() > 1780000000LL && cp_build_time() < 4102444800LL, "build time %lld", (long long)cp_build_time());

    printf("settings: %d failures\n", failures);
    return failures != 0;
}
