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

    s.light = s.large_font = s.reveal_toggle = true;
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

    printf("settings: %d failures\n", failures);
    return failures != 0;
}
