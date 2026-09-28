/* Host keyboard layouts. To add one: four strings giving the character on each
 * physical key (order of KEYS below) for base / Shift / AltGr / AltGr+Shift,
 * "•" where there is none, plus the characters that are dead keys.
 * Dead keys follow Windows behaviour; use the layout test on other hosts. */
#include <string.h>
#include "typing.h"

/* HID usages of the 49 character keys, as labelled on a US keyboard:
 * ` 1..0 - =  |  q..p [ ] \  |  a..l ; ' (ISO #)  |  (ISO \) z..m , . / */
static const uint8_t KEYS[49] = {
    0x35, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x2D, 0x2E,
    0x14, 0x1A, 0x08, 0x15, 0x17, 0x1C, 0x18, 0x0C, 0x12, 0x13, 0x2F, 0x30, 0x31,
    0x04, 0x16, 0x07, 0x09, 0x0A, 0x0B, 0x0D, 0x0E, 0x0F, 0x33, 0x34, 0x32,
    0x64, 0x1D, 0x1B, 0x06, 0x19, 0x05, 0x11, 0x10, 0x36, 0x37, 0x38,
};
static const uint8_t LEVEL_MODS[4] = {0, KBD_LSHIFT, KBD_ALTGR, KBD_ALTGR | KBD_LSHIFT};
#define NONE13 "•••••••••••••"
#define NONE12 "••••••••••••"
#define NONE11 "•••••••••••"
#define NONE49 NONE13 NONE13 NONE12 NONE11

struct kbd_layout {
    const char *name;
    const char *level[4];
    const char *dead;
};

static const kbd_layout LAYOUTS[] = {
    {"US QWERTY",
     {"`1234567890-=" "qwertyuiop[]\\" "asdfghjkl;'•" "•zxcvbnm,./",
      "~!@#$%^&*()_+" "QWERTYUIOP{}|" "ASDFGHJKL:\"•" "•ZXCVBNM<>?",
      NONE49, NONE49},
     ""},
    {"UK QWERTY",
     {"`1234567890-=" "qwertyuiop[]•" "asdfghjkl;'#" "\\zxcvbnm,./",
      "¬!\"£$%^&*()_+" "QWERTYUIOP{}•" "ASDFGHJKL:@~" "|ZXCVBNM<>?",
      "¦•••€••••••••" NONE13 NONE12 NONE11, NONE49},
     ""},
    {"FR AZERTY",
     {"²&é\"'(-è_çà)=" "azertyuiop^$•" "qsdfghjklmù*" "<wxcvbn,;:!",
      "•1234567890°+" "AZERTYUIOP¨£•" "QSDFGHJKLM%µ" ">WXCVBN?./§",
      "••~#{[|`\\^@]}" "••€••••••••¤•" NONE12 NONE11, NONE49},
     "^¨~`"},
    {"DE QWERTZ",
     {"^1234567890ß´" "qwertzuiopü+•" "asdfghjklöä#" "<yxcvbnm,.-",
      "°!\"§$%&/()=?`" "QWERTZUIOPÜ*•" "ASDFGHJKLÖÄ'" ">YXCVBNM;:_",
      "••²³•••{[]}\\•" "@•€••••••••~•" NONE12 "|••••••µ•••", NONE49},
     "^´`"},
};

/* Dead key + base letter -> composed character. */
static const struct { uint32_t accent; const char *pairs; } COMPOSE[] = {
    {'^', "aâeêiîoôuûAÂEÊIÎOÔUÛ"},
    {0xA8, "aäeëiïoöuüyÿAÄEËIÏOÖUÜ"},
    {0xB4, "aáeéiíoóuúyýAÁEÉIÍOÓUÚYÝ"},
    {'`', "aàeèiìoòuùAÀEÈIÌOÒUÙ"},
    {'~', "aãnñoõAÃNÑOÕ"},
};

uint32_t kbd_utf8_next(const char **s)
{
    const unsigned char *p = (const unsigned char *)*s;
    uint32_t c = *p++;
    int n = c < 0x80 ? 0 : c >= 0xF0 ? 3 : c >= 0xE0 ? 2 : c >= 0xC0 ? 1 : -1;
    if (n < 0) { *s = (const char *)p; return 0xFFFD; }
    if (n) c &= 0x3Fu >> n;
    for (; n; n--, p++) {
        if ((*p & 0xC0) != 0x80) { *s = (const char *)p; return 0xFFFD; }
        c = c << 6 | (*p & 0x3F);
    }
    *s = (const char *)p;
    return c;
}

int kbd_layout_count(void) { return (int)(sizeof LAYOUTS / sizeof *LAYOUTS); }
const kbd_layout *kbd_layout_get(int i) { return i >= 0 && i < kbd_layout_count() ? &LAYOUTS[i] : NULL; }
const char *kbd_layout_name(const kbd_layout *l) { return l->name; }

static bool is_dead(const kbd_layout *l, uint32_t cp)
{
    for (const char *s = l->dead; *s;)
        if (kbd_utf8_next(&s) == cp) return true;
    return false;
}

static bool find(const kbd_layout *l, uint32_t cp, kbd_stroke *out)
{
    for (int lv = 0; lv < 4; lv++) {
        const char *s = l->level[lv];
        for (int k = 0; k < 49 && *s; k++) {
            if (kbd_utf8_next(&s) == cp) {
                out->key = KEYS[k];
                out->mods = LEVEL_MODS[lv];
                return true;
            }
        }
    }
    return false;
}

int kbd_map(const kbd_layout *l, uint32_t cp, kbd_stroke out[2])
{
    static const kbd_stroke SPACE = {0x2C, 0};
    if (cp == '\n') { out[0] = (kbd_stroke){0x28, 0}; return 1; }
    if (cp == '\t') { out[0] = (kbd_stroke){0x2B, 0}; return 1; }
    if (cp == ' ') { out[0] = SPACE; return 1; }
    if (cp != 0x2022 && find(l, cp, &out[0])) {
        if (!is_dead(l, cp)) return 1;
        out[1] = SPACE; /* dead key alone: dead key + space */
        return 2;
    }
    for (size_t i = 0; i < sizeof COMPOSE / sizeof *COMPOSE; i++) {
        for (const char *s = COMPOSE[i].pairs; *s;) {
            uint32_t base = kbd_utf8_next(&s), res = kbd_utf8_next(&s);
            if (res != cp) continue;
            if (is_dead(l, COMPOSE[i].accent) && find(l, COMPOSE[i].accent, &out[0]) && find(l, base, &out[1]) &&
                !is_dead(l, base))
                return 2;
        }
    }
    return 0;
}

uint32_t kbd_untypeable(const kbd_layout *l, const char *utf8)
{
    kbd_stroke st[2];
    while (*utf8) {
        uint32_t cp = kbd_utf8_next(&utf8);
        if (!kbd_map(l, cp, st)) return cp;
    }
    return 0;
}

bool kbd_tables_ok(void)
{
    for (int i = 0; i < kbd_layout_count(); i++)
        for (int lv = 0; lv < 4; lv++) {
            const char *s = LAYOUTS[i].level[lv];
            int n = 0;
            while (*s) kbd_utf8_next(&s), n++;
            if (n != 49) return false;
        }
    return true;
}
