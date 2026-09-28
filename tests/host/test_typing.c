/* Layouts + auto-type. Real host typing is verified on the device (layout test). */
#include <stdio.h>
#include <string.h>
#include "typing.h"

static int failures;
#define CHECK(c, ...) do { if (!(c)) { failures++; printf("FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static const kbd_layout *layout(const char *prefix)
{
    for (int i = 0; i < kbd_layout_count(); i++)
        if (!strncmp(kbd_layout_name(kbd_layout_get(i)), prefix, strlen(prefix))) return kbd_layout_get(i);
    return NULL;
}

/* "key:mods key:mods" for one code point */
static const char *strokes(const kbd_layout *l, const char *ch)
{
    static char out[64];
    kbd_stroke st[2];
    int n = kbd_map(l, kbd_utf8_next(&ch), st);
    out[0] = 0;
    for (int i = 0; i < n; i++) sprintf(out + strlen(out), "%s%02x:%02x", i ? " " : "", st[i].key, st[i].mods);
    return out;
}

/* ---- auto-type mock ---- */
static char log_[4096];
static bool mock_field(void *ctx, const char *name, char *buf, size_t n)
{
    (void)ctx;
    const char *v = !strcmp(name, "UserName") ? "alice" : !strcmp(name, "Password") ? "p@ss" :
                    !strcmp(name, "PIN") ? "12" : !strcmp(name, "Euro") ? "5€" : !strcmp(name, "Notes") ? "a\nb" : NULL;
    if (!v) return false;
    snprintf(buf, n, "%s", v);
    return true;
}
static bool mock_totp(void *ctx, char *buf, size_t n) { (void)ctx; snprintf(buf, n, "123456"); return true; }
static void mock_stroke(void *ctx, uint8_t key, uint8_t mods)
{
    (void)ctx;
    sprintf(log_ + strlen(log_), "%02x%s ", key, mods == 0 ? "" : mods == KBD_LSHIFT ? "S" : mods == KBD_LCTRL ? "C" : "?");
}
static void mock_delay(void *ctx, int ms) { (void)ctx; sprintf(log_ + strlen(log_), "d%d ", ms); }
static const at_ops OPS = {mock_field, mock_totp, mock_stroke, mock_delay, NULL};

static int at(const char *seq, const kbd_layout *l, at_error *e)
{
    log_[0] = 0;
    return at_type(seq, l, &OPS, 0, e);
}

int main(void)
{
    const kbd_layout *us = layout("US"), *uk = layout("UK"), *fr = layout("FR"), *de = layout("DE");
    CHECK(kbd_tables_ok() && us && uk && fr && de, "tables");

    /* every printable ASCII character on every layout */
    char ascii[96];
    for (int c = 32; c < 127; c++) ascii[c - 32] = (char)c;
    ascii[95] = 0;
    for (int i = 0; i < kbd_layout_count(); i++) {
        uint32_t bad = kbd_untypeable(kbd_layout_get(i), ascii);
        CHECK(!bad, "%s can't type '%c'", kbd_layout_name(kbd_layout_get(i)), (char)bad);
    }
    CHECK(!kbd_untypeable(fr, "éèàçùâêîôûäëïöüÿ²µ£§°€¤ñ"), "FR accents");
    CHECK(!kbd_untypeable(de, "äöüÄÖÜß§°²³€µéèáàâêÉÈ"), "DE accents");
    CHECK(!kbd_untypeable(uk, "£€¬¦"), "UK extras");
    CHECK(kbd_untypeable(fr, "É") == 0xC9 && kbd_untypeable(us, "é") == 0xE9 && kbd_untypeable(us, "€") == 0x20AC,
          "untypeable detection");

    CHECK(!strcmp(strokes(us, "a"), "04:00") && !strcmp(strokes(us, "A"), "04:02"), "US a/A");
    CHECK(!strcmp(strokes(fr, "a"), "14:00") && !strcmp(strokes(fr, "1"), "1e:02"), "FR a/1");
    CHECK(!strcmp(strokes(fr, "é"), "1f:00") && !strcmp(strokes(fr, "@"), "27:40"), "FR é/@");
    CHECK(!strcmp(strokes(fr, "ê"), "2f:00 08:00") && !strcmp(strokes(fr, "ï"), "2f:02 0c:00"), "FR dead ^ ¨");
    CHECK(!strcmp(strokes(fr, "^"), "2f:00 2c:00"), "FR ^ alone = dead + space");
    CHECK(!strcmp(strokes(de, "z"), "1c:00") && !strcmp(strokes(de, "y"), "1d:00"), "DE z/y");
    CHECK(!strcmp(strokes(de, "é"), "2e:00 08:00") && !strcmp(strokes(de, "@"), "14:40"), "DE é/@");
    CHECK(!strcmp(strokes(uk, "£"), "20:02") && !strcmp(strokes(uk, "\""), "1f:02") && !strcmp(strokes(uk, "#"), "32:00"),
          "UK £ \" #");
    CHECK(!strcmp(strokes(us, "\n"), "28:00") && !strcmp(strokes(us, "\t"), "2b:00"), "newline/tab");

    /* auto-type */
    at_error e;
    CHECK(at(AT_DEFAULT_SEQUENCE, us, &e) == AT_OK, "default");
    CHECK(!strcmp(log_, "04 0f 0c 06 08 2b 13 1fS 16 16 28 "), "default strokes: %s", log_);
    CHECK(at("{TAB 3}^a~{+}{{}{}}", us, &e) == AT_OK && !strcmp(log_, "2b 2b 2b 04C 28 2eS 2fS 30S "), "keys: %s", log_);
    CHECK(at("{S:PIN}{DELAY 500}{notes}", us, &e) == AT_OK && !strcmp(log_, "1e 1f d500 04 28 05 "), "field: %s", log_);
    CHECK(at("{DELAY=20}ab", us, &e) == AT_OK && !strcmp(log_, "04 d20 05 d20 "), "key delay: %s", log_);
    CHECK(at("{TOTP}", us, &e) == AT_OK && !strcmp(log_, "1e 1f 20 21 22 23 "), "totp: %s", log_);

    CHECK(at("{USERNAME}{TAB}{S:Euro}", us, &e) == AT_UNTYPEABLE && !strcmp(e.detail, "Euro") && !log_[0],
          "untypeable field must type nothing: %s / %s", e.detail, log_);
    CHECK(at("{USERNAME}{S:Euro}", fr, &e) == AT_OK, "€ on FR");
    CHECK(at("{S:Missing}", us, &e) == AT_MISSING_FIELD && !strcmp(e.detail, "Missing"), "missing");
    CHECK(at("{USERNAME}{FOO}", us, &e) == AT_UNSUPPORTED && !strcmp(e.detail, "FOO") && !log_[0], "unsupported");
    CHECK(at("{URL}", us, &e) == AT_OK && !log_[0], "missing standard field types nothing");
    CHECK(at("+(ab)", us, &e) == AT_SYNTAX, "groups");
    CHECK(at("{TAB", us, &e) == AT_SYNTAX && at("{TAB x}", us, &e) == AT_SYNTAX, "syntax");

    printf("typing: %d failures\n", failures);
    return failures != 0;
}
