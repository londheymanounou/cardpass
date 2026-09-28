/* KeePass auto-type: {USERNAME} {PASSWORD} {TITLE} {URL} {NOTES} {TOTP} {S:Name},
 * special keys ({TAB 2}, {ENTER}, ...), {DELAY n}, {DELAY=n}, literal escapes
 * ({+} {{} ...) and the SendKeys modifiers + ^ % and ~ (Enter). */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "typing.h"

#define FIELD_MAX 8192

static const struct { const char *name; uint8_t key; } SPECIAL[] = {
    {"TAB", 0x2B}, {"ENTER", 0x28}, {"SPACE", 0x2C}, {"BACKSPACE", 0x2A}, {"BS", 0x2A}, {"BKSP", 0x2A},
    {"DELETE", 0x4C}, {"DEL", 0x4C}, {"INSERT", 0x49}, {"INS", 0x49}, {"UP", 0x52}, {"DOWN", 0x51},
    {"LEFT", 0x50}, {"RIGHT", 0x4F}, {"HOME", 0x4A}, {"END", 0x4D}, {"PGUP", 0x4B}, {"PGDN", 0x4E},
    {"ESC", 0x29}, {"F1", 0x3A}, {"F2", 0x3B}, {"F3", 0x3C}, {"F4", 0x3D}, {"F5", 0x3E}, {"F6", 0x3F},
    {"F7", 0x40}, {"F8", 0x41}, {"F9", 0x42}, {"F10", 0x43}, {"F11", 0x44}, {"F12", 0x45},
};
static const struct { const char *name, *field; } FIELDS[] = {
    {"USERNAME", "UserName"}, {"PASSWORD", "Password"}, {"TITLE", "Title"}, {"URL", "URL"}, {"NOTES", "Notes"},
};

typedef struct {
    const kbd_layout *l;
    const at_ops *ops;
    bool dry;
    int key_delay;
    uint8_t mods;   /* pending + ^ % */
    at_error *err;
    char *buf;
} run_t;

static void wipe(char *p, size_t n)
{
    volatile char *v = p;
    while (n--) *v++ = 0;
}

static int fail(run_t *r, int code, const char *detail, size_t n)
{
    r->err->code = code;
    snprintf(r->err->detail, sizeof r->err->detail, "%.*s", (int)(n < 47 ? n : 47), detail);
    return code;
}

static void stroke(run_t *r, uint8_t key, uint8_t mods)
{
    if (r->dry) return;
    r->ops->stroke(r->ops->ctx, key, mods);
    if (r->key_delay > 0) r->ops->delay(r->ops->ctx, r->key_delay);
}

/* Types one code point; pending modifiers apply to its last keystroke. */
static bool type_cp(run_t *r, uint32_t cp)
{
    kbd_stroke st[2];
    int n = kbd_map(r->l, cp, st);
    if (!n) return false;
    for (int i = 0; i < n; i++) stroke(r, st[i].key, st[i].mods | (i == n - 1 ? r->mods : 0));
    r->mods = 0;
    return true;
}

static int type_text(run_t *r, const char *s, const char *what)
{
    while (*s)
        if (!type_cp(r, kbd_utf8_next(&s))) return fail(r, AT_UNTYPEABLE, what, strlen(what));
    return AT_OK;
}

static int type_field(run_t *r, const char *name, bool standard)
{
    bool ok = r->ops->field(r->ops->ctx, name, r->buf, FIELD_MAX);
    if (!ok) r->buf[0] = 0;
    int rc = ok || standard ? type_text(r, r->buf, name) : fail(r, AT_MISSING_FIELD, name, strlen(name));
    wipe(r->buf, FIELD_MAX);
    return rc;
}

static bool ieq(const char *a, size_t n, const char *b)
{
    if (strlen(b) != n) return false;
    for (size_t i = 0; i < n; i++)
        if (toupper((unsigned char)a[i]) != b[i]) return false;
    return true;
}

/* {token}: t[0..n) is the text between the braces. */
static int placeholder(run_t *r, const char *t, size_t n)
{
    /* split "NAME arg" / "NAME=arg" */
    size_t nl = 0;
    while (nl < n && t[nl] != ' ' && t[nl] != '=') nl++;
    bool eq = nl < n && t[nl] == '=';
    const char *arg = nl < n ? t + nl + 1 : NULL;
    int count = 1;
    if (arg) {
        char *end;
        long v = strtol(arg, &end, 10);
        if (end != t + n || v < 0 || v > 100000) return fail(r, AT_SYNTAX, t, n);
        count = (int)v;
    }

    if (nl > 2 && (t[0] == 'S' || t[0] == 's') && t[1] == ':' && !arg) {
        char name[128];
        snprintf(name, sizeof name, "%.*s", (int)(n - 2), t + 2);
        return type_field(r, name, false);
    }
    if (ieq(t, nl, "DELAY")) {
        if (!arg) return fail(r, AT_SYNTAX, t, n);
        if (eq) r->key_delay = count;
        else if (!r->dry) r->ops->delay(r->ops->ctx, count);
        return AT_OK;
    }
    if (arg && eq) return fail(r, AT_SYNTAX, t, n);
    if (ieq(t, nl, "TOTP") && !arg) {
        if (!r->ops->totp || !r->ops->totp(r->ops->ctx, r->buf, FIELD_MAX)) return fail(r, AT_MISSING_FIELD, "TOTP", 4);
        int rc = type_text(r, r->buf, "TOTP");
        wipe(r->buf, FIELD_MAX);
        return rc;
    }
    for (size_t i = 0; i < sizeof FIELDS / sizeof *FIELDS; i++)
        if (ieq(t, nl, FIELDS[i].name) && !arg) return type_field(r, FIELDS[i].field, true);
    for (size_t i = 0; i < sizeof SPECIAL / sizeof *SPECIAL; i++) {
        if (!ieq(t, nl, SPECIAL[i].name)) continue;
        for (int k = 0; k < count; k++) stroke(r, SPECIAL[i].key, r->mods);
        r->mods = 0;
        return AT_OK;
    }
    /* literal character, e.g. {+} {{} {~} {a 3} */
    const char *p = t;
    uint32_t cp = kbd_utf8_next(&p);
    if ((size_t)(p - t) == nl) {
        uint8_t m = r->mods;
        for (int k = 0; k < count; k++) {
            r->mods = m;
            if (!type_cp(r, cp)) return fail(r, AT_UNTYPEABLE, t, nl);
        }
        return AT_OK;
    }
    return fail(r, AT_UNSUPPORTED, t, nl);
}

static int run(const char *seq, run_t *r)
{
    const char *s = seq;
    while (*s) {
        char c = *s;
        if (c == '{') {
            /* "{}}" is a literal '}' */
            const char *end = s[1] == '}' && s[2] == '}' ? s + 2 : strchr(s + 1, '}');
            if (!end || end == s + 1) return fail(r, AT_SYNTAX, s, strlen(s));
            int rc = placeholder(r, s + 1, (size_t)(end - s - 1));
            if (rc) return rc;
            s = end + 1;
        } else if (c == '+' || c == '^' || c == '%') {
            r->mods |= c == '+' ? KBD_LSHIFT : c == '^' ? KBD_LCTRL : KBD_LALT;
            s++;
        } else if (c == '~') {
            stroke(r, 0x28, r->mods);
            r->mods = 0;
            s++;
        } else if (c == '(' || c == ')') {
            return fail(r, AT_SYNTAX, s, 1); /* ponytail: modifier groups like +(abc) unsupported */
        } else {
            const char *p = s;
            if (!type_cp(r, kbd_utf8_next(&p))) return fail(r, AT_UNTYPEABLE, s, (size_t)(p - s));
            s = p;
        }
    }
    return AT_OK;
}

static int go(const char *seq, const kbd_layout *l, const at_ops *ops, int key_delay, bool dry, at_error *err)
{
    run_t r = {l, ops, dry, key_delay, 0, err, malloc(FIELD_MAX)};
    err->code = AT_OK;
    err->detail[0] = 0;
    if (!r.buf) return err->code = AT_NOMEM;
    int rc = run(seq, &r);
    wipe(r.buf, FIELD_MAX);
    free(r.buf);
    return rc;
}

int at_check(const char *seq, const kbd_layout *l, const at_ops *ops, at_error *err)
{
    return go(seq, l, ops, 0, true, err);
}

int at_type(const char *seq, const kbd_layout *l, const at_ops *ops, int key_delay_ms, at_error *err)
{
    int rc = go(seq, l, ops, key_delay_ms, true, err);
    return rc ? rc : go(seq, l, ops, key_delay_ms, false, err);
}
