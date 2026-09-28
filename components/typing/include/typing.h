/* Host keyboard layouts (char -> HID keystrokes) and KeePass auto-type sequences.
 * Hardware-free: keystrokes go to a callback (USB or BLE HID on the device). */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum { KBD_LCTRL = 0x01, KBD_LSHIFT = 0x02, KBD_LALT = 0x04, KBD_ALTGR = 0x40 };

typedef struct { uint8_t key, mods; } kbd_stroke;
typedef struct kbd_layout kbd_layout;

int kbd_layout_count(void);
const kbd_layout *kbd_layout_get(int i);
const char *kbd_layout_name(const kbd_layout *l);
/* Keystrokes for one code point (1 or 2 with a dead key). 0 = not typeable. */
int kbd_map(const kbd_layout *l, uint32_t cp, kbd_stroke out[2]);
/* First code point of utf8 that can't be typed on l, 0 if everything can. */
uint32_t kbd_untypeable(const kbd_layout *l, const char *utf8);
bool kbd_tables_ok(void); /* table sanity, for tests */
uint32_t kbd_utf8_next(const char **s);

/* ---- auto-type ---- */

#define AT_DEFAULT_SEQUENCE "{USERNAME}{TAB}{PASSWORD}{ENTER}"

enum { AT_OK, AT_SYNTAX, AT_UNSUPPORTED, AT_UNTYPEABLE, AT_MISSING_FIELD, AT_NOMEM };

typedef struct {
    int code;
    char detail[48];  /* placeholder or field name; never field contents */
} at_error;

typedef struct {
    /* Plaintext of a field ("UserName", "Password", "Title", "URL", "Notes", custom).
     * false = no such field. The buffer is wiped by the caller of this callback. */
    bool (*field)(void *ctx, const char *name, char *buf, size_t n);
    bool (*totp)(void *ctx, char *buf, size_t n);          /* current code, fresh enough to type */
    void (*stroke)(void *ctx, uint8_t key, uint8_t mods);  /* press + release */
    void (*delay)(void *ctx, int ms);
    void *ctx;
} at_ops;

/* Checks the whole sequence first (placeholders, fields, layout); types only if
 * everything is typeable, so a password is never typed partially. */
int at_type(const char *seq, const kbd_layout *l, const at_ops *ops, int key_delay_ms, at_error *err);
/* Check only (no keystrokes). */
int at_check(const char *seq, const kbd_layout *l, const at_ops *ops, at_error *err);
