/* CardPass application logic: screens, navigation, lock. Portable C.
 * The platform feeds keys and ticks, and pushes the dirty strips to the panel:
 *
 *   app_key(&a, key, down); app_tick(&a, now_ms);
 *   while (app_dirty(&a, &y0, &y1)) for each strip in [y0, y1): app_draw(&a, &strip); push
 */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "fido.h"
#include "kdbx.h"
#include "settings.h"
#include "ui.h"

/* Keys: a Unicode code point, or one of these (fn+; , . / are the arrows on the Cardputer). */
enum {
    K_ENTER = 0x110000, K_BACKSPACE, K_TAB, K_ESC, K_UP, K_DOWN, K_LEFT, K_RIGHT, K_DEL,
};
#define K_FN 0x1000000u   /* modifier bits OR-ed into the key */
#define K_CTRL 0x2000000u
#define K_KEY(k) ((k) & 0xFFFFFFu)

typedef struct {
    /* Names of files in the database folder ending with ext (".kdbx", ".keyx", ".key"). */
    int (*list_files)(void *ctx, const char *ext, char names[][64], int max);
    /* Full path for a file name in the database folder. */
    void (*path)(void *ctx, const char *name, char *out, size_t n);
    int64_t (*now)(void *ctx, bool *valid);   /* unix seconds UTC; valid = time was set */
    uint32_t (*millis)(void *ctx);             /* monotonic ms (KDF benchmark) */
    int (*battery)(void *ctx);                 /* percent, -1 unknown */
    /* Keyboard output (USB or BLE HID). hid_ready: a host is connected. */
    bool (*hid_ready)(void *ctx);
    void (*stroke)(void *ctx, uint8_t key, uint8_t mods);
    void (*delay)(void *ctx, int ms);
    void (*save_settings)(void *ctx, const char *text);
    void (*present)(void *ctx);                /* push dirty strips now (progress during long work) */
    void (*pump)(void *ctx);                   /* one loop pass: keys, app_tick, present (modal screens) */
    /* USB drive mode: enter = unmount the card and expose it to the PC (false: failed);
     * leave = stop and remount. The app has locked and wiped the database before entering. */
    bool (*usb_drive)(void *ctx, bool enter);
    void *ctx;
} app_platform;

enum {
    SCR_PICKER, SCR_UNLOCK, SCR_HOME, SCR_GROUP, SCR_SEARCH, SCR_ENTRY, SCR_QR,
    SCR_MENU, SCR_EDIT, SCR_GEN, SCR_SETTINGS, SCR_AUDIT, SCR_EXPIRY, SCR_CONFIRM, SCR_CREATE, SCR_HELP, SCR_FIDO, SCR_DRIVE,
};
#define APP_QR_MAX_VERSION 11   /* 61 modules: still 2 px/module on 135 px */
#define APP_QR_BYTES ((((APP_QR_MAX_VERSION) * 4 + 17) * ((APP_QR_MAX_VERSION) * 4 + 17) + 7) / 8 + 1)

#define APP_MAX_DBS 16
#define APP_RECENT 8
#define APP_MAX_ROWS 96

typedef struct {
    uint8_t kind;      /* entry view row kind */
    const kdbx_field *f;
    const kdbx_attachment *att;
    uint32_t off;      /* notes: byte offset of this wrapped line */
    uint16_t len;
} app_row;

struct app_edit;
struct app_gen;
struct app_create;

typedef struct {
    const app_platform *p;
    cp_settings cfg;
    const ui_theme *theme;
    const ui_font *font;
    int scr;
    int dirty_y0, dirty_y1;
    uint32_t now_ms, last_input_ms;

    /* picker / unlock */
    char dbs[APP_MAX_DBS][64];
    int ndbs;
    char keyfiles[APP_MAX_DBS][64];
    int nkeyfiles, keyfile;    /* keyfile: index + 1, 0 = none */
    char dbname[64], path[256];
    char pw[128];
    int pwlen;
    char msg[64];
    int progress;              /* KDF progress %, -1 = idle */

    kdbx_db *db;
    const kdbx_entry *recent[APP_RECENT];
    int nrecent;

    /* lists */
    int sel, top;
    const kdbx_group *group;
    char query[64];
    int qlen;
    void *hits;                /* list rows (entries + groups + extras) */
    int nhits, nentries, list_cap;

    /* entry view */
    const kdbx_entry *entry;
    app_row rows[APP_MAX_ROWS];
    int nrows;
    bool revealed;
    double pw_bits;
    int totp_period;
    int back_scr;

    /* QR of one field: only the modules are kept, wiped on exit */
    uint8_t qr[APP_QR_BYTES];
    uint32_t qr_until;
    char qr_label[32];

    /* menu / confirm */
    int menu_back, confirm_back, confirm_action;
    char confirm_text[64];
    bool weak_only, text_edit;

    /* passkey confirmation (modal, while a browser waits) */
    const fido_cred *fcreds;
    size_t nfcreds;
    char frp[64];
    int fdecision;             /* 0 pending, n > 0: creds[n-1] approved, -1 denied */
    bool fido_active;

    struct app_edit *ed;
    struct app_gen *gen;
    struct app_create *cr;
    float *audit_bits;         /* parallel to the list rows on the audit screen */
} app;

void app_init(app *a, const app_platform *p, const cp_settings *cfg);
void app_key(app *a, uint32_t key, bool down);
void app_tick(app *a, uint32_t now_ms);      /* auto-lock, TOTP countdown, QR timeout */
void app_lock(app *a);                        /* wipe everything, back to the picker */
bool app_dirty(app *a, int *y0, int *y1);     /* dirty band, then cleared */
void app_draw(app *a, ui_strip *s);           /* draws the whole screen clipped to s */
/* Modal passkey confirmation for fido_env.choose: returns the chosen index or -1 (denied/timeout). */
int app_ask_passkey(app *a, const char *rp, const fido_cred *creds, size_t n);
