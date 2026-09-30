/* CardPass application logic: screens, navigation, lock. Portable C.
 * The platform feeds keys and ticks, and pushes the dirty strips to the panel:
 *
 *   app_key(&a, key, down); app_tick(&a, now_ms);
 *   while (app_dirty(&a, &y0, &y1)) for each strip in [y0, y1): app_draw(&a, &strip); push
 */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "kdbx.h"
#include "ui.h"

/* Keys: a Unicode code point, or one of these (fn+; , . / are the arrows on the Cardputer). */
enum {
    K_ENTER = 0x110000, K_BACKSPACE, K_TAB, K_ESC, K_UP, K_DOWN, K_LEFT, K_RIGHT, K_DEL,
};
#define K_FN 0x1000000u   /* modifier bits OR-ed into the key */
#define K_CTRL 0x2000000u
#define K_KEY(k) ((k) & 0xFFFFFFu)

typedef struct {
    /* *.kdbx names in the database folder; returns count. */
    int (*list_dbs)(void *ctx, char names[][64], int max);
    /* Full path for a database name. */
    void (*db_path)(void *ctx, const char *name, char *out, size_t n);
    int64_t (*now)(void *ctx, bool *valid);   /* unix seconds UTC; valid = time was set */
    int (*battery)(void *ctx);                 /* percent, -1 unknown */
    void *ctx;
} app_platform;

typedef struct {
    const ui_theme *theme;
    const ui_font *font;
    bool reveal_hold;          /* hold R to reveal (else R toggles) */
    uint32_t autolock_ms;
    int tz_minutes;            /* display only */
} app_settings;

enum { SCR_PICKER, SCR_UNLOCK, SCR_HOME, SCR_GROUP, SCR_SEARCH, SCR_ENTRY };

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

typedef struct {
    const app_platform *p;
    app_settings set;
    int scr;
    int dirty_y0, dirty_y1;
    uint32_t now_ms, last_input_ms;

    /* picker / unlock */
    char dbs[APP_MAX_DBS][64];
    int ndbs;
    char dbname[64], path[256];
    char pw[128];
    int pwlen;
    char msg[64];

    kdbx_db *db;
    const kdbx_entry *recent[APP_RECENT];
    int nrecent;

    /* lists */
    int sel, top;
    const kdbx_group *group;
    char query[64];
    int qlen;
    void *hits;        /* list rows (entries + groups + extras) */
    int nhits, nentries, list_cap;

    /* entry view */
    const kdbx_entry *entry;
    app_row rows[APP_MAX_ROWS];
    int nrows;
    bool revealed;
    double pw_bits;
    int back_scr;
} app;

void app_init(app *a, const app_platform *p, const app_settings *s);
void app_key(app *a, uint32_t key, bool down);
void app_tick(app *a, uint32_t now_ms);      /* auto-lock, TOTP countdown */
void app_lock(app *a);                        /* wipe everything, back to the picker */
bool app_dirty(app *a, int *y0, int *y1);     /* dirty band, then cleared */
void app_draw(app *a, ui_strip *s);           /* draws the whole screen clipped to s */
