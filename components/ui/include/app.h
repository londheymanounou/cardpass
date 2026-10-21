/* CardPass application logic: screens, navigation, lock. Portable C.
 * The platform feeds keys and ticks, and pushes the dirty strips to the panel:
 *
 *   app_key(&a, key, down); app_tick(&a, now_ms);
 *   while (app_dirty(&a, &y0, &y1)) for each strip in [y0, y1): app_draw(&a, &strip); push
 */
#pragma once

extern void (*cp_heap_stats)(size_t *free_bytes, size_t *largest_block);   /* the firmware's heap numbers, shown when a save runs out of memory */
extern const char *cp_build_id;   /* shown on the splash screen; the firmware sets it to the image hash's first digits */
#include <stdbool.h>
#include <stdint.h>
#include "fido.h"
#include "kdbx.h"
#include "settings.h"
#include "ui.h"

/* Keys: a Unicode code point, or one of these (; , . / or fn+; , . / are the arrows on the Cardputer, Settings -> Arrows). */
enum {
    K_ENTER = 0x110000, K_BACKSPACE, K_TAB, K_ESC, K_UP, K_DOWN, K_LEFT, K_RIGHT, K_DEL,
};
#define K_FN 0x1000000u   /* modifier bits OR-ed into the key */
#define K_CTRL 0x2000000u
#define K_KEY(k) ((k) & 0xFFFFFFu)

typedef struct { char ssid[33]; bool secure; int8_t rssi; } app_ap;
enum { BT_OFF = 0, BT_ADVERTISING, BT_PAIR_CONFIRM, BT_CONNECTED };
enum { NTP_OK = 0, NTP_ERR_CONNECT = 1, NTP_ERR_PASSWORD = 2, NTP_ERR_SERVER = 3, NTP_ERR_BAD_TIME = 4 };

#define VC_ROOT "@vc"   /* browser folder of the mounted VeraCrypt container */
typedef struct { char name[64]; bool dir; uint32_t size; int64_t mtime; } app_dirent;   /* one entry of the file browser */

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
    /* Clock. set_time: system clock (UTC). Wi-Fi is on ONLY inside wifi_scan / ntp_sync and the
     * app never calls them while a database is open. ntp_sync: connect, query, switch Wi-Fi off. */
    /* Power. backlight: 0 = normal (settings brightness), 1 = dim, 2 = screen off. shutdown: deep sleep,
     * woken by the keyboard only (used when the battery is critical, after the app locked and wiped). */
    void (*backlight)(void *ctx, int state);
    void (*shutdown)(void *ctx);
    void (*set_time)(void *ctx, int64_t unix_s);
    int (*wifi_scan)(void *ctx, app_ap *out, int max);
    int (*ntp_sync)(void *ctx, const char *ssid, const char *pass, int64_t *unix_s);
    /* Bluetooth typing: the radio is on only between bt_start and bt_stop. bt_state returns BT_* and,
     * while a host is pairing, its 6-digit numeric-comparison code. */
    bool (*bt_start)(void *ctx);
    void (*bt_stop)(void *ctx);
    int (*bt_state)(void *ctx, uint32_t *code);
    void (*bt_answer)(void *ctx, bool accept);
    void (*bt_forget)(void *ctx);
    /* File browser (key files): folders are relative to the SD card root ("" = root), no leading slash. */
    int (*list_dir)(void *ctx, const char *rel, app_dirent *out, int max);   /* entries (no . .. or hidden), count */
    void (*root_path)(void *ctx, const char *rel, char *out, size_t n);      /* full path of a root-relative path */
    void (*start_dir)(void *ctx, char *out, size_t n);                       /* where the browser starts (the database folder) */
    /* VeraCrypt container (AES-XTS + SHA-512): open the file at the SD-root-relative path `rel` and mount the FAT
     * inside it; its files then show up in the browser (and in list_dir/root_path) under the folder VC_ROOT.
     * 0 = ok, 5 = ok but read-only, 1 = wrong password / not a container, 2 = unreadable, 3 = unsupported variant,
     * 4 = no FAT inside. A standard (outer) volume is mounted read-only unless allow_outer_write: it might hide a hidden
     * volume, and any write to it can destroy that (deniability: the container can't say). A hidden volume is always
     * writable. progress(arg, 0..100) during each slow key derivation. */
    int (*vc_mount)(void *ctx, const char *rel, const uint8_t *pw, size_t pwlen, bool allow_outer_write,
                    void (*progress)(void *, int), void *arg);
    void (*vc_unmount)(void *ctx);                                           /* close it and wipe its keys */
    void *ctx;
} app_platform;

enum {
    SCR_PICKER, SCR_UNLOCK, SCR_HOME, SCR_GROUP, SCR_SEARCH, SCR_ENTRY, SCR_QR,
    SCR_MENU, SCR_EDIT, SCR_GEN, SCR_SETTINGS, SCR_AUDIT, SCR_EXPIRY, SCR_CONFIRM, SCR_CREATE, SCR_HELP, SCR_FIDO, SCR_DRIVE, SCR_TIME, SCR_ACCOUNT, SCR_GROUPS, SCR_VIEW, SCR_BT, SCR_SPLASH, SCR_BROWSE,
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
struct app_time;
struct app_acct;
struct app_groups;
struct app_view;
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
    char keyrel[160];          /* chosen key file, relative to the SD root ("" = none) */
    char br_dir[160];          /* file browser: current folder (relative to the SD root, or VC_ROOT/... inside a container) */
    int br_mode;               /* 0 = choosing a key file, 1 = choosing a database or container */
    bool vc_pending;           /* the unlock screen asks for a VeraCrypt container's password */
    bool vc_open;              /* a container is mounted */
    bool vc_write;             /* the container password screen: allow writing to a standard volume (Tab) */
    bool from_browse;          /* the unlock screen was reached from the browser (back returns there) */
    char vc_rel[160];          /* the container chosen, relative to the SD root */
    app_dirent *br_ents;       /* its entries, malloc'd while the browser is open */
    int br_n;
    int br_prompt;             /* browser: 0 none, 1 new folder, 2 rename, 3 delete? (a one-line prompt over the list) */
    char br_name[64];
    int br_namelen;
    int fails;                 /* wrong passwords in a row since the last good unlock (RAM only: a reboot resets it) */
    uint32_t fail_until;       /* millis: no unlock attempts before this once `fails` is 5 or more */
    bool pw_show;              /* the eye: show typed passwords; reset whenever the screen changes */
    int pw_show_scr;
    char query_prev[64];       /* the query the current hits are for (typing narrows them) */
    char dbname[64], path[256];
    /* Set time -> Wi-Fi -> "from a database": the network whose password the next unlock fetches (ssid "" = none).
     * Only lives on the picker / unlock / key file screens; the unlock it triggers ends locked again (app_time.c). */
    app_ap wifi_fetch;
    bool wifi_fetch_save;
    char pw[128];
    int pwlen;
    char msg[64];
    int progress;              /* KDF progress %, -1 = idle */
    uint32_t progress_t0, progress_ms;   /* start, and time of the last update (ms); 0 = not started */

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
    const fido_new *fnew;      /* a passkey registration is waiting for the user (else a sign-in: fcreds) */
    const kdbx_entry **flist;  /* registration: entries the passkey could be added to (row 1..nflist; row 0 = a new entry) */
    int nflist, fother;        /* fother: a last row "Other entry..." lists every entry */
    const kdbx_entry *fchosen; /* the decision: NULL = a new entry */
    int fdecision;             /* 0 pending, n > 0: creds[n-1] approved, -1 denied */
    bool fido_active;

    /* animations (optional, see app_anim.c) */
    bool anim_on, anim_live;   /* anim_live: something was moving at the last frame */
    int sel_prev;
    uint32_t sel_ms, scr_ms, anim_frame_ms, toast_ms;
    int last_scr;
    const void *last_group, *last_entry;
    char msg_prev[64];

    bool bt_on, bt_auto;       /* radio switched on by the user; screen opened by a pairing request */
    int bt_state, bt_return;
    uint32_t bt_code, bt_ms;
    uint32_t splash_until;     /* 0 until the first tick */

    int power;                 /* 0 normal, 1 dimmed, 2 screen off */
    int bat_low;               /* consecutive low battery readings */
    uint32_t bat_check_ms;
    int time_src;              /* 0 unknown, 1 by hand, 2 over Wi-Fi */
    uint32_t time_set_ms;      /* app clock when it was set: "set 4 min ago" */
    struct app_time *tm;
    struct app_acct *acct;
    struct app_groups *grp;
    struct app_view *view;

    struct app_edit *ed;
    struct app_gen *gen;
    struct app_create *cr;
    float *audit_bits;         /* parallel to the list rows on the audit screen */
} app;

void app_init(app *a, const app_platform *p, const cp_settings *cfg);
void app_key(app *a, uint32_t key, bool down);
void app_tick(app *a, uint32_t now_ms);      /* idle dim / screen off, auto-lock, battery, TOTP countdown, QR timeout */
void app_lock(app *a);                        /* wipe everything, back to the picker */
bool app_dirty(app *a, int *y0, int *y1);     /* dirty band, then cleared */
void app_draw(app *a, ui_strip *s);           /* draws the whole screen clipped to s */
/* Modal passkey confirmation for fido_env.choose: returns the chosen index or -1 (denied/timeout). */
int app_ask_passkey(app *a, const char *rp, const fido_cred *creds, size_t n);
/* Register a new passkey (authenticatorMakeCredential): confirm on the device, then save it as an entry. 0 stored,
 * 1 declined / timed out, 2 failed (also: not on a browsing screen, or locked). */
int app_register_passkey(app *a, const fido_new *n);
