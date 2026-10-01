/* Menu, settings, password audit, expiry list, confirmations, new database, help. */
#include "app_priv.h"
#include "strength.h"
#include "typing.h"

/* Rebuild and show a screen we are returning to. */
void ap_return(app *a, int scr)
{
    switch (scr) {
    case SCR_HOME: ap_go_home(a); return;
    case SCR_GROUP:
        a->scr = SCR_GROUP;
        ap_build_group(a, a->group ? a->group : kdbx_root_group(a->db), false);
        break;
    case SCR_SEARCH: a->scr = SCR_SEARCH; ap_build_search(a); break;
    case SCR_ENTRY:
        if (a->entry) { ap_open_entry(a, a->entry); return; }
        ap_go_home(a);
        return;
    case SCR_AUDIT: ap_audit_open(a); return;
    case SCR_EXPIRY: ap_expiry_open(a); return;
    default: a->scr = a->db ? SCR_HOME : SCR_PICKER; if (a->db) { ap_go_home(a); return; }
    }
    a->sel = a->top = 0;
    ap_mark_all(a);
}

/* ======================= menu ======================= */

enum { M_NEW_ENTRY, M_GENERATOR, M_AUDIT, M_EXPIRY, M_SETTINGS, M_LOCK, M_NEW_DB, M_DRIVE, M_TIME, M_GROUPS, M_ACCOUNT, M_BT };

static int menu_items(app *a, int *out)
{
    int n = 0;
    if (a->db) {
        out[n++] = M_NEW_ENTRY;
        out[n++] = M_GENERATOR;
        out[n++] = M_AUDIT;
        out[n++] = M_EXPIRY;
        out[n++] = M_SETTINGS;
        out[n++] = M_LOCK;
        out[n++] = M_DRIVE;
        out[n++] = M_TIME;
        out[n++] = M_GROUPS;
        out[n++] = M_ACCOUNT;
        out[n++] = M_BT;
    } else {
        out[n++] = M_NEW_DB;
        out[n++] = M_SETTINGS;
        out[n++] = M_DRIVE;
        out[n++] = M_TIME;
        out[n++] = M_BT;
    }
    return n;
}

void ap_menu_open(app *a)
{
    a->menu_back = a->scr;
    a->scr = SCR_MENU;
    a->sel = a->top = 0;
    a->msg[0] = 0;
    ap_mark_all(a);
}

void ap_menu_key(app *a, uint32_t k, bool fn)
{
    (void)fn;
    int it[14], n = menu_items(a, it);
    if (k == K_UP) ap_move_sel(a, n, -1);
    else if (k == K_DOWN) ap_move_sel(a, n, 1);
    else if (k == '`' || k == K_ESC || k == K_TAB) { if (a->menu_back == SCR_PICKER) a->scr = SCR_PICKER, a->sel = 0, ap_mark_all(a); else ap_return(a, a->menu_back); }
    else if (k == K_ENTER) {
        int back = a->menu_back;
        switch (it[a->sel]) {
        case M_NEW_ENTRY:
            a->entry = NULL;
            a->back_scr = back == SCR_GROUP ? SCR_GROUP : SCR_HOME;
            ap_edit_open(a, NULL, back == SCR_GROUP ? a->group : NULL);
            break;
        case M_GENERATOR: a->scr = back; ap_gen_open(a, false); a->menu_back = back; break;
        case M_AUDIT: ap_audit_open(a); break;
        case M_EXPIRY: ap_expiry_open(a); break;
        case M_SETTINGS: a->scr = SCR_SETTINGS; a->sel = a->top = 0; a->text_edit = false; ap_mark_all(a); break;
        case M_LOCK: app_lock(a); break;
        case M_NEW_DB: ap_create_open(a); break;
        case M_TIME: ap_time_open(a, back); break;
        case M_GROUPS: a->scr = back; ap_groups_open(a); break;
        case M_ACCOUNT: ap_account_open(a); break;
        case M_BT: ap_bt_open(a, back); break;
        case M_DRIVE: ap_confirm(a, CONFIRM_DRIVE, a->db ? "Lock and share the SD card with a PC?" : "Share the SD card with a PC?"); break;
        }
    }
}

void ap_menu_draw(app *a, ui_strip *s, const char **hint)
{
    static const char *const names[] = {"New entry", "Password generator", "Password audit", "Expiring entries",
                                        "Settings", "Lock now", "New database", "USB drive", "Set time", "Groups", "Change password", "Bluetooth"};
    static const char *const icons[] = {"+", ICON_BOLT, ICON_WARNING, ICON_CLOCK, ICON_COG, ICON_LOCK, "+", ICON_USB, ICON_CLOCK, ICON_FOLDER_OPEN, ICON_KEY, ICON_BLUETOOTH};
    int it[14], n = menu_items(a, it);
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    for (int i = 0; i < n; i++) ap_draw_row(a, s, i, icons[it[i]], T->accent, names[it[i]], NULL, 0);
    *hint = U_ENTER " choose  ` back";
}

/* ======================= settings ======================= */

enum { S_THEME, S_FONT, S_REVEAL, S_AUTOLOCK, S_DIM, S_OFF, S_LAYOUT, S_DELAY, S_TZ, S_WEAK, S_EXPIRY, S_ANIM, S_AUTOTYPE, S_SPLASH, S_COUNT };
static const int AUTOLOCK[] = {60, 120, 300, 600, 1800, 0};
static const int DELAYS[] = {0, 4, 8, 15, 30, 60};
static const int DIM_S[] = {0, 10, 20, 30, 60, 120};
static const int OFF_S[] = {0, 20, 45, 60, 120, 300};
static const int EXPIRY_DAYS[] = {0, 7, 14, 30, 60};

static int step_in(const int *v, int n, int cur, int d)
{
    int i = 0;
    while (i < n && v[i] != cur) i++;
    if (i == n) i = 0;
    return v[(i + d + n) % n];
}

void ap_apply_settings(app *a)
{
    a->theme = a->cfg.light ? &ui_light : &ui_dark;
    a->font = a->cfg.large_font ? &ui_font_large : &ui_font_small;
    char buf[2048];
    if (cp_settings_format(&a->cfg, buf, sizeof buf)) a->p->save_settings(a->p->ctx, buf);
    ap_wipe(buf, sizeof buf);                              /* may contain Wi-Fi passwords */
}

static void settings_change(app *a, int d)
{
    cp_settings *c = &a->cfg;
    switch (a->sel) {
    case S_THEME: c->light = !c->light; break;
    case S_FONT: c->large_font = !c->large_font; break;
    case S_ANIM: c->animations = !c->animations; break;
    case S_SPLASH: c->splash = !c->splash; break;
    case S_REVEAL: c->reveal_toggle = !c->reveal_toggle; break;
    case S_AUTOLOCK: c->autolock_s = step_in(AUTOLOCK, 6, c->autolock_s, d); break;
    case S_DIM: c->dim_s = step_in(DIM_S, 6, c->dim_s, d); break;
    case S_OFF: c->off_s = step_in(OFF_S, 6, c->off_s, d); break;
    case S_LAYOUT: {
        int n = kbd_layout_count(), i = 0;
        while (i < n && strcmp(kbd_layout_name(kbd_layout_get(i)), c->layout)) i++;
        i = (i + d + n) % n;
        snprintf(c->layout, sizeof c->layout, "%s", kbd_layout_name(kbd_layout_get(i)));
        break;
    }
    case S_DELAY: c->typing_delay_ms = step_in(DELAYS, 6, c->typing_delay_ms, d); break;
    case S_TZ: c->tz_minutes += d * 15; if (c->tz_minutes > 14 * 60) c->tz_minutes = -12 * 60; if (c->tz_minutes < -12 * 60) c->tz_minutes = 14 * 60; break;
    case S_WEAK: c->weak_bits += d * 8; if (c->weak_bits > 128) c->weak_bits = 40; if (c->weak_bits < 40) c->weak_bits = 128; break;
    case S_EXPIRY: c->expiry_days = step_in(EXPIRY_DAYS, 5, c->expiry_days, d); break;
    }
    a->theme = c->light ? &ui_light : &ui_dark;
    a->font = c->large_font ? &ui_font_large : &ui_font_small;
}

void ap_settings_key(app *a, uint32_t k, bool fn)
{
    ap_mark_all(a);
    if (a->text_edit) { /* default auto-type sequence: append / backspace */
        int len = (int)strlen(a->cfg.autotype);
        if (k == K_ENTER || k == K_ESC) {
            a->text_edit = false;
            if (!a->cfg.autotype[0]) cp_settings_default(&(cp_settings){0}), snprintf(a->cfg.autotype, sizeof a->cfg.autotype, "{USERNAME}{TAB}{PASSWORD}{ENTER}");
        } else if (k == K_BACKSPACE) ap_utf8_backspace(a->cfg.autotype, &len);
        else if (ap_printable(k) && !fn) ap_utf8_append(a->cfg.autotype, &len, sizeof a->cfg.autotype, k);
        return;
    }
    if (k == K_UP) ap_move_sel(a, S_COUNT, -1);
    else if (k == K_DOWN) ap_move_sel(a, S_COUNT, 1);
    else if (k == K_LEFT) settings_change(a, -1);
    else if (k == K_RIGHT || (k == K_ENTER && a->sel != S_AUTOTYPE)) settings_change(a, 1);
    else if (k == K_ENTER) a->text_edit = true;
    else if (k == '`' || k == K_ESC) {
        ap_apply_settings(a);
        if (a->menu_back == SCR_PICKER) { a->scr = SCR_PICKER; a->sel = 0; }
        else ap_return(a, a->menu_back);
    }
}

void ap_settings_draw(app *a, ui_strip *s, const char **hint)
{
    static const char *const names[] = {"Theme", "Text size", "Reveal", "Auto-lock", "Dim after", "Screen off", "Keyboard", "Key delay",
                                        "Time zone", "Weak below", "Expiry warn", "Animations", "Auto-type", "Splash"};
    const cp_settings *c = &a->cfg;
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    for (int i = a->top; i < S_COUNT && i < a->top + ap_visible(a); i++) {
        char v[100];
        switch (i) {
        case S_THEME: snprintf(v, sizeof v, "%s", c->light ? "Light" : "Dark"); break;
        case S_FONT: snprintf(v, sizeof v, "%s", c->large_font ? "Large" : "Small"); break;
        case S_ANIM: snprintf(v, sizeof v, "%s", c->animations ? "On" : "Off"); break;
        case S_SPLASH: snprintf(v, sizeof v, "%s", c->splash ? "On" : "Off"); break;
        case S_REVEAL: snprintf(v, sizeof v, "%s", c->reveal_toggle ? "Press R" : "Hold R"); break;
        case S_AUTOLOCK: if (c->autolock_s) snprintf(v, sizeof v, "%d min", c->autolock_s / 60); else snprintf(v, sizeof v, "Never"); break;
        case S_DIM: if (c->dim_s) snprintf(v, sizeof v, "%d s", c->dim_s); else snprintf(v, sizeof v, "Never"); break;
        case S_OFF: if (c->off_s) snprintf(v, sizeof v, "%d s", c->off_s); else snprintf(v, sizeof v, "Never"); break;
        case S_LAYOUT: snprintf(v, sizeof v, "%s", c->layout); break;
        case S_DELAY: snprintf(v, sizeof v, "%d ms", c->typing_delay_ms); break;
        case S_TZ: snprintf(v, sizeof v, "UTC%c%d:%02d", c->tz_minutes < 0 ? '-' : '+', abs(c->tz_minutes) / 60, abs(c->tz_minutes) % 60); break;
        case S_WEAK: snprintf(v, sizeof v, "%d bits", c->weak_bits); break;
        case S_EXPIRY: snprintf(v, sizeof v, "%d days", c->expiry_days); break;
        case S_AUTOTYPE: snprintf(v, sizeof v, "%s", c->autotype); break;
        }
        int y = CONTENT_Y + (i - a->top) * ap_row_h(a), h = ap_row_h(a);
        if (y + h <= s->y0 || y >= s->y0 + s->h) continue;
        bool sel = i == a->sel;
        ap_row_bg(a, s, y, h, i);
        ui_text(s, &ui_font_small, PAD + 2, y + (h - ui_font_small.height) / 2, names[i], T->dim, 72);
        if (sel && a->text_edit) ap_draw_field(a, s, 78, y, UI_W - 80, h, c->autotype, false, (int)strlen(c->autotype));
        else ui_text(s, F, 80, y + (h - F->height) / 2, v, sel ? T->sel_fg : T->fg, UI_W - 80 - PAD);
    }
    ap_draw_scrollbar(a, s, S_COUNT);
    *hint = a->text_edit ? U_ENTER " done" : a->sel == S_AUTOTYPE ? U_ENTER " edit  ` save & back" : U_LR " change  ` save & back";
}

/* ======================= audit / expiry ======================= */

typedef struct { const kdbx_entry *e; float v; } scored;
static int by_value(const void *x, const void *y)
{
    float p = ((const scored *)x)->v, q = ((const scored *)y)->v;
    return p < q ? -1 : p > q;
}

/* Fill the list rows (and audit_bits) from scored entries. */
static void set_report(app *a, scored *sc, int n, int scr)
{
    qsort(sc, (size_t)n, sizeof *sc, by_value);
    free(a->audit_bits);
    a->audit_bits = malloc(sizeof(float) * (size_t)(n ? n : 1));
    int m = 0;
    for (int i = 0; i < n; i++) {
        if (scr == SCR_AUDIT && a->weak_only && sc[i].v >= a->cfg.weak_bits) continue;
        ap_items(a)[m] = (list_item){sc[i].e, LI_ENTRY};
        if (a->audit_bits) a->audit_bits[m] = sc[i].v;
        m++;
    }
    a->nhits = m;
    a->scr = scr;
    a->sel = a->top = 0;
    ap_mark_all(a);
}

/* Decrypt one password at a time, estimate, wipe (plan: only the score is kept). */
void ap_audit_open(app *a)
{
    scored *sc = malloc(sizeof *sc * (size_t)(a->nentries ? a->nentries : 1));
    char *buf = malloc(REVEAL_MAX);
    int n = 0;
    const kdbx_group *bin = kdbx_recycle_bin(a->db);
    if (!sc || !buf) { free(sc); free(buf); snprintf(a->msg, sizeof a->msg, "Out of memory"); return; }
    for (const kdbx_entry *e = kdbx_entries(a->db); e; e = e->next) {
        const kdbx_field *f = kdbx_field_get(e, "Password");
        if (!f || !f->len || (bin && e->group == bin)) continue;
        if (kdbx_reveal(a->db, f, buf, REVEAL_MAX) == KDBX_OK) sc[n++] = (scored){e, (float)strength_bits(buf)};
        ap_wipe(buf, REVEAL_MAX);
    }
    free(buf);
    set_report(a, sc, n, SCR_AUDIT);
    free(sc);
}

static int64_t horizon(app *a, bool *valid)
{
    int64_t now = a->p->now(a->p->ctx, valid);
    return now + (int64_t)a->cfg.expiry_days * 86400;
}

int ap_expiring_count(app *a)
{
    bool valid;
    int64_t h = horizon(a, &valid);
    int n = 0;
    const kdbx_group *bin = kdbx_recycle_bin(a->db);
    if (!valid) return 0; /* unknown time: no warnings rather than wrong ones */
    for (const kdbx_entry *e = kdbx_entries(a->db); e; e = e->next)
        if (e->expires && e->expiry <= h && !(bin && e->group == bin)) n++;
    return n;
}

void ap_expiry_open(app *a)
{
    bool valid;
    int64_t h = horizon(a, &valid);
    scored *sc = malloc(sizeof *sc * (size_t)(a->nentries ? a->nentries : 1));
    int n = 0;
    const kdbx_group *bin = kdbx_recycle_bin(a->db);
    if (!sc) return;
    for (const kdbx_entry *e = kdbx_entries(a->db); e && valid; e = e->next)
        if (e->expires && e->expiry <= h && !(bin && e->group == bin)) sc[n++] = (scored){e, (float)(e->expiry / 60)};
    set_report(a, sc, n, SCR_EXPIRY);
    free(sc);
    if (!valid) snprintf(a->msg, sizeof a->msg, "Time not set");
}

void ap_report_key(app *a, uint32_t k, bool fn)
{
    (void)fn;
    if (k == K_UP) ap_move_sel(a, a->nhits, -1);
    else if (k == K_DOWN) ap_move_sel(a, a->nhits, 1);
    else if (k == K_ENTER && a->nhits) ap_open_entry(a, ap_items(a)[a->sel].p);
    else if ((k == 'w' || k == 'W') && a->scr == SCR_AUDIT) a->weak_only = !a->weak_only, ap_audit_open(a);
    else if (k == '`' || k == K_ESC) ap_go_home(a);
}

void ap_report_draw(app *a, ui_strip *s, const char **hint)
{
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    bool valid;
    int64_t now = a->p->now(a->p->ctx, &valid);
    for (int i = a->top; i < a->nhits && i < a->top + ap_visible(a); i++) {
        const kdbx_entry *e = ap_items(a)[i].p;
        char r[40];
        uint16_t c;
        if (a->scr == SCR_AUDIT) {
            float b = a->audit_bits ? a->audit_bits[i] : 0;
            bool weak = b < a->cfg.weak_bits;
            snprintf(r, sizeof r, "%s %.0f bits", weak ? "Weak" : "Strong", b);
            c = weak ? T->warn : T->ok;
        } else {
            int64_t d = (e->expiry - now) / 86400;
            if (e->expiry <= now) snprintf(r, sizeof r, "expired"), c = T->danger;
            else snprintf(r, sizeof r, d ? "in %lld d" : "today", (long long)d), c = T->warn;
        }
        ap_draw_row(a, s, i, ICON_KEY, T->dim, *e->title ? e->title : "(no title)", r, c);
    }
    if (!a->nhits)
        ui_text(s, F, PAD * 2, CONTENT_Y + 8, a->scr == SCR_AUDIT ? (a->weak_only ? "No weak password" : "No passwords")
                                                                  : (a->msg[0] ? a->msg : "Nothing expires soon"), T->dim, UI_W);
    ap_draw_scrollbar(a, s, a->nhits);
    *hint = a->scr == SCR_AUDIT ? (a->weak_only ? U_ENTER " open  W show all  ` back" : U_ENTER " open  W weak only  ` back")
                                : U_ENTER " open  ` back";
}

/* ======================= confirm ======================= */

void ap_confirm(app *a, int action, const char *text)
{
    a->confirm_back = a->scr;
    a->confirm_action = action;
    snprintf(a->confirm_text, sizeof a->confirm_text, "%s", text);
    a->scr = SCR_CONFIRM;
    ap_mark_all(a);
}

void ap_confirm_key(app *a, uint32_t k, bool fn)
{
    (void)fn;
    bool yes = k == K_ENTER, no = k == '`' || k == K_ESC;
    ap_mark_all(a);
    switch (a->confirm_action) {
    case CONFIRM_DELETE_ENTRY:
        if (yes) {
            kdbx_edit ed[2];
            size_t n = kdbx_delete_entry(a->db, a->entry, ed);
            int m = 0; /* no longer "recent" */
            for (int i = 0; i < a->nrecent; i++)
                if (a->recent[i] != a->entry) a->recent[m++] = a->recent[i];
            a->nrecent = m;
            bool moved = ed[n - 1].op == KDBX_EDIT_ENTRY_MOVE;
            int back = a->back_scr;
            a->entry = NULL;
            if (ap_save(a, ed, n)) {
                ap_return(a, back == SCR_ENTRY ? SCR_HOME : back);
                snprintf(a->msg, sizeof a->msg, moved ? "Moved to the recycle bin" : "Deleted");
            }
        } else if (no) {
            a->scr = SCR_ENTRY;
        }
        break;
    case CONFIRM_DELETE_GROUP:
        if (yes) ap_groups_delete(a);
        else if (no) a->scr = SCR_GROUPS;
        break;
    case CONFIRM_DRIVE:
        if (yes) {
            app_lock(a);                                   /* wipes the database and every buffer first */
            if (a->p->usb_drive(a->p->ctx, true)) a->scr = SCR_DRIVE;
            else snprintf(a->msg, sizeof a->msg, "No SD card or USB error");
        } else if (no) {
            a->scr = SCR_MENU;
        }
        break;
    case CONFIRM_SAVE_EDIT:
        if (yes) ap_edit_finish(a, true);
        else if (k == 'd' || k == 'D') ap_edit_finish(a, false);
        else if (no) a->scr = SCR_EDIT;
        break;
    }
}

void ap_confirm_draw(app *a, ui_strip *s, const char **hint)
{
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    ui_fill(s, PAD * 2, CONTENT_Y + 20, UI_W - PAD * 4, 50, T->bar_bg);
    ui_fill(s, PAD * 2, CONTENT_Y + 20, 3, 50, T->warn);
    const char *t = a->confirm_text;   /* wrapped over up to two lines */
    for (int line = 0; line < 2 && *t; line++) {
        char buf[64];
        size_t n = ui_wrap(F, t, UI_W - PAD * 8);
        snprintf(buf, sizeof buf, "%.*s", (int)n, t);
        ui_text(s, F, PAD * 4, CONTENT_Y + 26 + line * (F->height + 3), buf, T->fg, UI_W - PAD * 6);
        t += n;
        while (*t == ' ') t++;
    }
    *hint = a->confirm_action == CONFIRM_SAVE_EDIT ? U_ENTER " save  D discard  ` keep editing" : U_ENTER " yes  ` no";
}

/* ======================= new database ======================= */

enum { C_NAME, C_PW, C_PW2, C_CIPHER, C_TIME, C_KEYFILE, C_CREATE, C_COUNT };

struct app_create {
    char name[48], pw[128], pw2[128];
    int cipher;       /* KDBX_AES256 / KDBX_CHACHA20 */
    int seconds;      /* unlock-time target */
    bool keyfile;
    bool editing;
};

void ap_create_free(app *a)
{
    if (!a->cr) return;
    ap_wipe(a->cr, sizeof *a->cr);
    free(a->cr);
    a->cr = NULL;
}

void ap_create_open(app *a)
{
    ap_create_free(a);
    if (!(a->cr = calloc(1, sizeof *a->cr))) return;
    snprintf(a->cr->name, sizeof a->cr->name, "passwords");
    a->cr->seconds = 2;
    a->scr = SCR_CREATE;
    a->sel = a->top = 0;
    a->msg[0] = 0;
    ap_mark_all(a);
}

static char *create_buf(struct app_create *c, int row, int *cap)
{
    switch (row) {
    case C_NAME: *cap = (int)sizeof c->name; return c->name;
    case C_PW: *cap = (int)sizeof c->pw; return c->pw;
    case C_PW2: *cap = (int)sizeof c->pw2; return c->pw2;
    default: return NULL;
    }
}

/* Rounds for the time target, from a short benchmark of this device's AES-KDF. */
uint64_t ap_benchmark_rounds(app *a, int seconds)
{
    static const uint8_t seed[32], in[32];
    uint8_t out[32];
    uint64_t probe = 20000;
    uint32_t dt;
    for (;;) {                      /* long enough to time well: the hardware path does 20,000 rounds in ~40 ms */
        uint32_t t0 = a->p->millis(a->p->ctx);
        kdbx_aes_kdf(seed, probe, in, out);
        dt = a->p->millis(a->p->ctx) - t0;
        if (dt >= 250 || probe >= 1000000) break;
        probe *= 4;
    }
    uint64_t r = probe * (uint64_t)seconds * 1000u / (dt ? dt : 1);
    return r < 10000 ? 10000 : r > 100000000 ? 100000000 : r;
}

static void do_create(app *a)
{
    struct app_create *c = a->cr;
    if (!c->name[0] || strchr(c->name, '/') || strchr(c->name, '\\')) { snprintf(a->msg, sizeof a->msg, "Invalid name"); return; }
    if (strcmp(c->pw, c->pw2)) { snprintf(a->msg, sizeof a->msg, "Passwords differ"); return; }
    if (!c->pw[0] && !c->keyfile) { snprintf(a->msg, sizeof a->msg, "Set a password or a key file"); return; }

    char file[64], kfile[64], kpath[256];
    snprintf(file, sizeof file, "%s.kdbx", c->name);
    snprintf(kfile, sizeof kfile, "%s.keyx", c->name);
    a->p->path(a->p->ctx, file, a->path, sizeof a->path);
    FILE *kf = NULL;
    if (c->keyfile) {
        a->p->path(a->p->ctx, kfile, kpath, sizeof kpath);
        if ((kf = fopen(kpath, "rb"))) { fclose(kf); snprintf(a->msg, sizeof a->msg, "Key file already exists"); return; }
        kf = fopen(kpath, "wb");
        if (!kf || kdbx_keyfile_create(kf)) { if (kf) fclose(kf); snprintf(a->msg, sizeof a->msg, "Can't write the key file"); return; }
        fclose(kf);
        kf = fopen(kpath, "rb");
    }
    snprintf(a->msg, sizeof a->msg, "Measuring this device\xE2\x80\xA6");
    ap_mark_all(a);
    a->p->present(a->p->ctx);
    uint64_t rounds = ap_benchmark_rounds(a, c->seconds);

    kdbx_key key;
    kdbx_err e = kdbx_key_init(&key, c->pw[0] ? c->pw : NULL, strlen(c->pw), kf);
    if (kf) fclose(kf);
    bool valid;
    int64_t now = a->p->now(a->p->ctx, &valid);
    a->progress = 0;
    kdbx_set_progress(ap_kdf_progress, a);
    if (!e) e = kdbx_create(a->path, c->cipher, rounds, &key, c->name, now, &a->db);
    kdbx_set_progress(NULL, NULL);
    ap_progress_end(a);
    kdbx_key_wipe(&key);
    if (e) {
        snprintf(a->msg, sizeof a->msg, e == KDBX_ERR_IO ? "%s exists or SD error" : "%s", e == KDBX_ERR_IO ? file : kdbx_strerror(e));
        return;
    }
    snprintf(a->dbname, sizeof a->dbname, "%s", file);
    ap_create_free(a);
    if (!ap_reindex(a)) { app_lock(a); return; }
    snprintf(a->cfg.last_db, sizeof a->cfg.last_db, "%s", file);
    ap_apply_settings(a);
    ap_go_home(a);
    snprintf(a->msg, sizeof a->msg, "Created %.40s", file);
}

void ap_create_key(app *a, uint32_t k, bool fn)
{
    struct app_create *c = a->cr;
    if (!c) return;
    ap_mark_all(a);
    int cap;
    char *b = create_buf(c, a->sel, &cap);
    if (c->editing && b) {
        int len = (int)strlen(b);
        if (k == K_ENTER) c->editing = false, ap_move_sel(a, C_COUNT, 1);
        else if (k == K_ESC) c->editing = false;
        else if (k == K_BACKSPACE) ap_utf8_backspace(b, &len);
        else if (ap_printable(k) && !fn) ap_utf8_append(b, &len, cap, k);
        return;
    }
    a->msg[0] = 0;
    if (k == K_UP) ap_move_sel(a, C_COUNT, -1);
    else if (k == K_DOWN) ap_move_sel(a, C_COUNT, 1);
    else if (k == '`' || k == K_ESC) { ap_create_free(a); app_lock(a); }
    else if (b && (k == K_ENTER || ap_printable(k))) {
        c->editing = true;
        if (k != K_ENTER && !fn) { int len = (int)strlen(b); ap_utf8_append(b, &len, cap, k); }
    } else if (a->sel == C_CIPHER && (k == K_ENTER || k == K_LEFT || k == K_RIGHT)) c->cipher = c->cipher == KDBX_AES256 ? KDBX_CHACHA20 : KDBX_AES256;
    else if (a->sel == C_TIME && (k == K_ENTER || k == K_LEFT || k == K_RIGHT)) {
        static const int t[] = {1, 2, 3, 5};
        c->seconds = step_in(t, 4, c->seconds, k == K_LEFT ? -1 : 1);
    } else if (a->sel == C_KEYFILE && (k == K_ENTER || k == K_LEFT || k == K_RIGHT)) c->keyfile = !c->keyfile;
    else if (a->sel == C_CREATE && k == K_ENTER) do_create(a);
}

void ap_create_draw(app *a, ui_strip *s, const char **hint)
{
    struct app_create *c = a->cr;
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    if (!c) return;
    if (a->progress >= 0) { ap_draw_progress(a, s, "Creating" "\xE2\x80\xA6"); return; }
    static const char *const names[] = {"Name", "Password", "Repeat", "Cipher", "Unlock in", "Key file", ""};
    for (int i = a->top; i < C_COUNT && i < a->top + ap_visible(a); i++) {
        int y = CONTENT_Y + (i - a->top) * ap_row_h(a), h = ap_row_h(a);
        if (y + h <= s->y0 || y >= s->y0 + s->h) continue;
        bool sel = i == a->sel;
        if (i == C_CREATE) { ap_draw_row(a, s, i, ICON_CHECK, T->ok, "Create database", NULL, 0); continue; }
        ap_row_bg(a, s, y, h, i);
        ui_text(s, &ui_font_small, PAD + 2, y + (h - ui_font_small.height) / 2, names[i], T->dim, 60);
        char v[64];
        const char *b = NULL;
        switch (i) {
        case C_NAME: b = c->name; break;
        case C_PW: b = c->pw; break;
        case C_PW2: b = c->pw2; break;
        case C_CIPHER: snprintf(v, sizeof v, "%s", c->cipher == KDBX_AES256 ? "AES-256" : "ChaCha20"); break;
        case C_TIME: snprintf(v, sizeof v, "~%d s (AES-KDF)", c->seconds); break;
        case C_KEYFILE: snprintf(v, sizeof v, c->keyfile ? "Generate %s.keyx" : "None", c->name); break;
        }
        if (b && sel && c->editing) ap_draw_field(a, s, 62, y, UI_W - 64, h, b, i != C_NAME, (int)strlen(b));
        else if (b) ui_text(s, F, 66, y + (h - F->height) / 2, i == C_NAME ? b : b[0] ? U_BULLETS : "\xE2\x80\x94", sel ? T->sel_fg : T->fg, UI_W - 70);
        else ui_text(s, F, 66, y + (h - F->height) / 2, v, sel ? T->sel_fg : T->fg, UI_W - 70);
    }
    if (a->msg[0]) *hint = a->msg;
    else *hint = c->editing ? U_ENTER " next  fn+` stop" : U_ENTER " edit/choose  ` cancel";
}

/* ======================= help ======================= */

void ap_help_draw(app *a, ui_strip *s, const char **hint)
{
    static const char *const entry[] = {
        U_ENTER "  type the selected field", "A  auto-type the whole login", "R  reveal     Q  QR code",
        "E  edit  F  favorite  M  move", "fn+bksp  delete (recycle bin)", "tab  menu  T  time  fn+L  lock"};
    static const char *const list[] = {
        "type  search (accents and case ignored)", U_UPDOWN "  move    " U_ENTER "  open", "`  back    fn+`  clear search",
        "tab  menu: new entry, generator,", "     audit, expiring, settings", "fn+L  lock now"};
    const char *const *l = a->menu_back == SCR_ENTRY ? entry : list;
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    for (int i = 0; i < 6; i++) ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + 4 + i * 16, l[i], T->fg, UI_W - PAD * 4);
    *hint = "any key: back";
}

/* ======================= USB drive mode ======================= */

void ap_drive_key(app *a, uint32_t k, bool fn)
{
    (void)fn;
    if (k != '`' && k != K_ESC && k != K_ENTER) return;
    bool ok = a->p->usb_drive(a->p->ctx, false);
    app_lock(a);                                           /* back to the picker, files rescanned */
    if (!ok) snprintf(a->msg, sizeof a->msg, "SD card not remounted: reinsert it");
}

void ap_drive_draw(app *a, ui_strip *s, const char **hint)
{
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    ui_text(s, F, PAD * 2, CONTENT_Y + 6, "The SD card is a drive", T->accent, UI_W - PAD * 4);
    static const char *const lines[] = {"Copy .kdbx and key files on your PC.", "Eject the drive on the PC first,",
                                        "then leave here. Nothing is unlocked:", "no database is open in this mode."};
    for (int i = 0; i < 4; i++) ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + 30 + i * 14, lines[i], T->fg, UI_W - PAD * 4);
    *hint = "` done (after ejecting on the PC)";
}
