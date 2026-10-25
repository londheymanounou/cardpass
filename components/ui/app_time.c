/* Setting the clock. The ADV has no RTC, so after every power-on the time must come from here:
 *  - manually (entered as local time, converted to UTC with the time zone setting), or
 *  - over Wi-Fi + NTP. Wi-Fi is only ever available while no database is open (the security rules in CLAUDE.md),
 *    and any time earlier than the firmware build date is rejected as obviously wrong. */
#include "app_priv.h"

enum { TM_MENU, TM_MANUAL, TM_LIST, TM_PASSWORD, TM_BUSY, TM_RESULT };
#define MAX_AP 12

struct app_time {
    int mode, back, sel, top;
    int v[6];                    /* local year month day hour minute second */
    int field, typed;
    app_ap ap[MAX_AP];
    int nap, chosen;
    char pw[64];
    int pwlen;
    bool save, ok, retry;        /* save the network; result ok; offer to retype the password */
    char text[64];               /* busy / result line */
    char note[64];               /* a small extra line on the password / result screens (Wi-Fi from a database) */
};

static const int WIDTH[6] = {4, 2, 2, 2, 2, 2};
static void fetch_start(app *a);

void ap_time_free(app *a)
{
    if (!a->tm) return;
    ap_wipe(a->tm, sizeof *a->tm);   /* holds a typed Wi-Fi password */
    free(a->tm);
    a->tm = NULL;
}

void ap_time_open(app *a, int back)
{
    ap_time_free(a);
    if (!(a->tm = calloc(1, sizeof *a->tm))) return;
    a->tm->back = back;
    a->scr = SCR_TIME;
    a->msg[0] = 0;
    ap_mark_all(a);
}

static void age_text(char *out, size_t n, uint32_t ms)
{
    uint32_t s = ms / 1000;
    if (s < 60) snprintf(out, n, "just now");
    else if (s < 3600) snprintf(out, n, "%u min ago", (unsigned)(s / 60));
    else snprintf(out, n, "%u h ago", (unsigned)(s / 3600));
}

static void fill_fields(app *a, int64_t utc)
{
    int y, mo, d, h, mi;
    ap_civil(utc + a->cfg.tz_minutes * 60, &y, &mo, &d, &h, &mi);
    struct app_time *t = a->tm;
    t->v[0] = y; t->v[1] = mo; t->v[2] = d; t->v[3] = h; t->v[4] = mi;
    t->v[5] = (int)(((utc + a->cfg.tz_minutes * 60) % 60 + 60) % 60);
    t->field = 0;
    t->typed = 0;
}

/* Local fields -> UTC; false if not a real date. */
static bool fields_to_utc(app *a, int64_t *utc)
{
    const int *v = a->tm->v;
    if (v[0] < 2000 || v[0] > 2099 || v[1] < 1 || v[1] > 12 || v[2] < 1 || v[2] > cp_days_in_month(v[0], v[1]) || v[3] > 23 ||
        v[4] > 59 || v[5] > 59)
        return false;
    *utc = cp_unix_from_civil(v[0], v[1], v[2], v[3], v[4], v[5]) - (int64_t)a->cfg.tz_minutes * 60;
    return true;
}

static void set_clock(app *a, int64_t utc, int src)
{
    a->p->set_time(a->p->ctx, utc);
    a->time_src = src;
    a->time_set_ms = a->now_ms;
}

/* ---------------- Wi-Fi ---------------- */

static void do_sync(app *a, const char *ssid, const char *pass, bool save)
{
    struct app_time *t = a->tm;
    t->mode = TM_BUSY;
    snprintf(t->text, sizeof t->text, "Connecting to %.32sâ¦", ssid);
    ap_mark_all(a);
    a->p->present(a->p->ctx);
    int64_t utc = 0;
    int r = a->db ? NTP_ERR_CONNECT : a->p->ntp_sync(a->p->ctx, ssid, pass, &utc);   /* never with a database open */
    if (r == NTP_OK && utc < cp_build_time()) r = NTP_ERR_BAD_TIME;
    t->ok = r == NTP_OK;
    t->retry = r == NTP_ERR_PASSWORD;
    if (t->ok) {
        set_clock(a, utc, 2);
        if (save) {
            cp_settings_wifi_save(&a->cfg, ssid, pass);
            ap_apply_settings(a);
        }
        snprintf(t->text, sizeof t->text, "Time set over Wi-Fi");
    } else {
        static const char *const why[] = {"", "Can't connect to the network", "Wrong password", "No answer from the time servers",
                                          "The server's time looks wrong"};
        snprintf(t->text, sizeof t->text, "%s", why[r > 0 && r <= NTP_ERR_BAD_TIME ? r : 1]);
    }
    if (r == NTP_ERR_PASSWORD && save) snprintf(t->text, sizeof t->text, "Wrong password: not saved");
    t->mode = TM_RESULT;
    ap_wipe(t->pw, sizeof t->pw);
    t->pwlen = 0;
    ap_mark_all(a);
}

static void start_scan(app *a)
{
    struct app_time *t = a->tm;
    if (a->db) { snprintf(a->msg, sizeof a->msg, "Lock the database first"); return; }
    t->mode = TM_BUSY;
    snprintf(t->text, sizeof t->text, "Looking for networks\xE2\x80\xA6");
    ap_mark_all(a);
    a->p->present(a->p->ctx);
    t->nap = a->p->wifi_scan(a->p->ctx, t->ap, MAX_AP);
    if (t->nap < 0) t->nap = 0;
    t->mode = TM_LIST;
    t->sel = t->top = 0;
    ap_mark_all(a);
}

static void choose_ap(app *a)
{
    struct app_time *t = a->tm;
    t->chosen = t->sel;
    const app_ap *ap = &t->ap[t->chosen];
    int saved = cp_settings_wifi_find(&a->cfg, ap->ssid);
    if (saved >= 0) do_sync(a, ap->ssid, a->cfg.wifi_pass[saved], false);
    else if (!ap->secure) do_sync(a, ap->ssid, "", false);
    else {
        t->mode = TM_PASSWORD;
        t->pwlen = 0;
        t->pw[0] = 0;
        t->save = true;
        ap_mark_all(a);
    }
}

/* ---------------- keys ---------------- */

static void leave(app *a)
{
    int back = a->tm->back;
    ap_time_free(a);
    ap_return(a, back);
}

void ap_time_key(app *a, uint32_t k, bool fn)
{
    struct app_time *t = a->tm;
    if (!t) return;
    a->msg[0] = 0;
    ap_mark_all(a);
    switch (t->mode) {
    case TM_MENU:
        if (k == K_UP || k == K_DOWN) t->sel = 1 - t->sel;
        else if (k == K_ENTER && t->sel == 0) {
            bool valid;
            int64_t now = a->p->now(a->p->ctx, &valid);
            fill_fields(a, valid ? now : cp_build_time());
            t->mode = TM_MANUAL;
        } else if (k == K_ENTER) start_scan(a);
        else if (k == '`' || k == K_ESC) leave(a);
        break;
    case TM_MANUAL: {
        int *f = &t->v[t->field];
        if (k >= '0' && k <= '9') {
            *f = t->typed == 0 ? (int)(k - '0') : *f * 10 + (int)(k - '0');
            if (++t->typed == WIDTH[t->field]) {
                t->typed = 0;
                if (t->field < 5) t->field++;
            }
        } else if (k == K_BACKSPACE) *f /= 10, t->typed = 0;
        else if (k == K_LEFT) t->field = (t->field + 5) % 6, t->typed = 0;
        else if (k == K_RIGHT || k == K_TAB) t->field = (t->field + 1) % 6, t->typed = 0;
        else if (k == K_UP || k == K_DOWN) { /* +-1 with wrap, staying inside the field's own range */
            static const int LO[6] = {2000, 1, 1, 0, 0, 0}, HI[6] = {2099, 12, 31, 23, 59, 59};
            int hi = t->field == 2 && t->v[1] >= 1 && t->v[1] <= 12 ? cp_days_in_month(t->v[0], t->v[1]) : HI[t->field];
            *f += k == K_UP ? 1 : -1;
            if (*f > hi) *f = LO[t->field];
            if (*f < LO[t->field]) *f = hi;
            t->typed = 0;
        } else if (k == K_ENTER) {
            int64_t utc;
            if (!fields_to_utc(a, &utc)) snprintf(a->msg, sizeof a->msg, "Not a valid date or time");
            else if (utc < cp_build_time()) snprintf(a->msg, sizeof a->msg, "Before the firmware build date");
            else {
                set_clock(a, utc, 1);
                t->mode = TM_MENU;
                snprintf(a->msg, sizeof a->msg, "Time set");
            }
        } else if (k == '`' || k == K_ESC) t->mode = TM_MENU;
        break;
    }
    case TM_LIST:
        if (k == K_UP) ap_move_sel_in(a, &t->sel, &t->top, t->nap, -1);
        else if (k == K_DOWN) ap_move_sel_in(a, &t->sel, &t->top, t->nap, 1);
        else if (k == K_ENTER && t->nap) choose_ap(a);
        else if (k == 'r' || k == 'R') start_scan(a);
        else if (k == '`' || k == K_ESC) t->mode = TM_MENU;
        break;
    case TM_PASSWORD:
        t->note[0] = 0;
        if (k == K_ENTER) do_sync(a, t->ap[t->chosen].ssid, t->pw, t->save);
        else if (k == K_DOWN) fetch_start(a);
        else if (k == K_ESC) { t->mode = TM_LIST; ap_wipe(t->pw, sizeof t->pw); t->pwlen = 0; }
        else if (k == K_TAB) t->save = !t->save;
        else if (k == K_BACKSPACE) ap_utf8_backspace(t->pw, &t->pwlen);
        else if (ap_printable(k) && !fn) ap_utf8_append(t->pw, &t->pwlen, sizeof t->pw, k);
        break;
    case TM_RESULT:
        if (t->retry && k == K_ENTER) { t->mode = TM_PASSWORD; t->pwlen = 0; t->pw[0] = 0; t->save = true; }
        else t->mode = TM_MENU;
        break;
    default: break;                                        /* busy: keys are ignored */
    }
}

/* ---------------- drawing ---------------- */

static void status(app *a, ui_strip *s)
{
    bool valid;
    int64_t now = a->p->now(a->p->ctx, &valid);
    char l1[48], l2[64], age[24];
    if (valid) {
        int y, mo, d, h, mi;
        ap_civil(now + a->cfg.tz_minutes * 60, &y, &mo, &d, &h, &mi);
        snprintf(l1, sizeof l1, "%04d-%02d-%02d  %02d:%02d:%02d", y, mo, d, h, mi, (int)(((now + a->cfg.tz_minutes * 60) % 60 + 60) % 60));
        if (a->time_src) {
            age_text(age, sizeof age, a->now_ms - a->time_set_ms);
            snprintf(l2, sizeof l2, "UTC%c%d:%02d  set %s %s", a->cfg.tz_minutes < 0 ? '-' : '+', abs(a->cfg.tz_minutes) / 60,
                     abs(a->cfg.tz_minutes) % 60, a->time_src == 1 ? "by hand" : "over Wi-Fi", age);
        } else {
            snprintf(l2, sizeof l2, "UTC%c%d:%02d", a->cfg.tz_minutes < 0 ? '-' : '+', abs(a->cfg.tz_minutes) / 60, abs(a->cfg.tz_minutes) % 60);
        }
    } else {
        snprintf(l1, sizeof l1, "Time not set");
        snprintf(l2, sizeof l2, "TOTP codes and expiry need the time");
    }
    ui_text(s, F, PAD * 2, CONTENT_Y + 4, l1, valid ? T->fg : T->warn, UI_W - PAD * 4);
    ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + 6 + F->height, l2, T->dim, UI_W - PAD * 4);
}

static void draw_fields(app *a, ui_strip *s, int from, int to, int y, const char *sep)
{
    struct app_time *t = a->tm;
    int x = PAD * 2, h = F->height;
    for (int i = from; i < to; i++) {
        char b[8];
        snprintf(b, sizeof b, "%0*d", WIDTH[i], t->v[i]);
        int w = ui_text_width(F, b);
        bool act = i == t->field;
        if (act) ui_fill(s, x - 2, y - 1, w + 4, h + 4, T->sel_bg);
        ui_text(s, F, x, y, b, act ? T->accent : T->fg, w + 2);
        ui_fill(s, x, y + h + 2, w, 1, act ? T->accent : T->dim);
        x += w;
        if (i < to - 1) x += ui_text(s, F, x + 2, y, sep, T->dim, 20) + 4;
    }
}

void ap_time_draw(app *a, ui_strip *s, const char **hint)
{
    struct app_time *t = a->tm;
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    if (!t) return;
    int h = ap_row_h(a);
    switch (t->mode) {
    case TM_MENU: {
        status(a, s);
        static const char *const names[] = {"Set by hand", "Sync over Wi-Fi"};
        for (int r = 0; r < 2; r++) {
            int y = CONTENT_Y + 44 + r * h;
            bool sel = r == t->sel;
            ui_fill(s, 0, y, UI_W, h, sel ? T->sel_bg : T->bg);
            if (sel) ui_fill(s, 0, y, 2, h, T->accent);
            ui_text(s, F, PAD * 2 + 2, y + (h - F->height) / 2, names[r], sel ? T->sel_fg : T->fg, UI_W - 100);
            if (r == 1 && a->db) ui_text(s, &ui_font_small, UI_W - PAD - 100, y + (h - ui_font_small.height) / 2, "lock first", T->warn, 100);
        }
        ap_draw_toast(a, s);
        *hint = U_UPDOWN " choose  " U_ENTER " open  ` back";
        break;
    }
    case TM_MANUAL: {
        ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + 2, "Your local time now:", T->dim, UI_W);
        draw_fields(a, s, 0, 3, CONTENT_Y + 16, "-");
        draw_fields(a, s, 3, 6, CONTENT_Y + 42, ":");
        int64_t utc;
        char p[64];
        if (fields_to_utc(a, &utc)) {
            int y, mo, d, hh, mi;
            ap_civil(utc, &y, &mo, &d, &hh, &mi);
            snprintf(p, sizeof p, "= %04d-%02d-%02d %02d:%02d:%02d UTC", y, mo, d, hh, mi, (int)((utc % 60 + 60) % 60));
            ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + 68, p, T->ok, UI_W - PAD * 4);
        } else {
            ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + 68, "not a valid date or time", T->danger, UI_W - PAD * 4);
        }
        ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + 82, "Set a few seconds ahead, press Enter on the beat", T->dim, UI_W - PAD * 2);
        ap_draw_toast(a, s);
        *hint = "0-9 type  " U_LR " field  " U_UPDOWN " +-1  " U_ENTER " set";
        break;
    }
    case TM_LIST:
        for (int i = t->top; i < t->nap && i < t->top + ap_visible(a); i++) {
            const app_ap *ap = &t->ap[i];
            int y = CONTENT_Y + (i - t->top) * h;
            bool sel = i == t->sel, saved = cp_settings_wifi_find(&a->cfg, ap->ssid) >= 0;
            ui_fill(s, 0, y, UI_W, h, sel ? T->sel_bg : T->bg);
            if (sel) ui_fill(s, 0, y, 2, h, T->accent);
            int ty = y + (h - F->height) / 2;
            int x = PAD * 2 + ui_text(s, F, PAD * 2, ty, ap->secure ? ICON_LOCK : ICON_WIFI, T->dim, 16) + 4;
            ui_text(s, F, x, ty, ap->ssid, sel ? T->sel_fg : T->fg, UI_W - x - 50);
            if (saved) ui_text(s, &ui_font_small, UI_W - PAD - 44, y + (h - ui_font_small.height) / 2, "saved", T->ok, 44);
        }
        if (!t->nap) ui_text(s, F, PAD * 2, CONTENT_Y + 8, "No network found", T->dim, UI_W);
        ap_draw_scrollbar_in(a, s, t->top, t->nap);
        *hint = U_UPDOWN " choose  " U_ENTER " connect  R rescan  ` back";
        break;
    case TM_PASSWORD: {
        char q[64];
        snprintf(q, sizeof q, "Password for %.36s", t->ap[t->chosen].ssid);
        ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + 6, q, T->dim, UI_W - PAD * 4);
        ap_draw_field(a, s, PAD * 2, CONTENT_Y + 22, UI_W - PAD * 4, F->height + 6, t->pw, true, t->pwlen);
        ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + 22 + F->height + 14, t->save ? "[x] remember this network (tab)" : "[ ] remember this network (tab)",
                t->save ? T->accent : T->dim, UI_W - PAD * 4);
        if (t->note[0]) ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + 22 + F->height + 32, t->note, T->danger, UI_W - PAD * 4);
        *hint = U_ENTER " connect  " U_DOWN " from database  fn+` back";
        break;
    }
    case TM_BUSY: ui_text(s, F, PAD * 2, CONTENT_Y + 30, t->text, T->fg, UI_W - PAD * 4); *hint = "please wait"; break;
    case TM_RESULT:
        if (t->ok) status(a, s);
        ui_text(s, F, PAD * 2, CONTENT_Y + (t->ok ? 50 : 24), t->text, t->ok ? T->ok : T->danger, UI_W - PAD * 4);
        if (t->note[0]) ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + (t->ok ? 72 : 46), t->note, T->dim, UI_W - PAD * 4);
        *hint = t->retry ? U_ENTER " retype password  any other key: back" : "any key";
        break;
    }
}

/* ---------------- Wi-Fi password from a database ----------------
 * On the password screen, down = "from a database": pick and unlock a .kdbx as usual, then open ANY entry (its
 * title need not match the network): ap_open_entry() hands over here instead of showing it. Its password is taken, the database is locked and wiped
 * (app_lock), and only then does the radio come on (the scan already turned it off). Saved like a typed password:
 * only if it connected and "remember" is ticked. */
void ap_wifi_password(app *a, const app_ap *ap)
{
    ap_time_open(a, SCR_PICKER);
    struct app_time *t = a->tm;
    if (!t) return;
    t->ap[0] = *ap;
    t->nap = 1;
    t->chosen = 0;
    t->save = true;
    t->mode = TM_PASSWORD;
}

static void fetch_start(app *a)
{
    struct app_time *t = a->tm;
    a->wifi_fetch = t->ap[t->chosen];
    a->wifi_fetch_save = t->save;
    ap_time_free(a);                                     /* also wipes anything typed so far */
    ap_rescan_files(a);
    a->scr = SCR_PICKER;
    a->sel = a->top = 0;
    for (int i = 0; i < a->ndbs; i++) /* preselect the last database */
        if (!strcmp(a->dbs[i], a->cfg.last_db)) a->sel = i;
    a->msg[0] = 0;
    ap_mark_all(a);
}

void ap_wifi_fetch_done(app *a, const kdbx_entry *e)
{
    app_ap ap = a->wifi_fetch;
    bool save = a->wifi_fetch_save;
    memset(&a->wifi_fetch, 0, sizeof a->wifi_fetch);
    char *pw = malloc(REVEAL_MAX);
    const kdbx_field *f = kdbx_field_get(e, "Password");
    bool ok = pw && f && kdbx_reveal(a->db, f, pw, REVEAL_MAX) == KDBX_OK && cp_wifi_valid(ap.ssid, pw);
    app_lock(a);                                         /* database closed and every buffer wiped before any radio */
    ap_wifi_password(a, &ap);
    if (a->tm && !ok) snprintf(a->tm->note, sizeof a->tm->note, "That entry has no Wi-Fi password (8-63)");
    else if (a->tm) do_sync(a, ap.ssid, pw, save);
    if (pw) { ap_wipe(pw, REVEAL_MAX); free(pw); }
    ap_mark_all(a);
}
