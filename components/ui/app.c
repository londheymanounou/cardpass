/* CardPass screens. Layout: status bar (14 px), content rows, key-hint footer (12 px). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "app.h"
#include "mbedtls/platform_util.h"
#include "search.h"
#include "strength.h"
#include "totp.h"
#include "ui_icons.h"

#define BAR_H 14
#define FOOT_H 12
#define CONTENT_Y BAR_H
#define CONTENT_H (UI_H - BAR_H - FOOT_H)
#define PAD 4
#define LABEL_W 56
#define REVEAL_MAX 1024

enum { LI_ENTRY, LI_GROUP, LI_FAV, LI_RECENT };
typedef struct { const void *p; uint8_t type; } list_item;

enum { R_USER, R_PASS, R_URL, R_TOTP, R_NOTES, R_FIELD, R_PASSKEY, R_ATT, R_EXPIRY, R_TAGS };

#define T (a->set.theme)
#define F (a->set.font)

static int row_h(const app *a) { return F->height + 3; }
static int visible_rows(const app *a) { return CONTENT_H / row_h(a); }
static void mark(app *a, int y0, int y1)
{
    if (a->dirty_y1 <= a->dirty_y0) { a->dirty_y0 = y0; a->dirty_y1 = y1; return; }
    if (y0 < a->dirty_y0) a->dirty_y0 = y0;
    if (y1 > a->dirty_y1) a->dirty_y1 = y1;
}
static void mark_all(app *a) { mark(a, 0, UI_H); }
static void mark_row(app *a, int i)
{
    int r = i - a->top;
    if (r >= 0 && r < visible_rows(a)) mark(a, CONTENT_Y + r * row_h(a), CONTENT_Y + (r + 1) * row_h(a));
}
static void wipe(void *p, size_t n) { mbedtls_platform_zeroize(p, n); }

/* ======================= lists ======================= */

static list_item *items(app *a) { return (list_item *)a->hits; }

static int title_cmp(const void *x, const void *y)
{
    const list_item *p = x, *q = y;
    const char *s = p->type == LI_GROUP ? ((const kdbx_group *)p->p)->name : ((const kdbx_entry *)p->p)->title;
    const char *t = q->type == LI_GROUP ? ((const kdbx_group *)q->p)->name : ((const kdbx_entry *)q->p)->title;
    if (p->type != q->type) return p->type == LI_GROUP ? -1 : 1;
    while (*s && *t) {
        unsigned c = search_fold(&s), d = search_fold(&t);
        if (c != d) return c < d ? -1 : 1;
    }
    return !!*s - !!*t;
}

/* unix seconds -> "YYYY-MM-DD" / "HH:MM" (civil-from-days, no libc time zone code) */
static void civil(int64_t t, int *y, int *mo, int *d, int *h, int *mi)
{
    int64_t days = t / 86400, sec = t % 86400;
    if (sec < 0) sec += 86400, days--;
    *h = (int)(sec / 3600);
    *mi = (int)(sec / 60 % 60);
    days += 719468;
    int64_t era = (days >= 0 ? days : days - 146096) / 146097, doe = days - era * 146097;
    int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365, doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    int64_t mp = (5 * doy + 2) / 153;
    *d = (int)(doy - (153 * mp + 2) / 5 + 1);
    *mo = (int)(mp < 10 ? mp + 3 : mp - 9);
    *y = (int)(yoe + era * 400 + (*mo <= 2));
}

/* Home: favorites, this session's recent entries, then the root group. */
static void build_group_list(app *a, const kdbx_group *g, bool home)
{
    list_item *it = items(a);
    int n = 0;
    if (home) {
        const kdbx_group *bin = kdbx_recycle_bin(a->db);
        int start = n;
        for (const kdbx_entry *e = kdbx_entries(a->db); e; e = e->next)
            if (search_has_tag(e->tags, "favorite") && e->group != bin) it[n++] = (list_item){e, LI_ENTRY};
        qsort(it + start, (size_t)(n - start), sizeof *it, title_cmp);
        for (int i = start; i < n; i++) it[i].type = LI_FAV;
        for (int i = 0; i < a->nrecent; i++) it[n++] = (list_item){a->recent[i], LI_RECENT};
    }
    int start = n;
    for (const kdbx_group *c = kdbx_groups(a->db); c; c = c->next)
        if (c->parent == g) it[n++] = (list_item){c, LI_GROUP};
    for (const kdbx_entry *e = kdbx_entries(a->db); e; e = e->next)
        if (e->group == g) it[n++] = (list_item){e, LI_ENTRY};
    qsort(it + start, (size_t)(n - start), sizeof *it, title_cmp);
    a->nhits = n;
    a->group = g;
}

static void build_search(app *a)
{
    search_hit *h = malloc(sizeof *h * (size_t)(a->nentries ? a->nentries : 1));
    int n = h ? (int)search_run(a->db, a->query, a->recent, (size_t)a->nrecent, h, (size_t)a->nentries) : 0;
    for (int i = 0; i < n; i++) items(a)[i] = (list_item){h[i].e, LI_ENTRY};
    free(h);
    a->nhits = n;
    a->sel = a->top = 0;
}

static void scroll_to_sel(app *a)
{
    int vis = visible_rows(a);
    if (a->sel < a->top) a->top = a->sel, mark_all(a);
    if (a->sel >= a->top + vis) a->top = a->sel - vis + 1, mark_all(a);
}

static void move_sel(app *a, int n, int delta)
{
    if (!n) return;
    int old = a->sel;
    a->sel = (a->sel + delta + n) % n; /* wraps around */
    mark_row(a, old);
    mark_row(a, a->sel);
    scroll_to_sel(a);
}

/* ======================= entry view ======================= */

static bool hidden_field(const char *k)
{
    return !strcmp(k, "Title") || !strcmp(k, "UserName") || !strcmp(k, "Password") || !strcmp(k, "URL") ||
           !strcmp(k, "Notes") || !strcmp(k, "otp") || !strncmp(k, "TimeOtp-", 8) || !strncmp(k, "KPEX_PASSKEY_", 13) ||
           !strncmp(k, "KPXC_PASSKEY_", 13);
}

static void add_row(app *a, uint8_t kind, const kdbx_field *f)
{
    if (a->nrows < APP_MAX_ROWS) a->rows[a->nrows++] = (app_row){kind, f, NULL, 0, 0};
}

static void open_entry(app *a, const kdbx_entry *e)
{
    a->entry = e;
    a->nrows = 0;
    a->revealed = false;
    a->back_scr = a->scr;
    const kdbx_field *f;
    if ((f = kdbx_field_get(e, "UserName")) && f->len) add_row(a, R_USER, f);
    if ((f = kdbx_field_get(e, "Password"))) {
        add_row(a, R_PASS, f);
        char *buf = malloc(REVEAL_MAX);
        a->pw_bits = buf && kdbx_reveal(a->db, f, buf, REVEAL_MAX) == KDBX_OK ? strength_bits(buf) : 0;
        if (buf) wipe(buf, REVEAL_MAX), free(buf);
    }
    if ((f = kdbx_field_get(e, "URL")) && f->len) add_row(a, R_URL, f);
    if ((f = kdbx_field_get(e, "otp")) || (f = kdbx_field_get(e, "TimeOtp-Secret-Base32")) ||
        (f = kdbx_field_get(e, "TimeOtp-Secret")) || (f = kdbx_field_get(e, "TimeOtp-Secret-Hex")) ||
        (f = kdbx_field_get(e, "TimeOtp-Secret-Base64")))
        add_row(a, R_TOTP, f);
    if ((f = kdbx_field_get(e, "KPEX_PASSKEY_RELYING_PARTY"))) add_row(a, R_PASSKEY, f);
    for (size_t i = 0; i < e->nfields; i++)
        if (!hidden_field(e->fields[i].key)) add_row(a, R_FIELD, &e->fields[i]);
    for (const kdbx_attachment *t = e->attachments; t; t = t->next)
        if (a->nrows < APP_MAX_ROWS) a->rows[a->nrows++] = (app_row){R_ATT, NULL, t, 0, 0};
    if (*e->tags) add_row(a, R_TAGS, NULL);
    if (e->expires) add_row(a, R_EXPIRY, NULL);
    if ((f = kdbx_field_get(e, "Notes")) && f->len) { /* last: may be long */
        if (f->stream_off != KDBX_PLAIN) add_row(a, R_FIELD, f);
        else {
            const char *s = (const char *)f->value, *p = s;
            while (*p) {
                if (a->nrows == APP_MAX_ROWS) { /* ponytail: long notes end in "…"; full text on the PC */
                    a->rows[APP_MAX_ROWS - 1].len = UINT16_MAX;
                    break;
                }
                size_t n = ui_wrap(F, p, UI_W - LABEL_W - 2 * PAD);
                a->rows[a->nrows++] = (app_row){R_NOTES, f, NULL, (uint32_t)(p - s), (uint16_t)n};
                p += n;
                if (*p == '\n') p++;
                else while (*p == ' ') p++;
            }
        }
    }

    /* remember as recent (most recent first, no duplicates) */
    int j = 0;
    while (j < a->nrecent && a->recent[j] != e) j++;
    if (j == a->nrecent && a->nrecent < APP_RECENT) a->nrecent++;
    if (j == APP_RECENT) j = APP_RECENT - 1;
    memmove(a->recent + 1, a->recent, sizeof *a->recent * (size_t)j);
    a->recent[0] = e;

    a->scr = SCR_ENTRY;
    a->sel = a->top = 0;
    mark_all(a);
}

/* ======================= lock / unlock ======================= */

static void free_lists(app *a)
{
    if (a->hits) wipe(a->hits, sizeof(list_item) * (size_t)a->list_cap), free(a->hits);
    a->hits = NULL;
}

void app_lock(app *a)
{
    kdbx_close(a->db);
    a->db = NULL;
    free_lists(a);
    wipe(a->pw, sizeof a->pw);
    wipe(a->query, sizeof a->query);
    wipe(a->recent, sizeof a->recent);
    wipe(a->rows, sizeof a->rows);
    a->pwlen = a->qlen = a->nrecent = a->nrows = 0;
    a->entry = NULL;
    a->group = NULL;
    a->revealed = false;
    a->ndbs = a->p->list_dbs(a->p->ctx, a->dbs, APP_MAX_DBS);
    a->scr = SCR_PICKER;
    a->sel = a->top = 0;
    mark_all(a);
}

static void unlock(app *a)
{
    kdbx_key k;
    kdbx_err e = kdbx_key_init(&k, a->pw, (size_t)a->pwlen, NULL);
    wipe(a->pw, sizeof a->pw);
    a->pwlen = 0;
    FILE *f = fopen(a->path, "rb");
    if (!e) e = f ? kdbx_open(f, &k, &a->db) : KDBX_ERR_IO;
    if (f) fclose(f);
    kdbx_key_wipe(&k);
    if (e) {
        snprintf(a->msg, sizeof a->msg, "%s", kdbx_strerror(e));
        mark_all(a);
        return;
    }
    a->nentries = 0;
    int ngroups = 0;
    for (const kdbx_entry *x = kdbx_entries(a->db); x; x = x->next) a->nentries++;
    for (const kdbx_group *g = kdbx_groups(a->db); g; g = g->next) ngroups++;
    a->list_cap = a->nentries + ngroups + APP_RECENT;
    a->hits = malloc(sizeof(list_item) * (size_t)a->list_cap);
    if (!a->hits) {
        app_lock(a);
        snprintf(a->msg, sizeof a->msg, "Out of memory");
        return;
    }
    a->msg[0] = 0;
    a->scr = SCR_HOME;
    build_group_list(a, kdbx_root_group(a->db), true);
    a->sel = a->top = 0;
    mark_all(a);
}

/* ======================= input ======================= */

static void utf8_append(char *buf, int *len, int cap, uint32_t cp)
{
    char t[4];
    int n = cp < 0x80 ? (t[0] = (char)cp, 1)
          : cp < 0x800 ? (t[0] = (char)(0xC0 | cp >> 6), t[1] = (char)(0x80 | (cp & 0x3F)), 2)
          : cp < 0x10000 ? (t[0] = (char)(0xE0 | cp >> 12), t[1] = (char)(0x80 | ((cp >> 6) & 0x3F)), t[2] = (char)(0x80 | (cp & 0x3F)), 3)
          : (t[0] = (char)(0xF0 | cp >> 18), t[1] = (char)(0x80 | ((cp >> 12) & 0x3F)), t[2] = (char)(0x80 | ((cp >> 6) & 0x3F)), t[3] = (char)(0x80 | (cp & 0x3F)), 4);
    if (*len + n >= cap) return;
    memcpy(buf + *len, t, (size_t)n);
    *len += n;
    buf[*len] = 0;
}

static void utf8_backspace(char *buf, int *len)
{
    while (*len > 0 && ((unsigned char)buf[--*len] & 0xC0) == 0x80) buf[*len] = 0;
    buf[*len] = 0;
}

static bool printable(uint32_t k) { return k >= 0x20 && k < 0x110000 && k != 0x7F; }

static void open_item(app *a, const list_item *it)
{
    if (it->type == LI_GROUP) {
        a->scr = SCR_GROUP;
        build_group_list(a, it->p, false);
        a->sel = a->top = 0;
        mark_all(a);
    } else {
        open_entry(a, it->p);
    }
}

static void go_back(app *a)
{
    switch (a->scr) {
    case SCR_UNLOCK: a->scr = SCR_PICKER; wipe(a->pw, sizeof a->pw); a->pwlen = 0; a->msg[0] = 0; break;
    case SCR_ENTRY:
        a->revealed = false;
        a->scr = a->back_scr;
        if (a->scr == SCR_SEARCH) build_search(a);
        else build_group_list(a, a->scr == SCR_HOME ? kdbx_root_group(a->db) : a->entry->group, a->scr == SCR_HOME);
        a->sel = a->top = 0;
        break;
    case SCR_SEARCH:
        wipe(a->query, sizeof a->query);
        a->qlen = 0;
        a->scr = SCR_HOME;
        build_group_list(a, kdbx_root_group(a->db), true);
        a->sel = a->top = 0;
        break;
    case SCR_GROUP: {
        const kdbx_group *parent = a->group->parent;
        bool home = parent == kdbx_root_group(a->db) || !parent;
        a->scr = home ? SCR_HOME : SCR_GROUP;
        build_group_list(a, home ? kdbx_root_group(a->db) : parent, home);
        a->sel = a->top = 0;
        break;
    }
    default: break;
    }
    mark_all(a);
}

void app_key(app *a, uint32_t key, bool down)
{
    uint32_t k = K_KEY(key);
    bool fn = key & K_FN;
    a->last_input_ms = a->now_ms;

    if (a->scr == SCR_ENTRY && (k == 'r' || k == 'R') && !fn) {
        bool r = a->set.reveal_hold ? down : (down ? !a->revealed : a->revealed);
        if (r != a->revealed) a->revealed = r, mark_row(a, a->sel);
        return;
    }
    if (!down) return;
    if (fn && (k == 'l' || k == 'L') && a->db) { app_lock(a); return; } /* fn+L: lock now */

    switch (a->scr) {
    case SCR_PICKER:
        if (k == K_UP) move_sel(a, a->ndbs, -1);
        else if (k == K_DOWN) move_sel(a, a->ndbs, 1);
        else if (k == K_ENTER && a->ndbs) {
            snprintf(a->dbname, sizeof a->dbname, "%s", a->dbs[a->sel]);
            a->p->db_path(a->p->ctx, a->dbname, a->path, sizeof a->path);
            a->scr = SCR_UNLOCK;
            a->msg[0] = 0;
            mark_all(a);
        }
        break;
    case SCR_UNLOCK: /* ` is a password character here: fn+` goes back */
        if (k == K_ESC) go_back(a);
        else if (k == K_ENTER) unlock(a);
        else if (k == K_BACKSPACE) utf8_backspace(a->pw, &a->pwlen), mark_all(a);
        else if (printable(k) && !fn) utf8_append(a->pw, &a->pwlen, sizeof a->pw, k), a->msg[0] = 0, mark_all(a);
        break;
    case SCR_HOME:
    case SCR_GROUP:
    case SCR_SEARCH:
        if (k == K_UP) move_sel(a, a->nhits, -1);
        else if (k == K_DOWN) move_sel(a, a->nhits, 1);
        else if (k == K_ENTER && a->nhits) open_item(a, &items(a)[a->sel]);
        else if (k == K_ESC || (k == '`' && a->scr != SCR_SEARCH)) go_back(a);
        else if (k == K_BACKSPACE && a->scr == SCR_SEARCH) {
            utf8_backspace(a->query, &a->qlen);
            if (!a->qlen) go_back(a);
            else build_search(a), mark_all(a);
        } else if (printable(k) && !fn && (k != ' ' || a->scr == SCR_SEARCH)) {
            if (a->scr != SCR_SEARCH) a->back_scr = a->scr, a->scr = SCR_SEARCH, a->qlen = 0, a->query[0] = 0;
            utf8_append(a->query, &a->qlen, sizeof a->query, k);
            build_search(a);
            mark_all(a);
        }
        break;
    case SCR_ENTRY:
        if (k == K_UP) { a->revealed = false; move_sel(a, a->nrows, -1); }
        else if (k == K_DOWN) { a->revealed = false; move_sel(a, a->nrows, 1); }
        else if (k == K_ESC || k == '`') go_back(a);
        break;
    }
}

void app_tick(app *a, uint32_t now_ms)
{
    uint32_t prev = a->now_ms;
    a->now_ms = now_ms;
    if (a->db && a->set.autolock_ms && now_ms - a->last_input_ms > a->set.autolock_ms) {
        app_lock(a);
        snprintf(a->msg, sizeof a->msg, "Locked after inactivity");
        return;
    }
    if (prev / 1000 != now_ms / 1000) {
        mark(a, 0, BAR_H); /* clock */
        if (a->scr == SCR_ENTRY)
            for (int i = 0; i < a->nrows; i++)
                if (a->rows[i].kind == R_TOTP) mark_row(a, i);
    }
}

void app_init(app *a, const app_platform *p, const app_settings *s)
{
    memset(a, 0, sizeof *a);
    a->p = p;
    a->set = *s;
    app_lock(a);
    a->msg[0] = 0;
}

bool app_dirty(app *a, int *y0, int *y1)
{
    if (a->dirty_y1 <= a->dirty_y0) return false;
    *y0 = a->dirty_y0;
    *y1 = a->dirty_y1;
    a->dirty_y0 = a->dirty_y1 = 0;
    return true;
}

/* ======================= drawing ======================= */

static void draw_bar(app *a, ui_strip *s, const char *title)
{
    ui_fill(s, 0, 0, UI_W, BAR_H, T->bar_bg);
    char right[48] = "";
    bool valid;
    int64_t now = a->p->now(a->p->ctx, &valid);
    if (valid) {
        int y, mo, d, h, mi;
        civil(now + a->set.tz_minutes * 60, &y, &mo, &d, &h, &mi);
        snprintf(right, sizeof right, "%02d:%02d ", h, mi);
    }
    int bat = a->p->battery(a->p->ctx);
    if (bat >= 0) {
        size_t l = strlen(right);
        snprintf(right + l, sizeof right - l, "%s%d%% ", bat > 60 ? ICON_BATTERY_FULL : bat > 20 ? ICON_BATTERY_HALF : ICON_BATTERY_EMPTY, bat);
    }
    strcat(right, a->db ? ICON_UNLOCK : ICON_LOCK);
    int rw = ui_text_width(&ui_font_small, right);
    ui_text(s, &ui_font_small, UI_W - PAD - rw, 1, right, bat >= 0 && bat <= 10 ? T->danger : T->bar_fg, rw);
    ui_text(s, &ui_font_small, PAD, 1, title, T->bar_fg, UI_W - 3 * PAD - rw);
}

static void draw_footer(app *a, ui_strip *s, const char *hint)
{
    ui_fill(s, 0, UI_H - FOOT_H, UI_W, FOOT_H, T->bg);
    ui_text(s, &ui_font_small, PAD, UI_H - FOOT_H, hint, T->dim, UI_W - 2 * PAD);
}

/* One list row: icon, text, dim right-aligned note. */
static void draw_row(app *a, ui_strip *s, int i, const char *icon, uint16_t icon_c, const char *text, const char *right,
                     uint16_t right_c)
{
    int y = CONTENT_Y + (i - a->top) * row_h(a), h = row_h(a);
    if (y + h <= s->y0 || y >= s->y0 + s->h) return;
    bool sel = i == a->sel;
    ui_fill(s, 0, y, UI_W, h, sel ? T->sel_bg : T->bg);
    if (sel) ui_fill(s, 0, y, 2, h, T->accent);
    int ty = y + (h - F->height) / 2, x = PAD + 2;
    if (icon) x += ui_text(s, F, x, ty, icon, icon_c, 16) + 4;
    int rw = right && *right ? ui_text_width(&ui_font_small, right) : 0;
    ui_text(s, F, x, ty, text, sel ? T->sel_fg : T->fg, UI_W - x - PAD - (rw ? rw + 6 : 0));
    if (rw) ui_text(s, &ui_font_small, UI_W - PAD - rw, y + (h - ui_font_small.height) / 2, right, right_c, rw);
}

static void draw_scrollbar(app *a, ui_strip *s, int n)
{
    int vis = visible_rows(a);
    if (n <= vis) return;
    int h = CONTENT_H * vis / n, y = CONTENT_Y + (CONTENT_H - h) * a->top / (n - vis);
    ui_fill(s, UI_W - 2, y, 2, h < 4 ? 4 : h, T->dim);
}

static void draw_list(app *a, ui_strip *s)
{
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    int vis = visible_rows(a);
    for (int i = a->top; i < a->nhits && i < a->top + vis; i++) {
        const list_item *it = &items(a)[i];
        if (it->type == LI_GROUP) {
            const kdbx_group *g = it->p;
            draw_row(a, s, i, ICON_FOLDER, T->accent, g->name, NULL, 0);
        } else {
            const kdbx_entry *e = it->p;
            const char *icon = it->type == LI_FAV ? ICON_STAR : it->type == LI_RECENT ? ICON_CLOCK : ICON_KEY;
            draw_row(a, s, i, icon, it->type == LI_ENTRY ? T->dim : T->accent, *e->title ? e->title : "(no title)",
                     e->username, T->dim);
        }
    }
    if (!a->nhits)
        ui_text(s, F, PAD * 2, CONTENT_Y + 8, a->scr == SCR_SEARCH ? "No match" : "Empty group", T->dim, UI_W);
    draw_scrollbar(a, s, a->nhits);
}

static void draw_entry_row(app *a, ui_strip *s, int i, char *buf)
{
    const app_row *r = &a->rows[i];
    int y = CONTENT_Y + (i - a->top) * row_h(a), h = row_h(a);
    if (y + h <= s->y0 || y >= s->y0 + s->h) return;
    bool sel = i == a->sel, reveal = sel && a->revealed;
    ui_fill(s, 0, y, UI_W, h, sel ? T->sel_bg : T->bg);
    if (sel) ui_fill(s, 0, y, 2, h, T->accent);
    int ty = y + (h - F->height) / 2, sy = y + (h - ui_font_small.height) / 2, vx = PAD + LABEL_W, vw = UI_W - vx - PAD;
    const char *label = "", *val = "";
    char right[40] = "";
    uint16_t vc = sel ? T->sel_fg : T->fg, rc = T->dim;
    bool masked = false;

    switch (r->kind) {
    case R_USER: label = "User"; val = (const char *)r->f->value; if (r->f->stream_off != KDBX_PLAIN) masked = true; break;
    case R_URL: label = "URL"; val = (const char *)r->f->value; break;
    case R_PASS:
        label = "Pass";
        if (!r->f->len) { val = "(empty)"; vc = T->dim; break; }
        masked = true;
        snprintf(right, sizeof right, "%s %.0f bits", a->pw_bits >= 64 ? "Strong" : "Weak", a->pw_bits);
        rc = a->pw_bits >= 64 ? T->ok : T->warn;
        break;
    case R_FIELD: label = r->f->key; val = (const char *)r->f->value; masked = r->f->stream_off != KDBX_PLAIN; break;
    case R_NOTES:
        label = r->off == 0 ? "Notes" : "";
        if (r->len == UINT16_MAX) { val = "\xE2\x80\xA6"; vc = T->dim; break; }
        memcpy(buf, (const char *)r->f->value + r->off, r->len);
        buf[r->len] = 0;
        val = buf;
        break;
    case R_TOTP: {
        label = "TOTP";
        bool valid;
        int64_t now = a->p->now(a->p->ctx, &valid);
        totp t;
        bool ok = kdbx_reveal(a->db, r->f, buf, REVEAL_MAX) == KDBX_OK;
        if (ok && !strcmp(r->f->key, "otp")) ok = totp_from_uri(&t, buf);
        else if (ok) {
            totp_init(&t);
            ok = totp_set_keepass(&t, r->f->key, buf);
            for (size_t k = 0; ok && k < a->entry->nfields; k++) {
                const kdbx_field *x = &a->entry->fields[k];
                if (!strncmp(x->key, "TimeOtp-", 8) && strncmp(x->key, "TimeOtp-Secret", 14) &&
                    kdbx_reveal(a->db, x, buf, REVEAL_MAX) == KDBX_OK)
                    totp_set_keepass(&t, x->key, buf);
            }
        }
        wipe(buf, REVEAL_MAX);
        if (!ok) { val = "invalid TOTP settings"; vc = T->danger; break; }
        if (!valid) { val = "time not set"; vc = T->warn; totp_wipe(&t); break; }
        char code[16];
        totp_code(&t, (uint64_t)now, code);
        int rem = totp_remaining(&t, (uint64_t)now), per = t.period;
        totp_wipe(&t);
        size_t cl = strlen(code);
        if (cl == 6 || cl == 8) { /* 123 456 */
            memmove(code + cl / 2 + 1, code + cl / 2, cl / 2 + 1);
            code[cl / 2] = ' ';
        }
        snprintf(buf, REVEAL_MAX, "%s", code);
        wipe(code, sizeof code);
        val = buf;
        snprintf(right, sizeof right, "%ds", rem);
        rc = rem <= 5 ? T->danger : T->dim;
        int bw = 40, bx = UI_W - PAD - bw;
        ui_fill(s, bx, y + h - 3, bw, 2, T->field_bg);
        ui_fill(s, bx, y + h - 3, bw * rem / per, 2, rc);
        break;
    }
    case R_PASSKEY: label = "Passkey"; val = (const char *)r->f->value; break;
    case R_ATT:
        label = "File";
        val = r->att->name;
        snprintf(right, sizeof right, "%s %.1f KB", ICON_FILE, r->att->size / 1024.0);
        break;
    case R_TAGS: label = "Tags"; val = a->entry->tags; break;
    case R_EXPIRY: {
        label = "Expires";
        int yy, mo, d, hh, mi;
        civil(a->entry->expiry, &yy, &mo, &d, &hh, &mi);
        snprintf(buf, 32, "%04d-%02d-%02d", yy, mo, d);
        val = buf;
        bool valid;
        if (a->p->now(a->p->ctx, &valid) > a->entry->expiry && valid) { vc = T->danger; strcpy(right, "expired"); rc = T->danger; }
        break;
    }
    }
    ui_text(s, &ui_font_small, PAD + 2, sy, label, T->dim, LABEL_W - 4);
    int rw = right[0] ? ui_text_width(&ui_font_small, right) : 0;
    if (rw) ui_text(s, &ui_font_small, UI_W - PAD - rw, sy - (r->kind == R_TOTP ? 1 : 0), right, rc, rw);
    int maxw = vw - (rw ? rw + 6 : 0);
    if (masked && !reveal) {
        ui_text(s, F, vx, ty, "\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2", vc, maxw);
    } else if (masked) {
        if (kdbx_reveal(a->db, r->f, buf, REVEAL_MAX) == KDBX_OK) ui_text(s, F, vx, ty, buf, T->accent, maxw);
        else ui_text(s, F, vx, ty, "(too long to show)", T->dim, maxw);
        wipe(buf, REVEAL_MAX);
    } else {
        ui_text(s, F, vx, ty, val, vc, maxw);
    }
}

void app_draw(app *a, ui_strip *s)
{
    char title[96];
    const char *hint = "";
    switch (a->scr) {
    case SCR_PICKER: snprintf(title, sizeof title, "CardPass"); break;
    case SCR_UNLOCK: snprintf(title, sizeof title, "Unlock %s", a->dbname); break;
    case SCR_HOME: snprintf(title, sizeof title, "%s", a->dbname); break;
    case SCR_GROUP: snprintf(title, sizeof title, "%s %s", ICON_FOLDER_OPEN, a->group->name); break;
    case SCR_SEARCH: snprintf(title, sizeof title, "%s", a->dbname); break;
    case SCR_ENTRY: snprintf(title, sizeof title, "%s %s", ICON_KEY, a->entry->title); break;
    }
    if (s->y0 < BAR_H) draw_bar(a, s, title);

    char *buf = malloc(REVEAL_MAX);
    if (!buf) return;
    switch (a->scr) {
    case SCR_PICKER:
        ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
        for (int i = a->top; i < a->ndbs && i < a->top + visible_rows(a); i++)
            draw_row(a, s, i, ICON_LOCK, T->accent, a->dbs[i], NULL, 0);
        if (!a->ndbs) ui_text(s, F, PAD * 2, CONTENT_Y + 8, "No .kdbx files on the SD card", T->dim, UI_W);
        if (a->msg[0]) ui_text(s, &ui_font_small, PAD * 2, UI_H - FOOT_H - 13, a->msg, T->warn, UI_W);
        hint = "\xE2\x86\x91\xE2\x86\x93 choose  \xE2\x86\xB5 open";
        break;
    case SCR_UNLOCK: {
        ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
        ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + 8, "Master password", T->dim, UI_W);
        int fy = CONTENT_Y + 24, fh = F->height + 8;
        ui_fill(s, PAD * 2, fy, UI_W - PAD * 4, fh, T->field_bg);
        ui_fill(s, PAD * 2, fy + fh - 2, UI_W - PAD * 4, 2, T->accent);
        int n = 0;
        for (const char *p = a->pw; *p;) ui_utf8_next(&p), n++;
        char dots[3 * 40 + 1] = "";
        for (int i = 0; i < n && i < 40; i++) strcat(dots, "\xE2\x80\xA2");
        int w = ui_text(s, F, PAD * 3, fy + 4, dots, T->fg, UI_W - PAD * 8);
        ui_fill(s, PAD * 3 + w + 1, fy + 3, 2, F->height + 2, T->accent); /* cursor */
        if (a->msg[0]) ui_text(s, F, PAD * 2, fy + fh + 8, a->msg, T->danger, UI_W - PAD * 4);
        hint = "\xE2\x86\xB5 unlock  fn+` back";
        break;
    }
    case SCR_HOME:
    case SCR_GROUP:
        draw_list(a, s);
        hint = a->scr == SCR_HOME ? "type to search  \xE2\x86\xB5 open  fn+L lock" : "type to search  \xE2\x86\xB5 open  ` back";
        break;
    case SCR_SEARCH: {
        draw_list(a, s);
        snprintf(title, sizeof title, "%s %s", ICON_SEARCH, a->query);
        if (s->y0 < BAR_H) { /* query replaces the title */
            ui_fill(s, 0, 0, UI_W / 2 + 40, BAR_H, T->bar_bg);
            int w = ui_text(s, &ui_font_small, PAD, 1, title, T->accent, UI_W / 2 + 30);
            ui_fill(s, PAD + w + 1, 2, 1, 10, T->accent);
        }
        hint = "\xE2\x86\x91\xE2\x86\x93 choose  \xE2\x86\xB5 open  fn+` clear";
        break;
    }
    case SCR_ENTRY:
        ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
        for (int i = a->top; i < a->nrows && i < a->top + visible_rows(a); i++) draw_entry_row(a, s, i, buf);
        draw_scrollbar(a, s, a->nrows);
        hint = a->set.reveal_hold ? "hold R reveal   ` back" : "R reveal   ` back";
        break;
    }
    wipe(buf, REVEAL_MAX);
    free(buf);
    if (s->y0 + s->h > UI_H - FOOT_H) draw_footer(a, s, hint);
}
