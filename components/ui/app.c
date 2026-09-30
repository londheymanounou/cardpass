/* CardPass core screens: picker, unlock, home/groups/search, entry view, QR.
 * Layout: status bar (14 px), content rows, key-hint footer (12 px). */
#include "app_priv.h"
#include "mbedtls/platform_util.h"
#include "qrcodegen.h"
#include "search.h"
#include "strength.h"
#include "totp.h"

#define QR_SHOW_MS 20000

/* ======================= shared helpers ======================= */

int ap_row_h(const app *a) { return F->height + 3; }
int ap_visible(const app *a) { return CONTENT_H / ap_row_h(a); }
void ap_wipe(void *p, size_t n) { mbedtls_platform_zeroize(p, n); }

void ap_mark(app *a, int y0, int y1)
{
    if (a->dirty_y1 <= a->dirty_y0) { a->dirty_y0 = y0; a->dirty_y1 = y1; return; }
    if (y0 < a->dirty_y0) a->dirty_y0 = y0;
    if (y1 > a->dirty_y1) a->dirty_y1 = y1;
}
void ap_mark_all(app *a) { ap_mark(a, 0, UI_H); }
void ap_mark_row(app *a, int i)
{
    int r = i - a->top;
    if (r >= 0 && r < ap_visible(a)) ap_mark(a, CONTENT_Y + r * ap_row_h(a), CONTENT_Y + (r + 1) * ap_row_h(a));
}

/* unix seconds -> civil date/time (no libc time zone code) */
void ap_civil(int64_t t, int *y, int *mo, int *d, int *h, int *mi)
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

void ap_utf8_append(char *buf, int *len, int cap, uint32_t cp)
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

void ap_utf8_backspace(char *buf, int *len)
{
    while (*len > 0 && ((unsigned char)buf[--*len] & 0xC0) == 0x80) buf[*len] = 0;
    buf[*len] = 0;
}

bool ap_printable(uint32_t k) { return k >= 0x20 && k < 0x110000 && k != 0x7F; }

/* ======================= lists ======================= */

list_item *ap_items(app *a) { return (list_item *)a->hits; }

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

/* Home: expiry alert, favorites, this session's recent entries, then the root group. */
void ap_build_group(app *a, const kdbx_group *g, bool home)
{
    list_item *it = ap_items(a);
    int n = 0;
    if (home) {
        if (ap_expiring_count(a)) it[n++] = (list_item){NULL, LI_ALERT};
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

void ap_build_search(app *a)
{
    search_hit *h = malloc(sizeof *h * (size_t)(a->nentries ? a->nentries : 1));
    int n = h ? (int)search_run(a->db, a->query, a->recent, (size_t)a->nrecent, h, (size_t)a->nentries) : 0;
    for (int i = 0; i < n; i++) ap_items(a)[i] = (list_item){h[i].e, LI_ENTRY};
    free(h);
    a->nhits = n;
    a->sel = a->top = 0;
}

void ap_go_home(app *a)
{
    a->scr = SCR_HOME;
    ap_build_group(a, kdbx_root_group(a->db), true);
    a->sel = a->top = 0;
    ap_mark_all(a);
}

static void scroll_to_sel(app *a)
{
    int vis = ap_visible(a);
    if (a->sel < a->top) a->top = a->sel, ap_mark_all(a);
    if (a->sel >= a->top + vis) a->top = a->sel - vis + 1, ap_mark_all(a);
}

void ap_move_sel_in(app *a, int *sel, int *top, int n, int delta)
{
    if (!n) return;
    *sel = (*sel + delta + n) % n;
    int vis = ap_visible(a);
    if (*sel < *top) *top = *sel;
    if (*sel >= *top + vis) *top = *sel - vis + 1;
    ap_mark_all(a);
}

void ap_move_sel(app *a, int n, int delta)
{
    if (!n) return;
    int old = a->sel;
    a->sel = (a->sel + delta + n) % n; /* wraps around */
    if (n > 1) ap_sel_changed(a, old);
    ap_mark_row(a, old);
    ap_mark_row(a, a->sel);
    scroll_to_sel(a);
}

static void free_lists(app *a)
{
    if (a->hits) ap_wipe(a->hits, sizeof(list_item) * (size_t)a->list_cap), free(a->hits);
    a->hits = NULL;
    free(a->audit_bits);
    a->audit_bits = NULL;
}

bool ap_reindex(app *a)
{
    free_lists(a);
    a->nentries = 0;
    int ngroups = 0;
    for (const kdbx_entry *x = kdbx_entries(a->db); x; x = x->next) a->nentries++;
    for (const kdbx_group *g = kdbx_groups(a->db); g; g = g->next) ngroups++;
    a->list_cap = a->nentries + ngroups + APP_RECENT + 1;
    a->hits = malloc(sizeof(list_item) * (size_t)a->list_cap);
    a->nhits = 0;
    return a->hits != NULL;
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

static const kdbx_field *totp_field(const kdbx_entry *e)
{
    const kdbx_field *f;
    if ((f = kdbx_field_get(e, "otp")) || (f = kdbx_field_get(e, "TimeOtp-Secret-Base32")) ||
        (f = kdbx_field_get(e, "TimeOtp-Secret")) || (f = kdbx_field_get(e, "TimeOtp-Secret-Hex")) ||
        (f = kdbx_field_get(e, "TimeOtp-Secret-Base64")))
        return f;
    return NULL;
}

void ap_open_entry(app *a, const kdbx_entry *e)
{
    if (a->scr == SCR_HOME || a->scr == SCR_GROUP || a->scr == SCR_SEARCH || a->scr == SCR_AUDIT || a->scr == SCR_EXPIRY)
        a->back_scr = a->scr;
    a->entry = e;
    a->nrows = 0;
    a->revealed = false;
    const kdbx_field *f;
    if ((f = kdbx_field_get(e, "UserName")) && f->len) add_row(a, R_USER, f);
    if ((f = kdbx_field_get(e, "Password"))) {
        add_row(a, R_PASS, f);
        char *buf = malloc(REVEAL_MAX);
        a->pw_bits = buf && kdbx_reveal(a->db, f, buf, REVEAL_MAX) == KDBX_OK ? strength_bits(buf) : 0;
        if (buf) ap_wipe(buf, REVEAL_MAX), free(buf);
    }
    if ((f = kdbx_field_get(e, "URL")) && f->len) add_row(a, R_URL, f);
    if ((f = totp_field(e))) add_row(a, R_TOTP, f);
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
    ap_mark_all(a);
}

/* Current code of an entry's TOTP field into out (digits only). */
bool ap_totp_now(app *a, const kdbx_entry *e, const kdbx_field *f, char *out, size_t n)
{
    bool valid, ok;
    int64_t now = a->p->now(a->p->ctx, &valid);
    totp t;
    char *buf = malloc(REVEAL_MAX);
    if (!f) f = totp_field(e);
    if (!buf || !f || !valid || n < 11) { free(buf); return false; }
    ok = kdbx_reveal(a->db, f, buf, REVEAL_MAX) == KDBX_OK;
    if (ok && !strcmp(f->key, "otp")) ok = totp_from_uri(&t, buf);
    else if (ok) {
        totp_init(&t);
        ok = totp_set_keepass(&t, f->key, buf);
        for (size_t k = 0; ok && k < e->nfields; k++) {
            const kdbx_field *x = &e->fields[k];
            if (!strncmp(x->key, "TimeOtp-", 8) && strncmp(x->key, "TimeOtp-Secret", 14) &&
                kdbx_reveal(a->db, x, buf, REVEAL_MAX) == KDBX_OK)
                totp_set_keepass(&t, x->key, buf);
        }
    }
    ap_wipe(buf, REVEAL_MAX);
    free(buf);
    if (!ok || !totp_valid(&t)) { totp_wipe(&t); return false; }
    totp_code(&t, (uint64_t)now, out);
    a->totp_period = t.period;
    totp_wipe(&t);
    return true;
}

/* ======================= lock / unlock ======================= */

void ap_rescan_files(app *a)
{
    a->ndbs = a->p->list_files(a->p->ctx, ".kdbx", a->dbs, APP_MAX_DBS);
    a->nkeyfiles = a->p->list_files(a->p->ctx, ".keyx", a->keyfiles, APP_MAX_DBS);
    a->nkeyfiles += a->p->list_files(a->p->ctx, ".key", a->keyfiles + a->nkeyfiles, APP_MAX_DBS - a->nkeyfiles);
}

void app_lock(app *a)
{
    kdbx_close(a->db);
    a->db = NULL;
    free_lists(a);
    ap_edit_free(a);
    ap_gen_free(a);
    ap_create_free(a);
    ap_time_free(a);
    ap_account_free(a);
    ap_groups_free(a);
    ap_view_free(a);
    ap_wipe(a->pw, sizeof a->pw);
    ap_wipe(a->query, sizeof a->query);
    ap_wipe(a->recent, sizeof a->recent);
    ap_wipe(a->rows, sizeof a->rows);
    ap_wipe(a->qr, sizeof a->qr);
    a->pwlen = a->qlen = a->nrecent = a->nrows = 0;
    a->entry = NULL;
    a->group = NULL;
    a->revealed = false;
    a->progress = -1;
    ap_rescan_files(a);
    a->keyfile = 0;
    a->scr = SCR_PICKER;
    a->sel = a->top = 0;
    for (int i = 0; i < a->ndbs; i++) /* preselect the last database */
        if (!strcmp(a->dbs[i], a->cfg.last_db)) a->sel = i;
    ap_mark_all(a);
}

void ap_kdf_progress(void *ctx, int pct)
{
    app *a = ctx;
    if (pct == a->progress) return;
    a->progress = pct;
    ap_mark(a, CONTENT_Y, UI_H - FOOT_H);
    a->p->present(a->p->ctx);
}

static void unlock(app *a)
{
    kdbx_key k;
    FILE *kf = NULL;
    char kpath[256];
    if (a->keyfile) {
        a->p->path(a->p->ctx, a->keyfiles[a->keyfile - 1], kpath, sizeof kpath);
        if (!(kf = fopen(kpath, "rb"))) { snprintf(a->msg, sizeof a->msg, "Key file not readable"); ap_mark_all(a); return; }
    }
    /* no password typed + key file = key-file-only database */
    kdbx_err e = kdbx_key_init(&k, a->pwlen || !kf ? a->pw : NULL, (size_t)a->pwlen, kf);
    if (kf) fclose(kf);
    ap_wipe(a->pw, sizeof a->pw);
    a->pwlen = 0;
    a->progress = 0;
    kdbx_set_progress(ap_kdf_progress, a);
    FILE *f = fopen(a->path, "rb");
    if (!e) e = f ? kdbx_open(f, &k, &a->db) : KDBX_ERR_IO;
    if (f) fclose(f);
    kdbx_set_progress(NULL, NULL);
    kdbx_key_wipe(&k);
    a->progress = -1;
    if (e) {
        snprintf(a->msg, sizeof a->msg, "%s", kdbx_strerror(e));
        ap_mark_all(a);
        return;
    }
    if (!ap_reindex(a)) {
        app_lock(a);
        snprintf(a->msg, sizeof a->msg, "Out of memory");
        return;
    }
    if (strcmp(a->cfg.last_db, a->dbname)) {
        snprintf(a->cfg.last_db, sizeof a->cfg.last_db, "%s", a->dbname);
        ap_apply_settings(a);
    }
    a->msg[0] = 0;
    ap_go_home(a);
}

/* ======================= QR ======================= */

/* Plaintext of an entry-view row (for QR). */
static bool row_text(app *a, const app_row *r, char *buf, size_t n)
{
    switch (r->kind) {
    case R_TOTP: return ap_totp_now(a, a->entry, r->f, buf, n);
    case R_NOTES: /* the whole note */
    case R_USER: case R_PASS: case R_URL: case R_FIELD: case R_PASSKEY:
        return kdbx_reveal(a->db, r->f, buf, n) == KDBX_OK && buf[0];
    default: return false;
    }
}

static void show_qr(app *a, const app_row *r)
{
    char *buf = malloc(REVEAL_MAX);
    uint8_t *tmp = malloc(APP_QR_BYTES);
    bool ok = buf && tmp && row_text(a, r, buf, REVEAL_MAX) &&
              qrcodegen_encodeText(buf, tmp, a->qr, qrcodegen_Ecc_LOW, 1, APP_QR_MAX_VERSION, qrcodegen_Mask_AUTO, true);
    if (buf) ap_wipe(buf, REVEAL_MAX), free(buf);
    if (tmp) ap_wipe(tmp, APP_QR_BYTES), free(tmp);
    if (!ok) {
        ap_wipe(a->qr, sizeof a->qr);
        snprintf(a->msg, sizeof a->msg, "Too long for a QR code");
        ap_mark_all(a);
        return;
    }
    static const char *const labels[] = {[R_USER] = "User", [R_PASS] = "Password", [R_URL] = "URL", [R_TOTP] = "TOTP",
                                         [R_NOTES] = "Notes", [R_PASSKEY] = "Passkey"};
    snprintf(a->qr_label, sizeof a->qr_label, "%s", r->kind == R_FIELD ? r->f->key : labels[r->kind]);
    a->scr = SCR_QR;
    a->qr_until = a->now_ms + QR_SHOW_MS;
    ap_mark_all(a);
}

static void close_qr(app *a)
{
    ap_wipe(a->qr, sizeof a->qr);
    a->scr = SCR_ENTRY;
    ap_mark_all(a);
}

/* ======================= input ======================= */

static void open_item(app *a, const list_item *it)
{
    if (it->type == LI_ALERT) {
        ap_expiry_open(a);
    } else if (it->type == LI_GROUP) {
        a->scr = SCR_GROUP;
        ap_build_group(a, it->p, false);
        a->sel = a->top = 0;
        ap_mark_all(a);
    } else {
        ap_open_entry(a, it->p);
    }
}

static void go_back(app *a)
{
    switch (a->scr) {
    case SCR_UNLOCK: a->scr = SCR_PICKER; ap_wipe(a->pw, sizeof a->pw); a->pwlen = 0; a->msg[0] = 0; break;
    case SCR_ENTRY:
        a->revealed = false;
        a->scr = a->back_scr;
        if (a->scr == SCR_SEARCH) ap_build_search(a);
        else if (a->scr == SCR_AUDIT) { ap_audit_open(a); return; }
        else if (a->scr == SCR_EXPIRY) { ap_expiry_open(a); return; }
        else if (a->scr == SCR_GROUP) ap_build_group(a, a->entry->group, false);
        else { ap_go_home(a); return; }
        a->sel = a->top = 0;
        break;
    case SCR_SEARCH:
        ap_wipe(a->query, sizeof a->query);
        a->qlen = 0;
        ap_go_home(a);
        return;
    case SCR_GROUP: {
        const kdbx_group *parent = a->group->parent;
        if (parent == kdbx_root_group(a->db) || !parent) { ap_go_home(a); return; }
        ap_build_group(a, parent, false);
        a->sel = a->top = 0;
        break;
    }
    default: break;
    }
    ap_mark_all(a);
}

#define BAT_CRITICAL 3          /* percent: lock, wipe and shut down (3 readings in a row) */
#define BAT_POLL_MS 5000

static void set_power(app *a, int state)
{
    if (state == a->power) return;
    a->power = state;
    a->p->backlight(a->p->ctx, state);
    if (state == 0) ap_mark_all(a);               /* the panel kept nothing worth trusting: redraw */
}

void app_key(app *a, uint32_t key, bool down)
{
    uint32_t k = K_KEY(key);
    bool fn = key & K_FN;
    a->last_input_ms = a->now_ms;
    ap_anim_key(a);
    if (a->power) {                               /* any key wakes; a key that woke a dark screen does nothing else */
        bool was_off = a->power == 2;
        set_power(a, 0);
        if (was_off) return;
    }

    if (a->scr == SCR_ENTRY && (k == 'r' || k == 'R') && !fn) {
        bool r = !a->cfg.reveal_toggle ? down : (down ? !a->revealed : a->revealed);
        if (r != a->revealed) a->revealed = r, ap_mark_row(a, a->sel);
        return;
    }
    if (!down) return;
    if (fn && (k == 'l' || k == 'L') && a->db && !a->fido_active) { app_lock(a); return; } /* fn+L: lock now */
    if (a->scr == SCR_DRIVE) { ap_drive_key(a, k, fn); return; }   /* nothing else is reachable in drive mode */
    if (k == K_TAB && (a->scr == SCR_PICKER || a->scr == SCR_HOME || a->scr == SCR_GROUP || a->scr == SCR_SEARCH ||
                       a->scr == SCR_ENTRY)) {
        ap_menu_open(a);
        return;
    }
    if (k == '?' && a->scr != SCR_UNLOCK && a->scr != SCR_EDIT && a->scr != SCR_SEARCH && a->scr != SCR_CREATE &&
        a->scr != SCR_HELP && a->scr != SCR_QR && a->scr != SCR_FIDO) {
        a->menu_back = a->scr;
        a->scr = SCR_HELP;
        ap_mark_all(a);
        return;
    }

    switch (a->scr) {
    case SCR_PICKER:
        if (k == K_UP) ap_move_sel(a, a->ndbs, -1);
        else if (k == K_DOWN) ap_move_sel(a, a->ndbs, 1);
        else if (k == K_ENTER && a->ndbs) {
            snprintf(a->dbname, sizeof a->dbname, "%s", a->dbs[a->sel]);
            a->p->path(a->p->ctx, a->dbname, a->path, sizeof a->path);
            a->scr = SCR_UNLOCK;
            a->msg[0] = 0;
            ap_mark_all(a);
        }
        break;
    case SCR_UNLOCK: /* ` is a password character here: fn+` goes back */
        if (k == K_ESC) go_back(a);
        else if (k == K_ENTER) unlock(a);
        else if (k == K_TAB) a->keyfile = (a->keyfile + 1) % (a->nkeyfiles + 1), ap_mark_all(a);
        else if (k == K_BACKSPACE) ap_utf8_backspace(a->pw, &a->pwlen), ap_mark_all(a);
        else if (ap_printable(k) && !fn) ap_utf8_append(a->pw, &a->pwlen, sizeof a->pw, k), a->msg[0] = 0, ap_mark_all(a);
        break;
    case SCR_HOME:
    case SCR_GROUP:
    case SCR_SEARCH:
        if (a->msg[0]) a->msg[0] = 0, ap_mark(a, UI_H - FOOT_H - 14, UI_H - FOOT_H);
        if (k == K_UP) ap_move_sel(a, a->nhits, -1);
        else if (k == K_DOWN) ap_move_sel(a, a->nhits, 1);
        else if (k == K_ENTER && a->nhits) open_item(a, &ap_items(a)[a->sel]);
        else if (k == K_ESC || (k == '`' && a->scr != SCR_SEARCH)) go_back(a);
        else if (k == K_BACKSPACE && a->scr == SCR_SEARCH) {
            ap_utf8_backspace(a->query, &a->qlen);
            if (!a->qlen) go_back(a);
            else ap_build_search(a), ap_mark_all(a);
        } else if (ap_printable(k) && !fn && (k != ' ' || a->scr == SCR_SEARCH)) {
            if (a->scr != SCR_SEARCH) a->scr = SCR_SEARCH, a->qlen = 0, a->query[0] = 0;
            ap_utf8_append(a->query, &a->qlen, sizeof a->query, k);
            ap_build_search(a);
            ap_mark_all(a);
        }
        break;
    case SCR_ENTRY:
        a->msg[0] = 0;
        ap_mark(a, UI_H - FOOT_H - 14, UI_H);
        if (k == K_UP) { a->revealed = false; ap_move_sel(a, a->nrows, -1); }
        else if (k == K_DOWN) { a->revealed = false; ap_move_sel(a, a->nrows, 1); }
        else if (k == K_ESC || k == '`') go_back(a);
        else if ((k == 'q' || k == 'Q') && a->nrows) show_qr(a, &a->rows[a->sel]);
        else ap_entry_key(a, k, fn);
        break;
    case SCR_QR: close_qr(a); break; /* any key clears it */
    case SCR_MENU: ap_menu_key(a, k, fn); break;
    case SCR_EDIT: ap_edit_key(a, k, fn); break;
    case SCR_GEN: ap_gen_key(a, k, fn); break;
    case SCR_SETTINGS: ap_settings_key(a, k, fn); break;
    case SCR_AUDIT: case SCR_EXPIRY: ap_report_key(a, k, fn); break;
    case SCR_CONFIRM: ap_confirm_key(a, k, fn); break;
    case SCR_CREATE: ap_create_key(a, k, fn); break;
    case SCR_HELP: a->scr = a->menu_back; ap_mark_all(a); break;
    case SCR_FIDO: ap_fido_key(a, k, fn); break;
    case SCR_DRIVE: ap_drive_key(a, k, fn); break;
    case SCR_TIME: ap_time_key(a, k, fn); break;
    case SCR_ACCOUNT: ap_account_key(a, k, fn); break;
    case SCR_GROUPS: ap_groups_key(a, k, fn); break;
    case SCR_VIEW: ap_view_key(a, k, fn); break;
    }
}

void app_tick(app *a, uint32_t now_ms)
{
    uint32_t prev = a->now_ms;
    a->now_ms = now_ms;
    if (a->scr == SCR_QR && (int32_t)(now_ms - a->qr_until) >= 0) close_qr(a);
    /* idle: dim, then screen off (never while a browser is waiting for the user) */
    uint32_t idle = now_ms - a->last_input_ms;
    int want = 0;
    if (!a->fido_active) {
        if (a->cfg.off_s && idle >= (uint32_t)a->cfg.off_s * 1000u) want = 2;
        else if (a->cfg.dim_s && idle >= (uint32_t)a->cfg.dim_s * 1000u) want = 1;
    }
    set_power(a, want);

    /* critical battery: lock, wipe, deep sleep (readings sag under load: 3 in a row) */
    if (now_ms - a->bat_check_ms >= BAT_POLL_MS && !a->fido_active) {
        a->bat_check_ms = now_ms;
        int bat = a->p->battery(a->p->ctx);
        a->bat_low = bat >= 0 && bat <= BAT_CRITICAL ? a->bat_low + 1 : 0;
        if (a->bat_low >= 3) {
            app_lock(a);
            set_power(a, 0);
            snprintf(a->msg, sizeof a->msg, "Battery empty: locked");
            ap_mark_all(a);
            a->p->present(a->p->ctx);
            a->p->shutdown(a->p->ctx);
            return;
        }
    }
    uint32_t lock_ms = (uint32_t)a->cfg.autolock_s * 1000u;
    if (a->db && lock_ms && !a->fido_active && now_ms - a->last_input_ms > lock_ms) {
        app_lock(a);
        snprintf(a->msg, sizeof a->msg, "Locked after inactivity");
        return;
    }
    ap_anim_tick(a, now_ms);
    if (prev / 1000 != now_ms / 1000 && a->power != 2) {     /* nothing to update on a dark screen */
        ap_mark(a, 0, BAR_H); /* clock */
        if (a->scr == SCR_TIME) ap_mark(a, CONTENT_Y, CONTENT_Y + 40);
        if (a->scr == SCR_ENTRY)
            for (int i = 0; i < a->nrows; i++)
                if (a->rows[i].kind == R_TOTP) ap_mark_row(a, i);
    }
}

void app_init(app *a, const app_platform *p, const cp_settings *cfg)
{
    memset(a, 0, sizeof *a);
    a->p = p;
    a->cfg = *cfg;
    a->sel_prev = -1;
    a->last_scr = -1;
    a->theme = cfg->light ? &ui_light : &ui_dark;
    a->font = cfg->large_font ? &ui_font_large : &ui_font_small;
    app_lock(a);
    a->msg[0] = 0;
}

bool app_dirty(app *a, int *y0, int *y1)
{
    ap_anim_nav_check(a);
    if (a->power == 2 || a->dirty_y1 <= a->dirty_y0) return false;   /* dark: keep the range for the wake-up redraw */
    *y0 = a->dirty_y0;
    *y1 = a->dirty_y1;
    a->dirty_y0 = a->dirty_y1 = 0;
    return true;
}

/* ======================= drawing ======================= */

void ap_draw_bar(app *a, ui_strip *s, const char *title)
{
    ui_fill(s, 0, 0, UI_W, BAR_H, T->bar_bg);
    char right[48] = "";
    bool valid;
    int64_t now = a->p->now(a->p->ctx, &valid);
    if (valid) {
        int y, mo, d, h, mi;
        ap_civil(now + a->cfg.tz_minutes * 60, &y, &mo, &d, &h, &mi);
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

void ap_draw_footer(app *a, ui_strip *s, const char *hint)
{
    ui_fill(s, 0, UI_H - FOOT_H, UI_W, FOOT_H, T->bg);
    ui_text(s, &ui_font_small, PAD, UI_H - FOOT_H, hint, T->dim, UI_W - 2 * PAD);
}

/* One list row: icon, text, dim right-aligned note. */
void ap_draw_row(app *a, ui_strip *s, int i, const char *icon, uint16_t icon_c, const char *text, const char *right,
                 uint16_t right_c)
{
    int y = CONTENT_Y + (i - a->top) * ap_row_h(a), h = ap_row_h(a);
    if (y + h <= s->y0 || y >= s->y0 + s->h) return;
    bool sel = i == a->sel;
    ap_row_bg(a, s, y, h, i);
    int ty = y + (h - F->height) / 2, x = PAD + 2;
    if (icon) x += ui_text(s, F, x, ty, icon, icon_c, 16) + 4;
    int rw = right && *right ? ui_text_width(&ui_font_small, right) : 0;
    ui_text(s, F, x, ty, text, sel ? T->sel_fg : T->fg, UI_W - x - PAD - (rw ? rw + 6 : 0));
    if (rw) ui_text(s, &ui_font_small, UI_W - PAD - rw, y + (h - ui_font_small.height) / 2, right, right_c, rw);
}

void ap_draw_scrollbar_in(app *a, ui_strip *s, int top, int n)
{
    int vis = ap_visible(a);
    if (n <= vis) return;
    int h = CONTENT_H * vis / n, y = CONTENT_Y + (CONTENT_H - h) * top / (n - vis);
    ui_fill(s, UI_W - 2, y, 2, h < 4 ? 4 : h, T->dim);
}

void ap_draw_scrollbar(app *a, ui_strip *s, int n) { ap_draw_scrollbar_in(a, s, a->top, n); }

void ap_draw_list(app *a, ui_strip *s)
{
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    int vis = ap_visible(a);
    for (int i = a->top; i < a->nhits && i < a->top + vis; i++) {
        const list_item *it = &ap_items(a)[i];
        if (it->type == LI_ALERT) {
            char t[48];
            snprintf(t, sizeof t, "%d expired or expiring", ap_expiring_count(a));
            ap_draw_row(a, s, i, ICON_WARNING, T->warn, t, NULL, 0);
        } else if (it->type == LI_GROUP) {
            const kdbx_group *g = it->p;
            ap_draw_row(a, s, i, ICON_FOLDER, T->accent, g->name, NULL, 0);
        } else {
            const kdbx_entry *e = it->p;
            const char *icon = it->type == LI_FAV ? ICON_STAR : it->type == LI_RECENT ? ICON_CLOCK : ICON_KEY;
            ap_draw_row(a, s, i, icon, it->type == LI_ENTRY ? T->dim : T->accent, *e->title ? e->title : "(no title)",
                        e->username, T->dim);
        }
    }
    if (!a->nhits)
        ui_text(s, F, PAD * 2, CONTENT_Y + 8, a->scr == SCR_SEARCH ? "No match" : "Empty group", T->dim, UI_W);
    ap_draw_scrollbar(a, s, a->nhits);
    ap_draw_toast(a, s);
}

/* One-line message (saved, typed, errors) above the footer until the next key. */
void ap_draw_toast(app *a, ui_strip *s)
{
    if (!a->msg[0]) return;
    int w = ui_text_width(&ui_font_small, a->msg) + 8;
    if (w > UI_W - 2 * PAD) w = UI_W - 2 * PAD;
    int y = UI_H - FOOT_H - 14 + ap_toast_offset(a);          /* slides up from behind the footer */
    ui_fill(s, UI_W - w - PAD, y, w, 13, T->bar_bg);
    ui_text(s, &ui_font_small, UI_W - w - PAD + 4, y, a->msg, T->warn, w - 8);
}

/* Text box; cursor = byte offset or -1. Long text scrolls so the cursor stays visible. */
void ap_draw_field(app *a, ui_strip *s, int x, int y, int w, int fh, const char *text, bool masked, int cursor)
{

    ui_fill(s, x, y, w, fh, T->field_bg);
    ui_fill(s, x, y + fh - 2, w, 2, cursor >= 0 ? T->accent : T->dim);
    char shown[3 * 64 + 1];
    const char *t = text;
    int cpos = cursor;
    if (masked) {
        int n = 0, cn = 0;
        for (const char *p = text; *p && n < 64;) {
            if (p - text < cursor) cn++;
            ui_utf8_next(&p);
            n++;
        }
        shown[0] = 0;
        for (int i = 0; i < n; i++) strcat(shown, "\xE2\x80\xA2");
        t = shown;
        cpos = cursor >= 0 ? cn * 3 : -1;
    }
    /* scroll: drop leading characters until the cursor fits */
    int inner = w - 8;
    char head[512];
    while (cpos > 0) {
        int n = cpos < (int)sizeof head - 1 ? cpos : (int)sizeof head - 1;
        memcpy(head, t, (size_t)n);
        head[n] = 0;
        if (ui_text_width(F, head) <= inner - 4) break;
        const char *q = t;
        ui_utf8_next(&q);
        cpos -= (int)(q - t);
        t = q;
    }
    int tw = ui_text(s, F, x + 4, y + 3, t, T->fg, inner);
    if (cursor >= 0) {
        int n = cpos < (int)sizeof head - 1 ? cpos : (int)sizeof head - 1;
        memcpy(head, t, (size_t)n);
        head[n] = 0;
        int cx = x + 4 + ui_text_width(F, head);
        if (cx > x + 4 + tw) cx = x + 4 + tw;
        ui_fill(s, cx, y + 2, 2, F->height + 2, T->accent);
    }
    ap_wipe(shown, sizeof shown);
    ap_wipe(head, sizeof head);
}

static void draw_entry_row(app *a, ui_strip *s, int i, char *buf)
{
    const app_row *r = &a->rows[i];
    int y = CONTENT_Y + (i - a->top) * ap_row_h(a), h = ap_row_h(a);
    if (y + h <= s->y0 || y >= s->y0 + s->h) return;
    bool sel = i == a->sel, reveal = sel && a->revealed;
    ap_row_bg(a, s, y, h, i);
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
        snprintf(right, sizeof right, "%s %.0f bits", a->pw_bits >= a->cfg.weak_bits ? "Strong" : "Weak", a->pw_bits);
        rc = a->pw_bits >= a->cfg.weak_bits ? T->ok : T->warn;
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
        if (!valid) { val = "time not set"; vc = T->warn; break; }
        if (!ap_totp_now(a, a->entry, r->f, buf, REVEAL_MAX)) { val = "invalid TOTP settings"; vc = T->danger; break; }
        size_t cl = strlen(buf);
        if (cl == 6 || cl == 8) { /* 123 456 */
            memmove(buf + cl / 2 + 1, buf + cl / 2, cl / 2 + 1);
            buf[cl / 2] = ' ';
        }
        val = buf;
        int per = a->totp_period ? a->totp_period : 30, rem = per - (int)(now % per);
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
        ap_civil(a->entry->expiry, &yy, &mo, &d, &hh, &mi);
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
        ui_text(s, F, vx, ty, U_BULLETS, vc, maxw);
    } else if (masked) {
        if (kdbx_reveal(a->db, r->f, buf, REVEAL_MAX) == KDBX_OK) ui_text(s, F, vx, ty, buf, T->accent, maxw);
        else ui_text(s, F, vx, ty, "(too long to show)", T->dim, maxw);
        ap_wipe(buf, REVEAL_MAX);
    } else {
        ui_text(s, F, vx, ty, val, vc, maxw);
    }
}

static void draw_qr(app *a, ui_strip *s)
{
    const uint16_t white = 0xFFFF, black = 0; /* always black on white so phones can scan it */
    int n = qrcodegen_getSize(a->qr), scale = UI_H / (n + 4), oy = (UI_H - n * scale) / 2, ox = oy; /* >= 2-module quiet zone */
    ui_fill(s, 0, 0, UI_W, UI_H, white);
    for (int yy = 0; yy < n; yy++) {
        int py = oy + yy * scale;
        if (py + scale <= s->y0 || py >= s->y0 + s->h) continue;
        for (int xx = 0; xx < n; xx++)
            if (qrcodegen_getModule(a->qr, xx, yy)) ui_fill(s, ox + xx * scale, py, scale, scale, black);
    }
    int tx = ox + n * scale + 8;
    ui_text(s, &ui_font_small, tx, 20, a->qr_label, black, UI_W - tx - 2);
    ui_text(s, &ui_font_small, tx, UI_H - 28, "any key", RGB565(90, 90, 90), UI_W - tx - 2);
    ui_text(s, &ui_font_small, tx, UI_H - 15, "to close", RGB565(90, 90, 90), UI_W - tx - 2);
}

static void draw_unlock(app *a, ui_strip *s)
{
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    if (a->progress >= 0) { /* KDF running */
        ui_text(s, F, PAD * 2, CONTENT_Y + 24, "Unlocking\xE2\x80\xA6", T->fg, UI_W);
        int bw = UI_W - PAD * 4, by = CONTENT_Y + 50;
        ui_fill(s, PAD * 2, by, bw, 6, T->field_bg);
        ui_fill(s, PAD * 2, by, bw * a->progress / 100, 6, T->accent);
        return;
    }
    ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + 6, "Master password", T->dim, UI_W);
    int fy = CONTENT_Y + 20;
    ap_draw_field(a, s, PAD * 2, fy, UI_W - PAD * 4, F->height + 6, a->pw, true, a->pwlen);
    char kf[96];
    snprintf(kf, sizeof kf, "%s Key file: %s", ICON_FILE, a->keyfile ? a->keyfiles[a->keyfile - 1] : "none");
    ui_text(s, &ui_font_small, PAD * 2, fy + F->height + 12, kf, a->keyfile ? T->accent : T->dim, UI_W - PAD * 4);
    if (a->msg[0]) ui_text(s, F, PAD * 2, fy + F->height + 30, a->msg, T->danger, UI_W - PAD * 4);
}

void app_draw(app *a, ui_strip *s)
{
    char title[96];
    const char *hint = "";
    if (a->scr == SCR_QR) { draw_qr(a, s); return; }
    switch (a->scr) {
    case SCR_PICKER: snprintf(title, sizeof title, "CardPass"); break;
    case SCR_UNLOCK: snprintf(title, sizeof title, "Unlock %s", a->dbname); break;
    case SCR_GROUP: snprintf(title, sizeof title, "%s %s", ICON_FOLDER_OPEN, a->group->name); break;
    case SCR_ENTRY: snprintf(title, sizeof title, "%s %s", ICON_KEY, a->entry->title); break;
    case SCR_MENU: snprintf(title, sizeof title, "Menu"); break;
    case SCR_EDIT: snprintf(title, sizeof title, "Edit entry"); break;
    case SCR_GEN: snprintf(title, sizeof title, "Generator"); break;
    case SCR_SETTINGS: snprintf(title, sizeof title, "%s Settings", ICON_COG); break;
    case SCR_AUDIT: snprintf(title, sizeof title, "Password audit"); break;
    case SCR_EXPIRY: snprintf(title, sizeof title, "%s Expiring", ICON_CLOCK); break;
    case SCR_CREATE: snprintf(title, sizeof title, "New database"); break;
    case SCR_HELP: snprintf(title, sizeof title, "Keys"); break;
    case SCR_FIDO: snprintf(title, sizeof title, "%s Passkey", ICON_KEY); break;
    case SCR_DRIVE: snprintf(title, sizeof title, "%s USB drive", ICON_USB); break;
    case SCR_TIME: snprintf(title, sizeof title, "%s Time", ICON_CLOCK); break;
    case SCR_ACCOUNT: snprintf(title, sizeof title, "Change password"); break;
    case SCR_GROUPS: snprintf(title, sizeof title, "%s Groups", ICON_FOLDER_OPEN); break;
    case SCR_VIEW: snprintf(title, sizeof title, "%s %.40s", ICON_FILE, ap_view_name(a)); break;
    default: snprintf(title, sizeof title, "%s", a->db ? a->dbname : "CardPass");
    }
    if (s->y0 < BAR_H) ap_draw_bar(a, s, title);

    char *buf = malloc(REVEAL_MAX);
    if (!buf) return;
    switch (a->scr) {
    case SCR_PICKER:
        ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
        for (int i = a->top; i < a->ndbs && i < a->top + ap_visible(a); i++)
            ap_draw_row(a, s, i, ICON_LOCK, T->accent, a->dbs[i], NULL, 0);
        if (!a->ndbs) ui_text(s, F, PAD * 2, CONTENT_Y + 8, "No .kdbx files on the SD card", T->dim, UI_W);
        if (a->msg[0]) ui_text(s, &ui_font_small, PAD * 2, UI_H - FOOT_H - 13, a->msg, T->warn, UI_W);
        hint = U_UPDOWN " choose  " U_ENTER " open  tab menu";
        break;
    case SCR_UNLOCK:
        draw_unlock(a, s);
        hint = a->nkeyfiles ? U_ENTER " unlock  tab key file  fn+` back" : U_ENTER " unlock  fn+` back";
        break;
    case SCR_HOME:
    case SCR_GROUP:
        ap_draw_list(a, s);
        hint = "type to search  " U_ENTER " open  tab menu";
        break;
    case SCR_SEARCH: {
        ap_draw_list(a, s);
        snprintf(title, sizeof title, "%s %s", ICON_SEARCH, a->query);
        if (s->y0 < BAR_H) { /* query replaces the title */
            ui_fill(s, 0, 0, UI_W / 2 + 40, BAR_H, T->bar_bg);
            int w = ui_text(s, &ui_font_small, PAD, 1, title, T->accent, UI_W / 2 + 30);
            ui_fill(s, PAD + w + 1, 2, 1, 10, T->accent);
        }
        hint = U_UPDOWN " choose  " U_ENTER " open  fn+` clear";
        break;
    }
    case SCR_ENTRY:
        ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
        for (int i = a->top; i < a->nrows && i < a->top + ap_visible(a); i++) draw_entry_row(a, s, i, buf);
        ap_draw_scrollbar(a, s, a->nrows);
        ap_draw_toast(a, s);
        hint = U_ENTER " type  A auto  E edit  Q qr  ? keys";
        if (a->nrows && a->rows[a->sel].kind == R_TOTP) { /* the code needs the clock */
            bool valid;
            a->p->now(a->p->ctx, &valid);
            if (!valid) hint = "T set the time  ` back";
        }
        break;
    case SCR_MENU: ap_menu_draw(a, s, &hint); break;
    case SCR_EDIT: ap_edit_draw(a, s, &hint); break;
    case SCR_GEN: ap_gen_draw(a, s, &hint); break;
    case SCR_SETTINGS: ap_settings_draw(a, s, &hint); break;
    case SCR_AUDIT: case SCR_EXPIRY: ap_report_draw(a, s, &hint); break;
    case SCR_CONFIRM: ap_confirm_draw(a, s, &hint); break;
    case SCR_CREATE: ap_create_draw(a, s, &hint); break;
    case SCR_HELP: ap_help_draw(a, s, &hint); break;
    case SCR_FIDO: ap_fido_draw(a, s, &hint); break;
    case SCR_DRIVE: ap_drive_draw(a, s, &hint); break;
    case SCR_TIME: ap_time_draw(a, s, &hint); break;
    case SCR_ACCOUNT: ap_account_draw(a, s, &hint); break;
    case SCR_GROUPS: ap_groups_draw(a, s, &hint); break;
    case SCR_VIEW: ap_view_draw(a, s, &hint); break;
    }
    ap_wipe(buf, REVEAL_MAX);
    free(buf);
    if (s->y0 + s->h > UI_H - FOOT_H) ap_draw_footer(a, s, hint);
    ap_slide_apply(a, s);
}
