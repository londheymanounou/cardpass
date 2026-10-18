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

int ap_row_h(const app *a) { return F->height + 1; }
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
    a->query_prev[0] = 0;                                  /* the list is no longer search hits: never narrow over it */
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
    size_t pl = strlen(a->query_prev);
    bool narrow = a->scr == SCR_SEARCH && pl && !strncmp(a->query, a->query_prev, pl);   /* typed more: a subset */
    const kdbx_entry **among = narrow ? malloc(sizeof *among * (size_t)(a->nhits ? a->nhits : 1)) : NULL;
    if (among)
        for (int i = 0; i < a->nhits; i++) among[i] = ap_items(a)[i].p;
    int n = !h ? 0
          : among ? (int)search_run_among(a->db, a->query, a->recent, (size_t)a->nrecent, among, (size_t)a->nhits, h, (size_t)a->nentries)
                  : (int)search_run(a->db, a->query, a->recent, (size_t)a->nrecent, h, (size_t)a->nentries);
    free(among);
    snprintf(a->query_prev, sizeof a->query_prev, "%s", a->query);
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
    a->query_prev[0] = 0;
    if (a->hits) ap_wipe(a->hits, sizeof(list_item) * (size_t)a->list_cap), free(a->hits);
    a->hits = NULL;
    free(a->audit_bits);
    a->audit_bits = NULL;
}

bool ap_reindex(app *a)
{
    a->query_prev[0] = 0;                                  /* new index: old entry pointers are dead */
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
    if (a->wifi_fetch.ssid[0]) { ap_wifi_fetch_done(a, e); return; }   /* browsing only to pick the Wi-Fi password's entry */
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
}

void app_lock(app *a)
{
    ap_bt_off(a);                                    /* a locked device must not stay discoverable */
    kdbx_close(a->db);
    a->db = NULL;
    ap_vc_close(a);                                  /* a mounted VeraCrypt container too: its keys are wiped */
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
    ap_wipe(a->query_prev, sizeof a->query_prev);
    ap_wipe(a->recent, sizeof a->recent);
    ap_wipe(a->rows, sizeof a->rows);
    ap_wipe(a->qr, sizeof a->qr);
    a->pwlen = a->qlen = a->nrecent = a->nrows = 0;
    a->entry = NULL;
    a->group = NULL;
    a->revealed = false;
    a->progress = -1;
    a->progress_t0 = 0;
    ap_rescan_files(a);
    a->keyrel[0] = 0;
    ap_browse_free(a);
    a->pw_show = false;
    a->scr = SCR_PICKER;
    a->sel = a->top = 0;
    for (int i = 0; i < a->ndbs; i++) /* preselect the last database */
        if (!strcmp(a->dbs[i], a->cfg.last_db)) a->sel = i;
    ap_mark_all(a);
}

void ap_progress_end(app *a)
{
    a->progress = -1;
    a->progress_t0 = 0;
}

static void mmss(char *out, size_t n, uint32_t ms)
{
    uint32_t s = (ms + 500) / 1000;
    if (s >= 3600) snprintf(out, n, "%u:%02u:%02u", (unsigned)(s / 3600), (unsigned)(s / 60 % 60), (unsigned)(s % 60));
    else snprintf(out, n, "%u:%02u", (unsigned)(s / 60), (unsigned)(s % 60));
}

/* Percentage, bar, elapsed time and an estimate of the time left. The clock is the time of the last update, so
 * redrawing the same state always gives the same picture. */
void ap_draw_progress(app *a, ui_strip *s, const char *title)
{
    int pct = a->progress < 0 ? 0 : a->progress > 100 ? 100 : a->progress;
    char num[8], t1[16], t2[16], line[64];
    snprintf(num, sizeof num, "%d%%", pct);
    int nw = ui_text_width(F, num);
    ui_text(s, F, PAD * 2, CONTENT_Y + 12, pct >= 100 ? "Almost done" "\xE2\x80\xA6" : title, T->fg, UI_W - PAD * 4 - nw - 6);
    ui_text(s, F, UI_W - PAD * 2 - nw, CONTENT_Y + 12, num, T->accent, nw + 2);
    int bw = UI_W - PAD * 4, by = CONTENT_Y + 40;
    ui_round(s, PAD * 2, by, bw, 8, 8, T->field_bg);                 /* capsules */
    if (pct) ui_round(s, PAD * 2, by, bw * pct / 100 < 8 ? 8 : bw * pct / 100, 8, 8, T->accent);
    uint32_t el = a->progress_t0 ? a->progress_ms - a->progress_t0 : 0;
    mmss(t1, sizeof t1, el);
    if (pct >= 4 && pct < 100) {
        mmss(t2, sizeof t2, (uint32_t)((uint64_t)el * (uint32_t)(100 - pct) / (uint32_t)pct));
        snprintf(line, sizeof line, "%s elapsed, about %s left", t1, t2);
    } else {
        snprintf(line, sizeof line, pct >= 100 ? "%s elapsed" : "%s elapsed, estimating" "\xE2\x80\xA6", t1);
    }
    ui_text(s, &ui_font_small, PAD * 2, by + 16, line, T->dim, UI_W - PAD * 4);
    ui_text(s, &ui_font_small, PAD * 2, by + 34, "Key derivation is slow on purpose.", T->dim, UI_W - PAD * 4);
    ui_text(s, &ui_font_small, PAD * 2, by + 46, "Keep the device powered.", T->dim, UI_W - PAD * 4);
    if (!kdbx_kdf_accel_active()) ui_text(s, &ui_font_small, PAD * 2, by + 58, "Hardware AES off: slower.", T->warn, UI_W - PAD * 4);
}

void ap_kdf_progress(void *ctx, int pct)
{
    app *a = ctx;
    uint32_t now = a->p->millis(a->p->ctx);
    if (!a->progress_t0) a->progress_t0 = now ? now : 1;
    a->progress_ms = now;
    if (pct == a->progress) return;
    a->progress = pct;
    ap_mark(a, CONTENT_Y, UI_H - FOOT_H);
    a->p->present(a->p->ctx);
}

static void unlock(app *a)
{
    if (a->vc_pending) { ap_vc_unlock(a); return; }       /* the unlock screen is asking for a container's password */
    kdbx_key k;
    FILE *kf = NULL;
    char kpath[256];
    if (a->keyrel[0]) {
        a->p->root_path(a->p->ctx, a->keyrel, kpath, sizeof kpath);
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
    ap_progress_end(a);
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
    if (!a->vc_open && strcmp(a->cfg.last_db, a->dbname)) {   /* not for a database inside a container: the settings file is plain text */
        snprintf(a->cfg.last_db, sizeof a->cfg.last_db, "%s", a->dbname);
        ap_apply_settings(a);
    }
    a->msg[0] = 0;
    a->from_browse = false;
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
    case SCR_UNLOCK:
        ap_wipe(a->pw, sizeof a->pw);
        a->pwlen = 0;
        a->msg[0] = 0;
        a->vc_pending = false;
        if (a->from_browse) { a->from_browse = false; ap_browse_open_db(a, true); return; }   /* back to the folder */
        a->scr = SCR_PICKER;
        break;
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
    if (a->pw_show_scr != (int)a->scr) a->pw_show = false, a->pw_show_scr = (int)a->scr;   /* hidden again on every new screen */
    ap_anim_key(a);
    if (a->power) {                               /* any key wakes; a key that woke a dark screen does nothing else */
        bool was_off = a->power == 2;
        set_power(a, 0);
        if (was_off) return;
    }
    if (a->wifi_fetch.ssid[0] && a->scr != SCR_PICKER && a->scr != SCR_UNLOCK && a->scr != SCR_BROWSE && a->scr != SCR_HOME &&
        a->scr != SCR_GROUP && a->scr != SCR_SEARCH)
        memset(&a->wifi_fetch, 0, sizeof a->wifi_fetch);   /* left the fetch (menu, drive, ...): the next unlock is a normal one */
    if (a->wifi_fetch.ssid[0] && a->scr == SCR_HOME && a->db && down && (k == K_ESC || k == '`')) {   /* give up: lock, back to the password */
        app_ap ap = a->wifi_fetch;
        memset(&a->wifi_fetch, 0, sizeof a->wifi_fetch);
        app_lock(a);
        ap_wifi_password(a, &ap);
        return;
    }

    if (a->scr == SCR_ENTRY && (k == 'r' || k == 'R') && !fn) {
        bool r = !a->cfg.reveal_toggle ? down : (down ? !a->revealed : a->revealed);
        if (r != a->revealed) a->revealed = r, ap_mark_all(a);
        return;
    }
    if (a->scr == SCR_ENTRY && (k == 'e' || k == 'E') && fn) {   /* fn+E: the same eye as on password fields, always a toggle */
        if (down) a->revealed = !a->revealed, ap_mark_all(a);
        return;
    }
    if (a->scr == SCR_SPLASH) { if (down) ap_splash_leave(a); return; }   /* any key skips the splash */
    if (!down) return;
    if (fn && (k == 'e' || k == 'E') && (a->scr == SCR_UNLOCK || a->scr == SCR_ACCOUNT || a->scr == SCR_CREATE || a->scr == SCR_TIME)) {
        a->pw_show = !a->pw_show;                                      /* the eye next to a password field */
        ap_mark_all(a);
        return;
    }
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
        if (a->wifi_fetch.ssid[0] && (k == K_ESC || k == '`')) {   /* give up on the database: back to the password */
            app_ap ap = a->wifi_fetch;
            memset(&a->wifi_fetch, 0, sizeof a->wifi_fetch);
            ap_wifi_password(a, &ap);
            break;
        }
        if (k == K_UP) ap_move_sel(a, a->ndbs + 1, -1);                 /* the last row browses the whole card */
        else if (k == K_DOWN) ap_move_sel(a, a->ndbs + 1, 1);
        else if (k == K_ENTER && a->sel == a->ndbs) ap_browse_open_db(a, false);
        else if (k == K_ENTER) {
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
        else if (k == K_TAB && a->vc_pending) a->vc_write = !a->vc_write, ap_mark_all(a);
        else if (k == K_TAB) ap_browse_open(a);
        else if (k == K_BACKSPACE && fn) a->keyrel[0] = 0, ap_mark_all(a);   /* fn+Backspace: no key file */
        else if (k == K_BACKSPACE) ap_utf8_backspace(a->pw, &a->pwlen), ap_mark_all(a);
        else if (ap_printable(k) && !fn) ap_utf8_append(a->pw, &a->pwlen, sizeof a->pw, k), a->msg[0] = 0, ap_mark_all(a);
        break;
    case SCR_HOME:
    case SCR_GROUP:
    case SCR_SEARCH:
        if (a->msg[0]) a->msg[0] = 0, ap_mark(a, UI_H - FOOT_H - TOAST_H, UI_H - FOOT_H);
        if (k == K_UP) ap_move_sel(a, a->nhits, -1);
        else if (k == K_DOWN) ap_move_sel(a, a->nhits, 1);
        else if (k == K_ENTER && a->nhits) open_item(a, &ap_items(a)[a->sel]);
        else if (k == K_ESC || (k == '`' && a->scr != SCR_SEARCH)) go_back(a);
        else if (k == K_BACKSPACE && a->scr == SCR_SEARCH) {
            ap_utf8_backspace(a->query, &a->qlen);
            if (!a->qlen) go_back(a);
            else ap_build_search(a), ap_mark_all(a);
        } else if (ap_printable(k) && !fn && (k != ' ' || a->scr == SCR_SEARCH)) {
            if (a->scr != SCR_SEARCH) a->scr = SCR_SEARCH, a->qlen = 0, a->query[0] = 0, a->query_prev[0] = 0;
            ap_utf8_append(a->query, &a->qlen, sizeof a->query, k);
            ap_build_search(a);
            ap_mark_all(a);
        }
        break;
    case SCR_ENTRY:
        a->msg[0] = 0;
        ap_mark(a, UI_H - FOOT_H - TOAST_H, UI_H);
        if (k == K_UP) { a->revealed = false; ap_move_sel(a, a->nrows, -1); ap_mark_all(a); }
        else if (k == K_DOWN) { a->revealed = false; ap_move_sel(a, a->nrows, 1); ap_mark_all(a); }
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
    case SCR_BT: ap_bt_key(a, k, fn); break;
    case SCR_BROWSE: ap_browse_key(a, k, fn); break;
    }
}

void app_tick(app *a, uint32_t now_ms)
{
    uint32_t prev = a->now_ms;
    a->now_ms = now_ms;
    ap_splash_tick(a, now_ms);
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
    if ((a->db || a->vc_open) && lock_ms && !a->fido_active && now_ms - a->last_input_ms > lock_ms) {
        app_lock(a);
        snprintf(a->msg, sizeof a->msg, "Locked after inactivity");
        return;
    }
    ap_anim_tick(a, now_ms);
    ap_bt_tick(a, now_ms);
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
    a->theme = &ui_themes[cfg->theme & 3];
    a->font = cfg->large_font ? &ui_font_large : &ui_font_body;
    app_lock(a);
    a->msg[0] = 0;
    if (cfg->splash) { a->scr = SCR_SPLASH; ap_mark_all(a); }
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

/* Right-aligned status item ending at x; returns its left edge minus the gap to the next item. */
static int bar_item(ui_strip *s, int x, const char *t, uint16_t c)
{
    int w = ui_text_width(&ui_font_small, t);
    ui_text(s, &ui_font_small, x - w, 0, t, c, w);
    return x - w - BAR_GAP;
}

/* Bio-Resonant status bar: raised surface, full-width subtle hairline, secondary-ink caption items, right to left:
 * lock state, battery (a capsule meter that fills with the charge), clock, Bluetooth. Colour only to signal. */
int ap_draw_bar(app *a, ui_strip *s, const char *title)
{
    ui_fill(s, 0, 0, UI_W, BAR_H - 2, T->raised);
    ui_fill(s, 0, BAR_H - 2, UI_W, UI_STROKE, T->faint);
    ui_fill(s, 0, BAR_H - 1, UI_W, 1, T->bg);                           /* air between the hairline and a selected row */
    int x = bar_item(s, UI_W - PAD, a->db ? ICON_UNLOCK : ICON_LOCK, a->db ? T->accent : T->dim);
    int bat = a->p->battery(a->p->ctx);
    if (bat >= 0) {
        uint16_t c = bat <= 10 ? T->danger : bat <= 20 ? T->warn : T->dim;
        x -= 2;                                                          /* the nub */
        ui_fill(s, x, 7, 2, 4, c);
        x -= 15;
        ui_round_ring(s, x, 5, 15, 8, 3, UI_STROKE, c, T->raised);
        ui_round(s, x + 2, 7, (11 * bat + 99) / 100, 4, 1, c);            /* any charge shows at least 1 px */
        char t[16];   /* room for any int: IDF builds with -Werror=format-truncation */
        snprintf(t, sizeof t, "%d%%", bat);
        x = bar_item(s, x - 3, t, c);
    }
    bool valid;
    int64_t now = a->p->now(a->p->ctx, &valid);
    if (valid && a->cfg.bar_clock) {
        int y, mo, d, h, mi;
        char t[16];   /* room for any int: IDF builds with -Werror=format-truncation */
        ap_civil(now + a->cfg.tz_minutes * 60, &y, &mo, &d, &h, &mi);
        snprintf(t, sizeof t, "%02d:%02d", h, mi);
        x = bar_item(s, x, t, T->dim);
    }
    if (a->bt_on) x = bar_item(s, x, ICON_BLUETOOTH, T->accent);
    ui_text(s, &ui_font_title, PAD, 0, title, T->bar_fg, x - PAD);
    return x;
}

void ap_draw_footer(app *a, ui_strip *s, const char *hint)
{
    ui_fill(s, 0, UI_H - FOOT_H, UI_W, FOOT_H, T->bg);
    ui_text(s, &ui_font_small, PAD, UI_H - FOOT_H - 1, hint, T->dim, UI_W - 2 * PAD);
}

/* One list row: icon, text, dim right-aligned note. */
void ap_draw_row(app *a, ui_strip *s, int i, const char *icon, uint16_t icon_c, const char *text, const char *right,
                 uint16_t right_c)
{
    int y = CONTENT_Y + (i - a->top) * ap_row_h(a), h = ap_row_h(a);
    if (y + h <= s->y0 || y >= s->y0 + s->h) return;
    bool sel = i == a->sel;
    ap_row_bg(a, s, y, h, i);
    int ty = y + (h - F->height) / 2, x = ROW_X0;
    if (icon) x += ui_text(s, F, x, ty, icon, icon_c, 16) + 4;
    int rw = right && *right ? ui_text_width(&ui_font_small, right) : 0;
    ui_text(s, F, x, ty, text, sel ? T->sel_fg : T->fg, ROW_X1 - x - (rw ? rw + 6 : 0));
    if (rw) ui_text(s, &ui_font_small, ROW_X1 - rw, y + (h - ui_font_small.height) / 2, right, right_c, rw);
}

void ap_draw_scrollbar_in(app *a, ui_strip *s, int top, int n)
{
    int vis = ap_visible(a);
    if (n <= vis) return;
    int h = CONTENT_H * vis / n, y = CONTENT_Y + (CONTENT_H - h) * top / (n - vis);
    ui_round(s, UI_W - 3, CONTENT_Y + 1, 2, CONTENT_H - 2, 1, T->field_bg);
    ui_round(s, UI_W - 3, y, 2, h < 6 ? 6 : h, 1, T->accent);
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
    int w = ui_text_width(&ui_font_small, a->msg) + 14;
    if (w > UI_W - 2 * PAD) w = UI_W - 2 * PAD;
    int y = UI_H - FOOT_H - TOAST_H + ap_toast_offset(a);     /* slides up from behind the footer */
    ui_round_ring(s, UI_W - w - PAD, y, w, TOAST_H - 1, UI_RADIUS_SM, UI_STROKE, T->faint, T->overlay);
    ui_text(s, &ui_font_small, UI_W - w - PAD + 7, y + 1, a->msg, T->fg, w - 14);
}

/* Text box; cursor = byte offset or -1. Long text scrolls so the cursor stays visible. */
void ap_draw_field(app *a, ui_strip *s, int x, int y, int w, int fh, const char *text, bool masked, int cursor)
{

    if (cursor >= 0) ui_round_ring(s, x, y, w, fh, UI_RADIUS_XS, UI_STROKE, T->focus, T->field_bg);
    else ui_round(s, x, y, w, fh, UI_RADIUS_XS, T->field_bg);
    bool eye = masked && cursor >= 0;                    /* an active password field has the eye (fn+E) */
    if (eye) ui_text(s, F, x + w - 14, y + 3, a->pw_show ? ICON_EYE_OFF : ICON_EYE, a->pw_show ? T->accent : T->dim, 14);
    if (masked && a->pw_show) masked = false;
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
    int inner = w - 8 - (eye ? 14 : 0);
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
    int ty = y + (h - F->height) / 2, sy = y + (h - ui_font_small.height) / 2, vx = PAD + LABEL_W, vw = ROW_X1 - vx;
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
    if (masked && reveal) right[0] = 0;                 /* the whole row width is for the secret */
    ui_text(s, &ui_font_small, ROW_X0, sy, label, T->dim, LABEL_W - 8);
    int rw = right[0] ? ui_text_width(&ui_font_small, right) : 0;
    if (rw) ui_text(s, &ui_font_small, ROW_X1 - rw, sy - (r->kind == R_TOTP ? 1 : 0), right, rc, rw);
    int maxw = vw - (rw ? rw + 6 : 0);
    if (masked && !reveal) {
        ui_text(s, F, vx, ty, U_BULLETS, vc, maxw);
    } else if (masked) {
        if (kdbx_reveal(a->db, r->f, buf, REVEAL_MAX) == KDBX_OK) {
            const ui_font *rf = ui_text_width(F, buf) <= maxw ? F : &ui_font_small;
            ui_text(s, rf, vx, y + (h - rf->height) / 2, buf, T->accent, maxw);
        }
        else ui_text(s, F, vx, ty, "(too long to show)", T->dim, maxw);
        ap_wipe(buf, REVEAL_MAX);
    } else {
        ui_text(s, F, vx, ty, val, vc, maxw);
    }
}

/* A revealed secret too wide for one row even in the small font gets the whole content area, wrapped. */
static bool reveal_masked(const app_row *r)
{
    if (!r->f) return false;
    return (r->kind == R_PASS && r->f->len) || ((r->kind == R_USER || r->kind == R_FIELD) && r->f->stream_off != KDBX_PLAIN);
}

static bool reveal_needs_panel(app *a, char *buf)
{
    if (!a->revealed || !a->nrows || !reveal_masked(&a->rows[a->sel])) return false;
    bool need = kdbx_reveal(a->db, a->rows[a->sel].f, buf, REVEAL_MAX) == KDBX_OK &&
                ui_text_width(&ui_font_small, buf) > UI_W - PAD - (PAD + LABEL_W);
    ap_wipe(buf, REVEAL_MAX);
    return need;
}

static void draw_reveal_panel(app *a, ui_strip *s, char *buf)
{
    const app_row *r = &a->rows[a->sel];
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    ui_text(s, &ui_font_small, PAD + 2, CONTENT_Y + 2, r->kind == R_PASS ? "Pass" : r->kind == R_USER ? "User" : r->f->key, T->dim, UI_W - 2 * PAD);
    if (kdbx_reveal(a->db, r->f, buf, REVEAL_MAX) == KDBX_OK) {
        const int w = UI_W - 2 * PAD, top = CONTENT_Y + 14;
        const ui_font *f = F;
        size_t total = strlen(buf), off = 0;
        int n = 0, room = (UI_H - FOOT_H - top) / (f->height + 1);
        while (off < total && n <= room) {
            size_t k = ui_wrap(f, buf + off, w);
            off += k ? k : 1;
            n++;
        }
        if (n > room) f = &ui_font_small;                 /* long: smaller font, more lines */
        char line[256];
        int y = top;
        for (off = 0; off < total && y + f->height <= UI_H - FOOT_H; y += f->height + 1) {
            size_t k = ui_wrap(f, buf + off, w);
            if (!k) k = 1;
            if (k > sizeof line - 1) k = sizeof line - 1;
            memcpy(line, buf + off, k);
            line[k] = 0;
            ui_text(s, f, PAD, y, line, T->accent, w);
            off += k;
        }
        ap_wipe(line, sizeof line);
    } else {
        ui_text(s, F, PAD, CONTENT_Y + 16, "(too long to show)", T->dim, UI_W - 2 * PAD);
    }
    ap_wipe(buf, REVEAL_MAX);
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
    if (a->progress >= 0) { ap_draw_progress(a, s, "Unlocking" "\xE2\x80\xA6"); return; }
    ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + 1, a->vc_pending ? "VeraCrypt container password" : "Master password", T->dim, UI_W);
    int fy = CONTENT_Y + 19;
    ap_draw_field(a, s, PAD * 2, fy, UI_W - PAD * 4, F->height + 6, a->pw, true, a->pwlen);
    char kf[192];
    snprintf(kf, sizeof kf, "%s Key file: %s", ICON_FILE, a->keyrel[0] ? a->keyrel : "none");
    if (a->vc_pending) {
        ui_text(s, &ui_font_small, PAD * 2, fy + F->height + 9, a->vc_write ? "Saving on (risks a hidden volume)" : "Saving off (tab: allow saving)",
                a->vc_write ? T->warn : T->dim, UI_W - PAD * 4);
    } else {
        ui_text(s, &ui_font_small, PAD * 2, fy + F->height + 9, kf, a->keyrel[0] ? T->accent : T->dim, UI_W - PAD * 4);
    }
    if (a->msg[0]) ui_text(s, F, PAD * 2, fy + F->height + 28, a->msg, T->danger, UI_W - PAD * 4);
}

void app_draw(app *a, ui_strip *s)
{
    ui_set_on_fill(T->sel_bg, T->sel_fg);
    char title[96];
    const char *hint = "";
    if (a->scr == SCR_QR) { draw_qr(a, s); return; }
    if (a->scr == SCR_SPLASH) { ap_splash_draw(a, s); return; }
    switch (a->scr) {
    case SCR_PICKER:
        if (a->wifi_fetch.ssid[0]) snprintf(title, sizeof title, "%s %.32s", ICON_WIFI, a->wifi_fetch.ssid);
        else snprintf(title, sizeof title, "CardPass");
        break;
    case SCR_UNLOCK:
        if (a->wifi_fetch.ssid[0]) snprintf(title, sizeof title, "%s %.32s", ICON_WIFI, a->wifi_fetch.ssid);
        else snprintf(title, sizeof title, "Unlock %s", a->dbname);
        break;
    case SCR_HOME:
        if (a->wifi_fetch.ssid[0]) { snprintf(title, sizeof title, "%s %.32s", ICON_WIFI, a->wifi_fetch.ssid); break; }
        snprintf(title, sizeof title, "%s", a->db ? a->dbname : "CardPass");
        break;
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
    case SCR_BT: snprintf(title, sizeof title, "%s Bluetooth", ICON_BLUETOOTH); break;
    case SCR_BROWSE:
        if (!a->br_mode) snprintf(title, sizeof title, "%s Key file /%.60s", ICON_FOLDER_OPEN, a->br_dir);
        else if (!strncmp(a->br_dir, VC_ROOT, strlen(VC_ROOT))) snprintf(title, sizeof title, "%s Container%.60s", ICON_FOLDER_OPEN, a->br_dir + strlen(VC_ROOT));
        else snprintf(title, sizeof title, "%s Open /%.60s", ICON_FOLDER_OPEN, a->br_dir);
        break;
    case SCR_GROUPS: snprintf(title, sizeof title, "%s Groups", ICON_FOLDER_OPEN); break;
    case SCR_VIEW: snprintf(title, sizeof title, "%s %.40s", ICON_FILE, ap_view_name(a)); break;
    default: snprintf(title, sizeof title, "%s", a->db ? a->dbname : "CardPass");
    }
    int bar_x = s->y0 < BAR_H ? ap_draw_bar(a, s, title) : 0;

    char *buf = malloc(REVEAL_MAX);
    if (!buf) return;
    switch (a->scr) {
    case SCR_PICKER:
        ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
        for (int i = a->top; i <= a->ndbs && i < a->top + ap_visible(a); i++) {
            if (i < a->ndbs) ap_draw_row(a, s, i, ICON_LOCK, T->accent, a->dbs[i], NULL, 0);
            else ap_draw_row(a, s, i, ICON_FOLDER, T->accent, "Browse SD card", NULL, 0);
        }
        if (!a->ndbs) ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + ap_row_h(a) + 6, "No .kdbx in the CardPass folder", T->dim, UI_W);
        if (a->msg[0]) ui_text(s, &ui_font_small, PAD * 2, UI_H - FOOT_H - 17, a->msg, T->warn, UI_W);
        hint = a->wifi_fetch.ssid[0] ? U_UPDOWN " choose  " U_ENTER " open  ` cancel" : U_UPDOWN " choose  " U_ENTER " open  tab menu";
        break;
    case SCR_UNLOCK:
        draw_unlock(a, s);
        hint = a->progress >= 0 ? "" : a->vc_pending ? U_ENTER " ok  tab saving  fn+E eye  fn+` back" : U_ENTER " ok  tab file  fn+E eye  fn+` back";
        break;
    case SCR_HOME:
    case SCR_GROUP:
        ap_draw_list(a, s);
        hint = a->wifi_fetch.ssid[0] ? U_UPDOWN " pick the entry  " U_ENTER " use  ` cancel" : "type to search  " U_ENTER " open  tab menu";
        break;
    case SCR_SEARCH: {
        ap_draw_list(a, s);
        snprintf(title, sizeof title, "%s %s", ICON_SEARCH, a->query);
        if (s->y0 < BAR_H) { /* query replaces the title */
            ui_fill(s, 0, 0, bar_x, BAR_H - 2, T->raised);
            int w = ui_text(s, &ui_font_small, PAD, 1, title, T->accent, bar_x - PAD - 2);
            ui_fill(s, PAD + w + 1, 2, 1, 10, T->accent);
        }
        hint = U_UPDOWN " choose  " U_ENTER " open  fn+` clear";
        break;
    }
    case SCR_ENTRY:
        if (reveal_needs_panel(a, buf)) draw_reveal_panel(a, s, buf);
        else {
            ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
            for (int i = a->top; i < a->nrows && i < a->top + ap_visible(a); i++) draw_entry_row(a, s, i, buf);
            ap_draw_scrollbar(a, s, a->nrows);
        }
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
    case SCR_BT: ap_bt_draw(a, s, &hint); break;
    case SCR_BROWSE: ap_browse_draw(a, s, &hint); break;
    }
    ap_wipe(buf, REVEAL_MAX);
    free(buf);
    if (s->y0 + s->h > UI_H - FOOT_H) ap_draw_footer(a, s, hint);
    ap_slide_apply(a, s);
}
