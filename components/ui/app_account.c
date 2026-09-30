/* Change the master password / key file / unlock time of the open database.
 * The current password is asked again and verified against the file first (KDF + header HMAC).
 * After a successful change the old backup (name.kdbx.bak) is deleted: it still opens with the OLD
 * password, which is exactly what a password change is meant to get rid of. */
#include "app_priv.h"

enum { A_CUR, A_NEW, A_NEW2, A_KEYFILE, A_TIME, A_APPLY, A_COUNT };
enum { KF_NONE, KF_KEEP, KF_NEW };

struct app_acct {
    char cur[128], pw[128], pw2[128];
    int kf;          /* KF_* */
    int seconds;     /* 0 = keep the current rounds */
    bool editing;
};

void ap_account_free(app *a)
{
    if (!a->acct) return;
    ap_wipe(a->acct, sizeof *a->acct);       /* holds typed passwords */
    free(a->acct);
    a->acct = NULL;
}

void ap_account_open(app *a)
{
    ap_account_free(a);
    if (!(a->acct = calloc(1, sizeof *a->acct))) return;
    a->acct->kf = a->keyfile ? KF_KEEP : KF_NONE;
    a->scr = SCR_ACCOUNT;
    a->sel = a->top = 0;
    a->msg[0] = 0;
    ap_mark_all(a);
}

static char *buf_of(struct app_acct *c, int row, int *cap)
{
    *cap = (int)sizeof c->cur;
    return row == A_CUR ? c->cur : row == A_NEW ? c->pw : row == A_NEW2 ? c->pw2 : NULL;
}

/* Composite key from a password (may be empty) and an optional key file. */
static kdbx_err make_key(kdbx_key *k, const char *pw, const char *keyfile_path)
{
    FILE *kf = keyfile_path ? fopen(keyfile_path, "rb") : NULL;
    if (keyfile_path && !kf) return KDBX_ERR_KEYFILE;
    kdbx_err e = kdbx_key_init(k, pw[0] || !kf ? pw : NULL, strlen(pw), kf);
    if (kf) fclose(kf);
    return e;
}

static void apply(app *a)
{
    struct app_acct *c = a->acct;
    char kpath[256], newkf[256], file[80];
    kdbx_key cur, nk;
    if (strcmp(c->pw, c->pw2)) { snprintf(a->msg, sizeof a->msg, "New passwords differ"); return; }
    if (!c->pw[0] && c->kf == KF_NONE) { snprintf(a->msg, sizeof a->msg, "Set a password or a key file"); return; }
    if (c->kf == KF_KEEP && !a->keyfile) c->kf = KF_NONE;

    /* 1. the current credentials must open the file */
    if (a->keyfile) a->p->path(a->p->ctx, a->keyfiles[a->keyfile - 1], kpath, sizeof kpath);
    kdbx_err e = make_key(&cur, c->cur, a->keyfile ? kpath : NULL);
    if (!e) {
        FILE *f = fopen(a->path, "rb");
        a->progress = 0;
        kdbx_set_progress(ap_kdf_progress, a);
        e = f ? kdbx_check_key(f, &cur) : KDBX_ERR_IO;
        kdbx_set_progress(NULL, NULL);
        ap_progress_end(a);
        if (f) fclose(f);
    }
    kdbx_key_wipe(&cur);
    if (e) { snprintf(a->msg, sizeof a->msg, e == KDBX_ERR_KEY ? "Current password is wrong" : "%s", e == KDBX_ERR_KEY ? "" : kdbx_strerror(e)); ap_mark_all(a); return; }

    /* 2. the new key file */
    const char *nkp = NULL;
    if (c->kf == KF_KEEP) nkp = kpath;
    else if (c->kf == KF_NEW) {
        size_t n = strlen(a->dbname);
        if (n > 5 && !strcmp(a->dbname + n - 5, ".kdbx")) n -= 5;                          /* name.kdbx -> name.keyx */
        snprintf(file, sizeof file, "%.*s.keyx", (int)n, a->dbname);
        a->p->path(a->p->ctx, file, newkf, sizeof newkf);
        FILE *t = fopen(newkf, "rb");
        if (t) { fclose(t); snprintf(a->msg, sizeof a->msg, "%.40s already exists", file); return; }
        FILE *w = fopen(newkf, "wb");
        if (!w || kdbx_keyfile_create(w)) { if (w) fclose(w); remove(newkf); snprintf(a->msg, sizeof a->msg, "Can't write the key file"); return; }
        fclose(w);
        nkp = newkf;
    }
    if ((e = make_key(&nk, c->pw, nkp)) != KDBX_OK) { snprintf(a->msg, sizeof a->msg, "%s", kdbx_strerror(e)); return; }

    /* 3. rewrite the file with the new key (new KDF seed, optionally new rounds) */
    uint64_t rounds = c->seconds ? ap_benchmark_rounds(a, c->seconds) : 0;
    bool ok = ap_save_ex(a, NULL, 0, &nk, rounds);
    kdbx_key_wipe(&nk);
    if (!ok) { if (c->kf == KF_NEW) remove(newkf); return; }      /* ap_save_ex set the message */

    char bak[300];
    snprintf(bak, sizeof bak, "%s.bak", a->path);
    remove(bak);                                                  /* still opens with the old password */
    ap_rescan_files(a);
    a->keyfile = 0;
    if (nkp) {
        const char *base = strrchr(nkp, '/') ? strrchr(nkp, '/') + 1 : nkp;
        for (int i = 0; i < a->nkeyfiles; i++) if (!strcmp(a->keyfiles[i], base)) a->keyfile = i + 1;
    }
    ap_account_free(a);
    ap_go_home(a);
    snprintf(a->msg, sizeof a->msg, "Password changed. Old backup removed");
}

void ap_account_key(app *a, uint32_t k, bool fn)
{
    struct app_acct *c = a->acct;
    if (!c) return;
    ap_mark_all(a);
    int cap;
    char *b = buf_of(c, a->sel, &cap);
    if (c->editing && b) {
        int len = (int)strlen(b);
        if (k == K_ENTER) c->editing = false, ap_move_sel(a, A_COUNT, 1);
        else if (k == K_ESC) c->editing = false;
        else if (k == K_BACKSPACE) ap_utf8_backspace(b, &len);
        else if (ap_printable(k) && !fn) ap_utf8_append(b, &len, cap, k);
        return;
    }
    a->msg[0] = 0;
    if (k == K_UP) ap_move_sel(a, A_COUNT, -1);
    else if (k == K_DOWN) ap_move_sel(a, A_COUNT, 1);
    else if (k == '`' || k == K_ESC) { ap_account_free(a); ap_go_home(a); }
    else if (b && (k == K_ENTER || ap_printable(k))) {
        c->editing = true;
        if (k != K_ENTER && !fn) { int len = (int)strlen(b); ap_utf8_append(b, &len, cap, k); }
    } else if (a->sel == A_KEYFILE && (k == K_ENTER || k == K_LEFT || k == K_RIGHT)) {
        int n = a->keyfile ? 3 : 2, d = k == K_LEFT ? n - 1 : 1;    /* KEEP only exists if a key file is in use */
        static const int order3[] = {KF_NONE, KF_KEEP, KF_NEW}, order2[] = {KF_NONE, KF_NEW};
        const int *o = a->keyfile ? order3 : order2;
        int i = 0;
        while (i < n && o[i] != c->kf) i++;
        c->kf = o[(i + d) % n];
    } else if (a->sel == A_TIME && (k == K_ENTER || k == K_LEFT || k == K_RIGHT)) {
        static const int t[] = {0, 1, 2, 3, 5};
        int i = 0;
        while (i < 5 && t[i] != c->seconds) i++;
        c->seconds = t[(i + (k == K_LEFT ? 4 : 1)) % 5];
    } else if (a->sel == A_APPLY && k == K_ENTER) apply(a);
}

void ap_account_draw(app *a, ui_strip *s, const char **hint)
{
    struct app_acct *c = a->acct;
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    if (!c) return;
    if (a->progress >= 0) { ap_draw_progress(a, s, "Working" "\xE2\x80\xA6"); return; }
    static const char *const names[] = {"Current", "New", "Repeat", "Key file", "Unlock in", ""};
    for (int i = a->top; i < A_COUNT && i < a->top + ap_visible(a); i++) {
        int y = CONTENT_Y + (i - a->top) * ap_row_h(a), h = ap_row_h(a);
        if (y + h <= s->y0 || y >= s->y0 + s->h) continue;
        bool sel = i == a->sel;
        if (i == A_APPLY) { ap_draw_row(a, s, i, ICON_CHECK, T->ok, "Change password", NULL, 0); continue; }
        ap_row_bg(a, s, y, h, i);
        ui_text(s, &ui_font_small, PAD + 2, y + (h - ui_font_small.height) / 2, names[i], T->dim, 60);
        char v[64];
        const char *b = i == A_CUR ? c->cur : i == A_NEW ? c->pw : i == A_NEW2 ? c->pw2 : NULL;
        if (i == A_KEYFILE) snprintf(v, sizeof v, "%s", c->kf == KF_NONE ? "None" : c->kf == KF_KEEP ? "Keep current" : "Generate new");
        else if (i == A_TIME) { if (c->seconds) snprintf(v, sizeof v, "~%d s", c->seconds); else snprintf(v, sizeof v, "Keep as is"); }
        if (b && sel && c->editing) ap_draw_field(a, s, 62, y, UI_W - 64, h, b, true, (int)strlen(b));
        else if (b) ui_text(s, F, 66, y + (h - F->height) / 2, b[0] ? U_BULLETS : "\xE2\x80\x94", sel ? T->sel_fg : T->fg, UI_W - 70);
        else ui_text(s, F, 66, y + (h - F->height) / 2, v, sel ? T->sel_fg : T->fg, UI_W - 70);
    }
    ap_draw_toast(a, s);
    *hint = c->editing ? U_ENTER " next  fn+` stop" : U_ENTER " edit/choose  ` cancel";
}
