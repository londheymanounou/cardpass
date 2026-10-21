/* Passkey confirmation: a browser asked to sign in. This is the "user presence" step of
 * WebAuthn: the request is answered only if the user presses Enter on the device.
 * Modal: runs a local loop through the platform's pump() (keys, ticks, drawing) so the
 * CTAP2 code can simply call it and get the decision back. */
#include <strings.h>
#include "app_priv.h"

#define FIDO_TIMEOUT_MS 30000

int app_ask_passkey(app *a, const char *rp, const fido_cred *c, size_t n)
{
    if (!a->db || !n) return -1;
    int scr = a->scr, sel = a->sel, top = a->top;
    a->fcreds = c;
    a->nfcreds = n;
    snprintf(a->frp, sizeof a->frp, "%.63s", rp);
    a->fdecision = 0;
    a->fido_active = true;                     /* suspends auto-lock and fn+L while the database is in use */
    a->scr = SCR_FIDO;
    a->sel = a->top = 0;
    a->last_input_ms = a->now_ms;
    ap_mark_all(a);
    uint32_t start = a->now_ms;
    while (!a->fdecision && (uint32_t)(a->now_ms - start) < FIDO_TIMEOUT_MS) a->p->pump(a->p->ctx);
    int r = a->fdecision > 0 ? a->fdecision - 1 : -1;
    a->fido_active = false;
    a->fcreds = NULL;
    a->nfcreds = 0;
    a->scr = scr;
    a->sel = sel;
    a->top = top;
    a->last_input_ms = a->now_ms;
    ap_mark_all(a);
    return r;
}

/* The entry for a new passkey, in KeePassXC's field names and formats (so KeePassXC and the sign-in path read it). */
static bool save_passkey(app *a, const fido_new *n)
{
    char title[400], url[300];
    if (n->user_name[0]) snprintf(title, sizeof title, "%s (%s)", n->rp_id, n->user_name);
    else snprintf(title, sizeof title, "%s", n->rp_id);
    snprintf(url, sizeof url, "https://%s", n->rp_id);
    const kdbx_edit_field f[] = {
        {"Title", title, false}, {"UserName", n->user_name, false}, {"Password", "", true}, {"URL", url, false}, {"Notes", "", false},
        {"KPEX_PASSKEY_CREDENTIAL_ID", n->cred_b64, false}, {"KPEX_PASSKEY_PRIVATE_KEY_PEM", n->pem, true},
        {"KPEX_PASSKEY_RELYING_PARTY", n->rp_id, false}, {"KPEX_PASSKEY_USERNAME", n->user_name, false},
        {"KPEX_PASSKEY_USER_HANDLE", n->user_b64, false}, {"KPEX_PASSKEY_FLAG_BE", "1", false}, {"KPEX_PASSKEY_FLAG_BS", "1", false}};
    kdbx_edit ed = {.op = KDBX_EDIT_ENTRY, .create = true, .fields = f, .nfields = sizeof f / sizeof *f};
    kdbx_new_uuid(ed.uuid);
    memcpy(ed.parent, kdbx_root_group(a->db)->uuid, 16);
    return ap_save(a, &ed, 1);
}

/* ---- where a new passkey goes: a new entry, or one that already exists (the row list of the confirmation) ---- */

#define FL_MAX 200

static bool has_ci(const char *hay, const char *needle)
{
    size_t nl = strlen(needle);
    if (!nl) return false;
    for (; *hay; hay++)
        if (!strncasecmp(hay, needle, nl)) return true;
    return false;
}

static bool has_passkey(const kdbx_entry *e) { return kdbx_field_get(e, "KPEX_PASSKEY_PRIVATE_KEY_PEM") != NULL; }

/* every entry outside the recycle bin can take a passkey; one that already holds a passkey has it replaced (after a warning) */
static bool eligible(const app *a, const kdbx_entry *e) { return e->group != kdbx_recycle_bin(a->db); }

/* all = every eligible entry; else the likely ones: the site in the URL, or its name / first label in the title */
static void build_flist(app *a, bool all)
{
    const fido_new *n = a->fnew;
    char label[64] = "";
    const char *h = !strncmp(n->rp_id, "www.", 4) ? n->rp_id + 4 : n->rp_id;
    size_t l = strcspn(h, ".");
    if (l >= 3 && l < sizeof label) memcpy(label, h, l), label[l] = 0;
    free(a->flist);
    a->flist = malloc(sizeof *a->flist * FL_MAX);
    a->nflist = a->fother = 0;
    int total = 0;
    for (const kdbx_entry *e = a->flist ? kdbx_entries(a->db) : NULL; e; e = e->next) {
        if (!eligible(a, e)) continue;
        total++;
        bool m = (all || has_ci(e->url, n->rp_id) || (n->rp_name[0] && has_ci(e->title, n->rp_name)) || (label[0] && has_ci(e->title, label))) && (all || !has_passkey(e));   /* suggestions never replace a passkey */
        if (m && a->nflist < FL_MAX) a->flist[a->nflist++] = e;
    }
    a->fother = !all && total > a->nflist;
}

#define LIST_Y0(a) (CONTENT_Y + 4 + F->height + 2 + ui_font_small.height + 4)
static int list_vis(app *a) { return (UI_H - FOOT_H - LIST_Y0(a)) / ap_row_h(a); }

int app_register_passkey(app *a, const fido_new *n)
{
    /* only while browsing: a save re-indexes the database, which would pull entries out from under an open editor */
    if (!a->db || (a->scr != SCR_HOME && a->scr != SCR_GROUP && a->scr != SCR_SEARCH && a->scr != SCR_ENTRY)) return 2;
    int scr = a->scr;
    a->fnew = n;
    a->fchosen = NULL;
    a->fwarn = NULL;
    build_flist(a, false);
    a->fdecision = 0;
    a->fido_active = true;
    a->scr = SCR_FIDO;
    a->sel = a->top = 0;
    a->last_input_ms = a->now_ms;
    ap_mark_all(a);
    uint32_t start = a->now_ms;
    while (!a->fdecision && (uint32_t)(a->now_ms - start) < FIDO_TIMEOUT_MS) a->p->pump(a->p->ctx);
    bool yes = a->fdecision > 0;
    a->fnew = NULL;
    a->scr = scr;
    int r = 1;
    char what[48] = "";
    if (a->fchosen) snprintf(what, sizeof what, "%.40s", a->fchosen->title);   /* the index is freed by the save */
    if (yes) r = (a->fchosen ? ap_add_passkey(a, a->fchosen, n) : save_passkey(a, n)) ? 0 : 2;
    free(a->flist);
    a->flist = NULL;
    a->nflist = a->fother = 0;
    a->fchosen = NULL;
    a->fwarn = NULL;
    a->fido_active = false;
    a->last_input_ms = a->now_ms;
    char why[sizeof a->msg];
    memcpy(why, a->msg, sizeof why);                 /* the save's own message ("Not saved: ...") must survive the redraw */
    if (a->db) ap_return(a, scr);                    /* rebuild the screen we came from: the list has a new entry */
    if (r == 2) {
        memcpy(a->msg, why, sizeof a->msg);
        if (!a->msg[0] || !strncmp(a->msg, "Saving", 6)) snprintf(a->msg, sizeof a->msg, "Passkey not saved");
    }
    if (!r && what[0]) snprintf(a->msg, sizeof a->msg, "Passkey added to %.40s", what);
    else if (!r) snprintf(a->msg, sizeof a->msg, "Passkey saved: %.40s", n->rp_id);
    ap_mark_all(a);
    return r;
}

void ap_fido_key(app *a, uint32_t k, bool fn)
{
    (void)fn;
    if (a->fnew && a->fwarn) {                                       /* "this entry already has a passkey: replace it?" */
        if (k == K_ENTER) a->fchosen = a->fwarn, a->fwarn = NULL, a->fdecision = 1;
        else if (k == '`' || k == K_ESC) a->fwarn = NULL;
        ap_mark_all(a);
        return;
    }
    if (a->fnew) {                                                   /* registration: pick where it goes, Enter, ` denies */
        int rows = 1 + a->nflist + a->fother;
        if (k == K_UP || k == K_DOWN) {
            ap_move_sel(a, rows, k == K_UP ? -1 : 1);
            int v = list_vis(a);
            if (a->sel < a->top) a->top = a->sel;
            else if (a->sel >= a->top + v) a->top = a->sel - v + 1;
        } else if (k == K_ENTER) {
            if (a->fother && a->sel == rows - 1) { build_flist(a, true); a->top = 0; a->sel = a->nflist ? 1 : 0; }   /* every entry */
            else {
                const kdbx_entry *e = a->sel ? a->flist[a->sel - 1] : NULL;
                if (e && has_passkey(e)) { a->fwarn = e; ap_mark_all(a); return; }          /* replacing one: ask first */
                a->fchosen = e;
                a->fdecision = 1;
            }
        } else if (k == '`' || k == K_ESC) a->fdecision = -1;
        ap_mark_all(a);
        return;
    }
    if (k == K_UP || k == K_DOWN) ap_move_sel(a, (int)a->nfcreds, k == K_UP ? -1 : 1);
    else if (k == K_ENTER) a->fdecision = a->sel + 1;
    else if (k == '`' || k == K_ESC) a->fdecision = -1;
    ap_mark_all(a);
}

void ap_fido_draw(app *a, ui_strip *s, const char **hint)
{
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    if (a->fnew && a->fwarn) {
        char old[128] = "", line[200];
        const kdbx_field *rf = kdbx_field_get(a->fwarn, "KPEX_PASSKEY_RELYING_PARTY");
        if (!rf || kdbx_reveal(a->db, rf, old, sizeof old)) old[0] = 0;
        ui_text(s, F, PAD * 2, CONTENT_Y + 4, "Replace its passkey?", T->warn, UI_W - PAD * 4);
        ui_text(s, F, PAD * 2, CONTENT_Y + 4 + F->height + 4, a->fwarn->title, T->fg, UI_W - PAD * 4);
        snprintf(line, sizeof line, "It holds one for %s", old[0] ? old : "another site");
        ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + 4 + 2 * F->height + 10, line, T->dim, UI_W - PAD * 4);
        ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + 4 + 2 * F->height + 24, "The old one stays in the entry's history.", T->dim, UI_W - PAD * 4);
        *hint = U_ENTER " replace  ` back";
        return;
    }
    if (a->fnew) {
        char who[200];
        snprintf(who, sizeof who, "%s: save to", a->fnew->user_name[0] ? a->fnew->user_name : "(no name)");
        ui_text(s, F, PAD * 2, CONTENT_Y + 4, a->fnew->rp_id, T->accent, UI_W - PAD * 4);
        ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + 4 + F->height + 2, who, T->dim, UI_W - PAD * 4);
        int h = ap_row_h(a), y0 = LIST_Y0(a), rows = 1 + a->nflist + a->fother;
        for (int i = a->top; i < rows && y0 + (i - a->top) * h + h <= UI_H - FOOT_H; i++) {
            int y = y0 + (i - a->top) * h;
            if (y + h <= s->y0 || y >= s->y0 + s->h) continue;
            bool sel = i == a->sel;
            ap_row_bg(a, s, y, h, i);
            const char *icon = i == 0 ? "+" : a->fother && i == rows - 1 ? ICON_FOLDER_OPEN : ICON_KEY;
            const kdbx_entry *e = i && !(a->fother && i == rows - 1) ? a->flist[i - 1] : NULL;
            const char *name = i == 0 ? "New entry" : e ? e->title : "Other entry...";
            int x = PAD * 2 + ui_text(s, F, PAD * 2, y + (h - F->height) / 2, icon, i == 0 ? T->accent : T->dim, 16) + 4;
            int tag = e && has_passkey(e) ? ui_text_width(&ui_font_small, "passkey") + 6 : 0;
            ui_text(s, F, x, y + (h - F->height) / 2, name, sel ? T->sel_fg : T->fg, UI_W - x - PAD - tag);
            if (tag) ui_text(s, &ui_font_small, UI_W - PAD - tag + 6, y + (h - ui_font_small.height) / 2, "passkey", sel ? T->sel_fg : T->warn, tag);
        }
        *hint = U_UPDOWN " choose  " U_ENTER " save  ` deny";
        return;
    }
    ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + 4, a->nfcreds > 1 ? "Sign in to (choose the account)" : "Sign in to", T->dim, UI_W);
    ui_text(s, F, PAD * 2, CONTENT_Y + 18, a->frp, T->accent, UI_W - PAD * 4);
    int h = ap_row_h(a), y0 = CONTENT_Y + 18 + F->height + 6;
    for (size_t i = 0; i < a->nfcreds && y0 + (int)i * h + h <= UI_H - FOOT_H; i++) {
        int y = y0 + (int)i * h;
        bool sel = (int)i == a->sel;
        if (y + h <= s->y0 || y >= s->y0 + s->h) continue;
        ap_row_bg(a, s, y, h, (int)i);
        const char *name = a->fcreds[i].user_name[0] ? a->fcreds[i].user_name : "(no name)";
        int x = PAD * 2 + ui_text(s, F, PAD * 2, y + (h - F->height) / 2, ICON_KEY, T->dim, 16) + 4;
        ui_text(s, F, x, y + (h - F->height) / 2, name, sel ? T->sel_fg : T->fg, UI_W - x - PAD);
    }
    *hint = U_ENTER " approve  ` deny  (30 s)";
}
