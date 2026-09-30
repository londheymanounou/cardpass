/* Passkey confirmation: a browser asked to sign in. This is the "user presence" step of
 * WebAuthn: the request is answered only if the user presses Enter on the device.
 * Modal: runs a local loop through the platform's pump() (keys, ticks, drawing) so the
 * CTAP2 code can simply call it and get the decision back. */
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

void ap_fido_key(app *a, uint32_t k, bool fn)
{
    (void)fn;
    if (k == K_UP || k == K_DOWN) ap_move_sel(a, (int)a->nfcreds, k == K_UP ? -1 : 1);
    else if (k == K_ENTER) a->fdecision = a->sel + 1;
    else if (k == '`' || k == K_ESC) a->fdecision = -1;
    ap_mark_all(a);
}

void ap_fido_draw(app *a, ui_strip *s, const char **hint)
{
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + 4, a->nfcreds > 1 ? "Sign in to (choose the account)" : "Sign in to", T->dim, UI_W);
    ui_text(s, F, PAD * 2, CONTENT_Y + 18, a->frp, T->accent, UI_W - PAD * 4);
    int h = ap_row_h(a), y0 = CONTENT_Y + 18 + F->height + 6;
    for (size_t i = 0; i < a->nfcreds && y0 + (int)i * h + h <= UI_H - FOOT_H; i++) {
        int y = y0 + (int)i * h;
        bool sel = (int)i == a->sel;
        if (y + h <= s->y0 || y >= s->y0 + s->h) continue;
        ui_fill(s, 0, y, UI_W, h, sel ? T->sel_bg : T->bg);
        if (sel) ui_fill(s, 0, y, 2, h, T->accent);
        const char *name = a->fcreds[i].user_name[0] ? a->fcreds[i].user_name : "(no name)";
        int x = PAD * 2 + ui_text(s, F, PAD * 2, y + (h - F->height) / 2, ICON_KEY, T->dim, 16) + 4;
        ui_text(s, F, x, y + (h - F->height) / 2, name, sel ? T->sel_fg : T->fg, UI_W - x - PAD);
    }
    *hint = U_ENTER " approve  ` deny  (30 s)";
}
