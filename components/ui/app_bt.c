/* Bluetooth typing. The radio is on only while the user has switched it on here (the security rules in CLAUDE.md):
 * it goes off after 2 minutes without typing, and whenever the app locks. Pairing uses numeric
 * comparison: the code is shown here and must be confirmed with Enter. */
#include "app_priv.h"

#define BT_IDLE_MS 120000u

void ap_bt_open(app *a, int back)
{
    a->bt_return = back;
    a->bt_auto = false;
    a->scr = SCR_BT;
    a->msg[0] = 0;
    ap_mark_all(a);
}

void ap_bt_off(app *a)
{
    if (!a->bt_on) return;
    a->p->bt_stop(a->p->ctx);
    a->bt_on = false;
    a->bt_state = BT_OFF;
    a->bt_code = 0;
}

static void leave(app *a)
{
    if (a->bt_auto) { a->scr = a->bt_return; a->bt_auto = false; ap_mark_all(a); }
    else ap_return(a, a->bt_return);
}

void ap_bt_key(app *a, uint32_t k, bool fn)
{
    (void)fn;
    a->msg[0] = 0;
    ap_mark_all(a);
    if (a->bt_state == BT_PAIR_CONFIRM) {
        if (k == K_ENTER || k == K_ESC || k == '`') {
            a->p->bt_answer(a->p->ctx, k == K_ENTER);
            a->bt_code = 0;
            if (a->bt_auto) leave(a);
        }
        return;
    }
    if (k == K_ENTER) {
        if (a->bt_on) ap_bt_off(a);
        else {
            snprintf(a->msg, sizeof a->msg, "Starting Bluetooth\xE2\x80\xA6");
            ap_mark_all(a);
            a->p->present(a->p->ctx);
            a->bt_on = a->p->bt_start(a->p->ctx);
            a->bt_ms = a->now_ms;
            a->msg[0] = 0;
            if (!a->bt_on) snprintf(a->msg, sizeof a->msg, "Bluetooth could not start");
        }
    } else if (k == 'f' || k == 'F') {
        a->p->bt_forget(a->p->ctx);
        snprintf(a->msg, sizeof a->msg, "All pairings forgotten");
    } else if (k == '`' || k == K_ESC) {
        leave(a);
    }
}

/* Polled every tick while Bluetooth is on: state changes, pairing prompt, idle shutdown. */
void ap_bt_tick(app *a, uint32_t now)
{
    if (!a->bt_on) return;
    uint32_t code = 0;
    int st = a->p->bt_state(a->p->ctx, &code);
    if (st != a->bt_state || code != a->bt_code) {
        a->bt_state = st;
        a->bt_code = code;
        if (st != BT_OFF) a->bt_ms = now;
        ap_mark_all(a);
    }
    if (st == BT_PAIR_CONFIRM && a->scr != SCR_BT &&
        (a->scr == SCR_HOME || a->scr == SCR_GROUP || a->scr == SCR_ENTRY || a->scr == SCR_PICKER || a->scr == SCR_MENU)) {
        a->bt_return = a->scr;                         /* a host wants to pair: show the code now */
        a->bt_auto = true;
        a->scr = SCR_BT;
        a->last_input_ms = now;                        /* keep the screen on while it waits */
        ap_mark_all(a);
    }
    if (st == BT_OFF || (st != BT_PAIR_CONFIRM && now - a->bt_ms >= BT_IDLE_MS)) {
        ap_bt_off(a);
        snprintf(a->msg, sizeof a->msg, "Bluetooth off");
        ap_mark_all(a);
    }
}

void ap_bt_draw(app *a, ui_strip *s, const char **hint)
{
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    int y = CONTENT_Y + 8;
    if (a->bt_state == BT_PAIR_CONFIRM) {
        char code[16];
        snprintf(code, sizeof code, "%03u %03u", (unsigned)(a->bt_code / 1000 % 1000), (unsigned)(a->bt_code % 1000));
        ui_text(s, F, PAD * 2, y, "Pair with this device?", T->fg, UI_W);
        ui_text(s, &ui_font_small, PAD * 2, y + 24, "Does your device show the same code?", T->dim, UI_W - PAD * 4);
        ui_fill(s, PAD * 2, y + 42, 118, F->height + 10, T->field_bg);
        ui_text(s, F, PAD * 2 + 8, y + 47, code, T->accent, 110);
        *hint = U_ENTER " yes, same  ` no";
        return;
    }
    const char *line1, *line2;
    uint16_t c = T->fg;
    switch (a->bt_state) {
    case BT_ADVERTISING: line1 = "Visible as \"CardPass\""; line2 = "Pair it in your device's Bluetooth settings."; c = T->accent; break;
    case BT_CONNECTED: line1 = "Connected"; line2 = "Typing now goes to this device."; c = T->ok; break;
    default: line1 = "Bluetooth is off"; line2 = "Turn it on to type without a cable."; break;
    }
    ui_text(s, F, PAD * 2, y, line1, c, UI_W - PAD * 4);
    ui_text(s, &ui_font_small, PAD * 2, y + 24, line2, T->dim, UI_W - PAD * 4);
    ui_text(s, &ui_font_small, PAD * 2, y + 40, "It turns itself off after 2 min without typing.", T->dim, UI_W - PAD * 4);
    ap_draw_toast(a, s);
    *hint = a->bt_on ? U_ENTER " turn off  F forget pairings  ` back" : U_ENTER " turn on  F forget pairings  ` back";
}
