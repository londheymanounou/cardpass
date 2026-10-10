/* Optional UI animations (Settings -> Animations). No framebuffer exists, so every effect is a pure
 * function of state + time, evaluated while the strips are drawn:
 *   - selection cross-fade: the old row's highlight fades out while the new one fades in (80 ms)
 *   - rows slide in from the right when a list / entry is entered (staggered, 161 ms + 18 ms per row)
 *   - the toast slides up from behind the footer (161 ms)
 * Frames are driven from app_tick (60 fps, only while something is moving). A key press ends the
 * slide immediately; everything is off below 15 % battery, when dimmed and during passkey prompts. */
#include "app_priv.h"
#include "motion_br.h"

#define SEL_MS BR_MS_FEEDBACK      /* Bio-Resonant tiers (motion_br.h, from its tokens): 80 ms */
#define SLIDE_MS BR_MS_ELEMENT     /* 161 ms */
#define SLIDE_STAGGER 18
#define SLIDE_DX 60
#define TOAST_MS BR_MS_ELEMENT     /* 161 ms */
#define TOAST_DY TOAST_H
#define FRAME_MS 16                 /* 62.5 fps: the firmware loop is paced at 16 ms */
#define LOW_BATTERY 15

static int ease(int t) { return br_ease(t); }   /* the design system's spring step response, not a hand-picked curve */

static uint16_t blend(uint16_t c0, uint16_t c1, int w)
{
    int r = ((c0 >> 11) * (256 - w) + (c1 >> 11) * w) >> 8, g = (((c0 >> 5) & 63) * (256 - w) + ((c1 >> 5) & 63) * w) >> 8,
        b = ((c0 & 31) * (256 - w) + (c1 & 31) * w) >> 8;
    return (uint16_t)(r << 11 | g << 5 | b);
}

/* Highlight strength of row i, 0..256. */
int ap_row_weight(const app *a, int i)
{
    int w = i == a->sel ? 256 : 0;
    if (a->anim_on && a->sel_prev >= 0) {
        uint32_t el = a->now_ms - a->sel_ms;
        if (el < SEL_MS) {
            int t = (int)(el * 256 / SEL_MS);
            if (i == a->sel) w = t;
            else if (i == a->sel_prev) w = 256 - t;
        }
    }
    return w;
}

void ap_row_bg(app *a, ui_strip *s, int y, int h, int i)
{
    int w = ap_row_weight(a, i);
    ui_fill(s, 0, y, UI_W, h, T->bg);
    if (w == 0) return;
    uint16_t fill = w >= 256 ? T->sel_bg : blend(T->bg, T->sel_bg, w), ring = w >= 256 ? T->ring : blend(T->bg, T->ring, w);
    ui_round_ring(s, PAD / 2, y, UI_W - PAD - 4, h, h, UI_STROKE, ring, fill);    /* r = h: a capsule */
}

void ap_sel_changed(app *a, int old)
{
    a->sel_prev = old;
    a->sel_ms = a->now_ms;
}

/* ---- slide-in ---- */

static bool slides(const app *a)
{
    switch (a->scr) {
    case SCR_PICKER: case SCR_HOME: case SCR_GROUP: case SCR_ENTRY: case SCR_MENU: case SCR_SETTINGS: case SCR_AUDIT:
    case SCR_EXPIRY: case SCR_GROUPS: return true;
    default: return false;
    }
}

static bool slide_running(const app *a)
{
    return a->anim_on && slides(a) && a->now_ms - a->scr_ms < SLIDE_MS + SLIDE_STAGGER * 8 + FRAME_MS;
}

/* Shift the drawn rows right by their remaining offset (called after the screen was drawn into s). */
void ap_slide_apply(app *a, ui_strip *s)
{
    if (!slide_running(a)) return;
    int h = ap_row_h(a);
    uint32_t el = a->now_ms - a->scr_ms;
    for (int r = 0; r < ap_visible(a); r++) {                      /* full rows only: the toast stays put */
        int y = CONTENT_Y + r * h;
        int start = r * SLIDE_STAGGER;
        int t = (int)el <= start ? 0 : (int)((el - (uint32_t)start) * 256 / SLIDE_MS);
        int dx = SLIDE_DX * (256 - ease(t)) / 256;
        if (dx <= 0) continue;
        a->anim_live = true;   /* drawn off position: the tick owes a settled redraw, even if it never sees the slide run */
        for (int yy = y > s->y0 ? y : s->y0; yy < y + h && yy < s->y0 + s->h; yy++) {
            uint16_t *row = s->px + (yy - s->y0) * UI_W;
            memmove(row + dx, row, (size_t)(UI_W - dx) * sizeof *row);
            for (int x = 0; x < dx; x++) row[x] = T->bg;
        }
    }
}

/* ---- toast ---- */

int ap_toast_offset(const app *a)
{
    if (!a->anim_on || !a->msg[0]) return 0;
    uint32_t el = a->now_ms - a->toast_ms;
    return el >= TOAST_MS ? 0 : TOAST_DY * (256 - ease((int)(el * 256 / TOAST_MS))) / 256;
}

/* ---- driving ---- */

/* Called from app_dirty (once per present): a new screen / group / entry restarts the slide-in. */
void ap_anim_nav_check(app *a)
{
    if (a->scr != a->last_scr || a->group != a->last_group || a->entry != a->last_entry) {
        a->last_scr = a->scr;
        a->last_group = a->group;
        a->last_entry = a->entry;
        a->scr_ms = a->now_ms;
        a->sel_prev = -1;
    }
}

void ap_anim_key(app *a)                           /* any key: finish the slide now */
{
    if (slide_running(a)) {
        a->scr_ms = a->now_ms - 100000u;
        ap_mark(a, CONTENT_Y, UI_H);
    }
}

void ap_anim_tick(app *a, uint32_t now)
{
    int bat = a->p->battery(a->p->ctx);
    bool on = a->cfg.animations && a->power == 0 && !a->fido_active && (bat < 0 || bat > LOW_BATTERY);
    if (!on && a->anim_on) ap_mark(a, CONTENT_Y, UI_H);          /* redraw in the final state */
    a->anim_on = on;
    if (strcmp(a->msg, a->msg_prev)) {                            /* a new toast */
        snprintf(a->msg_prev, sizeof a->msg_prev, "%s", a->msg);
        a->toast_ms = now;
    }
    /* due after 3/4 of a frame: the loop wakes every 16 ms with jitter, and gating on a full 16 ms made a pass that
     * woke at 15.9 ms skip its frame (53 fps measured in QEMU instead of the loop's 62.5) */
    if (!on || now - a->anim_frame_ms < FRAME_MS * 3 / 4) return;
    bool sel = a->sel_prev >= 0 && now - a->sel_ms < SEL_MS + FRAME_MS;
    bool toast = a->msg[0] && now - a->toast_ms < TOAST_MS + FRAME_MS;
    bool slide = slide_running(a);
    bool was = a->anim_live;
    a->anim_live = sel || toast || slide;
    if (!a->anim_live) {   /* a busy loop (unlock) can skip past the last frame: draw the final state anyway */
        if (was) ap_mark(a, CONTENT_Y, UI_H);
        return;
    }
    a->anim_frame_ms = now;
    if (slide || toast) ap_mark(a, CONTENT_Y, UI_H);
    else { ap_mark_row(a, a->sel_prev); ap_mark_row(a, a->sel); }
}
