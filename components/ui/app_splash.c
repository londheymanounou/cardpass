/* CardPass logo / splash screen: a tilted blank card with a key inside, drawn from distance functions
 * (no bitmap, anti-aliased, follows the theme). Shown at start-up when Settings -> Splash is on. */
#include "app_priv.h"

#define SPLASH_MS 3000u

void (*cp_heap_stats)(size_t *free_bytes, size_t *largest_block) = NULL;
const char *cp_build_id = "dev";   /* the firmware sets it to the first hex digits of the image's hash at start-up */

/* The logo is a pre-baked sprite (tools/gen_logo.py -> logo_data.c): three 4-bit coverage layers (card, outline,
 * key) in flash. Drawing is table lookups: card over background and outline over that come from one 16x16 colour
 * table built per theme, the key (a few hundred pixels) blends on top. No maths per pixel, no RAM for the image. */
extern const int logo_x0, logo_y0, logo_w, logo_h;
extern const uint8_t logo_card[], logo_line[], logo_key[];

static inline int nib(const uint8_t *row, int x) { return x & 1 ? row[x >> 1] & 15 : row[x >> 1] >> 4; }

static void logo_rows(ui_strip *s, const ui_theme *t)
{
    static uint16_t tab[16][16], kb, kf, kl;
    static bool built;
    if (!built || kb != t->bg || kf != t->field_bg || kl != t->fg) {      /* per theme, 256 blends once */
        for (int c = 0; c < 16; c++)
            for (int l = 0; l < 16; l++) tab[c][l] = ui_mix(ui_mix(t->bg, t->field_bg, c * 17), t->fg, l * 17);
        kb = t->bg, kf = t->field_bg, kl = t->fg, built = true;
    }
    int bpr = (logo_w + 1) / 2;
    int y0 = s->y0 > logo_y0 ? s->y0 : logo_y0, y1 = s->y0 + s->h < logo_y0 + logo_h ? s->y0 + s->h : logo_y0 + logo_h;
    for (int y = y0; y < y1; y++) {
        uint16_t *row = s->px + (y - s->y0) * UI_W + logo_x0;
        const uint8_t *c = logo_card + (y - logo_y0) * bpr, *l = logo_line + (y - logo_y0) * bpr, *k = logo_key + (y - logo_y0) * bpr;
        for (int x = 0; x < logo_w; x++) {
            int cc = nib(c, x), ll = nib(l, x);
            if (!(cc | ll)) continue;                                        /* background stays as filled */
            uint16_t v = tab[cc][ll];
            int kk = nib(k, x);
            if (kk) v = kk == 15 ? t->accent : ui_mix(v, t->accent, kk * 17);
            row[x] = v;
        }
    }
}

void ap_splash_draw(app *a, ui_strip *s)
{
    const ui_theme *t = T;
    ui_fill(s, 0, s->y0, UI_W, s->h, t->bg);
    logo_rows(s, t);
    const ui_font *f = &ui_font_large;
    const char *name = "CardPass";
    int w = ui_text_width(f, name), y = 108;
    if (y + f->height > s->y0 && y < s->y0 + s->h) ui_text(s, f, (UI_W - w) / 2, y, name, t->fg, UI_W);
    const ui_font *sm = &ui_font_small;
    int bw = ui_text_width(sm, cp_build_id), by = UI_H - sm->height - 2;   /* build id, bottom-right: compare with `tools/package.py` */
    if (by + sm->height > s->y0 && by < s->y0 + s->h) ui_text(s, sm, UI_W - bw - PAD, by, cp_build_id, t->dim, bw + 1);
    (void)a;
}

void ap_splash_leave(app *a)
{
    if (a->scr != SCR_SPLASH) return;
    a->scr = SCR_PICKER;
    ap_mark_all(a);
}

void ap_splash_tick(app *a, uint32_t now)
{
    if (a->scr != SCR_SPLASH) return;
    if (!a->splash_until) a->splash_until = now + SPLASH_MS;           /* the clock starts at the first tick */
    if ((int32_t)(now - a->splash_until) >= 0) ap_splash_leave(a);
}
