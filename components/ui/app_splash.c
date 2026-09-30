/* CardPass logo / splash screen: a tilted blank card with a key inside, drawn from distance functions
 * (no bitmap, anti-aliased, follows the theme). Shown at start-up when Settings -> Splash is on. */
#include <math.h>
#include "app_priv.h"

#define SPLASH_MS 3000u

static uint16_t mix(uint16_t a, uint16_t b, float t)             /* RGB565 blend, t = share of b */
{
    if (t <= 0.f) return a;
    if (t >= 1.f) return b;
    int w = (int)(t * 256.f);
    int r = ((a >> 11) * (256 - w) + (b >> 11) * w) >> 8, g = (((a >> 5) & 63) * (256 - w) + ((b >> 5) & 63) * w) >> 8,
        bl = ((a & 31) * (256 - w) + (b & 31) * w) >> 8;
    return (uint16_t)(r << 11 | g << 5 | bl);
}

static float clamp01(float v) { return v < 0.f ? 0.f : v > 1.f ? 1.f : v; }
static float sd_box(float x, float y, float hw, float hh, float r)   /* rounded box, negative inside */
{
    float qx = fabsf(x) - (hw - r), qy = fabsf(y) - (hh - r);
    float ox = qx > 0 ? qx : 0, oy = qy > 0 ? qy : 0;
    float in = qx > qy ? qx : qy;
    return sqrtf(ox * ox + oy * oy) + (in < 0 ? in : 0) - r;
}

#define CARD_CX 120.f
#define CARD_CY 52.f
#define CARD_TILT (-18.f * 3.14159265f / 180.f)
#define KEY_TILT (-38.f * 3.14159265f / 180.f)

static void logo_row(int y, uint16_t *out, const ui_theme *t)
{
    static float cs, sn, kc, ks;
    static bool init;
    if (!init) { cs = cosf(CARD_TILT); sn = sinf(CARD_TILT); kc = cosf(KEY_TILT); ks = sinf(KEY_TILT); init = true; }
    for (int x = 0; x < UI_W; x++) {
        uint16_t c = t->bg;
        float dx = (float)x + .5f - CARD_CX, dy = (float)y + .5f - CARD_CY;
        if (fabsf(dx) < 76.f && fabsf(dy) < 62.f) {
            float u = dx * cs + dy * sn, v = -dx * sn + dy * cs;          /* card coordinates */
            float sc = sd_box(u, v, 52.f, 33.f, 9.f);
            c = mix(c, t->field_bg, clamp01(.5f - sc));                   /* blank card */
            c = mix(c, t->fg, clamp01(.5f - (fabsf(sc + 1.5f) - 1.5f)));  /* 3 px outline, inside the edge */
            float ku = u * kc + v * ks, kv = -u * ks + v * kc;            /* key coordinates: axis along ku */
            float bx = ku - 17.f, bl = sqrtf(bx * bx + kv * kv);
            float ring = bl - 9.f > 4.f - bl ? bl - 9.f : 4.f - bl;        /* bow with a hole */
            float shaft = sd_box(ku + 8.f, kv, 18.f, 2.4f, 0.f);
            float t1 = sd_box(ku + 18.f, kv + 5.f, 1.8f, 5.f, 0.f), t2 = sd_box(ku + 10.f, kv + 4.f, 1.8f, 4.f, 0.f);
            float sk = ring < shaft ? ring : shaft;
            sk = sk < t1 ? sk : t1;
            sk = sk < t2 ? sk : t2;
            c = mix(c, t->accent, clamp01(.5f - sk));
        }
        out[x] = c;
    }
}

void ap_splash_draw(app *a, ui_strip *s)
{
    const ui_theme *t = T;
    for (int r = 0; r < s->h; r++) logo_row(s->y0 + r, s->px + r * UI_W, t);
    const ui_font *f = &ui_font_large;
    const char *name = "CardPass";
    int w = ui_text_width(f, name), y = 108;
    if (y + f->height > s->y0 && y < s->y0 + s->h) ui_text(s, f, (UI_W - w) / 2, y, name, t->fg, UI_W);
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
