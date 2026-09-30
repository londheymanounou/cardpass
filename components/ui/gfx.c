#include <string.h>
#include "ui.h"

int ui_overflow;

/* All colours of the UI (plan: one palette struct per theme, nothing hard-coded). */
const ui_theme ui_dark = {
    .bg = RGB565(16, 18, 22), .fg = RGB565(232, 234, 238), .dim = RGB565(140, 146, 158),
    .accent = RGB565(255, 176, 32), .sel_bg = RGB565(52, 58, 72), .sel_fg = RGB565(255, 255, 255),
    .bar_bg = RGB565(30, 33, 40), .bar_fg = RGB565(200, 204, 212), .ok = RGB565(86, 200, 120),
    .warn = RGB565(255, 176, 32), .danger = RGB565(255, 92, 92), .field_bg = RGB565(36, 40, 48),
};
const ui_theme ui_light = {
    .bg = RGB565(248, 248, 246), .fg = RGB565(24, 26, 30), .dim = RGB565(104, 110, 120),
    .accent = RGB565(196, 110, 0), .sel_bg = RGB565(214, 222, 238), .sel_fg = RGB565(0, 0, 0),
    .bar_bg = RGB565(228, 228, 224), .bar_fg = RGB565(48, 52, 60), .ok = RGB565(20, 140, 60),
    .warn = RGB565(190, 110, 0), .danger = RGB565(200, 30, 30), .field_bg = RGB565(236, 236, 232),
};

uint32_t ui_utf8_next(const char **s)
{
    const unsigned char *p = (const unsigned char *)*s;
    uint32_t c = *p++;
    int n = c < 0x80 ? 0 : c >= 0xF0 ? 3 : c >= 0xE0 ? 2 : c >= 0xC0 ? 1 : -1;
    if (n < 0) { *s = (const char *)p; return 0xFFFD; }
    if (n) c &= 0x3Fu >> n;
    for (; n; n--, p++) {
        if ((*p & 0xC0) != 0x80) { *s = (const char *)p; return 0xFFFD; }
        c = c << 6 | (*p & 0x3F);
    }
    *s = (const char *)p;
    return c;
}

void ui_fill(ui_strip *s, int x, int y, int w, int h, uint16_t c)
{
    int x1 = x + w, y1 = y + h;
    if (x < 0) x = 0;
    if (x1 > UI_W) x1 = UI_W;
    if (y < s->y0) y = s->y0;
    if (y1 > s->y0 + s->h) y1 = s->y0 + s->h;
    for (int yy = y; yy < y1; yy++) {
        uint16_t *row = s->px + (yy - s->y0) * UI_W;
        for (int xx = x; xx < x1; xx++) row[xx] = c;
    }
}

/* Glyph for cp; icons missing from the large font come from the small one. */
static const ui_glyph *glyph(const ui_font *f, uint32_t cp, const ui_font **from)
{
    for (int pass = 0; pass < 2; pass++) {
        size_t lo = 0, hi = f->n;
        while (lo < hi) {
            size_t mid = (lo + hi) / 2;
            if (f->g[mid].cp < cp) lo = mid + 1;
            else hi = mid;
        }
        if (lo < f->n && f->g[lo].cp == cp) {
            *from = f;
            return &f->g[lo];
        }
        if (f == &ui_font_small) break;
        f = &ui_font_small;
    }
    return NULL;
}

static int advance(const ui_font *f, uint32_t cp)
{
    const ui_font *from;
    const ui_glyph *g = glyph(f, cp, &from);
    return g ? g->adv : f->height / 2 + 1;
}

int ui_text_width(const ui_font *f, const char *s)
{
    int w = 0;
    while (*s) w += advance(f, ui_utf8_next(&s));
    return w;
}

static void draw_glyph(ui_strip *s, const ui_font *f, int x, int y, uint32_t cp, uint16_t fg)
{
    const ui_font *from;
    const ui_glyph *g = glyph(f, cp, &from);
    int base = y + f->ascent;
    if (!g) { /* placeholder box */
        int w = f->height / 2 - 1, h = f->ascent - 1;
        ui_fill(s, x, base - h, w, 1, fg);
        ui_fill(s, x, base - 1, w, 1, fg);
        ui_fill(s, x, base - h, 1, h, fg);
        ui_fill(s, x + w - 1, base - h, 1, h, fg);
        return;
    }
    int top = base - g->yoff - g->h, bpr = (g->w + 7) / 8;
    if (from != f) top = base - (f->ascent - from->ascent) / 2 - g->yoff - g->h; /* centre small icons */
    const uint8_t *b = from->bits + g->off;
    for (int r = 0; r < g->h; r++) {
        int yy = top + r;
        if (yy < s->y0 || yy >= s->y0 + s->h) continue;
        uint16_t *row = s->px + (yy - s->y0) * UI_W;
        for (int c = 0; c < g->w; c++) {
            int xx = x + g->xoff + c;
            if (b[r * bpr + c / 8] & (0x80 >> (c % 8))) {
                if (xx < 0 || xx >= UI_W) { ui_overflow++; continue; }
                row[xx] = fg;
            }
        }
    }
}

int ui_text(ui_strip *s, const ui_font *f, int x, int y, const char *utf8, uint16_t fg, int max_w)
{
    if (y >= s->y0 + s->h || y + f->height <= s->y0) return ui_text_width(f, utf8) < max_w ? ui_text_width(f, utf8) : max_w;
    int full = ui_text_width(f, utf8), dots = advance(f, 0x2026), w = 0;
    bool cut = full > max_w;
    const char *p = utf8;
    while (*p) {
        uint32_t cp = ui_utf8_next(&p);
        int a = advance(f, cp);
        if (cut && w + a > max_w - dots) {
            draw_glyph(s, f, x + w, y, 0x2026, fg);
            return w + dots;
        }
        draw_glyph(s, f, x + w, y, cp, fg);
        w += a;
    }
    return w;
}

size_t ui_wrap(const ui_font *f, const char *utf8, int max_w)
{
    const char *p = utf8, *last_space = NULL;
    int w = 0;
    while (*p && *p != '\n') {
        const char *q = p;
        uint32_t cp = ui_utf8_next(&q);
        int a = advance(f, cp);
        if (w + a > max_w) break;
        w += a;
        p = q;
        if (cp == ' ' || cp == '-') last_space = p;
    }
    if (*p && *p != '\n' && last_space) return (size_t)(last_space - utf8);
    if (p == utf8 && *p && *p != '\n') ui_utf8_next(&p); /* always make progress */
    return (size_t)(p - utf8);
}
