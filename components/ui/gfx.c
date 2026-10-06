/* CardPass drawing, Bio-Resonant look. Everything draws into a strip (a band of the 240x135 panel): no
 * framebuffer ever exists. Hot paths, because every strip redraws everything that crosses it:
 *   - glyphs are found through a direct index (one table read below U+0500), not a search;
 *   - 4-bit anti-aliased text is blended through a cached 16-colour ramp per (background, ink) pair: one table
 *     read per pixel instead of three multiplies and three divides;
 *   - fills write two pixels per 32-bit store when the row is aligned;
 *   - superellipse corners come from one coverage quadrant per radius, computed once and mirrored (4x4
 *     supersampled, exact by symmetry), so drawing a shape never supersamples;
 *   - text that does not cross the strip is only measured, never decoded. */
#include <math.h>
#include <stdint.h>
#include <string.h>
#include "ui.h"

int ui_overflow;

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

/* ======================= pixels ======================= */

/* floor(x / 255) without a divide, exact for x <= 65534 */
static inline int div255(int x) { return (x + 1 + (x >> 8)) >> 8; }

uint16_t ui_mix(uint16_t dst, uint16_t src, int a)
{
    if (a >= 255) return src;
    if (a <= 0) return dst;
    int r = div255((dst >> 11) * (255 - a) + (src >> 11) * a);
    int g = div255(((dst >> 5) & 63) * (255 - a) + ((src >> 5) & 63) * a);
    int b = div255((dst & 31) * (255 - a) + (src & 31) * a);
    return (uint16_t)(r << 11 | g << 5 | b);
}

typedef uint32_t __attribute__((may_alias)) u32_alias;

static inline void span(uint16_t *row, int x0, int x1, uint16_t c)
{
    if (x0 < 0) x0 = 0;
    if (x1 > UI_W) x1 = UI_W;
    if (x0 >= x1) return;
#ifdef UI_NAIVE
    for (int i = x0; i < x1; i++) row[i] = c;
    return;
#endif
    if (((uintptr_t)(row + x0) & 3) && x0 < x1) row[x0++] = c;
    uint32_t cc = (uint32_t)c << 16 | c;
    u32_alias *p = (u32_alias *)(void *)(row + x0);
    int n = (x1 - x0) >> 1;
    for (int i = 0; i < n; i++) p[i] = cc;
    if ((x1 - x0) & 1) row[x1 - 1] = c;
}

void ui_fill(ui_strip *s, int x, int y, int w, int h, uint16_t c)
{
    int y1 = y + h;
    if (y < s->y0) y = s->y0;
    if (y1 > s->y0 + s->h) y1 = s->y0 + s->h;
    for (int yy = y; yy < y1; yy++) span(s->px + (yy - s->y0) * UI_W, x, x + w, c);
}

/* 16-step blend ramps, (background, ink) -> colour per 4-bit coverage. Text is drawn on a handful of surfaces,
 * so 8 slots cover a screen; a miss costs 14 blends once. */
typedef struct { uint16_t bg, fg, c[16]; bool used; } ramp;
static ramp ramps[8];
static unsigned ramp_next;

static const uint16_t *get_ramp(uint16_t bg, uint16_t fg)
{
    for (int i = 0; i < 8; i++)
        if (ramps[i].used && ramps[i].bg == bg && ramps[i].fg == fg) return ramps[i].c;
    ramp *r = &ramps[ramp_next++ & 7];
    r->bg = bg, r->fg = fg, r->used = true;
    r->c[0] = bg;
    for (int k = 1; k < 15; k++) r->c[k] = ui_mix(bg, fg, k * 17);
    r->c[15] = fg;
    return r->c;
}

/* ======================= text ======================= */

static uint16_t on_fill = 0, on_ink = 0;
static bool on_set;
void ui_set_on_fill(uint16_t fill, uint16_t ink) { on_fill = fill, on_ink = ink, on_set = true; }

static const ui_glyph *find(const ui_font *f, uint32_t cp)
{
#ifndef UI_NAIVE
    if (f->idx && cp < f->nidx) {
        uint16_t i = f->idx[cp];
        return i ? &f->g[i - 1] : NULL;
    }
#endif
    size_t lo = 0, hi = f->n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (f->g[mid].cp < cp) lo = mid + 1;
        else hi = mid;
    }
    return lo < f->n && f->g[lo].cp == cp ? &f->g[lo] : NULL;
}

/* Glyph for cp; icons and anything the face lacks come from the pixel font. */
static const ui_glyph *glyph(const ui_font *f, uint32_t cp, const ui_font **from)
{
    const ui_glyph *g = find(f, cp);
    if (g) { *from = f; return g; }
    if (f != &ui_font_px && (g = find(&ui_font_px, cp))) { *from = &ui_font_px; return g; }
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
    if (!g) { /* placeholder box: never garbage */
        int w = f->height / 2 - 1, h = f->ascent - 1;
        ui_fill(s, x, base - h, w, 1, fg);
        ui_fill(s, x, base - 1, w, 1, fg);
        ui_fill(s, x, base - h, 1, h, fg);
        ui_fill(s, x + w - 1, base - h, 1, h, fg);
        return;
    }
    int top = base - g->yoff - g->h;
    if (from != f) top = base - (f->ascent - from->ascent) / 2 - g->yoff - g->h; /* centre pixel-font icons */
    int r0 = s->y0 - top > 0 ? s->y0 - top : 0, r1 = s->y0 + s->h - top < g->h ? s->y0 + s->h - top : g->h;
    if (r0 >= r1) return;
    int gx = x + g->xoff;
    const uint8_t *b = from->bits + g->off;
    if (from->bpp == 4) {
        int bpr = (g->w + 1) >> 1;
        uint16_t last_bg = 0;
        const uint16_t *rp = NULL;
        for (int r = r0; r < r1; r++) {
            uint16_t *row = s->px + (top + r - s->y0) * UI_W;
            const uint8_t *src = b + r * bpr;
            for (int c = 0; c < g->w; c++) {
                int k = (c & 1) ? src[c >> 1] & 15 : src[c >> 1] >> 4;
                if (!k) continue;
                int xx = gx + c;
                if (xx < 0 || xx >= UI_W) { ui_overflow++; continue; }
                uint16_t d = row[xx], ink = on_set && d == on_fill ? on_ink : fg;
#ifdef UI_NAIVE
                row[xx] = ui_mix(d, ink, k * 17);
                (void)rp, (void)last_bg;
#else
                if (k == 15) { row[xx] = ink; continue; }
                if (!rp || d != last_bg) rp = get_ramp(last_bg = d, ink);
                row[xx] = rp[k];
#endif
            }
        }
    } else {
        int bpr = (g->w + 7) / 8;
        for (int r = r0; r < r1; r++) {
            uint16_t *row = s->px + (top + r - s->y0) * UI_W;
            for (int c = 0; c < g->w; c++) {
                if (!(b[r * bpr + c / 8] & (0x80 >> (c % 8)))) continue;
                int xx = gx + c;
                if (xx < 0 || xx >= UI_W) { ui_overflow++; continue; }
                row[xx] = on_set && row[xx] == on_fill ? on_ink : fg;
            }
        }
    }
}

int ui_text(ui_strip *s, const ui_font *f, int x, int y, const char *utf8, uint16_t fg, int max_w)
{
    int full = ui_text_width(f, utf8);
    if (y >= s->y0 + s->h || y + f->height <= s->y0) return full < max_w ? full : max_w;   /* measured, not decoded */
    int dots = advance(f, 0x2026), w = 0;
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

/* ======================= superellipse ======================= */

#define MAXR 16
typedef struct { int16_t r; int16_t n10; uint8_t cov[MAXR * MAXR]; } corner;
static corner corners[6];
static unsigned corner_next;

/* Bio-Resonant fit (its SPECIFICATION 2.2/2.3): 2r never exceeds the short side; when it would, r = half of it
 * and n = 2 (a capsule); below the crossover radius the exponent relaxes to 2.5. Returns n x 10. */
static int fit(int w, int h, int *r)
{
    int m = (w < h ? w : h) / 2;
    if (*r >= m) { *r = m; return 20; }
    return *r < UI_SHAPE_CROSSOVER ? 25 : 40;
}

static const uint8_t *corner_cov(int r, int n10)
{
    for (int k = 0; k < 6; k++)
        if (corners[k].r == r && corners[k].n10 == n10) return corners[k].cov;
    corner *c = &corners[corner_next++ % 6];
    c->r = (int16_t)r;
    c->n10 = (int16_t)n10;
    for (int j = 0; j < r; j++)
        for (int i = 0; i < r; i++) {
            int hit = 0;
            for (int b = 0; b < 4; b++)
                for (int a = 0; a < 4; a++) {
                    float u = fabsf(i + (a + 0.5f) / 4 - r) / r, v = fabsf(j + (b + 0.5f) / 4 - r) / r;
                    float e = n10 == 20 ? u * u + v * v
                            : n10 == 40 ? (u * u) * (u * u) + (v * v) * (v * v)
                                        : powf(u, 2.5f) + powf(v, 2.5f);
                    hit += e <= 1.0f;
                }
            c->cov[j * r + i] = (uint8_t)((hit * 15 + 8) / 16);   /* 4-bit: blended through the ramps */
        }
    return c->cov;
}

/* corner pixel: coverage k (0..15) of c over what is there, through the (background, colour) ramp */
static inline void px(uint16_t *row, int x, uint16_t c, int k, uint16_t *last_bg, const uint16_t **rp)
{
    if (x < 0 || x >= UI_W) return;
    if (k == 15) { row[x] = c; return; }
    uint16_t d = row[x];
    if (!*rp || d != *last_bg) *rp = get_ramp(*last_bg = d, c);
    row[x] = (*rp)[k];
}

void ui_round(ui_strip *s, int x, int y, int w, int h, int r, uint16_t c)
{
    if (w <= 0 || h <= 0) return;
    if (r < 0) r = 0;
    int n10 = fit(w, h, &r);
    if (r > MAXR) r = MAXR;
    const uint8_t *cov = r ? corner_cov(r, n10) : NULL;
    uint16_t last_bg = 0;
    const uint16_t *rp = NULL;
    int j0 = y > s->y0 ? y : s->y0, j1 = y + h < s->y0 + s->h ? y + h : s->y0 + s->h;
    for (int yy = j0; yy < j1; yy++) {
        uint16_t *row = s->px + (yy - s->y0) * UI_W;
        int jy = yy - y, qj = jy < r ? jy : jy >= h - r ? h - 1 - jy : -1;   /* row inside a corner zone, mirrored */
        if (qj < 0) { span(row, x, x + w, c); continue; }
        const uint8_t *cr = cov + qj * r;
        for (int i = 0; i < r; i++) {
            if (!cr[i]) continue;
            px(row, x + i, c, cr[i], &last_bg, &rp);
            px(row, x + w - 1 - i, c, cr[i], &last_bg, &rp);
        }
        span(row, x + r, x + w - r, c);
    }
}

void ui_round_ring(ui_strip *s, int x, int y, int w, int h, int r, int stroke, uint16_t ring, uint16_t fill)
{
    ui_round(s, x, y, w, h, r, ring);
    ui_round(s, x + stroke, y + stroke, w - 2 * stroke, h - 2 * stroke, r > stroke ? r - stroke : 0, fill);
}
