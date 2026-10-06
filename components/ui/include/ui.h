/* CardPass UI core: portable C, no display driver. Screens draw into a strip
 * (a horizontal band of the 240x135 panel, RGB565) which the platform pushes to
 * the panel; no full framebuffer (65 KB) ever exists. On the PC the strips are
 * assembled into PNGs (tests/host/render.c). */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define UI_W 240
#define UI_H 135

/* ---------------- fonts ---------------- */
typedef struct { uint32_t cp; uint8_t w, h; int8_t xoff, yoff; uint8_t adv; uint32_t off; } ui_glyph;
/* bpp 4: anti-aliased, rows padded to bytes, high nibble first; bpp 0/1: 1-bit rows. idx: glyph index + 1 for
 * code points below nidx (0 = missing), so the common lookup is one table read. */
typedef struct {
    const ui_glyph *g; size_t n; const uint8_t *bits; int ascent, height;
    uint8_t bpp; const uint16_t *idx; uint16_t nidx;
} ui_font;
/* IBM Plex Sans, the Bio-Resonant typeface (font_br.c): */
extern const ui_font ui_font_small;   /* 12 px: labels, hints, status, toasts */
extern const ui_font ui_font_title;   /* 12 px Medium: screen titles */
extern const ui_font ui_font_body;    /* 13 px: rows and values */
extern const ui_font ui_font_large;   /* 21 px: rows and values in large text, the Bio-Resonant caption size */
extern const ui_font ui_font_px;      /* Cozette pixel font: icons and anything Plex lacks (font_data.c) */

/* ---------------- drawing ---------------- */
typedef struct {
    uint16_t *px;   /* UI_W * h pixels */
    int y0, h;      /* screen rows y0 .. y0+h-1 */
} ui_strip;

#define RGB565(r, g, b) (uint16_t)((((r) & 0xF8) << 8) | (((g) & 0xFC) << 3) | ((b) >> 3))

void ui_fill(ui_strip *s, int x, int y, int w, int h, uint16_t c);
uint16_t ui_mix(uint16_t dst, uint16_t src, int a);   /* a: 0..255 of src over dst */
/* Bio-Resonant superellipse ("squircle", n = 4; a capsule when r reaches half the short side; n = 2.5 below the
 * crossover radius), anti-aliased from a cached corner quadrant. ring: outer shape in ring, inner one inset by
 * stroke at radius r - stroke (parallel curves), filled with fill. */
/* Ink on the accent fill is always the on-accent ink (Bio-Resonant ink-on-accent): text landing on a `fill` pixel
 * is drawn in `ink` instead of the colour asked for. Set once per draw from the theme. */
void ui_set_on_fill(uint16_t fill, uint16_t ink);
void ui_round(ui_strip *s, int x, int y, int w, int h, int r, uint16_t c);
void ui_round_ring(ui_strip *s, int x, int y, int w, int h, int r, int stroke, uint16_t ring, uint16_t fill);
/* Draws utf8 with its top at y; clipped to max_w pixels with "…" if longer.
 * Returns the width drawn. Missing glyphs are drawn as a box, never garbage. */
int ui_text(ui_strip *s, const ui_font *f, int x, int y, const char *utf8, uint16_t fg, int max_w);
int ui_text_width(const ui_font *f, const char *utf8);
/* Byte length of the longest prefix of utf8 that fits in max_w (word wrap helper:
 * prefers breaking after a space). */
size_t ui_wrap(const ui_font *f, const char *utf8, int max_w);
uint32_t ui_utf8_next(const char **s);
extern int ui_overflow; /* host builds: text that ran off the panel edge */

/* ---------------- theme ---------------- */
/* Bio-Resonant roles (generated from its tokens by tools/gen_br_theme.py, theme_br.c) */
typedef struct {
    uint16_t bg, fg, dim, faint, accent, sel_bg, sel_fg, bar_bg, bar_fg, ok, warn, danger, field_bg;
    uint16_t raised, overlay, rule, ring, focus;
    bool dark;
} ui_theme;
enum { UI_THEME_DUSK, UI_THEME_DEEP_NIGHT, UI_THEME_DAYLIGHT, UI_THEME_SUNRISE, UI_THEMES };
extern const ui_theme ui_themes[UI_THEMES];
extern const char *const ui_theme_names[UI_THEMES];

/* Bio-Resonant geometry, panel pixels: its tokens (cardputer/tokens.h, caption 21 px) scaled by 13/21 to CardPass's
 * body size, rounded. Large text uses the unscaled tokens. */
#define UI_RADIUS_XS 4
#define UI_RADIUS_SM 7
#define UI_STROKE 1
#define UI_SHAPE_CROSSOVER 6
