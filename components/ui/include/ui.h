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
typedef struct { const ui_glyph *g; size_t n; const uint8_t *bits; int ascent, height; } ui_font;
extern const ui_font ui_font_small, ui_font_large;

/* ---------------- drawing ---------------- */
typedef struct {
    uint16_t *px;   /* UI_W * h pixels */
    int y0, h;      /* screen rows y0 .. y0+h-1 */
} ui_strip;

#define RGB565(r, g, b) (uint16_t)((((r) & 0xF8) << 8) | (((g) & 0xFC) << 3) | ((b) >> 3))

void ui_fill(ui_strip *s, int x, int y, int w, int h, uint16_t c);
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
typedef struct {
    uint16_t bg, fg, dim, accent, sel_bg, sel_fg, bar_bg, bar_fg, ok, warn, danger, field_bg;
} ui_theme;
extern const ui_theme ui_dark, ui_light;
