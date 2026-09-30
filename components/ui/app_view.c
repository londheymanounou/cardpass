/* Read-only text view of an attachment. The bytes are re-read from the (verified) database file into
 * a heap buffer that is wiped when the viewer closes or the device locks; nothing is ever written
 * out. Binary files are not shown (open them on the PC). */
#include "app_priv.h"

#define VIEW_MAX 16384        /* first 16 KB: notes, recovery codes, SSH configs; RAM is tight while unlocked */
#define MAX_LINES 1024

struct app_view {
    char name[64];
    uint8_t *buf;
    size_t len;
    uint32_t size;
    bool text, truncated;
    uint16_t *line;           /* start offset of every wrapped line */
    int nlines, top;
    char note[64];
};

const char *ap_view_name(const app *a) { return a->view ? a->view->name : ""; }

void ap_view_free(app *a)
{
    struct app_view *v = a->view;
    if (!v) return;
    if (v->buf) ap_wipe(v->buf, VIEW_MAX + 1), free(v->buf);
    free(v->line);
    free(v);
    a->view = NULL;
}

static void wrap_lines(app *a, struct app_view *v)
{
    size_t off = 0;
    v->nlines = 0;
    while (off < v->len) {
        if (v->nlines == MAX_LINES) { v->truncated = true; break; }
        v->line[v->nlines++] = (uint16_t)off;
        size_t n = ui_wrap(F, (const char *)v->buf + off, UI_W - 2 * PAD - 4);
        if (n == 0) n = 1;
        off += n;
        if (off < v->len && v->buf[off] == '\n') off++;
        else while (off < v->len && v->buf[off] == ' ') off++;   /* the break was a space */
    }
}

void ap_view_open(app *a, const kdbx_attachment *att)
{
    ap_view_free(a);
    struct app_view *v = a->view = calloc(1, sizeof *v);
    if (!v) { snprintf(a->msg, sizeof a->msg, "Out of memory"); return; }
    snprintf(v->name, sizeof v->name, "%s", att->name);
    v->size = att->size;
    v->buf = calloc(1, VIEW_MAX + 1);
    v->line = malloc(sizeof *v->line * MAX_LINES);
    a->scr = SCR_VIEW;
    ap_mark_all(a);
    if (!v->buf || !v->line) { snprintf(v->note, sizeof v->note, "Out of memory"); return; }
    size_t got = 0;
    snprintf(v->note, sizeof v->note, "Reading\xE2\x80\xA6");
    a->p->present(a->p->ctx);
    kdbx_err e = kdbx_attachment_read(a->db, a->path, att, v->buf, VIEW_MAX, &got);
    v->note[0] = 0;
    if (e) { snprintf(v->note, sizeof v->note, "%s", kdbx_strerror(e)); return; }
    v->len = got;
    v->truncated = att->size > got;
    v->text = kdbx_is_text(v->buf, got, v->truncated);
    if (!v->text) {
        snprintf(v->note, sizeof v->note, "Not a text file (%.1f KB): open it on the PC", att->size / 1024.0);
        return;
    }
    for (size_t i = 0; i < got; i++)
        if (v->buf[i] == '\t' || v->buf[i] == '\r') v->buf[i] = ' ';
    wrap_lines(a, v);
}

static int rows(const app *a) { return CONTENT_H / ap_row_h(a); }

void ap_view_key(app *a, uint32_t k, bool fn)
{
    struct app_view *v = a->view;
    (void)fn;
    if (!v) return;
    int max_top = v->nlines > rows(a) ? v->nlines - rows(a) : 0;
    if (k == K_UP) v->top = v->top > 0 ? v->top - 1 : 0;
    else if (k == K_DOWN) v->top = v->top < max_top ? v->top + 1 : max_top;
    else if (k == K_LEFT) v->top = v->top > rows(a) ? v->top - rows(a) : 0;
    else if (k == K_RIGHT) v->top = v->top + rows(a) < max_top ? v->top + rows(a) : max_top;
    else if (k == '`' || k == K_ESC) { ap_view_free(a); a->scr = SCR_ENTRY; }
    ap_mark_all(a);
}

void ap_view_draw(app *a, ui_strip *s, const char **hint)
{
    struct app_view *v = a->view;
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    if (!v) return;
    if (!v->text) {
        ui_text(s, F, PAD * 2, CONTENT_Y + 8, v->name, T->accent, UI_W - PAD * 4);
        int y = CONTENT_Y + 8 + F->height + 6;
        const char *t = v->note;
        for (int line = 0; line < 3 && *t; line++) {
            char b[64];
            size_t n = ui_wrap(&ui_font_small, t, UI_W - PAD * 4);
            snprintf(b, sizeof b, "%.*s", (int)n, t);
            ui_text(s, &ui_font_small, PAD * 2, y + line * 13, b, T->dim, UI_W - PAD * 4);
            t += n;
        }
        *hint = "` back";
        return;
    }
    int h = ap_row_h(a);
    for (int r = 0; r < rows(a) && v->top + r < v->nlines; r++) {
        int i = v->top + r, y = CONTENT_Y + r * h;
        if (y + h <= s->y0 || y >= s->y0 + s->h) continue;
        size_t off = v->line[i], end = i + 1 < v->nlines ? v->line[i + 1] : v->len;
        char b[160];
        size_t n = end - off < sizeof b - 1 ? end - off : sizeof b - 1;
        while (n && (v->buf[off + n - 1] == '\n' || v->buf[off + n - 1] == ' ')) n--;
        memcpy(b, v->buf + off, n);
        b[n] = 0;
        ui_text(s, F, PAD * 2, y + (h - F->height) / 2, b, T->fg, UI_W - PAD * 4 - 4);
    }
    ap_draw_scrollbar_in(a, s, v->top, v->nlines);
    if (v->truncated && v->top + rows(a) >= v->nlines) ui_text(s, &ui_font_small, PAD * 2, UI_H - FOOT_H - 12, "\xE2\x80\xA6 first 16 KB shown", T->dim, UI_W);
    *hint = U_UPDOWN " scroll  " U_LR " page  ` back";
}
