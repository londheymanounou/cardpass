/* File browser for choosing a key file: in KeePass any file can be a key file, so this walks the whole SD card
 * (folders first, ".." to go up, starting in the database folder). Shown from the unlock screen with Tab. */
#include <stdlib.h>
#include "app_priv.h"

#define BR_MAX 160

static int cmp_ent(const void *x, const void *y)
{
    const app_dirent *a = x, *b = y;
    if (a->dir != b->dir) return a->dir ? -1 : 1;                  /* folders first */
    return strcmp(a->name, b->name);
}

static int has_up(const app *a) { return a->br_dir[0] ? 1 : 0; }
static int rows(const app *a) { return a->br_n + has_up(a); }
static bool is_up(const app *a, int i) { return has_up(a) && i == 0; }
static const app_dirent *ent(const app *a, int i) { return &a->br_ents[i - has_up(a)]; }

void ap_browse_free(app *a)
{
    free(a->br_ents);
    a->br_ents = NULL;
    a->br_n = 0;
}

static void load(app *a)
{
    a->br_n = a->br_ents ? a->p->list_dir(a->p->ctx, a->br_dir, a->br_ents, BR_MAX) : 0;
    if (a->br_n < 0) a->br_n = 0;
    if (a->br_n > 1) qsort(a->br_ents, (size_t)a->br_n, sizeof *a->br_ents, cmp_ent);
    a->sel = a->top = 0;
}

static void select_row(app *a, int i)
{
    int vis = ap_visible(a);
    a->sel = i;
    a->top = i >= vis ? i - vis + 1 : 0;
}

void ap_browse_open(app *a)
{
    ap_browse_free(a);
    a->br_ents = calloc(BR_MAX, sizeof *a->br_ents);
    if (!a->br_ents) { snprintf(a->msg, sizeof a->msg, "Out of memory"); ap_mark_all(a); return; }
    a->br_dir[0] = 0;
    const char *chosen = NULL;
    if (a->keyrel[0]) {                                  /* start where the current key file is, with it selected */
        const char *sl = strrchr(a->keyrel, '/');
        if (sl) { size_t n = (size_t)(sl - a->keyrel); memcpy(a->br_dir, a->keyrel, n); a->br_dir[n] = 0; }
        chosen = sl ? sl + 1 : a->keyrel;
    } else {
        a->p->start_dir(a->p->ctx, a->br_dir, sizeof a->br_dir);
    }
    load(a);
    if (chosen)
        for (int i = has_up(a); i < rows(a); i++)
            if (!ent(a, i)->dir && !strcmp(ent(a, i)->name, chosen)) { select_row(a, i); break; }
    a->scr = SCR_BROWSE;
    a->msg[0] = 0;
    ap_mark_all(a);
}

static void leave(app *a)
{
    ap_browse_free(a);
    a->scr = SCR_UNLOCK;
    ap_mark_all(a);
}

static void go_up(app *a)
{
    if (!a->br_dir[0]) return;
    char came[64] = "";
    const char *sl = strrchr(a->br_dir, '/');
    snprintf(came, sizeof came, "%.63s", sl ? sl + 1 : a->br_dir);
    if (sl) a->br_dir[sl - a->br_dir] = 0;
    else a->br_dir[0] = 0;
    load(a);
    for (int i = has_up(a); i < rows(a); i++)            /* land on the folder we came out of */
        if (ent(a, i)->dir && !strcmp(ent(a, i)->name, came)) { select_row(a, i); break; }
}

static bool join(char *dst, size_t n, const char *dir, const char *name)
{
    int w = dir[0] ? snprintf(dst, n, "%s/%s", dir, name) : snprintf(dst, n, "%s", name);
    return w > 0 && (size_t)w < n;
}

void ap_browse_key(app *a, uint32_t k, bool fn)
{
    (void)fn;
    ap_mark_all(a);
    a->msg[0] = 0;
    int n = rows(a);
    if (k == K_UP && n) ap_move_sel(a, n, -1);
    else if (k == K_DOWN && n) ap_move_sel(a, n, 1);
    else if (k == K_LEFT || k == K_BACKSPACE) go_up(a);
    else if (k == K_ENTER && n) {
        if (is_up(a, a->sel)) { go_up(a); return; }
        const app_dirent *e = ent(a, a->sel);
        char path[sizeof a->keyrel];
        if (!join(path, sizeof path, a->br_dir, e->name)) { snprintf(a->msg, sizeof a->msg, "Path too long"); return; }
        if (e->dir) {
            snprintf(a->br_dir, sizeof a->br_dir, "%s", path);
            load(a);
        } else {
            snprintf(a->keyrel, sizeof a->keyrel, "%s", path);
            leave(a);
        }
    } else if (k == K_ESC || k == '`') leave(a);
}

static void size_text(char *out, size_t n, uint32_t b)
{
    if (b < 1024) snprintf(out, n, "%u B", (unsigned)b);
    else if (b < 1024 * 1024) snprintf(out, n, "%.1f KB", b / 1024.0);
    else snprintf(out, n, "%.1f MB", b / 1048576.0);
}

void ap_browse_draw(app *a, ui_strip *s, const char **hint)
{
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    int n = rows(a);
    for (int i = a->top; i < n && i < a->top + ap_visible(a); i++) {
        int y = CONTENT_Y + (i - a->top) * ap_row_h(a), h = ap_row_h(a);
        if (y + h <= s->y0 || y >= s->y0 + s->h) continue;
        bool sel = i == a->sel;
        ap_row_bg(a, s, y, h, i);
        const char *icon, *name;
        char size[16] = "";
        bool dir = true;
        if (is_up(a, i)) { icon = ICON_FOLDER_OPEN; name = ".."; }
        else {
            const app_dirent *e = ent(a, i);
            dir = e->dir;
            icon = dir ? ICON_FOLDER : ICON_FILE;
            name = e->name;
            if (!dir) size_text(size, sizeof size, e->size);
        }
        int sw = size[0] ? ui_text_width(&ui_font_small, size) : 0;
        int sy = y + (h - ui_font_small.height) / 2;
        ui_text(s, &ui_font_small, PAD + 2, sy, icon, dir ? T->accent : T->dim, 14);
        ui_text(s, F, PAD + 18, y + (h - F->height) / 2, name, sel ? T->sel_fg : T->fg, UI_W - PAD * 2 - 18 - sw - 8);
        if (sw) ui_text(s, &ui_font_small, UI_W - PAD - 6 - sw, sy, size, T->dim, sw);
    }
    if (!n) ui_text(s, F, PAD * 2, CONTENT_Y + 12, "(empty folder)", T->dim, UI_W - PAD * 4);
    ap_draw_scrollbar(a, s, n);
    ap_draw_toast(a, s);
    *hint = U_ENTER " open  left: up  ` cancel";
}
