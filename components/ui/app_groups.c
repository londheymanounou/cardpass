/* Group management: create, rename, move, delete (recycle bin semantics) and moving an entry.
 * Every change is one safe save; pointers are re-found by UUID afterwards (ap_save). */
#include "app_priv.h"

enum { G_NEW, G_RENAME, G_MOVE, G_DELETE, G_ACTIONS, G_ENTRY_MOVE };
enum { GM_ACTIONS, GM_NAME, GM_CHOOSE };

struct app_groups {
    int mode, action;
    int back;                     /* screen to return to */
    uint8_t target[16];           /* group (or entry) the action applies to */
    char name[48];
    int namelen;
    const kdbx_group **gl;        /* destination list, tree order */
    int *depth;
    int ng;
};

void ap_groups_free(app *a)
{
    if (!a->grp) return;
    free(a->grp->gl);
    free(a->grp->depth);
    free(a->grp);
    a->grp = NULL;
}

static bool is_root(const app *a, const kdbx_group *g) { return g == kdbx_root_group(a->db); }
static bool is_bin(const app *a, const kdbx_group *g) { return g == kdbx_recycle_bin(a->db); }

static void collect(struct app_groups *m, const kdbx_db *db, const kdbx_group *parent, int d, const kdbx_group *skip)
{
    for (const kdbx_group *c = kdbx_groups(db); c; c = c->next) {
        if (c->parent != parent || c == skip) continue;   /* skip: a moved group and everything below it */
        m->gl[m->ng] = c;
        m->depth[m->ng++] = d;
        collect(m, db, c, d + 1, skip);
    }
}

/* Destination list. A group can't go into itself or below itself; no-op moves are left out. */
static bool build_choices(app *a)
{
    struct app_groups *m = a->grp;
    int n = 0;
    for (const kdbx_group *g = kdbx_groups(a->db); g; g = g->next) n++;
    free(m->gl);
    free(m->depth);
    m->gl = malloc(sizeof *m->gl * (size_t)n);
    m->depth = malloc(sizeof *m->depth * (size_t)n);
    m->ng = 0;
    if (!m->gl || !m->depth) return false;
    const kdbx_group *root = kdbx_root_group(a->db), *skip = m->action == G_MOVE ? ap_find_group(a->db, m->target) : NULL;
    m->gl[m->ng] = root;
    m->depth[m->ng++] = 0;
    collect(m, a->db, root, 1, skip);
    /* drop the current location: moving there changes nothing */
    const kdbx_group *here = m->action == G_MOVE ? (skip ? skip->parent : NULL) : a->entry ? a->entry->group : NULL;
    int k = 0;
    for (int i = 0; i < m->ng; i++)
        if (m->gl[i] != here) { m->gl[k] = m->gl[i]; m->depth[k++] = m->depth[i]; }
    m->ng = k;
    return true;
}

static void open_common(app *a, int mode, int action, int back)
{
    ap_groups_free(a);
    if (!(a->grp = calloc(1, sizeof *a->grp))) return;
    a->grp->mode = mode;
    a->grp->action = action;
    a->grp->back = back;
    a->scr = SCR_GROUPS;
    a->sel = a->top = 0;
    a->msg[0] = 0;
    ap_mark_all(a);
}

void ap_groups_open(app *a)                       /* actions for the group being viewed */
{
    int back = a->scr == SCR_GROUP ? SCR_GROUP : SCR_HOME;
    const kdbx_group *g = a->group ? a->group : kdbx_root_group(a->db);
    open_common(a, GM_ACTIONS, G_ACTIONS, back);
    if (a->grp) memcpy(a->grp->target, g->uuid, 16);
}

void ap_groups_move_entry(app *a)
{
    uint8_t u[16];
    memcpy(u, a->entry->uuid, 16);
    open_common(a, GM_CHOOSE, G_ENTRY_MOVE, SCR_ENTRY);
    if (!a->grp) return;
    memcpy(a->grp->target, u, 16);
    if (!build_choices(a)) ap_groups_free(a);
}

static void finish(app *a, bool ok)
{
    int back = a->grp->back;
    ap_groups_free(a);
    if (ok && back == SCR_ENTRY && a->entry) { char m[64]; memcpy(m, a->msg, sizeof m); ap_open_entry(a, a->entry); memcpy(a->msg, m, sizeof m); }
    else if (ok) { char m[64]; memcpy(m, a->msg, sizeof m); ap_go_home(a); memcpy(a->msg, m, sizeof m); }
    else if (a->db) a->scr = back == SCR_ENTRY ? SCR_ENTRY : SCR_HOME, ap_mark_all(a);
}

void ap_groups_delete(app *a)                     /* after the confirmation */
{
    kdbx_edit ed[2];
    const kdbx_group *g = ap_find_group(a->db, a->grp->target);
    if (!g) { finish(a, false); return; }
    size_t n = kdbx_delete_group(a->db, g, ed);
    bool moved = ed[n - 1].op == KDBX_EDIT_GROUP_MOVE;
    a->entry = NULL;
    bool ok = ap_save(a, ed, n);
    if (ok) snprintf(a->msg, sizeof a->msg, moved ? "Moved to the recycle bin" : "Deleted");
    if (!a->grp) return;                            /* ap_save locked the app */
    finish(a, ok);
}

static void run(app *a)
{
    struct app_groups *m = a->grp;
    kdbx_edit e = {0};
    memcpy(e.uuid, m->target, 16);
    const kdbx_group *dest = m->mode == GM_CHOOSE && m->ng ? m->gl[a->sel] : NULL;
    switch (m->action) {
    case G_NEW: e.op = KDBX_EDIT_GROUP; e.create = true; e.name = m->name; memcpy(e.parent, m->target, 16); kdbx_new_uuid(e.uuid); break;
    case G_RENAME: e.op = KDBX_EDIT_GROUP; e.name = m->name; break;
    case G_MOVE: e.op = KDBX_EDIT_GROUP_MOVE; if (dest) memcpy(e.parent, dest->uuid, 16); break;
    case G_ENTRY_MOVE: e.op = KDBX_EDIT_ENTRY_MOVE; if (dest) memcpy(e.parent, dest->uuid, 16); break;
    default: return;
    }
    bool ok = ap_save(a, &e, 1);
    if (!a->grp) return;                            /* app was locked by a failed re-index */
    finish(a, ok);
}

static void start_action(app *a, int action)
{
    struct app_groups *m = a->grp;
    const kdbx_group *g = ap_find_group(a->db, m->target);
    if (!g) return;
    if ((action == G_MOVE || action == G_DELETE) && (is_root(a, g) || is_bin(a, g))) {
        snprintf(a->msg, sizeof a->msg, is_root(a, g) ? "The root group stays" : "The recycle bin stays");
        return;
    }
    m->action = action;
    a->sel = a->top = 0;
    if (action == G_NEW || action == G_RENAME) {
        m->mode = GM_NAME;
        snprintf(m->name, sizeof m->name, "%s", action == G_RENAME ? g->name : "");
        m->namelen = (int)strlen(m->name);
    } else if (action == G_MOVE) {
        m->mode = GM_CHOOSE;
        if (!build_choices(a)) { ap_groups_free(a); ap_go_home(a); }
    } else {
        char t[64];
        snprintf(t, sizeof t, "Delete group \"%.30s\" and all inside?", g->name);
        a->menu_back = SCR_GROUPS;
        ap_confirm(a, CONFIRM_DELETE_GROUP, t);
    }
}

void ap_groups_key(app *a, uint32_t k, bool fn)
{
    struct app_groups *m = a->grp;
    if (!m) return;
    a->msg[0] = 0;
    ap_mark_all(a);
    if (m->mode == GM_NAME) {
        if (k == K_ENTER && m->name[0]) run(a);
        else if (k == K_ESC || (k == '`' && fn)) { m->mode = GM_ACTIONS; a->sel = m->action; }
        else if (k == K_BACKSPACE) ap_utf8_backspace(m->name, &m->namelen);
        else if (ap_printable(k) && !fn) ap_utf8_append(m->name, &m->namelen, sizeof m->name, k);
        return;
    }
    int n = m->mode == GM_ACTIONS ? 4 : m->ng;
    if (k == K_UP) ap_move_sel(a, n, -1);
    else if (k == K_DOWN) ap_move_sel(a, n, 1);
    else if (k == '`' || k == K_ESC) {
        if (m->mode == GM_CHOOSE && m->action != G_ENTRY_MOVE) { m->mode = GM_ACTIONS; a->sel = m->action; a->top = 0; }
        else finish(a, false);
    } else if (k == K_ENTER) {
        if (m->mode == GM_ACTIONS) start_action(a, a->sel);
        else if (m->ng) run(a);
    }
}

void ap_groups_draw(app *a, ui_strip *s, const char **hint)
{
    struct app_groups *m = a->grp;
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    if (!m) return;
    if (m->mode == GM_NAME) {
        ui_text(s, &ui_font_small, PAD * 2, CONTENT_Y + 6, m->action == G_NEW ? "Name of the new group" : "New name", T->dim, UI_W);
        ap_draw_field(a, s, PAD * 2, CONTENT_Y + 22, UI_W - PAD * 4, F->height + 6, m->name, false, m->namelen);
        ap_draw_toast(a, s);
        *hint = U_ENTER " save  fn+` back";
        return;
    }
    if (m->mode == GM_ACTIONS) {
        static const char *const names[] = {"New group here", "Rename this group", "Move this group", "Delete this group"};
        static const char *const icons[] = {"+", ICON_COG, ICON_FOLDER_OPEN, ICON_TRASH};
        const kdbx_group *g = ap_find_group(a->db, m->target);
        for (int i = 0; i < 4; i++) {
            bool locked = g && (i >= G_MOVE) && (is_root(a, g) || is_bin(a, g));
            ap_draw_row(a, s, i, icons[i], locked ? T->dim : T->accent, names[i], locked ? "not here" : NULL, T->dim);
        }
        ap_draw_toast(a, s);
        *hint = U_ENTER " choose  ` back";
        return;
    }
    for (int i = a->top; i < m->ng && i < a->top + ap_visible(a); i++) {
        char t[80];
        int d = m->depth[i] < 8 ? m->depth[i] : 8;
        snprintf(t, sizeof t, "%*s%.60s", d * 2, "", m->gl[i]->name);
        ap_draw_row(a, s, i, ICON_FOLDER, T->accent, t, NULL, 0);
    }
    if (!m->ng) ui_text(s, F, PAD * 2, CONTENT_Y + 8, "No other group to move to", T->dim, UI_W);
    ap_draw_scrollbar(a, s, m->ng);
    *hint = m->action == G_ENTRY_MOVE ? U_ENTER " move here  ` cancel" : U_ENTER " move here  ` back";
}
