/* Entry actions (type, auto-type, favorite, delete), saving, the entry editor
 * and the password generator. Plaintext being edited lives in heap buffers
 * that are wiped when the editor closes or the device locks. */
#include "app_priv.h"
#include "gen.h"
#include "search.h"
#include "typing.h"

/* ======================= typing ======================= */

typedef struct { app *a; } type_ctx;

static const kbd_layout *layout(app *a)
{
    for (int i = 0; i < kbd_layout_count(); i++)
        if (!strcmp(kbd_layout_name(kbd_layout_get(i)), a->cfg.layout)) return kbd_layout_get(i);
    return kbd_layout_get(0);
}

static bool at_field(void *ctx, const char *name, char *buf, size_t n)
{
    app *a = ((type_ctx *)ctx)->a;
    const kdbx_field *f = kdbx_field_get(a->entry, name);
    return f && kdbx_reveal(a->db, f, buf, n) == KDBX_OK;
}

/* Current code; waits for the next one if this one is about to expire. */
static bool at_totp(void *ctx, char *buf, size_t n)
{
    app *a = ((type_ctx *)ctx)->a;
    bool valid;
    int64_t now = a->p->now(a->p->ctx, &valid);
    if (!ap_totp_now(a, a->entry, NULL, buf, n)) return false;
    int per = a->totp_period ? a->totp_period : 30, rem = per - (int)(now % per);
    if (rem < 3) {
        a->p->delay(a->p->ctx, rem * 1000 + 100);
        return ap_totp_now(a, a->entry, NULL, buf, n);
    }
    return true;
}

static void at_stroke(void *ctx, uint8_t key, uint8_t mods) { app *a = ((type_ctx *)ctx)->a; a->p->stroke(a->p->ctx, key, mods); }
static void at_delay(void *ctx, int ms) { app *a = ((type_ctx *)ctx)->a; a->p->delay(a->p->ctx, ms); }

static void type_seq(app *a, const char *seq)
{
    if (!a->p->hid_ready(a->p->ctx)) {
        snprintf(a->msg, sizeof a->msg, "Connect USB or pair Bluetooth");
        return;
    }
    type_ctx c = {a};
    at_ops ops = {at_field, at_totp, at_stroke, at_delay, &c};
    at_error e;
    const kbd_layout *l = layout(a);
    switch (at_type(seq, l, &ops, a->cfg.typing_delay_ms, &e)) {
    case AT_OK: snprintf(a->msg, sizeof a->msg, "Typed " "\xE2\x9C\x93"); break;
    case AT_UNTYPEABLE: snprintf(a->msg, sizeof a->msg, "%s: not on %s", e.detail, kbd_layout_name(l)); break;
    case AT_UNSUPPORTED: snprintf(a->msg, sizeof a->msg, "Unsupported {%s}", e.detail); break;
    case AT_MISSING_FIELD: snprintf(a->msg, sizeof a->msg, "No field %s", e.detail); break;
    default: snprintf(a->msg, sizeof a->msg, "Bad auto-type sequence");
    }
}

/* ======================= saving ======================= */

static const kdbx_entry *find_entry(const kdbx_db *db, const uint8_t u[16])
{
    for (const kdbx_entry *e = kdbx_entries(db); e; e = e->next)
        if (!memcmp(e->uuid, u, 16)) return e;
    return NULL;
}

static const kdbx_group *find_group(const kdbx_db *db, const uint8_t u[16])
{
    for (const kdbx_group *g = kdbx_groups(db); g; g = g->next)
        if (!memcmp(g->uuid, u, 16)) return g;
    return NULL;
}

bool ap_save(app *a, const kdbx_edit *ed, size_t n)
{
    uint8_t eu[16] = {0}, gu[16] = {0}, ru[APP_RECENT][16];
    bool he = a->entry, hg = a->group;
    if (he) memcpy(eu, a->entry->uuid, 16);
    if (hg) memcpy(gu, a->group->uuid, 16);
    for (int i = 0; i < a->nrecent; i++) memcpy(ru[i], a->recent[i]->uuid, 16);
    snprintf(a->msg, sizeof a->msg, "Saving\xE2\x80\xA6");
    ap_mark_all(a);
    a->p->present(a->p->ctx);

    bool valid;
    int64_t now = a->p->now(a->p->ctx, &valid);
    kdbx_err e = kdbx_save(&a->db, a->path, ed, n, now, NULL, 0);
    if (!a->db) { /* saved, but the new index did not fit: start over */
        app_lock(a);
        snprintf(a->msg, sizeof a->msg, e ? "Saved. Unlock again" : "Saved");
        return false;
    }
    if (e) {
        snprintf(a->msg, sizeof a->msg, "Not saved: %s", kdbx_strerror(e));
        ap_mark_all(a);
        return false;
    }
    if (!ap_reindex(a)) {
        app_lock(a);
        snprintf(a->msg, sizeof a->msg, "Saved. Out of memory: unlock again");
        return false;
    }
    a->entry = he ? find_entry(a->db, eu) : NULL;
    a->group = hg ? find_group(a->db, gu) : NULL;
    if (!a->group) a->group = kdbx_root_group(a->db);
    int m = 0;
    for (int i = 0; i < a->nrecent; i++) {
        const kdbx_entry *x = find_entry(a->db, ru[i]);
        if (x) a->recent[m++] = x;
    }
    a->nrecent = m;
    snprintf(a->msg, sizeof a->msg, "Saved " "\xE2\x9C\x93");
    return true;
}

/* All strings of an entry as plaintext edit fields (values malloc'd; free with free_fields). */
static int entry_fields(app *a, const kdbx_entry *e, kdbx_edit_field *out, int max)
{
    int n = 0;
    for (size_t i = 0; i < e->nfields && n < max; i++) {
        const kdbx_field *f = &e->fields[i];
        char *v = malloc(f->len + 1);
        if (!v || kdbx_reveal(a->db, f, v, f->len + 1)) { free(v); continue; }
        out[n++] = (kdbx_edit_field){f->key, v, f->stream_off != KDBX_PLAIN};
    }
    return n;
}

static void free_fields(kdbx_edit_field *f, int n)
{
    for (int i = 0; i < n; i++) {
        ap_wipe((char *)f[i].value, strlen(f[i].value));
        free((char *)f[i].value);
    }
}

/* Toggle the "favorite" tag (the favorites list lives in the database itself). */
static void toggle_favorite(app *a)
{
    const kdbx_entry *e = a->entry;
    kdbx_edit_field fields[64];
    int n = entry_fields(a, e, fields, 64);
    char tags[256] = "";
    bool fav = search_has_tag(e->tags, "favorite");
    /* rebuild the tag list without "favorite", then add it back if turning on */
    for (const char *p = e->tags; *p;) {
        size_t len = strcspn(p, ";,");
        char t[128];
        snprintf(t, sizeof t, "%.*s", (int)len, p);
        char *s = t;
        while (*s == ' ') s++;
        if (*s && !search_has_tag(s, "favorite") && strlen(tags) + strlen(s) + 2 < sizeof tags) {
            if (*tags) strcat(tags, ";");
            strcat(tags, s);
        }
        p += len;
        if (*p) p++;
    }
    if (!fav && strlen(tags) + 10 < sizeof tags) {
        if (*tags) strcat(tags, ";");
        strcat(tags, "favorite");
    }
    kdbx_edit ed = {.op = KDBX_EDIT_ENTRY, .fields = fields, .nfields = (size_t)n, .tags = tags,
                    .expires = e->expires, .expiry = e->expiry};
    memcpy(ed.uuid, e->uuid, 16);
    bool ok = ap_save(a, &ed, 1);
    free_fields(fields, n);
    if (ok && a->entry) {
        ap_open_entry(a, a->entry);
        snprintf(a->msg, sizeof a->msg, fav ? "Removed from favorites" : "Added to favorites");
    }
}

bool ap_entry_key(app *a, uint32_t k, bool fn)
{
    const app_row *r = a->nrows ? &a->rows[a->sel] : NULL;
    if (k == K_ENTER && r) {
        char seq[80];
        switch (r->kind) {
        case R_USER: type_seq(a, "{USERNAME}"); break;
        case R_PASS: type_seq(a, "{PASSWORD}"); break;
        case R_URL: type_seq(a, "{URL}"); break;
        case R_TOTP: type_seq(a, "{TOTP}"); break;
        case R_NOTES: type_seq(a, "{NOTES}"); break;
        case R_FIELD:
            if (strchr(r->f->key, '}') || strlen(r->f->key) > 60) snprintf(a->msg, sizeof a->msg, "Can't type this field");
            else snprintf(seq, sizeof seq, "{S:%s}", r->f->key), type_seq(a, seq);
            break;
        default: return false;
        }
    } else if (k == 'a' || k == 'A') {
        if (a->entry->autotype_off) snprintf(a->msg, sizeof a->msg, "Auto-type is off for this entry");
        else type_seq(a, kdbx_autotype(a->entry, a->cfg.autotype));
    } else if (k == 'f' || k == 'F') {
        toggle_favorite(a);
    } else if (k == 't' || k == 'T') {
        ap_time_open(a, SCR_ENTRY);
    } else if (k == 'e' || k == 'E') {
        ap_edit_open(a, a->entry, NULL);
    } else if (k == K_DEL || (fn && k == K_BACKSPACE)) {
        char t[64];
        snprintf(t, sizeof t, "Delete \"%.40s\"?", a->entry->title);
        ap_confirm(a, CONFIRM_DELETE_ENTRY, t);
    } else {
        return false;
    }
    ap_mark_all(a);
    return true;
}

/* ======================= entry editor ======================= */

#define ED_MAX 24

struct app_edit {
    bool create;
    uint8_t uuid[16], parent[16];
    int n;
    char key[ED_MAX][48];
    char *val[ED_MAX];
    int cap[ED_MAX];
    bool prot[ED_MAX], hidden[ED_MAX];  /* hidden: carried over untouched (passkey, TimeOtp-*) */
    char tags[160];
    bool expires;
    int64_t expiry;
    int rowmap[ED_MAX + 2];             /* visible row -> field index, -1 tags, -2 add */
    int nrows;
    int editing;                        /* row being edited, -1 none */
    bool editing_key;                   /* a new field: typing its name */
    int cursor;
    char *backup;
    int backup_cap;
    bool dirty;
};

static const char *const STD[] = {"Title", "UserName", "Password", "URL", "Notes"};

static bool hidden_key(const char *k)
{
    return !strncmp(k, "KPEX_PASSKEY_", 13) || !strncmp(k, "KPXC_PASSKEY_", 13) || !strncmp(k, "TimeOtp-", 8);
}

static bool add_field(struct app_edit *ed, const char *key, const char *val, bool prot)
{
    if (ed->n == ED_MAX) return false;
    int i = ed->n, len = (int)strlen(val);
    int cap = len + (strcmp(key, "Notes") ? 256 : 2048);
    if (!(ed->val[i] = calloc(1, (size_t)cap))) return false;
    memcpy(ed->val[i], val, (size_t)len);
    snprintf(ed->key[i], sizeof ed->key[i], "%s", key);
    ed->cap[i] = cap;
    ed->prot[i] = prot;
    ed->hidden[i] = hidden_key(key);
    ed->n++;
    return true;
}

static void build_rows(struct app_edit *ed)
{
    ed->nrows = 0;
    for (int i = 0; i < ed->n; i++)
        if (!ed->hidden[i]) ed->rowmap[ed->nrows++] = i;
    ed->rowmap[ed->nrows++] = -1;
    ed->rowmap[ed->nrows++] = -2;
}

void ap_edit_free(app *a)
{
    struct app_edit *ed = a->ed;
    if (!ed) return;
    for (int i = 0; i < ed->n; i++) ap_wipe(ed->val[i], (size_t)ed->cap[i]), free(ed->val[i]);
    if (ed->backup) ap_wipe(ed->backup, (size_t)ed->backup_cap), free(ed->backup);
    ap_wipe(ed, sizeof *ed);
    free(ed);
    a->ed = NULL;
}

void ap_edit_open(app *a, const kdbx_entry *e, const kdbx_group *parent)
{
    ap_edit_free(a);
    struct app_edit *ed = a->ed = calloc(1, sizeof *ed);
    if (!ed) { snprintf(a->msg, sizeof a->msg, "Out of memory"); return; }
    ed->editing = -1;
    char *buf = malloc(8192);
    if (!buf) { ap_edit_free(a); return; }
    for (int s = 0; s < 5; s++) { /* standard fields first, always present */
        const kdbx_field *f = e ? kdbx_field_get(e, STD[s]) : NULL;
        buf[0] = 0;
        if (f && kdbx_reveal(a->db, f, buf, 8192)) buf[0] = 0;
        add_field(ed, STD[s], buf, f ? f->stream_off != KDBX_PLAIN : s == 2);
    }
    for (size_t i = 0; e && i < e->nfields; i++) {
        const kdbx_field *f = &e->fields[i];
        bool std = false;
        for (int s = 0; s < 5; s++) std |= !strcmp(f->key, STD[s]);
        if (std) continue;
        buf[0] = 0;
        if (kdbx_reveal(a->db, f, buf, 8192)) buf[0] = 0;
        add_field(ed, f->key, buf, f->stream_off != KDBX_PLAIN);
    }
    ap_wipe(buf, 8192);
    free(buf);
    if (e) {
        ed->create = false;
        memcpy(ed->uuid, e->uuid, 16);
        snprintf(ed->tags, sizeof ed->tags, "%s", e->tags);
        ed->expires = e->expires;
        ed->expiry = e->expiry;
    } else {
        ed->create = true;
        kdbx_new_uuid(ed->uuid);
        const kdbx_group *g = parent ? parent : kdbx_root_group(a->db);
        memcpy(ed->parent, g->uuid, 16);
    }
    build_rows(ed);
    a->scr = SCR_EDIT;
    a->sel = a->top = 0;
    ap_mark_all(a);
}

static char *row_buf(struct app_edit *ed, int row, int *cap)
{
    *cap = 0;
    int fi = ed->rowmap[row];
    if (fi == -1) { *cap = (int)sizeof ed->tags; return ed->tags; }
    if (fi < 0) return NULL;
    if (ed->editing_key) { *cap = (int)sizeof ed->key[fi]; return ed->key[fi]; }
    *cap = ed->cap[fi];
    return ed->val[fi];
}

static void begin_edit(app *a, int row)
{
    struct app_edit *ed = a->ed;
    int cap;
    char *b = row_buf(ed, row, &cap);
    if (!b) return;
    if (ed->backup) ap_wipe(ed->backup, (size_t)ed->backup_cap), free(ed->backup);
    ed->backup = malloc((size_t)cap);
    ed->backup_cap = cap;
    if (ed->backup) memcpy(ed->backup, b, (size_t)cap);
    ed->editing = row;
    ed->cursor = (int)strlen(b);
}

static void end_edit(app *a, bool keep)
{
    struct app_edit *ed = a->ed;
    int cap;
    char *b = row_buf(ed, ed->editing, &cap);
    if (!keep && b && ed->backup) memcpy(b, ed->backup, (size_t)cap);
    if (keep) ed->dirty = true;
    if (ed->backup) ap_wipe(ed->backup, (size_t)ed->backup_cap), free(ed->backup);
    ed->backup = NULL;
    bool was_key = ed->editing_key;
    int row = ed->editing;
    ed->editing = -1;
    ed->editing_key = false;
    int fi = ed->rowmap[row];
    if (was_key) {
        if (!keep || !ed->key[fi][0]) { /* cancelled new field: drop it */
            ap_wipe(ed->val[fi], (size_t)ed->cap[fi]);
            free(ed->val[fi]);
            memmove(&ed->key[fi], &ed->key[fi + 1], sizeof ed->key[0] * (size_t)(ed->n - fi - 1));
            memmove(&ed->val[fi], &ed->val[fi + 1], sizeof ed->val[0] * (size_t)(ed->n - fi - 1));
            memmove(&ed->cap[fi], &ed->cap[fi + 1], sizeof ed->cap[0] * (size_t)(ed->n - fi - 1));
            memmove(&ed->prot[fi], &ed->prot[fi + 1], sizeof ed->prot[0] * (size_t)(ed->n - fi - 1));
            memmove(&ed->hidden[fi], &ed->hidden[fi + 1], sizeof ed->hidden[0] * (size_t)(ed->n - fi - 1));
            ed->n--;
            build_rows(ed);
        } else {
            begin_edit(a, row); /* now its value */
        }
    }
}

/* Insert a code point at the cursor. */
static void insert(char *b, int cap, int *cursor, uint32_t cp)
{
    char t[5];
    int n = 0, len = (int)strlen(b);
    ap_utf8_append(t, &n, sizeof t, cp);
    if (len + n >= cap) return;
    memmove(b + *cursor + n, b + *cursor, (size_t)(len - *cursor + 1));
    memcpy(b + *cursor, t, (size_t)n);
    *cursor += n;
}

static void text_key(app *a, uint32_t k, bool fn)
{
    struct app_edit *ed = a->ed;
    int cap;
    char *b = row_buf(ed, ed->editing, &cap);
    if (!b) { ed->editing = -1; return; }
    int len = (int)strlen(b);
    bool notes = !ed->editing_key && ed->rowmap[ed->editing] >= 0 && !strcmp(ed->key[ed->rowmap[ed->editing]], "Notes");
    if (k == K_ENTER && fn && notes) insert(b, cap, &ed->cursor, '\n');
    else if (k == K_ENTER) end_edit(a, true);
    else if (k == K_ESC) end_edit(a, false);
    else if (k == K_LEFT) { while (ed->cursor > 0 && ((unsigned char)b[--ed->cursor] & 0xC0) == 0x80) {} }
    else if (k == K_RIGHT) { if (ed->cursor < len) { const char *p = b + ed->cursor; ui_utf8_next(&p); ed->cursor = (int)(p - b); } }
    else if (k == K_BACKSPACE && ed->cursor > 0) {
        int c = ed->cursor;
        while (c > 0 && ((unsigned char)b[--c] & 0xC0) == 0x80) {}
        memmove(b + c, b + ed->cursor, (size_t)(len - ed->cursor + 1));
        ap_wipe(b + len - (ed->cursor - c), (size_t)(ed->cursor - c));
        ed->cursor = c;
    } else if (k == K_DEL && ed->cursor < len) {
        const char *p = b + ed->cursor;
        ui_utf8_next(&p);
        int n = (int)(p - b) - ed->cursor;
        memmove(b + ed->cursor, p, (size_t)(len - ed->cursor - n + 1));
        ap_wipe(b + len - n, (size_t)n);
    } else if (ap_printable(k) && !fn) {
        insert(b, cap, &ed->cursor, k);
    }
}

static void save_edit(app *a)
{
    struct app_edit *ed = a->ed;
    kdbx_edit_field f[ED_MAX];
    int n = 0;
    for (int i = 0; i < ed->n; i++)
        if (ed->key[i][0]) f[n++] = (kdbx_edit_field){ed->key[i], ed->val[i], ed->prot[i]};
    kdbx_edit e = {.op = KDBX_EDIT_ENTRY, .create = ed->create, .fields = f, .nfields = (size_t)n, .tags = ed->tags,
                   .expires = ed->expires, .expiry = ed->expiry};
    memcpy(e.uuid, ed->uuid, 16);
    memcpy(e.parent, ed->parent, 16);
    uint8_t u[16];
    memcpy(u, ed->uuid, 16);
    if (!ap_save(a, &e, 1)) { if (a->db) a->scr = SCR_EDIT, ap_mark_all(a); return; }
    ap_edit_free(a);
    const kdbx_entry *x = find_entry(a->db, u);
    if (x) { /* show the saved entry; back goes where the entry came from */
        char m[sizeof a->msg];
        memcpy(m, a->msg, sizeof m);
        ap_open_entry(a, x);
        memcpy(a->msg, m, sizeof m);
    } else {
        ap_go_home(a);
    }
}

static int ed_back(app *a) { return a->entry ? SCR_ENTRY : a->back_scr; }

void ap_edit_key(app *a, uint32_t k, bool fn)
{
    struct app_edit *ed = a->ed;
    if (!ed) return;
    a->msg[0] = 0;
    ap_mark_all(a);
    if (ed->editing >= 0) { text_key(a, k, fn); return; }
    int fi = ed->rowmap[a->sel];
    if (k == K_UP) ap_move_sel(a, ed->nrows, -1);
    else if (k == K_DOWN) ap_move_sel(a, ed->nrows, 1);
    else if (k == K_ENTER && fi == -2) { /* add a custom field: name first */
        if (add_field(ed, "", "", false)) {
            build_rows(ed);
            ed->editing_key = true;
            for (int r = 0; r < ed->nrows; r++)
                if (ed->rowmap[r] == ed->n - 1) a->sel = r;
            begin_edit(a, a->sel);
        }
    } else if (k == K_ENTER) begin_edit(a, a->sel);
    else if ((k == 'g' || k == 'G') && fi == 2) ap_gen_open(a, true);
    else if ((k == 'p' || k == 'P') && fi >= 5) ed->prot[fi] = !ed->prot[fi], ed->dirty = true;
    else if ((k == K_DEL || (fn && k == K_BACKSPACE)) && fi >= 5) { /* remove custom field */
        ap_wipe(ed->val[fi], (size_t)ed->cap[fi]);
        ed->key[fi][0] = 0;          /* empty key = dropped on save */
        ed->hidden[fi] = true;
        ed->dirty = true;
        build_rows(ed);
        if (a->sel >= ed->nrows) a->sel = ed->nrows - 1;
    } else if (fn && (k == 's' || k == 'S')) save_edit(a);
    else if (k == '`' || k == K_ESC) {
        if (ed->dirty) ap_confirm(a, CONFIRM_SAVE_EDIT, "Save changes?");
        else { ap_edit_free(a); ap_return(a, ed_back(a)); }
    }
}

/* called from the confirm screen */
void ap_edit_finish(app *a, bool save)
{
    if (save) { save_edit(a); return; }
    int back = ed_back(a);
    ap_edit_free(a);
    ap_return(a, back);
}

void ap_edit_draw(app *a, ui_strip *s, const char **hint)
{
    struct app_edit *ed = a->ed;
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    if (!ed) return;
    int h = ap_row_h(a);
    for (int r = a->top; r < ed->nrows && r < a->top + ap_visible(a); r++) {
        int y = CONTENT_Y + (r - a->top) * h, fi = ed->rowmap[r];
        if (y + h <= s->y0 || y >= s->y0 + s->h) continue;
        bool sel = r == a->sel;
        if (fi == -2) {
            ap_draw_row(a, s, r, "+", T->accent, "Add field", NULL, 0);
            continue;
        }
        ui_fill(s, 0, y, UI_W, h, sel ? T->sel_bg : T->bg);
        if (sel) ui_fill(s, 0, y, 2, h, T->accent);
        const char *label = fi == -1 ? "Tags" : fi == 1 ? "User" : fi == 2 ? "Pass" : ed->key[fi];
        int sy = y + (h - ui_font_small.height) / 2, vx = PAD + LABEL_W;
        if (r == ed->editing) {
            if (ed->editing_key) {
                ui_text(s, &ui_font_small, PAD + 2, sy, "Name", T->accent, LABEL_W - 4);
                ap_draw_field(a, s, vx - 4, y, UI_W - vx, h, ed->key[fi], false, ed->cursor);
            } else {
                ui_text(s, &ui_font_small, PAD + 2, sy, label, T->accent, LABEL_W - 4);
                ap_draw_field(a, s, vx - 4, y, UI_W - vx, h, fi == -1 ? ed->tags : ed->val[fi], false, ed->cursor);
            }
            continue;
        }
        ui_text(s, &ui_font_small, PAD + 2, sy, label[0] ? label : "(name)", T->dim, LABEL_W - 4);
        const char *v = fi == -1 ? ed->tags : ed->val[fi];
        char line[128];
        size_t nl = strcspn(v, "\n");
        snprintf(line, sizeof line, "%.*s%s", (int)(nl < 100 ? nl : 100), v, v[nl] ? " \xE2\x80\xA6" : "");
        bool masked = fi >= 0 && ed->prot[fi] && v[0];
        uint16_t c = v[0] ? (sel ? T->sel_fg : T->fg) : T->dim;
        ui_text(s, F, vx, y + (h - F->height) / 2, masked ? U_BULLETS : v[0] ? line : "\xE2\x80\x94", c, UI_W - vx - PAD - 14);
        if (fi >= 5 && ed->prot[fi]) ui_text(s, &ui_font_small, UI_W - PAD - 8, sy, ICON_LOCK, T->dim, 10);
        ap_wipe(line, sizeof line);
    }
    ap_draw_scrollbar(a, s, ed->nrows);
    if (ed->editing >= 0) {
        bool notes = !ed->editing_key && ed->rowmap[ed->editing] == 4;
        *hint = notes ? U_ENTER " done  fn+" U_ENTER " new line  fn+` cancel" : U_ENTER " done  " U_LR " move  fn+` cancel";
    } else {
        int fi = ed->rowmap[a->sel];
        *hint = fi == 2 ? U_ENTER " edit  G generate  fn+S save" : fi >= 5 ? U_ENTER " edit  P protect  fn+bksp del" : U_ENTER " edit  fn+S save  ` back";
    }
}

/* ======================= generator ======================= */

struct app_gen {
    bool for_edit, words;
    gen_pw_opts pw;
    gen_pp_opts pp;
    char value[256];
};

static void regenerate(app *a)
{
    struct app_gen *g = a->gen;
    bool ok = g->words ? gen_passphrase(&g->pp, g->value, sizeof g->value) : gen_password(&g->pw, g->value, sizeof g->value);
    if (!ok) snprintf(g->value, sizeof g->value, "%s", "");
}

void ap_gen_free(app *a)
{
    if (!a->gen) return;
    ap_wipe(a->gen, sizeof *a->gen);
    free(a->gen);
    a->gen = NULL;
}

void ap_gen_open(app *a, bool for_edit)
{
    ap_gen_free(a);
    struct app_gen *g = a->gen = calloc(1, sizeof *g);
    if (!g) return;
    g->for_edit = for_edit;
    g->pw = (gen_pw_opts){20, GEN_UPPER | GEN_LOWER | GEN_DIGITS | GEN_SYMBOLS, false, true};
    g->pp = (gen_pp_opts){6, '-', GEN_CAP_NONE, false, false};
    regenerate(a);
    a->menu_back = a->scr;
    a->scr = SCR_GEN;
    a->sel = a->top = 0;
    ap_mark_all(a);
}

static int gen_rows(const struct app_gen *g) { return g->words ? 5 : 7; }

static void gen_change(app *a, int d)
{
    struct app_gen *g = a->gen;
    static const char seps[] = {'-', ' ', '.', '_', 0};
    int r = a->sel;
    if (g->words) {
        if (r == 0) g->pp.words = g->pp.words + d < 4 ? 10 : g->pp.words + d > 10 ? 4 : g->pp.words + d;
        else if (r == 1) { int i = 0; while (seps[i] != g->pp.sep) i++; g->pp.sep = seps[(i + d + 5) % 5]; }
        else if (r == 2) g->pp.cap = (g->pp.cap + d + 3) % 3;
        else if (r == 3) g->pp.digit = !g->pp.digit;
        else g->pp.symbol = !g->pp.symbol;
    } else {
        static const unsigned bits[] = {GEN_UPPER, GEN_LOWER, GEN_DIGITS, GEN_SYMBOLS};
        if (r == 0) g->pw.length = g->pw.length + d < 4 ? 64 : g->pw.length + d > 64 ? 4 : g->pw.length + d;
        else if (r <= 4) {
            unsigned b = bits[r - 1];
            if ((g->pw.sets & ~b) || !(g->pw.sets & b)) g->pw.sets ^= b; /* keep at least one set */
        } else if (r == 5) g->pw.exclude_lookalike = !g->pw.exclude_lookalike;
        else g->pw.require_each = !g->pw.require_each;
    }
    regenerate(a);
}

void ap_gen_key(app *a, uint32_t k, bool fn)
{
    struct app_gen *g = a->gen;
    (void)fn;
    ap_mark_all(a);
    if (k == K_UP) ap_move_sel(a, gen_rows(g), -1);
    else if (k == K_DOWN) ap_move_sel(a, gen_rows(g), 1);
    else if (k == K_LEFT) gen_change(a, -1);
    else if (k == K_RIGHT) gen_change(a, 1);
    else if (k == K_TAB) g->words = !g->words, a->sel = 0, regenerate(a);
    else if (k == ' ') regenerate(a);
    else if (k == K_ENTER && g->for_edit && a->ed) { /* into the password field */
        struct app_edit *ed = a->ed;
        snprintf(ed->val[2], (size_t)ed->cap[2], "%s", g->value);
        ed->dirty = true;
        ap_gen_free(a);
        a->scr = SCR_EDIT;
        a->sel = 2;
        a->top = 0;
    } else if (k == K_ENTER && !g->for_edit) {
        if (!a->p->hid_ready(a->p->ctx)) snprintf(a->msg, sizeof a->msg, "Connect USB or pair Bluetooth");
        else { /* type it: literal text through the layout (braces escaped by at_type rules) */
            char seq[600] = "";
            int n = 0;
            for (const char *p = g->value; *p && n < (int)sizeof seq - 4; p++) {
                if (strchr("{}+^%~()[]", *p)) seq[n++] = '{', seq[n++] = *p, seq[n++] = '}';
                else seq[n++] = *p;
            }
            seq[n] = 0;
            const kdbx_entry *keep = a->entry;
            type_seq(a, seq);
            a->entry = keep;
            ap_wipe(seq, sizeof seq);
        }
    } else if (k == '`' || k == K_ESC) {
        int back = a->menu_back;
        ap_gen_free(a);
        if (back == SCR_EDIT) { a->scr = SCR_EDIT; a->sel = 2; a->top = 0; }
        else ap_return(a, back);
    }
}

void ap_gen_draw(app *a, ui_strip *s, const char **hint)
{
    struct app_gen *g = a->gen;
    ui_fill(s, 0, CONTENT_Y, UI_W, CONTENT_H, T->bg);
    if (!g) return;
    double bits = g->words ? gen_passphrase_bits(&g->pp) : gen_password_bits(&g->pw);
    /* the value, wrapped over two lines if needed */
    int vy = CONTENT_Y + 2;
    const char *v = g->value;
    for (int line = 0; line < 2 && *v; line++) {
        size_t n = ui_wrap(&ui_font_small, v, UI_W - 2 * PAD);
        char buf[128];
        snprintf(buf, sizeof buf, "%.*s", (int)n, v);
        ui_text(s, &ui_font_small, PAD, vy + line * 12, buf, T->accent, UI_W - 2 * PAD);
        ap_wipe(buf, sizeof buf);
        v += n;
    }
    char info[64];
    snprintf(info, sizeof info, "%s \xC2\xB7 %.1f bits%s", g->words ? "Passphrase" : "Password", bits,
             g->words && gen_passphrase_ambiguous(&g->pp) ? "  \xE2\x9A\xA0 no word boundary" : "");
    ui_text(s, &ui_font_small, PAD, vy + 25, info, bits >= a->cfg.weak_bits ? T->ok : T->warn, UI_W - 2 * PAD);

    /* options: a small list under the value */
    static const char *const cap_names[] = {"none", "Each word", "One word"};
    int oy = CONTENT_Y + 42, oh = 12;
    for (int r = 0; r < gen_rows(g); r++) {
        char l[40], val[24];
        if (g->words) {
            static const char *const names[] = {"Words", "Separator", "Capitals", "Digit", "Symbol"};
            snprintf(l, sizeof l, "%s", names[r]);
            if (r == 0) snprintf(val, sizeof val, "%d", g->pp.words);
            else if (r == 1) snprintf(val, sizeof val, "%s", g->pp.sep == ' ' ? "space" : g->pp.sep ? (char[2]){g->pp.sep, 0} : "none");
            else if (r == 2) snprintf(val, sizeof val, "%s", cap_names[g->pp.cap]);
            else snprintf(val, sizeof val, "%s", (r == 3 ? g->pp.digit : g->pp.symbol) ? "yes" : "no");
        } else {
            static const char *const names[] = {"Length", "A-Z", "a-z", "0-9", "Symbols", "No 0O1l|", "One of each"};
            static const unsigned bits_[] = {0, GEN_UPPER, GEN_LOWER, GEN_DIGITS, GEN_SYMBOLS};
            snprintf(l, sizeof l, "%s", names[r]);
            if (r == 0) snprintf(val, sizeof val, "%d", g->pw.length);
            else if (r <= 4) snprintf(val, sizeof val, "%s", g->pw.sets & bits_[r] ? "yes" : "no");
            else snprintf(val, sizeof val, "%s", (r == 5 ? g->pw.exclude_lookalike : g->pw.require_each) ? "yes" : "no");
        }
        int y = oy + (r % 4) * oh, x = r < 4 ? PAD : UI_W / 2 + PAD;
        if (y + oh <= s->y0 || y >= s->y0 + s->h) continue;
        bool sel = r == a->sel;
        if (sel) ui_fill(s, x - 2, y, UI_W / 2 - 4, oh, T->sel_bg);
        ui_text(s, &ui_font_small, x, y, l, sel ? T->sel_fg : T->dim, 70);
        ui_text(s, &ui_font_small, x + 72, y, val, sel ? T->accent : T->fg, UI_W / 2 - 80);
    }
    *hint = g->for_edit ? U_ENTER " use  space new  " U_LR " change  tab mode" : U_ENTER " type  space new  " U_LR " change  tab mode";
    if (a->msg[0]) *hint = a->msg;
}
