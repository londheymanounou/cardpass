/* Shared between app.c (core screens), app_edit.c (actions, editing, generator)
 * and app_tools.c (menu, settings, audit, expiry, create, help). */
#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "app.h"
#include "ui_icons.h"

#define BAR_H 14
#define FOOT_H 12
#define CONTENT_Y BAR_H
#define CONTENT_H (UI_H - BAR_H - FOOT_H)
#define PAD 4
#define LABEL_W 56
#define REVEAL_MAX 1024

#define T (a->theme)
#define F (a->font)

/* utf8 literals used in hints */
#define U_ENTER "\xE2\x86\xB5"
#define U_UPDOWN "\xE2\x86\x91\xE2\x86\x93"
#define U_LR "\xE2\x86\x90\xE2\x86\x92"
#define U_BULLETS "\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2"

enum { LI_ENTRY, LI_GROUP, LI_FAV, LI_RECENT, LI_ALERT };
typedef struct { const void *p; uint8_t type; } list_item;

enum { R_USER, R_PASS, R_URL, R_TOTP, R_NOTES, R_FIELD, R_PASSKEY, R_ATT, R_EXPIRY, R_TAGS };

/* layout + dirty tracking */
int ap_row_h(const app *a);
int ap_visible(const app *a);
void ap_mark(app *a, int y0, int y1);
void ap_mark_all(app *a);
void ap_mark_row(app *a, int i);
void ap_wipe(void *p, size_t n);
void ap_civil(int64_t t, int *y, int *mo, int *d, int *h, int *mi);

/* lists */
list_item *ap_items(app *a);
void ap_build_group(app *a, const kdbx_group *g, bool home);
void ap_build_search(app *a);
void ap_move_sel(app *a, int n, int delta);
void ap_go_home(app *a);
void ap_open_entry(app *a, const kdbx_entry *e);
bool ap_reindex(app *a);                       /* after the database changed: counts, list buffer */

/* text input */
void ap_utf8_append(char *buf, int *len, int cap, uint32_t cp);
void ap_utf8_backspace(char *buf, int *len);
bool ap_printable(uint32_t k);

/* drawing */
void ap_draw_bar(app *a, ui_strip *s, const char *title);
void ap_draw_footer(app *a, ui_strip *s, const char *hint);
void ap_draw_row(app *a, ui_strip *s, int i, const char *icon, uint16_t icon_c, const char *text, const char *right,
                 uint16_t right_c);
void ap_draw_scrollbar(app *a, ui_strip *s, int n);
void ap_draw_list(app *a, ui_strip *s);
void ap_draw_toast(app *a, ui_strip *s);
void ap_draw_field(app *a, ui_strip *s, int x, int y, int w, int h, const char *text, bool masked, int cursor);
bool ap_totp_now(app *a, const kdbx_entry *e, const kdbx_field *f, char *out, size_t n);

/* app_edit.c */
bool ap_entry_key(app *a, uint32_t k, bool fn);     /* entry-view actions; true if handled */
bool ap_save(app *a, const kdbx_edit *ed, size_t n);/* save + re-find everything by UUID */
void ap_edit_open(app *a, const kdbx_entry *e, const kdbx_group *parent); /* e NULL: new entry */
void ap_edit_key(app *a, uint32_t k, bool fn);
void ap_edit_draw(app *a, ui_strip *s, const char **hint);
void ap_edit_free(app *a);
void ap_edit_finish(app *a, bool save);             /* from the confirm screen */
void ap_gen_open(app *a, bool for_edit);
void ap_gen_key(app *a, uint32_t k, bool fn);
void ap_gen_draw(app *a, ui_strip *s, const char **hint);
void ap_gen_free(app *a);

/* app_tools.c */
void ap_return(app *a, int scr);                   /* rebuild and show a previous screen */
void ap_menu_open(app *a);
void ap_menu_key(app *a, uint32_t k, bool fn);
void ap_menu_draw(app *a, ui_strip *s, const char **hint);
void ap_settings_key(app *a, uint32_t k, bool fn);
void ap_settings_draw(app *a, ui_strip *s, const char **hint);
void ap_apply_settings(app *a);
void ap_audit_open(app *a);
void ap_expiry_open(app *a);
int ap_expiring_count(app *a);
void ap_report_key(app *a, uint32_t k, bool fn);    /* audit + expiry lists */
void ap_report_draw(app *a, ui_strip *s, const char **hint);
void ap_confirm(app *a, int action, const char *text);
void ap_confirm_key(app *a, uint32_t k, bool fn);
void ap_confirm_draw(app *a, ui_strip *s, const char **hint);
void ap_create_open(app *a);
void ap_create_key(app *a, uint32_t k, bool fn);
void ap_create_draw(app *a, ui_strip *s, const char **hint);
void ap_create_free(app *a);
void ap_help_draw(app *a, ui_strip *s, const char **hint);
void ap_kdf_progress(void *ctx, int pct);

enum { CONFIRM_DELETE_ENTRY = 1, CONFIRM_DISCARD_EDIT, CONFIRM_SAVE_EDIT };
