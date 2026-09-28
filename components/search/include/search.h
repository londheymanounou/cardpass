/* Fuzzy entry search: case- and accent-insensitive subsequence matching over
 * title, username, URL and tags, scored; favorites and recent entries boosted. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include "kdbx.h"

typedef struct {
    const kdbx_entry *e;
    int score;
} search_hit;

/* recent: this session's recent entries, most recent first (may be NULL).
 * Empty query lists everything (favorites, then recent, then by title).
 * max should be >= the number of entries. Returns hits written, best first. */
size_t search_run(const kdbx_db *db, const char *query, const kdbx_entry *const *recent, size_t nrecent,
                  search_hit *hits, size_t max);

/* Tags are separated by ';' or ','; comparison ignores case and surrounding spaces. */
bool search_has_tag(const char *tags, const char *tag);

/* Next code point of UTF-8 s, lowercased and with Latin accents removed
 * (é -> e, Ç -> c, ß -> s). Invalid bytes return U+FFFD. Advances *s. */
unsigned search_fold(const char **s);

/* Score one string (< 0 = no match). Exposed for tests. */
int search_score(const char *query, const char *text);
