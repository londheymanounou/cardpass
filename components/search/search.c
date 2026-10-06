#include <stdlib.h>
#include <string.h>
#include "search.h"

/* Folded base letter for U+00C0..U+017F ('*' = keep as is). */
static const char FOLD[] =
    "aaaaaaaceeeeiiiidnooooo*ouuuuyts"          /* C0-DF */
    "aaaaaaaceeeeiiiidnooooo*ouuuuyty"          /* E0-FF */
    "aaaaaacccccccc" "dddd" "eeeeeeeeee" "gggggggg" "hhhh" "iiiiiiiiii" "ii" "jj" "kkk"
    "llllllllll" "nnnnnnnnn" "oooooooo" "rrrrrr" "ssssssss" "tttttt" "uuuuuuuuuuuu"
    "ww" "yyy" "zzzzzz" "s";                    /* 100-17F */
_Static_assert(sizeof FOLD == 192 + 1, "fold table");

enum { FIELD_TITLE = 10, FIELD_USER = 4, FIELD_URL = 0, FIELD_TAGS = 4, FAVORITE = 20, RECENT = 15 };

unsigned search_fold(const char **s)
{
    const unsigned char *p = (const unsigned char *)*s;
    unsigned c = *p++, n = c < 0x80 ? 0 : c >= 0xF0 ? 3 : c >= 0xE0 ? 2 : c >= 0xC0 ? 1 : 4;
    if (n == 4) { *s = (const char *)p; return 0xFFFD; }
    if (n) c &= 0x3F >> n;
    for (; n; n--, p++) {
        if ((*p & 0xC0) != 0x80) { *s = (const char *)p; return 0xFFFD; }
        c = c << 6 | (*p & 0x3F);
    }
    *s = (const char *)p;
    if (c >= 'A' && c <= 'Z') return c + 32;
    if (c >= 0xC0 && c < 0x180 && FOLD[c - 0xC0] != '*') return (unsigned char)FOLD[c - 0xC0];
    return c;
}

static bool is_word(unsigned c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c >= 0x80; }

/* Greedy subsequence match of q[0..qn) (folded code points) in text. */
static int score_cps(const unsigned *q, size_t qn, const char *text)
{
    if (!qn) return 0;
    size_t qi = 0;
    int score = 0, gap = 0;
    bool prev_hit = false, started = false;
    unsigned prev = ' ';
    for (int i = 0; *text; i++) {
        unsigned c = search_fold(&text);
        if (c == q[qi]) {
            score += 1 + (prev_hit ? 5 : 0) + (!is_word(prev) ? 8 : 0) + (i == 0 ? 10 : 0);
            if (started) score -= gap < 3 ? gap : 3;
            started = prev_hit = true;
            gap = 0;
            if (++qi == qn) return score;
        } else {
            prev_hit = false;
            gap += started;
        }
        prev = c;
    }
    return -1;
}

static size_t fold_term(const char **q, unsigned *out, size_t max)
{
    size_t n = 0;
    while (**q == ' ') (*q)++;
    while (**q && **q != ' ') {
        unsigned c = search_fold(q);
        if (n < max) out[n++] = c;
    }
    return n;
}

int search_score(const char *query, const char *text)
{
    unsigned q[64];
    size_t n = fold_term(&query, q, 64);
    return score_cps(q, n, text);
}

bool search_has_tag(const char *tags, const char *tag)
{
    size_t tl = strlen(tag);
    for (const char *p = tags; *p;) {
        while (*p == ' ' || *p == ';' || *p == ',') p++;
        const char *e = p;
        while (*e && *e != ';' && *e != ',') e++;
        const char *end = e;
        while (end > p && end[-1] == ' ') end--;
        if ((size_t)(end - p) == tl) {
            size_t i = 0;
            while (i < tl && (p[i] | 0x20) == (tag[i] | 0x20)) i++;
            if (i == tl) return true;
        }
        p = e;
    }
    return false;
}

static int fold_cmp(const char *a, const char *b)
{
    while (*a && *b) {
        unsigned x = search_fold(&a), y = search_fold(&b);
        if (x != y) return x < y ? -1 : 1;
    }
    return !!*a - !!*b;
}

static int hit_cmp(const void *pa, const void *pb)
{
    const search_hit *a = pa, *b = pb;
    if (a->score != b->score) return b->score - a->score;
    return fold_cmp(a->e->title, b->e->title);
}

size_t search_run(const kdbx_db *db, const char *query, const kdbx_entry *const *recent, size_t nrecent,
                  search_hit *hits, size_t max)
{
    return search_run_among(db, query, recent, nrecent, NULL, 0, hits, max);
}

size_t search_run_among(const kdbx_db *db, const char *query, const kdbx_entry *const *recent, size_t nrecent,
                        const kdbx_entry *const *among, size_t namong, search_hit *hits, size_t max)
{
    unsigned terms[8][32];
    size_t tlen[8], nt = 0;
    for (const char *q = query; *q && nt < 8;) {
        if ((tlen[nt] = fold_term(&q, terms[nt], 32))) nt++;
    }

    size_t n = 0;
    size_t k = 0;
    for (const kdbx_entry *e = among ? (namong ? among[0] : NULL) : kdbx_entries(db); e && n < max;
         e = among ? (++k < namong ? among[k] : NULL) : e->next) {
        int total = 0;
        for (size_t t = 0; t < nt && total >= 0; t++) {
            int best = -1, s;
            if ((s = score_cps(terms[t], tlen[t], e->title)) >= 0 && s + FIELD_TITLE > best) best = s + FIELD_TITLE;
            if ((s = score_cps(terms[t], tlen[t], e->username)) >= 0 && s + FIELD_USER > best) best = s + FIELD_USER;
            if ((s = score_cps(terms[t], tlen[t], e->url)) >= 0 && s + FIELD_URL > best) best = s + FIELD_URL;
            if ((s = score_cps(terms[t], tlen[t], e->tags)) >= 0 && s + FIELD_TAGS > best) best = s + FIELD_TAGS;
            total = best < 0 ? -1 : total + best;
        }
        if (total < 0) continue;
        if (search_has_tag(e->tags, "favorite")) total += FAVORITE;
        for (size_t r = 0; r < nrecent; r++)
            if (recent[r] == e) { total += RECENT - (int)(r < 10 ? r : 10); break; }
        hits[n++] = (search_hit){e, total};
    }
    qsort(hits, n, sizeof *hits, hit_cmp);
    return n;
}
