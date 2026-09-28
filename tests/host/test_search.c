/* Search: folding, ranking, tags, speed on 1,000 entries.  test_search <testdata dir> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "search.h"

static int failures;
#define CHECK(c, ...) do { if (!(c)) { failures++; printf("FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static kdbx_db *open_db(const char *dir, const char *name)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    kdbx_key k;
    kdbx_db *db = NULL;
    kdbx_key_init(&k, "test", 4, NULL);
    if (f) kdbx_open(f, &k, &db), fclose(f);
    kdbx_key_wipe(&k);
    return db;
}

static void folded(const char *s, char *out)
{
    while (*s) {
        unsigned c = search_fold(&s);
        *out++ = c < 128 ? (char)c : '?';
    }
    *out = 0;
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : "testdata";
    char buf[128];
    search_hit hits[1100];
    size_t n;

    folded("Café Crème", buf);
    CHECK(!strcmp(buf, "cafe creme"), "%s", buf);
    folded("ŁÓDŹ Straße Ærø Ñ", buf);
    CHECK(!strcmp(buf, "lodz strase aro n"), "%s", buf);
    folded("\xff" "a\xc3", buf);
    CHECK(!strcmp(buf, "?a?"), "invalid utf8 %s", buf);

    CHECK(search_score("gml", "Gmail") > search_score("gml", "bigamal"), "gml");
    CHECK(search_score("xyz", "Gmail") < 0, "no match");

    CHECK(search_has_tag("favorite;email", "favorite"), "tag1");
    CHECK(search_has_tag("email, Favorite ", "favorite"), "tag2");
    CHECK(!search_has_tag("favorites;x", "favorite"), "tag3");

    kdbx_db *db = open_db(dir, "aes.kdbx");
    CHECK(db, "open aes");
    if (!db) return 1;

    n = search_run(db, "cafe", NULL, 0, hits, 1100);
    CHECK(n >= 1 && !strcmp(hits[0].e->title, "Café Crème"), "cafe -> %s", n ? hits[0].e->title : "-");
    n = search_run(db, "gml", NULL, 0, hits, 1100);
    CHECK(n >= 1 && !strcmp(hits[0].e->title, "Gmail"), "gml");
    n = search_run(db, "bank bob", NULL, 0, hits, 1100);
    CHECK(n == 1 && !strcmp(hits[0].e->title, "Bank"), "bank bob: %zu", n);
    n = search_run(db, "zzzq", NULL, 0, hits, 1100);
    CHECK(n == 0, "zzzq");

    /* Empty query: favorites, then recent, then by title */
    const kdbx_entry *visa = NULL;
    for (const kdbx_entry *e = kdbx_entries(db); e; e = e->next)
        if (!strcmp(e->title, "Visa")) visa = e;
    n = search_run(db, "", &visa, 1, hits, 1100);
    CHECK(n == 5, "all %zu", n);
    CHECK(n == 5 && !strcmp(hits[0].e->title, "Café Crème") && !strcmp(hits[1].e->title, "Gmail") &&
          hits[2].e == visa && !strcmp(hits[3].e->title, "Bank"), "home order");
    kdbx_close(db);

    db = open_db(dir, "big1000.kdbx");
    CHECK(db, "open big");
    if (!db) return 1;
    clock_t t0 = clock();
    for (int i = 0; i < 100; i++) n = search_run(db, "ste 42", NULL, 0, hits, 1100);
    double ms = (double)(clock() - t0) * 1000 / CLOCKS_PER_SEC / 100;
    CHECK(n > 0 && strstr(hits[0].e->title, "42"), "big: %zu %s", n, n ? hits[0].e->title : "-");
    printf("search 1000 entries: %.3f ms/query on host\n", ms);
    kdbx_close(db);

    printf("search: %d failures\n", failures);
    return failures != 0;
}
