#include <ctype.h>
#include <math.h>
#include <string.h>
#include "gen.h"
#include "strength.h"

#define MAXLEN 128

/* Most common password base words, most common first (cost = log2(rank)). */
static const char COMMON[] =
    "password 123456 qwerty azerty abc123 pass mail gmail email bank letmein monkey dragon football baseball welcome admin login master "
    "shadow sunshine princess iloveyou trustno1 superman batman starwars whatever freedom hello charlie donald "
    "michael jordan jennifer hunter killer soccer hockey summer winter spring autumn secret access flower "
    "passw0rd motdepasse soleil bonjour chouchou doudou marseille loulou coucou nicolas camille thomas "
    "passwort hallo schatz fussball sommer ficken lieben blume computer internet ninja mustang cookie "
    "pepper ginger maggie buster tigger jessica ashley amanda daniel andrew joshua matthew robert thomas "
    "love lovely angel baby family friend happy lucky money orange banana cheese chocolate coffee pizza "
    "purple silver golden diamond flower hello google facebook apple samsung microsoft windows linux "
    "admin root user guest test demo default changeme temp secret private qazwsx zaq1 asdf zxcv "
    "london paris berlin france germany england america canada "
    "january february march april june july august september october november december "
    "monday tuesday wednesday thursday friday saturday sunday";

static const char *const ROWS[] = {
    "`1234567890-=", "qwertyuiop[]", "asdfghjkl;'", "zxcvbnm,./", "azertyuiop", "qsdfghjklm",
    "wxcvbn", "qwertzuiop", "yxcvbnm", "1qaz2wsx3edc", "qazwsxedc",
};

static char unleet(char c)
{
    switch (c) {
    case '4': case '@': return 'a';
    case '3': return 'e';
    case '1': case '!': return 'i';
    case '0': return 'o';
    case '$': case '5': return 's';
    case '7': return 't';
    default: return (char)tolower((unsigned char)c);
    }
}

static void relax(double *best, int from, int to, double cost)
{
    if (best[from] + cost < best[to]) best[to] = best[from] + cost;
}

typedef struct { int start, len; double cost; } match;
typedef struct { match m[256]; int n; } matches;

/* Every occurrence of word w (lowercase) in the un-leeted password. */
static void match_word(const char *pw, const char *un, int n, const char *w, int wl, double base, matches *ms)
{
    if (wl < 3 || wl > n) return;
    for (const char *p = un; (p = strstr(p, w)) != NULL; p++) {
        int i = (int)(p - un);
        double cost = base;
        bool upper = false;
        for (int k = i; k < i + wl; k++) {
            if (isupper((unsigned char)pw[k])) upper = true;
            else if (pw[k] != un[k]) cost += 1; /* leet substitution */
        }
        if (ms->n < (int)(sizeof ms->m / sizeof *ms->m)) ms->m[ms->n++] = (match){i, wl, cost + (upper ? 1 : 0)};
    }
}

/* The EFF list is sorted, so the words starting with each letter pair are contiguous: wordpairs.c (generated into
 * ROM by tools/gen_wordpairs.py) has where each pair's run starts and how long it is, plus the few words not starting
 * with two letters ("t-shirt"), always checked. An estimate decodes only the runs of pairs present in the password. */
extern const uint16_t strength_pair_pos[676], strength_pair_len[676];
extern const char strength_odd_words[][16];
extern const int strength_n_odd;
static bool use_index = true;

void strength_use_index(bool on) { use_index = on; }

static void wipe(void *p, size_t n)
{
    volatile char *v = p;
    while (n--) *v++ = 0;
}

double strength_bits(const char *utf8)
{
    char pw[MAXLEN + 1], low[MAXLEN + 1], un[MAXLEN + 1], word[16];
    double best[MAXLEN + 1];
    static matches ms;
    ms.n = 0;
    int n = 0;
    bool lower = false, upperc = false, digit = false, symbol = false, other = false;

    for (const unsigned char *s = (const unsigned char *)utf8; *s && n < MAXLEN; s++) {
        if (*s >= 0x80) {
            other = true;
            if ((*s & 0xC0) == 0x80) continue; /* count code points, not bytes */
            pw[n] = '?';
        } else {
            pw[n] = (char)*s;
            lower |= islower(*s) != 0;
            upperc |= isupper(*s) != 0;
            digit |= isdigit(*s) != 0;
            symbol |= !isalnum(*s);
        }
        low[n] = (char)tolower((unsigned char)pw[n]);
        un[n] = unleet(pw[n]);
        n++;
    }
    pw[n] = low[n] = un[n] = 0;
    if (!n) return 0;

    double charset = (lower ? 26 : 0) + (upperc ? 26 : 0) + (digit ? 10 : 0) + (symbol ? 33 : 0) + (other ? 100 : 0);
    double brute = log2(charset);
    best[0] = 0;
    for (int i = 1; i <= n; i++) best[i] = INFINITY;

    /* dictionaries: common passwords (by rank), EFF words. A word can only match where its first two letters stand
     * next to each other in the unleeted password: a 26x26-bit table of those pairs skips almost every word before
     * the substring search (exact: words not starting with two letters are always searched). */
    uint32_t pair[26] = {0};
    for (int i = 0; i + 1 < n; i++) {
        unsigned x = (unsigned)(un[i] - 'a'), y = (unsigned)(un[i + 1] - 'a');
        if (x < 26 && y < 26) pair[x] |= 1u << y;
    }
#define MAY_MATCH(w) (!((unsigned)((w)[0] - 'a') < 26 && (unsigned)((w)[1] - 'a') < 26) || (pair[(w)[0] - 'a'] >> ((w)[1] - 'a') & 1))
    int rank = 1;
    for (const char *p = COMMON; *p; rank++) {
        const char *e = strchr(p, ' ');
        int wl = e ? (int)(e - p) : (int)strlen(p);
        if (wl < (int)sizeof word && wl >= 3 && wl <= n && MAY_MATCH(p)) {
            memcpy(word, p, (size_t)wl);
            word[wl] = 0;
            match_word(pw, un, n, word, wl, log2(rank), &ms);
        }
        p += wl + (e ? 1 : 0);
    }
    double eff = log2((double)gen_word_count());
    gen_word_iter it;
    if (use_index) {
        for (unsigned x = 0; x < 26; x++)
            for (unsigned y = 0; y < 26; y++) {
                unsigned k = x * 26 + y;
                if (!(pair[x] >> y & 1) || !strength_pair_len[k]) continue;
                gen_words_at(&it, strength_pair_pos[k], (char)('a' + x));
                for (unsigned c = 0; c < strength_pair_len[k] && gen_words_next(&it); c++)
                    if (it.len >= 3 && (int)it.len <= n) match_word(pw, un, n, it.word, (int)it.len, eff, &ms);
            }
        for (int i = 0; i < strength_n_odd; i++)
            match_word(pw, un, n, strength_odd_words[i], (int)strlen(strength_odd_words[i]), eff, &ms);
    } else {                                  /* the full scan: reference for the tests */
        gen_words_begin(&it);
        while (gen_words_next(&it))
            if (it.len >= 3 && (int)it.len <= n && MAY_MATCH(it.word)) match_word(pw, un, n, it.word, (int)it.len, eff, &ms);
    }
#undef MAY_MATCH

    for (int i = 0; i < n; i++) {
        if (best[i] == INFINITY) continue;
        relax(best, i, i + 1, brute);
        for (int m = 0; m < ms.n; m++)
            if (ms.m[m].start == i) relax(best, i, i + ms.m[m].len, ms.m[m].cost);

        /* repeats: aaaa */
        int j = i + 1;
        while (j < n && low[j] == low[i]) j++;
        for (int k = i + 3; k <= j; k++) relax(best, i, k, brute + log2(k - i));

        /* sequences: abcd, 4321 (same class, step +-1) */
        for (int step = -1; step <= 1; step += 2) {
            j = i + 1;
            while (j < n && low[j] - low[j - 1] == step && isalnum((unsigned char)low[j]) &&
                   !!isdigit((unsigned char)low[j]) == !!isdigit((unsigned char)low[i]))
                j++;
            bool obvious = strchr("a1z9", low[i]) != NULL;
            for (int k = i + 3; k <= j; k++)
                relax(best, i, k, (obvious ? 1 : log2(isdigit((unsigned char)low[i]) ? 10 : 26)) + log2(k - i) + (step < 0));
        }

        /* keyboard walks along a row, either direction */
        for (size_t r = 0; r < sizeof ROWS / sizeof *ROWS; r++) {
            const char *row = ROWS[r];
            int rl = (int)strlen(row);
            for (int dir = -1; dir <= 1; dir += 2) {
                const char *p = strchr(row, low[i]);
                if (!p) continue;
                int pos = (int)(p - row), k = i;
                while (k < n && pos >= 0 && pos < rl && row[pos] == low[k]) k++, pos += dir;
                for (int m = i + 3; m <= k; m++) relax(best, i, m, log2(sizeof ROWS / sizeof *ROWS) + log2(m - i) + 1);
            }
        }

        /* years 1900-2039 */
        if (i + 4 <= n && isdigit((unsigned char)low[i]) && isdigit((unsigned char)low[i + 1]) &&
            isdigit((unsigned char)low[i + 2]) && isdigit((unsigned char)low[i + 3])) {
            int y = (low[i] - '0') * 1000 + (low[i + 1] - '0') * 100 + (low[i + 2] - '0') * 10 + (low[i + 3] - '0');
            if (y >= 1900 && y <= 2039) relax(best, i, i + 4, log2(140));
        }
    }
    double bits = best[n];
    wipe(pw, sizeof pw);
    wipe(low, sizeof low);
    wipe(un, sizeof un);
    wipe(word, sizeof word);
    wipe(&ms, sizeof ms);
    return bits;
}
