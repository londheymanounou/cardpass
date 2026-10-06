#include <ctype.h>
#include <math.h>
#include <string.h>
#include "gen.h"

extern const unsigned gen_wordlist_count, gen_wordlist_size;
extern const uint8_t gen_wordlist[];

static const char SYMBOLS[] = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
static const char LOOKALIKE[] = "0O1lI|";
static const char PP_SYMBOLS[] = "!@#$%&*?";

uint32_t gen_uniform(uint32_t n)
{
    uint32_t r, limit = UINT32_MAX - UINT32_MAX % n; /* accept [0, limit) */
    do cp_random(&r, sizeof r);
    while (r >= limit);
    uint32_t v = r % n;
    r = 0;
    return v;
}

/* ---------------- passwords ---------------- */

static size_t charset(unsigned set, bool no_lookalike, char *out)
{
    size_t n = 0;
    for (int c = 33; c < 127; c++) {
        bool in = (set & GEN_UPPER && isupper(c)) || (set & GEN_LOWER && islower(c)) ||
                  (set & GEN_DIGITS && isdigit(c)) || (set & GEN_SYMBOLS && strchr(SYMBOLS, c));
        if (in && !(no_lookalike && strchr(LOOKALIKE, c))) out[n++] = (char)c;
    }
    out[n] = 0;
    return n;
}

static int nsets(unsigned sets) { return __builtin_popcount(sets & 15); }

bool gen_password(const gen_pw_opts *o, char *out, size_t outsz)
{
    char all[100], one[100];
    size_t n = charset(o->sets, o->exclude_lookalike, all);
    if (!n || o->length < 1 || (size_t)o->length >= outsz) return false;
    if (o->require_each && o->length < nsets(o->sets)) return false;

    /* Rejection: draw uniformly over all strings, retry if a set is missing.
     * Uniform over the valid strings, so gen_password_bits() is exact. */
    for (int tries = 0; tries < 10000; tries++) {
        for (int i = 0; i < o->length; i++) out[i] = all[gen_uniform((uint32_t)n)];
        out[o->length] = 0;
        bool ok = true;
        for (unsigned s = 1; s <= 8 && o->require_each; s <<= 1) {
            if (!(o->sets & s)) continue;
            charset(s, o->exclude_lookalike, one);
            if (!strpbrk(out, one)) ok = false;
        }
        if (ok) return true;
    }
    memset(out, 0, outsz);
    return false;
}

double gen_password_bits(const gen_pw_opts *o)
{
    char buf[100];
    double n = (double)charset(o->sets, o->exclude_lookalike, buf);
    if (n == 0 || o->length < 1) return 0;
    if (!o->require_each) return o->length * log2(n);
    /* Inclusion-exclusion: fraction of strings that contain every set. */
    double frac = 0;
    for (unsigned sub = 0; sub < 16; sub++) {
        if (sub & ~o->sets) continue;
        double missing = 0;
        for (unsigned s = 1; s <= 8; s <<= 1)
            if (sub & s) missing += (double)charset(s, o->exclude_lookalike, buf);
        frac += (nsets(sub) & 1 ? -1 : 1) * pow((n - missing) / n, o->length);
    }
    return frac > 0 ? o->length * log2(n) + log2(frac) : 0;
}

/* ---------------- passphrases ---------------- */

unsigned gen_word_count(void) { return gen_wordlist_count; }

void gen_words_begin(gen_word_iter *it) { it->pos = 0, it->len = 0, it->word[0] = 0; }

void gen_words_at(gen_word_iter *it, unsigned pos, char first) { it->pos = pos, it->word[0] = first, it->len = 1; }

bool gen_words_next(gen_word_iter *it)
{
    if (it->pos >= gen_wordlist_size) return false;
    size_t len = gen_wordlist[it->pos++] - 1u;            /* prefix shared with the previous word */
    while (it->pos < gen_wordlist_size && gen_wordlist[it->pos] >= 0x20 && len < 15) it->word[len++] = (char)gen_wordlist[it->pos++];
    it->word[len] = 0;
    it->len = len;
    return true;
}

const char *gen_word(unsigned idx, char out[16])
{
    /* Front-coded list: byte < 0x20 = (shared prefix length + 1), then the rest. */
    unsigned w = 0;
    size_t len = 0;
    for (unsigned i = 0; i < gen_wordlist_size; w++) {
        len = gen_wordlist[i++] - 1u;
        while (i < gen_wordlist_size && gen_wordlist[i] >= 0x20 && len < 15) out[len++] = (char)gen_wordlist[i++];
        if (w == idx) break;
    }
    out[len] = 0;
    return out;
}

bool gen_passphrase(const gen_pp_opts *o, char *out, size_t outsz)
{
    char word[16];
    if (o->words < 1 || o->words > 20) return false;
    uint32_t cap = o->cap == GEN_CAP_ONE ? gen_uniform((uint32_t)o->words) : 0;
    uint32_t dw = o->digit ? gen_uniform((uint32_t)o->words) : UINT32_MAX;
    uint32_t sw = o->symbol ? gen_uniform((uint32_t)o->words) : UINT32_MAX;
    size_t n = 0;
    bool ok = true;

    for (int i = 0; i < o->words && ok; i++) {
        gen_word(gen_uniform(gen_wordlist_count), word);
        if (o->cap == GEN_CAP_EACH || (o->cap == GEN_CAP_ONE && (uint32_t)i == cap))
            word[0] = (char)toupper((unsigned char)word[0]);
        size_t wl = strlen(word);
        if (n + wl + 4 >= outsz) { ok = false; break; }
        if (i && o->sep) out[n++] = o->sep;
        memcpy(out + n, word, wl);
        n += wl;
        if ((uint32_t)i == dw) out[n++] = (char)('0' + gen_uniform(10));
        if ((uint32_t)i == sw) out[n++] = PP_SYMBOLS[gen_uniform(sizeof PP_SYMBOLS - 1)];
    }
    memset(word, 0, sizeof word);
    if (!ok) { memset(out, 0, outsz); return false; }
    out[n] = 0;
    return true;
}

double gen_passphrase_bits(const gen_pp_opts *o)
{
    double w = o->words;
    double bits = w * log2((double)gen_wordlist_count);
    if (o->cap == GEN_CAP_ONE) bits += log2(w);
    if (o->digit) bits += log2(w) + log2(10);
    if (o->symbol) bits += log2(w) + log2((double)(sizeof PP_SYMBOLS - 1));
    return bits;
}

bool gen_passphrase_ambiguous(const gen_pp_opts *o)
{
    return !o->sep && o->cap == GEN_CAP_NONE;
}
