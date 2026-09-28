/* Generators: wordlist integrity, uniformity, constraints, exact entropy. */
#include <math.h>
#include <stdio.h>
#include <string.h>
#include "gen.h"

static int failures;
#define CHECK(c, ...) do { if (!(c)) { failures++; printf("FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

/* Test-only RNG (splitmix64). The device uses the hardware RNG. */
static uint64_t state = 0x1234567;
void gen_random(void *buf, size_t n)
{
    uint8_t *p = buf;
    while (n) {
        uint64_t z = (state += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        z ^= z >> 31;
        for (int i = 0; i < 8 && n; i++, n--) *p++ = (uint8_t)(z >> 8 * i);
    }
}

int main(void)
{
    char w[16], prev[16] = "", buf[256];

    /* Wordlist: 7776 sorted, distinct, [a-z-] */
    CHECK(gen_word_count() == 7776, "count");
    CHECK(!strcmp(gen_word(0, w), "abacus"), "first %s", w);
    CHECK(!strcmp(gen_word(7775, w), "zoom"), "last %s", w);
    for (unsigned i = 0; i < 7776; i++) {
        gen_word(i, w);
        CHECK(strlen(w) >= 3 && strspn(w, "abcdefghijklmnopqrstuvwxyz-") == strlen(w), "word %u '%s'", i, w);
        CHECK(strcmp(prev, w) < 0, "order %u '%s' '%s'", i, prev, w);
        strcpy(prev, w);
    }

    /* Uniformity (n = 3 is where modulo bias would show) */
    int counts[3] = {0};
    for (int i = 0; i < 300000; i++) counts[gen_uniform(3)]++;
    for (int i = 0; i < 3; i++) CHECK(fabs(counts[i] - 100000) < 1500, "uniform %d: %d", i, counts[i]);

    /* Passwords */
    gen_pw_opts po = {20, GEN_UPPER | GEN_LOWER | GEN_DIGITS | GEN_SYMBOLS, false, false};
    CHECK(fabs(gen_password_bits(&po) - 20 * log2(94)) < 1e-9, "bits all");
    po = (gen_pw_opts){3, GEN_UPPER | GEN_DIGITS, false, true};
    CHECK(fabs(gen_password_bits(&po) - log2(36.0 * 36 * 36 - 26 * 26 * 26 - 10 * 10 * 10)) < 1e-9,
          "require_each bits %f", gen_password_bits(&po));
    for (int i = 0; i < 2000; i++) {
        po = (gen_pw_opts){4, GEN_UPPER | GEN_LOWER | GEN_DIGITS | GEN_SYMBOLS, true, true};
        CHECK(gen_password(&po, buf, sizeof buf), "gen");
        CHECK(strlen(buf) == 4, "len");
        CHECK(strpbrk(buf, "ABCDEFGHJKLMNPQRSTUVWXYZ") && strpbrk(buf, "abcdefghijkmnopqrstuvwxyz") &&
              strpbrk(buf, "23456789") && strpbrk(buf, "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{}~"), "sets '%s'", buf);
        CHECK(!strpbrk(buf, "0O1lI|"), "lookalike '%s'", buf);
    }
    po = (gen_pw_opts){2, GEN_UPPER | GEN_LOWER | GEN_DIGITS, false, true};
    CHECK(!gen_password(&po, buf, sizeof buf), "impossible accepted");
    po = (gen_pw_opts){300, GEN_LOWER, false, false};
    CHECK(!gen_password(&po, buf, sizeof buf), "overflow accepted");

    /* Passphrases */
    gen_pp_opts pp = {6, '-', GEN_CAP_NONE, false, false};
    CHECK(fabs(gen_passphrase_bits(&pp) - 77.55) < 0.01, "6 words %.2f", gen_passphrase_bits(&pp));
    CHECK(gen_passphrase(&pp, buf, sizeof buf), "pp");
    int seps = 0;
    for (char *c = buf; *c; c++) seps += *c == '-';
    CHECK(seps >= 5, "separators '%s'", buf);
    printf("sample: %s  (%.1f bits)\n", buf, gen_passphrase_bits(&pp));

    pp = (gen_pp_opts){5, ' ', GEN_CAP_ONE, true, true};
    CHECK(gen_passphrase(&pp, buf, sizeof buf), "pp2");
    int up = 0, dig = 0, sym = 0;
    for (char *c = buf; *c; c++) up += *c >= 'A' && *c <= 'Z', dig += *c >= '0' && *c <= '9', sym += !!strchr("!@#$%&*?", *c);
    CHECK(up == 1 && dig == 1 && sym == 1, "cap/digit/symbol '%s'", buf);
    CHECK(fabs(gen_passphrase_bits(&pp) - (5 * log2(7776) + 3 * log2(5) + log2(10) + 3)) < 1e-9, "bits pp2");
    printf("sample: %s  (%.1f bits)\n", buf, gen_passphrase_bits(&pp));

    pp = (gen_pp_opts){4, 0, GEN_CAP_NONE, false, false};
    CHECK(gen_passphrase_ambiguous(&pp), "ambiguous");
    pp.cap = GEN_CAP_EACH;
    CHECK(!gen_passphrase_ambiguous(&pp), "not ambiguous");
    CHECK(!gen_passphrase(&pp, buf, 10), "small buffer accepted");

    printf("gen: %d failures\n", failures);
    return failures != 0;
}
