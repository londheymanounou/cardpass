/* Password + passphrase generators. Uniform choices only (rejection sampling),
 * so the entropy shown is exact for the chosen options. Caller wipes the output. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Provided by the platform: cryptographically secure random bytes
 * (device: esp_fill_random inside bootloader_random_enable/disable). */
void cp_random(void *buf, size_t n);

uint32_t gen_uniform(uint32_t n); /* [0, n), no modulo bias */

enum { GEN_UPPER = 1, GEN_LOWER = 2, GEN_DIGITS = 4, GEN_SYMBOLS = 8 };

typedef struct {
    int length;
    unsigned sets;          /* GEN_* bits */
    bool exclude_lookalike; /* drops 0 O 1 l I | */
    bool require_each;      /* at least one char from every chosen set */
} gen_pw_opts;

bool gen_password(const gen_pw_opts *o, char *out, size_t outsz);
double gen_password_bits(const gen_pw_opts *o);

enum { GEN_CAP_NONE, GEN_CAP_EACH, GEN_CAP_ONE };

typedef struct {
    int words;      /* 4..10 */
    char sep;       /* '-', ' ', '.', '_' or 0 for none */
    int cap;        /* GEN_CAP_* */
    bool digit;     /* append a digit to a random word */
    bool symbol;    /* append a symbol to a random word */
} gen_pp_opts;

bool gen_passphrase(const gen_pp_opts *o, char *out, size_t outsz);
double gen_passphrase_bits(const gen_pp_opts *o);
/* No separator and no capitals: word boundaries can't be seen (show a warning). */
bool gen_passphrase_ambiguous(const gen_pp_opts *o);

unsigned gen_word_count(void);
const char *gen_word(unsigned i, char out[16]);
