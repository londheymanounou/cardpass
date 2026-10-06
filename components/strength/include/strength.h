/* Password strength estimate (bits), zxcvbn-style but tiny: the cheapest split
 * into common words (leet/caps aware), EFF words, sequences, repeats, keyboard
 * walks, years and brute-force characters. An estimate, never exact. */
#pragma once

double strength_bits(const char *utf8);

/* Tests only: false = scan the whole word list instead of the pair index (results must be identical). */
void strength_use_index(bool on);
