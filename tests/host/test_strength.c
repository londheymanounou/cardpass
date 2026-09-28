/* Strength estimate vs KeePassXC's (zxcvbn) numbers from `keepassxc-cli estimate`.
 * Acceptance: obviously weak passwords are Weak (< 64 bits), estimates in range. */
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include "strength.h"

void cp_random(void *buf, size_t n) { (void)buf; (void)n; } /* gen.c links it; unused here */

int main(void)
{
    static const struct { const char *pw; double kpxc; } cases[] = {
        {"password1", 4.0}, {"azerty123", 11.75}, {"Summer2024!", 19.1}, {"Gm@il-p4ss!", 35.8},
        {"B4nk!pw", 28.9}, {"rootpw", 18.3}, {"p€ss wörd ✓", 107.8}, {"correct-horse-battery-staple", 70.9},
        {"Xk9#mQ2$vL7!pR4&", 95.7}, {"qwertyuiop", 4.5}, {"aaaaaaaaaaaa", 5.6}, {"abcdefgh", 4.0},
        {"12345678", 1.6}, {"crease-flavored-sinister-seismic-limeade-sanctity", 129.0},
        {"kT8vR2mQ9xL4nB7w", 91.1}, {"motdepasse", 12.8}, {"Bonjour2023", 19.8}, {"iloveyou!", 8.6},
        {"P@ssw0rd", 3.0},
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        double b = strength_bits(cases[i].pw);
        bool weak = b < 64, kweak = cases[i].kpxc < 64;
        /* same Weak/Strong label as KeePassXC, and within 2x or 25 bits */
        bool ok = weak == kweak && (fabs(b - cases[i].kpxc) < 25 || (b < 2 * cases[i].kpxc && cases[i].kpxc < 2 * b));
        printf("%-52s ours %6.1f  kpxc %6.1f  %s%s\n", cases[i].pw, b, cases[i].kpxc, weak ? "Weak" : "Strong",
               ok ? "" : "  <-- FAIL");
        failures += !ok;
    }
    printf("strength: %d failures\n", failures);
    return failures != 0;
}
