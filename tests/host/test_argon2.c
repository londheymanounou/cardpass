/* Argon2 + BLAKE2b against the reference implementation (testdata/argon2_vectors.txt from argon2-cffi / hashlib,
 * tools/gen_argon2_vectors.py) and the RFC 9106 test vectors (with secret and associated data). Every Argon2 vector
 * runs in RAM and twice through the encrypted swap file (tiny cache = mostly disk, bigger cache), which must give
 * the same tag bit for bit.
 *   test_argon2 <testdata dir> <work dir> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kdbx_priv.h"

static int failures;
#define CHECK(c, ...) do { if (!(c)) { failures++; printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static size_t unhex(const char *s, uint8_t *out, size_t max)
{
    if (!strcmp(s, "-")) return 0;
    size_t n = 0;
    for (; s[0] && s[1] && n < max; s += 2) {
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (uint8_t)v;
    }
    return n;
}

static int last_pct = -1, pct_calls;
static bool pct_ok = true;
static void prog(void *c, int pct)
{
    (void)c;
    if (pct < last_pct || pct > 100) pct_ok = false;
    last_pct = pct;
    pct_calls++;
}

static char swap_path[600];

int main(int argc, char **argv)
{
    const char *tdir = argc > 1 ? argv[1] : "testdata", *wdir = argc > 2 ? argv[2] : ".";
    char path[600];
    snprintf(path, sizeof path, "%s/argon2_vectors.txt", tdir);
    snprintf(swap_path, sizeof swap_path, "%s/argon2_test.swp", wdir);
    FILE *f = fopen(path, "r");
    if (!f) { printf("no %s\n", path); return 1; }
    static char line[8192];
    static uint8_t in[4096], pw[128], salt[128], want[64], got[64];
    int nb = 0, na = 0;
    while (fgets(line, sizeof line, f)) {
        char kind[8], a[4096], b[200], c[200];
        if (sscanf(line, "%7s", kind) != 1) continue;
        if (!strcmp(kind, "b2b")) {
            int outlen;
            sscanf(line, "%*s %d %4095s %199s", &outlen, a, b);
            size_t n = unhex(a, in, sizeof in);
            unhex(b, want, sizeof want);
            kdbx_blake2b(got, (size_t)outlen, in, n);
            CHECK(!memcmp(got, want, (size_t)outlen), "blake2b out %d in %zu", outlen, n);
            nb++;
        } else if (!strcmp(kind, "a2")) {
            unsigned ty, ver, t, m, p;
            sscanf(line, "%*s %u %u %u %u %u %199s %199s %199s", &ty, &ver, &t, &m, &p, a, b, c);
            size_t pwl = unhex(a, pw, sizeof pw), sl = unhex(b, salt, sizeof salt);
            unhex(c, want, sizeof want);
            kdbx_argon2_params ap = {ty, ver, p, t, m, salt, NULL, NULL, sl, 0, 0};
            const char *mode[] = {"RAM", "swap, 18-block cache", "swap, 256 KiB cache"};
            for (int k = 0; k < 3; k++) {
                if (k == 0) kdbx_set_argon2_memory((size_t)-1, NULL, 0);
                else kdbx_set_argon2_memory(0, swap_path, k == 1 ? 18 * 1024 : 256 * 1024);
                memset(got, 0, sizeof got);
                last_pct = -1, pct_calls = 0, pct_ok = true;
                kdbx_err e = kdbx_argon2(&ap, pw, pwl, got, 32, prog, NULL);
                CHECK(e == KDBX_OK && !memcmp(got, want, 32), "argon2 type %u v%x t%u m%u p%u (%s): %s", ty, ver, t, m, p, mode[k],
                      kdbx_strerror(e));
                CHECK(pct_ok && last_pct == 100, "progress (%s): last %d", mode[k], last_pct);
                FILE *sw = fopen(swap_path, "rb");
                CHECK(!sw, "swap file left behind (%s)", mode[k]);
                if (sw) fclose(sw);
            }
            na++;
        }
    }
    fclose(f);
    kdbx_set_argon2_memory((size_t)-1, NULL, 0);

    /* RFC 9106 section 5: 32 KiB, 3 passes, 4 lanes, with secret and associated data */
    {
        uint8_t P[32], S[16], K[8], X[12];
        memset(P, 1, 32); memset(S, 2, 16); memset(K, 3, 8); memset(X, 4, 12);
        static const char *const rfc[3] = {
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"};
        for (unsigned ty = 0; ty < 3; ty++) {
            kdbx_argon2_params ap = {ty, 0x13, 4, 3, 32, S, K, X, 16, 8, 12};
            unhex(rfc[ty], want, sizeof want);
            for (int k = 0; k < 2; k++) {
                if (k) kdbx_set_argon2_memory(0, swap_path, 18 * 1024);
                kdbx_err e = kdbx_argon2(&ap, P, 32, got, 32, NULL, NULL);
                CHECK(e == KDBX_OK && !memcmp(got, want, 32), "RFC 9106 type %u (%s)", ty, k ? "swap" : "RAM");
            }
            kdbx_set_argon2_memory((size_t)-1, NULL, 0);
        }
    }

    /* errors */
    {
        uint8_t s8[8] = {0};
        kdbx_argon2_params ap = {KDBX_ARGON2_ID, 0x13, 1, 1, 64, s8, NULL, NULL, 8, 0, 0};
        kdbx_set_argon2_memory(0, NULL, 0);
        CHECK(kdbx_argon2(&ap, s8, 8, got, 32, NULL, NULL) == KDBX_ERR_NOMEM, "no RAM and no swap -> out of memory");
        snprintf(path, sizeof path, "%s/no/such/dir/x.swp", wdir);
        kdbx_set_argon2_memory(0, path, 32 * 1024);
        CHECK(kdbx_argon2(&ap, s8, 8, got, 32, NULL, NULL) == KDBX_ERR_SWAP, "unwritable swap -> swap error");
        kdbx_set_argon2_memory((size_t)-1, NULL, 0);
        kdbx_argon2_params bad[] = {{3, 0x13, 1, 1, 64, s8, NULL, NULL, 8, 0, 0}, {0, 0x12, 1, 1, 64, s8, NULL, NULL, 8, 0, 0},
                                    {0, 0x13, 0, 1, 64, s8, NULL, NULL, 8, 0, 0}, {0, 0x13, 1, 0, 64, s8, NULL, NULL, 8, 0, 0},
                                    {0, 0x13, 4, 1, 31, s8, NULL, NULL, 8, 0, 0}};
        for (size_t i = 0; i < sizeof bad / sizeof *bad; i++)
            CHECK(kdbx_argon2(&bad[i], s8, 8, got, 32, NULL, NULL) == KDBX_ERR_KDF, "bad parameters %zu refused", i);
    }

    printf("argon2: %d blake2b + %d argon2 vectors (each in RAM and twice through swap), %d failures\n", nb, na, failures);
    return failures != 0;
}
