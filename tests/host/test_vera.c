/* VeraCrypt reader: opens testdata/vera_test.hc and vera_hidden.hc (built by tools/make_vera_test.py with OpenSSL, independent of
 * this code), checks every sector, rejects wrong passwords, and writes one sector into a copy
 * (python tools/make_vera_test.py --check <copy> then decrypts it independently). */
#include <stdio.h>
#include <string.h>
#include "vera.h"

static int failures;
#define CHECK(c, ...) do { if (!(c)) { failures++; printf("FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static int rd(void *io, uint64_t off, void *buf, size_t n)
{
    FILE *f = io;
    return fseek(f, (long)off, SEEK_SET) || fread(buf, 1, n, f) != n;
}

static int wr(void *io, uint64_t off, const void *buf, size_t n)
{
    FILE *f = io;
    return fseek(f, (long)off, SEEK_SET) || fwrite(buf, 1, n, f) != n || fflush(f);
}

static int last_pct = -1, calls;
static void prog(void *arg, int pct) { (void)arg; last_pct = pct; calls++; }

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    char src[512], work[512];
    snprintf(src, sizeof src, "%s/vera_test.hc", argv[1]);
    snprintf(work, sizeof work, "%s/vera_work.hc", argv[2]);

    FILE *in = fopen(src, "rb"), *out = fopen(work, "wb");
    if (!in || !out) { printf("cannot open test files\n"); return 2; }
    char b[4096];
    size_t n;
    while ((n = fread(b, 1, sizeof b, in)) > 0) fwrite(b, 1, n, out);
    fclose(in);
    fclose(out);

    FILE *f = fopen(work, "r+b");
    vera_io io = {rd, wr, f};
    vera v;
    const uint8_t pw[] = "cardpass-vera-test";

    CHECK(vera_open(&v, &io, (const uint8_t *)"wrong password", 14, NULL, NULL) == VERA_ERR_PASSWORD, "wrong password refused");
    CHECK(vera_open(&v, &io, pw, sizeof pw - 1, prog, NULL) == VERA_OK, "right password opens");
    CHECK(last_pct == 100 && calls == 100, "progress 1..100 (%d calls, last %d)", calls, last_pct);
    CHECK(vera_sectors(&v) == 128, "128 sectors");

    uint8_t s[512 * 4];
    for (uint32_t i = 0; i < 128; i++) {
        CHECK(vera_read(&v, i, 1, s) == VERA_OK, "read %u", i);
        bool ok = true;
        for (int j = 0; j < 512; j++) ok &= s[j] == (uint8_t)((i * 7 + j) & 255);
        CHECK(ok, "sector %u content", i);
    }
    CHECK(vera_read(&v, 124, 4, s) == VERA_OK && vera_read(&v, 125, 4, s) == VERA_ERR_IO && vera_read(&v, 128, 1, s) == VERA_ERR_IO,
          "range checks");

    memset(s, 0xA5, 512);
    CHECK(vera_write(&v, 5, 1, s) == VERA_OK, "write sector 5");
    CHECK(vera_read(&v, 5, 1, s) == VERA_OK && s[0] == 0xA5 && s[511] == 0xA5, "reads back");
    CHECK(vera_read(&v, 4, 1, s) == VERA_OK && s[0] == (uint8_t)(4 * 7), "neighbour untouched");
    vera_close(&v);
    CHECK(vera_sectors(&v) == 0 && vera_read(&v, 0, 1, s) == VERA_ERR_IO, "closed volume refuses I/O");
    fclose(f);

    /* hidden volume: the outer password opens the outer volume, the hidden one's opens the hidden volume */
    char hsrc[512];
    snprintf(hsrc, sizeof hsrc, "%s/vera_hidden.hc", argv[1]);
    FILE *hf = fopen(hsrc, "rb");
    if (!hf) { printf("cannot open %s\n", hsrc); return 2; }
    vera_io hio = {rd, NULL, hf};
    const uint8_t hpw[] = "cardpass-hidden-test";
    CHECK(vera_open(&v, &hio, pw, sizeof pw - 1, NULL, NULL) == VERA_OK && !vera_hidden(&v) && vera_sectors(&v) == 128, "outer volume opens");
    for (uint32_t i = 0; i < 96; i++) {
        bool ok = vera_read(&v, i, 1, s) == VERA_OK;
        for (int j = 0; j < 512; j++) ok &= s[j] == (uint8_t)((i * 7 + j) & 255);
        CHECK(ok, "outer sector %u", i);
    }
    vera_close(&v);
    CHECK(vera_open(&v, &hio, hpw, sizeof hpw - 1, NULL, NULL) == VERA_OK && vera_hidden(&v) && vera_sectors(&v) == 32, "hidden volume opens");
    for (uint32_t i = 0; i < 32; i++) {
        bool ok = vera_read(&v, i, 1, s) == VERA_OK;
        for (int j = 0; j < 512; j++) ok &= s[j] == (uint8_t)((i * 13 + j * 3 + 1) & 255);
        CHECK(ok, "hidden sector %u", i);
    }
    CHECK(vera_write(&v, 0, 1, s) == VERA_ERR_IO && vera_read(&v, 32, 1, s) == VERA_ERR_IO, "read-only io and range respected");
    vera_close(&v);
    CHECK(vera_open(&v, &hio, (const uint8_t *)"neither", 7, NULL, NULL) == VERA_ERR_PASSWORD, "neither password");
    fclose(hf);
    FILE *sf = fopen(src, "rb");
    vera_io sio = {rd, NULL, sf};
    CHECK(vera_open(&v, &sio, hpw, sizeof hpw - 1, NULL, NULL) == VERA_ERR_PASSWORD, "no hidden volume in a standard container");
    fclose(sf);

    /* a file that is not a VeraCrypt volume */
    FILE *z = tmpfile();
    uint8_t junk[512];
    for (int i = 0; i < 512; i++) junk[i] = (uint8_t)(i * 31 + 7);
    fwrite(junk, 1, 512, z);
    vera_io zio = {rd, NULL, z};
    CHECK(vera_open(&v, &zio, pw, sizeof pw - 1, NULL, NULL) == VERA_ERR_PASSWORD, "random file is not a volume");
    fclose(z);

    printf(failures ? "vera: %d FAILED\n" : "vera: ok\n", failures);
    return failures != 0;
}
