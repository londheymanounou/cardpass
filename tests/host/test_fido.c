/* Stage 7 core: CTAPHID framing + CTAP2 getInfo/getAssertion over KeePassXC passkeys.
 * Assertions are written to <work>/fido_out.txt; tools/check_passkeys.py verifies
 * the signatures with the public keys (pycryptodomex), independently of mbedTLS.
 *   test_fido <testdata dir> <work dir> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../components/fido/cbor.h"
#include "fido.h"
#include "mbedtls/sha256.h"

static int failures;
#define CHECK(c, ...) do { if (!(c)) { failures++; printf("  FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

/* ---- host side of the HID link ---- */
static uint8_t rx[4096], rxcmd;
static size_t rxlen, rxtotal;
static int rxseq, rxseq_bad;
static void on_report(void *ctx, const uint8_t r[64])
{
    (void)ctx;
    if (r[4] & 0x80) {
        rxcmd = r[4];
        rxtotal = (size_t)(r[5] << 8 | r[6]);
        rxlen = rxtotal < 57 ? rxtotal : 57;
        memcpy(rx, r + 7, rxlen);
        rxseq = rxseq_bad = 0;
    } else {
        size_t k = rxtotal - rxlen < 59 ? rxtotal - rxlen : 59;
        rxseq_bad |= r[4] != rxseq++;
        memcpy(rx + rxlen, r + 5, k);
        rxlen += k;
    }
}

static ctaphid hid;
static fido_env env;

static void send_msg(uint32_t cid, uint8_t cmd, const uint8_t *d, size_t n)
{
    uint8_t r[64] = {0};
    r[0] = (uint8_t)(cid >> 24); r[1] = (uint8_t)(cid >> 16); r[2] = (uint8_t)(cid >> 8); r[3] = (uint8_t)cid;
    r[4] = cmd;
    r[5] = (uint8_t)(n >> 8);
    r[6] = (uint8_t)n;
    size_t k = n < 57 ? n : 57, off;
    memcpy(r + 7, d, k);
    ctaphid_report(&hid, r, &env, on_report, NULL);
    uint8_t seq = 0;
    for (off = k; off < n; off += k) {
        memset(r + 4, 0, 60);
        r[4] = seq++;
        k = n - off < 59 ? n - off : 59;
        memcpy(r + 5, d + off, k);
        ctaphid_report(&hid, r, &env, on_report, NULL);
    }
}

/* ---- device UI stand-in ---- */
static const char *want_user;   /* pick this account; NULL = decline */
static size_t last_n;
static int choose(void *ctx, const char *rp, const fido_cred *c, size_t n)
{
    (void)ctx; (void)rp;
    last_n = n;
    for (size_t i = 0; i < n && want_user; i++)
        if (!strcmp(c[i].user_name, want_user)) return (int)i;
    return -1;
}

static uint32_t cid;
static uint8_t cdh[32];
static FILE *out;

/* getAssertion via CTAPHID; returns CTAP status. */
static int assertion(const char *rp, const fido_cred *allow, size_t nallow, const char *extra_opt, const char *label)
{
    uint8_t req[1024];
    cbor_w w = {req + 1, 0, sizeof req - 1, false};
    req[0] = 0x02;
    cbor_map(&w, 2 + (nallow ? 1 : 0) + (extra_opt ? 1 : 0));
    cbor_uint(&w, 1); cbor_text(&w, rp);
    cbor_uint(&w, 2); cbor_bytes(&w, cdh, 32);
    if (nallow) {
        cbor_uint(&w, 3);
        cbor_array(&w, nallow);
        for (size_t i = 0; i < nallow; i++) {
            cbor_map(&w, 2);
            cbor_text(&w, "id"); cbor_bytes(&w, allow[i].cred_id, allow[i].cred_len);
            cbor_text(&w, "type"); cbor_text(&w, "public-key");
        }
    }
    if (extra_opt) {
        cbor_uint(&w, 5);
        cbor_map(&w, 1);
        cbor_text(&w, extra_opt); cbor_bool(&w, true);
    }
    send_msg(cid, 0x90, req, 1 + w.n);
    if (rxcmd != 0x90 || !rxlen) return -1;
    if (rx[0] == 0 && label) {
        fprintf(out, "%s\t%s\t", label, rp);
        for (size_t i = 1; i < rxlen; i++) fprintf(out, "%02x", rx[i]);
        fprintf(out, "\t");
        for (int i = 0; i < 32; i++) fprintf(out, "%02x", cdh[i]);
        fprintf(out, "\n");
    }
    return rx[0];
}

int main(int argc, char **argv)
{
    const char *tdir = argc > 1 ? argv[1] : "testdata", *wdir = argc > 2 ? argv[2] : ".";
    char path[512];
    snprintf(path, sizeof path, "%s/passkeys.kdbx", tdir);
    FILE *f = fopen(path, "rb");
    kdbx_key k;
    kdbx_db *db = NULL;
    kdbx_key_init(&k, "test", 4, NULL);
    CHECK(f && kdbx_open(f, &k, &db) == KDBX_OK, "open passkeys.kdbx");
    if (f) fclose(f);
    kdbx_key_wipe(&k);
    if (!db) return 1;
    snprintf(path, sizeof path, "%s/fido_out.txt", wdir);
    out = fopen(path, "w");

    fido_cred creds[8];
    CHECK(fido_find(db, NULL, creds, 8) == 5, "all passkeys");
    CHECK(fido_find(db, "webauthn.io", creds, 8) == 2, "webauthn.io has 2");
    fido_cred bob = !strcmp(creds[0].user_name, "bob") ? creds[0] : creds[1];
    CHECK(bob.cred_len == 32 && bob.user_len == 16 && bob.be && bob.bs, "parsed fields");
    fido_cred gh;
    CHECK(fido_find(db, "github.com", &gh, 1) == 1 && !gh.be && !gh.bs, "flags off");

    env = (fido_env){db, choose, NULL};
    ctaphid_init(&hid);
    mbedtls_sha256((const uint8_t *)"{\"type\":\"webauthn.get\"}", 23, cdh, 0);

    /* INIT on the broadcast channel -> new channel id */
    uint8_t nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    send_msg(0xFFFFFFFF, 0x86, nonce, 8);
    CHECK(rxcmd == 0x86 && rxlen == 17 && !memcmp(rx, nonce, 8) && rx[16] == 0x0D, "INIT reply");
    cid = (uint32_t)rx[8] << 24 | rx[9] << 16 | rx[10] << 8 | rx[11];
    CHECK(cid && cid != 0xFFFFFFFF, "cid");

    /* multi-packet PING echo */
    uint8_t ping[300];
    for (int i = 0; i < 300; i++) ping[i] = (uint8_t)i;
    send_msg(cid, 0x81, ping, sizeof ping);
    CHECK(rxcmd == 0x81 && rxlen == 300 && !memcmp(rx, ping, 300) && !rxseq_bad, "PING echo");

    /* getInfo */
    uint8_t gi = 0x04;
    send_msg(cid, 0x90, &gi, 1);
    CHECK(rxcmd == 0x90 && rx[0] == 0 && rxlen > 40, "getInfo");
    {
        cbor_r r = {rx + 1, rx + rxlen, false};
        cbor_item it;
        CHECK(cbor_next(&r, &it) && it.type == CBOR_MAP && it.val == 6 && cbor_skip(&(cbor_r){rx + 1, rx + rxlen, false}),
              "getInfo is a 6-entry map");
    }

    /* assertions */
    want_user = "alice";
    CHECK(assertion("webauthn.io", NULL, 0, NULL, "alice") == 0 && last_n == 2, "discoverable, user picks alice");
    want_user = "bob";
    CHECK(assertion("webauthn.io", &bob, 1, NULL, "bob") == 0 && last_n == 1, "allow list -> bob (RSA)");
    want_user = "carol";
    CHECK(assertion("github.com", NULL, 0, "up", "carol") == 0, "github, up option");
    want_user = "erin";
    CHECK(assertion("strongbox.example", NULL, 0, NULL, "erin") == 0, "StrongBox credential id field");

    want_user = "carol";
    CHECK(assertion("github.com", &bob, 1, NULL, NULL) == CTAP2_ERR_NO_CREDENTIALS, "wrong allow list");
    CHECK(assertion("nothing.example", NULL, 0, NULL, NULL) == CTAP2_ERR_NO_CREDENTIALS, "unknown rp");
    want_user = "dave";
    CHECK(assertion("ed.example", NULL, 0, NULL, NULL) == CTAP2_ERR_UNSUPPORTED_ALGORITHM, "Ed25519 refused");
    want_user = NULL;
    CHECK(assertion("webauthn.io", NULL, 0, NULL, NULL) == CTAP2_ERR_OPERATION_DENIED, "user declines");
    want_user = "alice";
    CHECK(assertion("webauthn.io", NULL, 0, "rk", NULL) == CTAP2_ERR_UNSUPPORTED_OPTION, "rk option");

    uint8_t mc = 0x01, bad[3] = {0x02, 0xA1, 0xFF};
    send_msg(cid, 0x90, &mc, 1);
    CHECK(rx[0] == CTAP2_ERR_OPERATION_DENIED, "makeCredential refused");
    send_msg(cid, 0x90, bad, 3);
    CHECK(rx[0] == CTAP2_ERR_INVALID_CBOR, "bad CBOR");

    env.db = NULL; /* locked */
    CHECK(assertion("webauthn.io", NULL, 0, NULL, NULL) == CTAP2_ERR_NOT_ALLOWED, "locked");
    env.db = db;

    /* framing errors */
    uint8_t r[64] = {0};
    r[0] = 0x12; r[1] = 0x34; r[2] = 0x56; r[3] = 0x78; r[4] = 0x81; r[6] = 1;
    ctaphid_report(&hid, r, &env, on_report, NULL);
    CHECK(rxcmd == 0xBF && rx[0] == 0x0B, "unknown channel");
    uint8_t big[100] = {0};
    r[0] = (uint8_t)(cid >> 24); r[1] = (uint8_t)(cid >> 16); r[2] = (uint8_t)(cid >> 8); r[3] = (uint8_t)cid;
    r[4] = 0x81; r[5] = 0; r[6] = sizeof big;
    ctaphid_report(&hid, r, &env, on_report, NULL); /* first part of a 2-packet ping */
    r[4] = 5; /* wrong sequence number */
    ctaphid_report(&hid, r, &env, on_report, NULL);
    CHECK(rxcmd == 0xBF && rx[0] == 0x04, "bad sequence");
    (void)big;

    fclose(out);
    kdbx_close(db);
    printf("fido: %d failures\n", failures);
    return failures != 0;
}
