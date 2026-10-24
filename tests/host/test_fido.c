/* Stage 7 core: CTAPHID framing + CTAP2 getInfo/getAssertion over KeePassXC passkeys.
 * Assertions are written to <work>/fido_out.txt; tools/check_passkeys.py verifies
 * the signatures with the public keys (pycryptodomex), independently of mbedTLS.
 *   test_fido <testdata dir> <work dir> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../components/fido/cbor.h"
#include "fido.h"
#include "mbedtls/pk.h"
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
static int asked;
static int choose(void *ctx, const char *rp, const fido_cred *c, size_t n)
{
    (void)ctx; (void)rp;
    last_n = n;
    asked++;
    for (size_t i = 0; i < n && want_user; i++)
        if (!strcmp(c[i].user_name, want_user)) return (int)i;
    return -1;
}

static uint32_t cid;
static uint8_t cdh[32];
static FILE *out;

/* getAssertion via CTAPHID; returns CTAP status. */
static bool contains(const uint8_t *h, size_t n, const char *needle)   /* memmem is not on every host */
{
    size_t k = strlen(needle);
    for (size_t i = 0; i + k <= n; i++)
        if (!memcmp(h + i, needle, k)) return true;
    return false;
}

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
        if (!strcmp(extra_opt, "silent")) cbor_text(&w, "up"), cbor_bool(&w, false);     /* up=false */
        else cbor_text(&w, extra_opt), cbor_bool(&w, true);
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

/* ---- registration stand-ins ---- */
static fido_new got;
static int store_ret, store_calls;
static int store_cb(void *ctx, const fido_new *n)
{
    (void)ctx;
    got = *n;
    store_calls++;
    return store_ret;
}

void cp_random(void *buf, size_t n);
static int test_rng(void *ctx, unsigned char *p, size_t n)
{
    (void)ctx;
    cp_random(p, n);
    return 0;
}

static size_t b64url_dec(const char *s, uint8_t *out, size_t max)
{
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    uint32_t acc = 0;
    int bits = 0;
    size_t n = 0;
    for (; *s; s++) {
        const char *p = strchr(T, *s);
        if (!p) return 0;
        acc = acc << 6 | (uint32_t)(p - T);
        if ((bits += 6) >= 8 && n < max) out[n++] = (uint8_t)(acc >> (bits -= 8));
    }
    return n;
}

/* makeCredential via CTAPHID. variant: 0 normal, 1 options up=false, 2 pinUvAuthParam present, 3 no user. */
static int makecred(const char *rp, const char *user, const uint8_t *uid, size_t uidlen, int alg, const uint8_t *excl, size_t exlen,
                    int variant)
{
    uint8_t req[1024];
    cbor_w w = {req + 1, 0, sizeof req - 1, false};
    req[0] = 0x01;
    cbor_map(&w, 5 + (excl ? 1 : 0) + (variant == 2 ? 1 : 0) - (variant == 3 ? 1 : 0));
    cbor_uint(&w, 1); cbor_bytes(&w, cdh, 32);
    cbor_uint(&w, 2);
    cbor_map(&w, 2);
    cbor_text(&w, "id"); cbor_text(&w, rp);
    cbor_text(&w, "name"); cbor_text(&w, "Example");
    if (variant != 3) {
        cbor_uint(&w, 3);
        cbor_map(&w, 3);
        cbor_text(&w, "id"); cbor_bytes(&w, uid, uidlen);
        cbor_text(&w, "name"); cbor_text(&w, user);
        cbor_text(&w, "displayName"); cbor_text(&w, "Zoe Z");
    }
    cbor_uint(&w, 4);
    cbor_array(&w, 1);
    cbor_map(&w, 2);
    cbor_text(&w, "alg"); cbor_int(&w, alg);
    cbor_text(&w, "type"); cbor_text(&w, "public-key");
    if (excl) {
        cbor_uint(&w, 5);
        cbor_array(&w, 1);
        cbor_map(&w, 2);
        cbor_text(&w, "id"); cbor_bytes(&w, excl, exlen);
        cbor_text(&w, "type"); cbor_text(&w, "public-key");
    }
    cbor_uint(&w, 7);
    cbor_map(&w, variant == 1 ? 2 : 1);
    cbor_text(&w, "rk"); cbor_bool(&w, true);
    if (variant == 1) cbor_text(&w, "up"), cbor_bool(&w, false);
    if (variant == 2) cbor_uint(&w, 8), cbor_bytes(&w, cdh, 16);
    send_msg(cid, 0x90, req, 1 + w.n);
    return rxcmd != 0x90 || !rxlen ? -1 : rx[0];
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

    env = (fido_env){db, choose, NULL, store_cb};
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
    {   /* up=false: answered without asking, the UP flag is clear; with no passkey it is still NO_CREDENTIALS */
        int before = asked;
        CHECK(assertion("webauthn.io", &bob, 1, "silent", NULL) == 0 && asked == before, "silent probe: no prompt");
        CHECK(rxlen > 40, "silent probe: assertion returned");
        CHECK(rxlen < 140 && !contains(rx, rxlen, "alice") && !contains(rx, rxlen, "bob"), "silent probe: no user data");
        CHECK(assertion("webauthn.io", NULL, 0, "silent", NULL) == CTAP2_ERR_UNSUPPORTED_OPTION && asked == before,
              "silent probe without an allow list: refused (no listing of accounts)");
        CHECK(assertion("nothing.example", &bob, 1, "silent", NULL) == CTAP2_ERR_NO_CREDENTIALS && asked == before, "silent probe, no passkey");
        CHECK(assertion("webauthn.io", NULL, 0, NULL, NULL) == CTAP2_ERR_OPERATION_DENIED && asked == before + 1, "a normal request still asks");
    }
    want_user = "alice";
    CHECK(assertion("webauthn.io", NULL, 0, "rk", NULL) == CTAP2_ERR_UNSUPPORTED_OPTION, "rk option");

    /* registration (makeCredential) */
    {
        static const uint8_t uid[16] = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6};
        int stores = store_calls;
        store_ret = 0;
        CHECK(makecred("example.org", "zoe", uid, sizeof uid, -7, NULL, 0, 0) == 0 && store_calls == stores + 1, "register: ok");
        CHECK(!strcmp(got.rp_id, "example.org") && !strcmp(got.user_name, "zoe") && !strcmp(got.rp_name, "Example") &&
                  !strcmp(got.user_display, "Zoe Z"), "register: the entry's strings");
        /* response: {1: "none", 2: authData, 3: {}} */
        CHECK(rxlen > 120 && rx[1] == 0xA3 && !memcmp(rx + 2, "\x01\x64none\x02\x58", 8), "register: none attestation");
        const uint8_t *ad = rx + 11;
        size_t adl = rx[10];
        uint8_t h[32];
        mbedtls_sha256((const uint8_t *)"example.org", 11, h, 0);
        CHECK(adl == 37 + 16 + 2 + 32 + 77 && !memcmp(ad, h, 32) && ad[32] == 0x5D && !memcmp(ad + 33, "\0\0\0\0", 4), "register: authData header");
        CHECK(ad[53] == 0 && ad[54] == 32, "register: credential id length");
        CHECK(!memcmp(ad + 55 + 32, "\xA5\x01\x02\x03\x26\x20\x01\x21\x58\x20", 10) && ad[55 + 32 + 42] == 0x22, "register: COSE key");
        const uint8_t *x = ad + 87 + 10, *y = x + 35;        /* the COSE key starts at 87; y follows 0x22 0x58 0x20 */
        /* the credential id in the entry is the one in authData, and the PEM key is the one whose public key is in the COSE key */
        uint8_t cid_bin[48];
        CHECK(b64url_dec(got.cred_b64, cid_bin, sizeof cid_bin) == 32 && !memcmp(cid_bin, ad + 55, 32), "register: credential id stored");
        uint8_t uid_bin[32];
        CHECK(b64url_dec(got.user_b64, uid_bin, sizeof uid_bin) == sizeof uid && !memcmp(uid_bin, uid, sizeof uid), "register: user handle stored");
        CHECK(!strncmp(got.pem, "-----BEGIN PRIVATE KEY-----\n", 28), "register: PKCS#8 PEM");
        {
            mbedtls_pk_context priv, pubk;
            mbedtls_pk_init(&priv);
            mbedtls_pk_init(&pubk);
            uint8_t spki[91] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
                                0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04};
            memcpy(spki + 27, x, 32);
            memcpy(spki + 59, y, 32);
            uint8_t msg[32] = {1, 2, 3}, sig[100];
            size_t sl = 0;
            CHECK(!mbedtls_pk_parse_key(&priv, (const unsigned char *)got.pem, strlen(got.pem) + 1, NULL, 0, test_rng, NULL), "register: the PEM parses");
            CHECK(!mbedtls_pk_parse_public_key(&pubk, spki, sizeof spki), "register: the COSE key is a valid point");
            CHECK(!mbedtls_pk_sign(&priv, MBEDTLS_MD_SHA256, msg, 32, sig, sizeof sig, &sl, test_rng, NULL) &&
                      !mbedtls_pk_verify(&pubk, MBEDTLS_MD_SHA256, msg, 32, sig, sl), "register: the PEM key signs for the COSE public key");
            mbedtls_pk_free(&priv);
            mbedtls_pk_free(&pubk);
        }
        if (out) {                                           /* tools/check_passkeys.py re-reads this with OpenSSL */
            fprintf(out, "NEWKEY\texample.org\t%s\t", got.cred_b64);
            for (size_t i = 0; i < 32; i++) fprintf(out, "%02x", x[i]);
            fprintf(out, "\t");
            for (size_t i = 0; i < 32; i++) fprintf(out, "%02x", y[i]);
            fprintf(out, "\t");
            for (const char *p = got.pem; *p; p++) fprintf(out, "%02x", (unsigned char)*p);
            fprintf(out, "\n");
        }

        stores = store_calls;
        store_ret = 1;
        CHECK(makecred("example.org", "zoe", uid, sizeof uid, -7, NULL, 0, 0) == CTAP2_ERR_OPERATION_DENIED, "register: user declines");
        store_ret = 2;
        CHECK(makecred("example.org", "zoe", uid, sizeof uid, -7, NULL, 0, 0) == CTAP1_ERR_OTHER, "register: saving failed");
        store_ret = 0;
        stores = store_calls;
        CHECK(makecred("example.org", "zoe", uid, sizeof uid, -257, NULL, 0, 0) == CTAP2_ERR_UNSUPPORTED_ALGORITHM && store_calls == stores,
              "register: RS256 only is refused, no prompt");
        CHECK(makecred("example.org", "zoe", uid, 0, -7, NULL, 0, 0) == 0, "register: a user handle of any size");
        CHECK(makecred("webauthn.io", "bob2", uid, sizeof uid, -7, bob.cred_id, bob.cred_len, 0) == CTAP2_ERR_CREDENTIAL_EXCLUDED &&
                  store_calls == stores + 1, "register: excluded credential, no prompt");
        CHECK(makecred("example.org", "zoe", uid, sizeof uid, -7, NULL, 0, 1) == CTAP2_ERR_UNSUPPORTED_OPTION, "register: up=false refused");
        CHECK(makecred("example.org", "zoe", uid, sizeof uid, -7, NULL, 0, 2) == CTAP2_ERR_PIN_AUTH_INVALID, "register: no PIN protocol");
        CHECK(makecred("example.org", "zoe", uid, sizeof uid, -7, NULL, 0, 3) == CTAP2_ERR_MISSING_PARAMETER, "register: no user");
        env.db = NULL;
        CHECK(makecred("example.org", "zoe", uid, sizeof uid, -7, NULL, 0, 0) == CTAP2_ERR_NOT_ALLOWED, "register: locked");
        env.db = db;
    }

    uint8_t mc = 0x01, bad[3] = {0x02, 0xA1, 0xFF};
    send_msg(cid, 0x90, &mc, 1);
    CHECK(rx[0] == CTAP2_ERR_INVALID_CBOR, "makeCredential without a request");
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
