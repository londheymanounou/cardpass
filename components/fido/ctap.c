/* CTAP2 authenticator over KeePassXC passkeys. */
#include <stdlib.h>
#include <string.h>
#include "cbor.h"
#include "fido.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"

#define PEM_MAX 4096

/* CardPass AAGUID (random, fixed) */
static const uint8_t AAGUID[16] = {0x6c, 0x2f, 0x4b, 0x1e, 0x93, 0x0d, 0x4a, 0x57, 0xb8, 0x21, 0x5e, 0xc4, 0x0a, 0x77, 0xd3, 0x19};

enum { FLAG_UP = 0x01, FLAG_UV = 0x04, FLAG_BE = 0x08, FLAG_BS = 0x10 };

/* ---------------- passkeys in the database ---------------- */

static bool reveal(const kdbx_db *db, const kdbx_entry *e, const char *key, char *out, size_t n)
{
    const kdbx_field *f = kdbx_field_get(e, key);
    return f && kdbx_reveal(db, f, out, n) == KDBX_OK;
}

static int b64url_val(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-' || c == '+') return 62;
    if (c == '_' || c == '/') return 63;
    return -1;
}

/* base64url (or standard base64), padding optional. Returns length or 0 on error. */
static size_t b64url_decode(const char *s, uint8_t *out, size_t max)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t n = 0;
    for (; *s && *s != '='; s++) {
        int v = b64url_val((unsigned char)*s);
        if (v < 0) return 0;
        acc = acc << 6 | (uint32_t)v;
        if ((bits += 6) >= 8) {
            if (n == max) return 0;
            out[n++] = (uint8_t)(acc >> (bits -= 8));
        }
    }
    return n;
}

static bool flag_on(const kdbx_db *db, const kdbx_entry *e, const char *key)
{
    char v[8];
    return reveal(db, e, key, v, sizeof v) && (!strcmp(v, "1") || !strcmp(v, "true") || !strcmp(v, "True"));
}

size_t fido_find(const kdbx_db *db, const char *rp_id, fido_cred *out, size_t max)
{
    size_t n = 0;
    char buf[512];
    for (const kdbx_entry *e = kdbx_entries(db); e; e = e->next) {
        fido_cred c = {e, {0}, {0}, {0}, {0}, 0, 0, false, false};
        if (!reveal(db, e, "KPEX_PASSKEY_RELYING_PARTY", c.rp_id, sizeof c.rp_id) || !kdbx_field_get(e, "KPEX_PASSKEY_PRIVATE_KEY_PEM"))
            continue;
        if (rp_id && strcmp(rp_id, c.rp_id)) continue;
        /* StrongBox writes KPEX_PASSKEY_GENERATED_USER_ID; KeePassXC prefers it too */
        if (!reveal(db, e, "KPEX_PASSKEY_GENERATED_USER_ID", buf, sizeof buf) &&
            !reveal(db, e, "KPEX_PASSKEY_CREDENTIAL_ID", buf, sizeof buf))
            continue;
        c.cred_len = b64url_decode(buf, c.cred_id, sizeof c.cred_id);
        if (reveal(db, e, "KPEX_PASSKEY_USER_HANDLE", buf, sizeof buf)) c.user_len = b64url_decode(buf, c.user_id, sizeof c.user_id);
        if (!reveal(db, e, "KPXC_PASSKEY_USERNAME", c.user_name, sizeof c.user_name))
            reveal(db, e, "KPEX_PASSKEY_USERNAME", c.user_name, sizeof c.user_name);
        c.be = flag_on(db, e, "KPEX_PASSKEY_FLAG_BE");
        c.bs = flag_on(db, e, "KPEX_PASSKEY_FLAG_BS");
        mbedtls_platform_zeroize(buf, sizeof buf);
        if (!c.cred_len) continue;
        if (n < max) out[n] = c;
        n++;
    }
    return n;
}

/* ---------------- signing ---------------- */

void cp_random(void *buf, size_t n);
static int rng(void *ctx, unsigned char *out, size_t n)
{
    (void)ctx;
    cp_random(out, n);
    return 0;
}

/* Signs authData || clientDataHash with the entry's PEM key (ES256 / RS256). */
static int sign(const kdbx_db *db, const kdbx_entry *e, const uint8_t *auth, size_t alen, const uint8_t cdh[32],
                uint8_t *sig, size_t sigmax, size_t *siglen)
{
    char *pem = malloc(PEM_MAX);
    mbedtls_pk_context pk;
    mbedtls_sha256_context sha;
    uint8_t hash[32];
    int st = CTAP1_ERR_OTHER;

    mbedtls_pk_init(&pk);
    if (!pem) return st;
    if (!reveal(db, e, "KPEX_PASSKEY_PRIVATE_KEY_PEM", pem, PEM_MAX)) goto out;
    if (mbedtls_pk_parse_key(&pk, (const unsigned char *)pem, strlen(pem) + 1, NULL, 0, rng, NULL)) {
        st = CTAP2_ERR_UNSUPPORTED_ALGORITHM; /* e.g. Ed25519, not in mbedTLS 3.6 */
        goto out;
    }
    if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_ECKEY && mbedtls_pk_get_type(&pk) != MBEDTLS_PK_RSA) {
        st = CTAP2_ERR_UNSUPPORTED_ALGORITHM;
        goto out;
    }
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, auth, alen);
    mbedtls_sha256_update(&sha, cdh, 32);
    mbedtls_sha256_finish(&sha, hash);
    mbedtls_sha256_free(&sha);
    if (!mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 32, sig, sigmax, siglen, rng, NULL)) st = CTAP2_OK;
out:
    mbedtls_pk_free(&pk);
    mbedtls_platform_zeroize(pem, PEM_MAX);
    free(pem);
    return st;
}

/* ---------------- commands ---------------- */

static size_t get_info(uint8_t *resp, size_t max)
{
    cbor_w w = {resp + 1, 0, max - 1, false};
    cbor_map(&w, 6);
    cbor_uint(&w, 1); /* versions */
    cbor_array(&w, 1);
    cbor_text(&w, "FIDO_2_0");
    cbor_uint(&w, 3); /* aaguid */
    cbor_bytes(&w, AAGUID, 16);
    cbor_uint(&w, 4); /* options: canonical order = length, then bytes */
    cbor_map(&w, 4);
    cbor_text(&w, "rk"); cbor_bool(&w, true);
    cbor_text(&w, "up"); cbor_bool(&w, true);
    cbor_text(&w, "uv"); cbor_bool(&w, true);    /* unlocked with the master password */
    cbor_text(&w, "plat"); cbor_bool(&w, false);
    cbor_uint(&w, 5); /* maxMsgSize */
    cbor_uint(&w, CTAPHID_MAX_MSG);
    cbor_uint(&w, 9); /* transports */
    cbor_array(&w, 1);
    cbor_text(&w, "usb");
    cbor_uint(&w, 10); /* algorithms */
    cbor_array(&w, 2);
    int64_t algs[2] = {-7, -257};
    for (int i = 0; i < 2; i++) {
        cbor_map(&w, 2);
        cbor_text(&w, "alg"); cbor_int(&w, algs[i]);
        cbor_text(&w, "type"); cbor_text(&w, "public-key");
    }
    if (w.overflow) { resp[0] = CTAP1_ERR_OTHER; return 1; }
    resp[0] = CTAP2_OK;
    return 1 + w.n;
}

static bool text_eq(const cbor_item *it, const char *s)
{
    return it->type == CBOR_TEXT && it->val == strlen(s) && !memcmp(it->data, s, it->val);
}

#define MAX_ALLOW 16
#define MAX_CREDS 16

static int get_assertion(const fido_env *env, cbor_r *r, uint8_t *resp, size_t max, size_t *rlen)
{
    cbor_item it, k;
    char rp[256] = "";
    const uint8_t *cdh = NULL;
    struct { const uint8_t *id; size_t len; } allow[MAX_ALLOW];
    size_t nallow = 0;
    bool has_allow = false;

    if (!cbor_next(r, &it) || it.type != CBOR_MAP) return CTAP2_ERR_INVALID_CBOR;
    for (uint64_t i = 0; i < it.val; i++) {
        int64_t key;
        if (!cbor_next(r, &k) || !cbor_int_value(&k, &key)) return CTAP2_ERR_INVALID_CBOR;
        if (key == 1) {
            if (!cbor_next(r, &k) || k.type != CBOR_TEXT || k.val >= sizeof rp) return CTAP2_ERR_INVALID_CBOR;
            memcpy(rp, k.data, k.val);
            rp[k.val] = 0;
        } else if (key == 2) {
            if (!cbor_next(r, &k) || k.type != CBOR_BYTES || k.val != 32) return CTAP2_ERR_INVALID_CBOR;
            cdh = k.data;
        } else if (key == 3) {
            if (!cbor_next(r, &k) || k.type != CBOR_ARRAY) return CTAP2_ERR_INVALID_CBOR;
            has_allow = true;
            for (uint64_t a = 0; a < k.val; a++) {
                cbor_item m, kk, v;
                if (!cbor_next(r, &m) || m.type != CBOR_MAP) return CTAP2_ERR_INVALID_CBOR;
                for (uint64_t j = 0; j < m.val; j++) {
                    if (!cbor_next(r, &kk)) return CTAP2_ERR_INVALID_CBOR;
                    if (text_eq(&kk, "id")) {
                        if (!cbor_next(r, &v) || v.type != CBOR_BYTES) return CTAP2_ERR_INVALID_CBOR;
                        if (nallow < MAX_ALLOW) allow[nallow].id = v.data, allow[nallow++].len = (size_t)v.val;
                    } else if (!cbor_skip(r)) {
                        return CTAP2_ERR_INVALID_CBOR;
                    }
                }
            }
        } else if (key == 5) {
            if (!cbor_next(r, &k) || k.type != CBOR_MAP) return CTAP2_ERR_INVALID_CBOR;
            for (uint64_t j = 0; j < k.val; j++) {
                cbor_item kk, v;
                if (!cbor_next(r, &kk) || !cbor_next(r, &v)) return CTAP2_ERR_INVALID_CBOR;
                if (text_eq(&kk, "rk")) return CTAP2_ERR_UNSUPPORTED_OPTION; /* invalid for getAssertion */
                /* up=false (silent probe): still confirmed by the user below; uv: always verified */
            }
        } else if (key == 6) {
            return CTAP2_ERR_PIN_AUTH_INVALID; /* no clientPin declared */
        } else if (!cbor_skip(r)) {
            return CTAP2_ERR_INVALID_CBOR;
        }
    }
    if (r->err) return CTAP2_ERR_INVALID_CBOR;
    if (!rp[0] || !cdh) return CTAP2_ERR_MISSING_PARAMETER;

    /* candidates: the allow list, or every passkey for this RP (discoverable) */
    fido_cred *all = malloc(sizeof *all * MAX_CREDS), *pick = malloc(sizeof *pick * MAX_CREDS);
    int st = CTAP2_OK;
    if (!all || !pick) { st = CTAP1_ERR_OTHER; goto out; }
    size_t nall = fido_find(env->db, rp, all, MAX_CREDS), npick = 0;
    if (nall > MAX_CREDS) nall = MAX_CREDS;
    for (size_t i = 0; i < nall; i++) {
        bool ok = !has_allow;
        for (size_t a = 0; a < nallow && !ok; a++)
            ok = allow[a].len == all[i].cred_len && !memcmp(allow[a].id, all[i].cred_id, all[i].cred_len);
        if (ok) pick[npick++] = all[i];
    }
    if (!npick) { st = CTAP2_ERR_NO_CREDENTIALS; goto out; }
    int sel = env->choose(env->ctx, rp, pick, npick);
    if (sel < 0 || (size_t)sel >= npick) { st = CTAP2_ERR_OPERATION_DENIED; goto out; }
    const fido_cred *c = &pick[sel];

    uint8_t auth[37], sig[600];
    size_t siglen;
    mbedtls_sha256((const uint8_t *)rp, strlen(rp), auth, 0);
    auth[32] = FLAG_UP | FLAG_UV | (c->be ? FLAG_BE : 0) | (c->bs ? FLAG_BS : 0);
    memset(auth + 33, 0, 4); /* signature counter: KeePassXC always uses 0 */
    if ((st = sign(env->db, c->e, auth, sizeof auth, cdh, sig, sizeof sig, &siglen)) != CTAP2_OK) goto out;

    cbor_w w = {resp + 1, 0, max - 1, false};
    cbor_map(&w, c->user_len ? 4 : 3);
    cbor_uint(&w, 1);
    cbor_map(&w, 2);
    cbor_text(&w, "id"); cbor_bytes(&w, c->cred_id, c->cred_len);
    cbor_text(&w, "type"); cbor_text(&w, "public-key");
    cbor_uint(&w, 2);
    cbor_bytes(&w, auth, sizeof auth);
    cbor_uint(&w, 3);
    cbor_bytes(&w, sig, siglen);
    if (c->user_len) {
        cbor_uint(&w, 4);
        cbor_map(&w, c->user_name[0] ? 3 : 1);
        cbor_text(&w, "id"); cbor_bytes(&w, c->user_id, c->user_len);
        if (c->user_name[0]) {
            cbor_text(&w, "name"); cbor_text(&w, c->user_name);
            cbor_text(&w, "displayName"); cbor_text(&w, c->user_name);
        }
    }
    if (w.overflow) st = CTAP1_ERR_OTHER;
    else *rlen = w.n;
out:
    if (all) mbedtls_platform_zeroize(all, sizeof *all * MAX_CREDS);
    if (pick) mbedtls_platform_zeroize(pick, sizeof *pick * MAX_CREDS);
    free(all);
    free(pick);
    return st;
}

size_t ctap2_handle(const fido_env *env, const uint8_t *req, size_t n, uint8_t *resp, size_t max)
{
    if (!n || max < 2) { resp[0] = CTAP1_ERR_INVALID_COMMAND; return 1; }
    cbor_r r = {req + 1, req + n, false};
    size_t rlen = 0;
    int st;
    switch (req[0]) {
    case 0x04: return get_info(resp, max);                  /* authenticatorGetInfo */
    case 0x02:                                               /* authenticatorGetAssertion */
        st = env->db ? get_assertion(env, &r, resp, max, &rlen) : CTAP2_ERR_NOT_ALLOWED;
        break;
    case 0x01: st = CTAP2_ERR_OPERATION_DENIED; break;      /* makeCredential: register in KeePassXC */
    case 0x07: st = CTAP2_ERR_OPERATION_DENIED; break;      /* reset: never */
    case 0x08: st = CTAP2_ERR_NOT_ALLOWED; break;           /* getNextAssertion: the user picks on the device */
    default: st = CTAP1_ERR_INVALID_COMMAND;
    }
    resp[0] = (uint8_t)st;
    return st == CTAP2_OK ? 1 + rlen : 1;
}
