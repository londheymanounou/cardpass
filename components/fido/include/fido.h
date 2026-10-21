/* Passkeys stored as KeePassXC entries (KPEX_PASSKEY_* fields), used as a CTAP2 authenticator:
 * authenticatorGetInfo, authenticatorGetAssertion (ES256 and RS256) and authenticatorMakeCredential (ES256 only: a new
 * passkey becomes a KeePassXC-compatible entry through env->store). The private key PEM is decrypted per signature and
 * wiped. Transport: CTAPHID framing over 64-byte HID reports. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "kdbx.h"

typedef struct {
    const kdbx_entry *e;
    char rp_id[256];
    char user_name[128];
    uint8_t cred_id[128], user_id[128];
    size_t cred_len, user_len;
    bool be, bs;            /* backup eligible / backup state flags */
} fido_cred;

/* Passkeys in db for rp_id (all of them if rp_id is NULL). Returns count found (may exceed max). */
size_t fido_find(const kdbx_db *db, const char *rp_id, fido_cred *out, size_t max);

/* A passkey being registered: the strings that go into its database entry (KeePassXC's field names and formats). */
typedef struct {
    char rp_id[256], rp_name[128], user_name[128], user_display[128];
    char cred_b64[64];      /* credential id, base64url without padding */
    char user_b64[96];      /* user handle, same encoding */
    char pem[320];          /* PKCS#8 PEM private key: the caller wipes it as soon as it is stored */
} fido_new;

typedef struct {
    const kdbx_db *db;      /* NULL while locked: every request is answered "not allowed" */
    /* User presence + selection: show rp_id and the account(s), wait for a key press.
     * Returns the chosen index, or -1 if the user declined / timed out. */
    int (*choose)(void *ctx, const char *rp_id, const fido_cred *creds, size_t n);
    void *ctx;
    /* Registration: ask the user and save the new entry. 0 = stored, 1 = the user declined / timed out, else failed.
     * May replace the database (env->db is stale afterwards). NULL = registration refused. */
    int (*store)(void *ctx, const fido_new *n);
} fido_env;

/* CTAP2 status codes used */
enum {
    CTAP2_OK = 0x00, CTAP1_ERR_INVALID_COMMAND = 0x01, CTAP2_ERR_INVALID_CBOR = 0x12,
    CTAP1_ERR_INVALID_LENGTH = 0x03, CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19, CTAP2_ERR_MISSING_PARAMETER = 0x14, CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26,
    CTAP2_ERR_OPERATION_DENIED = 0x27, CTAP2_ERR_UNSUPPORTED_OPTION = 0x2B, CTAP2_ERR_NO_CREDENTIALS = 0x2E,
    CTAP2_ERR_NOT_ALLOWED = 0x30, CTAP2_ERR_PIN_AUTH_INVALID = 0x33, CTAP1_ERR_OTHER = 0x7F,
};

/* One CTAP2 message: req = command byte + CBOR; resp = status byte + CBOR. Returns resp length. */
size_t ctap2_handle(const fido_env *env, const uint8_t *req, size_t n, uint8_t *resp, size_t max);

/* ---- CTAPHID ---- */
#define CTAPHID_MAX_MSG 2048

typedef struct {
    uint32_t cid, next_cid;
    uint8_t cmd, seq;
    uint16_t len, got;
    bool busy;
    uint8_t msg[CTAPHID_MAX_MSG];
    uint8_t resp[CTAPHID_MAX_MSG];
} ctaphid;

typedef void (*ctaphid_send)(void *ctx, const uint8_t report[64]);

void ctaphid_init(ctaphid *h);
/* While choose() waits for the user, call this ~every 100 ms (KEEPALIVE, "user presence needed"). */
void ctaphid_keepalive(ctaphid *h, ctaphid_send send, void *ctx);
/* Feed one output report from the host; complete messages are handled (CBOR via
 * ctap2_handle) and the reply is sent as input reports through send. */
void ctaphid_report(ctaphid *h, const uint8_t report[64], const fido_env *env, ctaphid_send send, void *ctx);
