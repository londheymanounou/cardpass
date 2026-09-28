/* KDBX 4.x reader (AES-KDF only). Portable C, depends on mbedTLS + tinfl only.
 *
 * Unlock streams the file: nothing but the compact index stays in RAM, and
 * protected values stay encrypted (inner ChaCha20 stream, seekable) until
 * kdbx_reveal(). Everything is wiped by kdbx_close().
 */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef enum {
    KDBX_OK = 0,
    KDBX_ERR_IO,          /* read error / truncated file */
    KDBX_ERR_FORMAT,      /* not a KDBX file, or malformed */
    KDBX_ERR_VERSION,     /* KDBX 3.1 or older / newer than 4.x */
    KDBX_ERR_KDF,         /* Argon2 or unknown KDF */
    KDBX_ERR_CIPHER,      /* unsupported outer cipher or inner stream */
    KDBX_ERR_KEY,         /* wrong password / key file (header HMAC mismatch) */
    KDBX_ERR_CORRUPT,     /* checksum / block HMAC / payload damaged */
    KDBX_ERR_KEYFILE,     /* key file unreadable or invalid */
    KDBX_ERR_NOMEM,
} kdbx_err;

const char *kdbx_strerror(kdbx_err e);

/* Composite key. Wipe with kdbx_key_wipe() once kdbx_open() returned. */
typedef struct { uint8_t composite[32]; } kdbx_key;

/* password == NULL: no password component. keyfile == NULL: no key file. */
kdbx_err kdbx_key_init(kdbx_key *k, const char *password, size_t pwlen, FILE *keyfile);
void kdbx_key_wipe(kdbx_key *k);

#define KDBX_PLAIN UINT32_MAX /* kdbx_field.stream_off for unprotected values */

typedef struct kdbx_group {
    struct kdbx_group *next, *parent;
    const char *name;
    uint8_t uuid[16];
} kdbx_group;

typedef struct kdbx_field {
    struct kdbx_field *next;
    const char *key;
    const uint8_t *value;   /* plaintext (NUL-terminated) or ciphertext */
    uint32_t len;
    uint32_t stream_off;    /* KDBX_PLAIN, or offset in the inner keystream */
} kdbx_field;

typedef struct kdbx_entry {
    struct kdbx_entry *next;
    const kdbx_group *group;
    kdbx_field *fields;
    const char *title, *username, *url, *tags; /* never NULL ("" if missing or protected) */
    int64_t expiry;         /* unix seconds, valid if expires */
    bool expires;
    uint8_t uuid[16];
} kdbx_entry;

typedef struct kdbx_db kdbx_db;

kdbx_err kdbx_open(FILE *f, const kdbx_key *key, kdbx_db **out);
void kdbx_close(kdbx_db *db); /* wipes everything; NULL ok */

const kdbx_entry *kdbx_entries(const kdbx_db *db);
const kdbx_group *kdbx_groups(const kdbx_db *db);
const kdbx_field *kdbx_field_get(const kdbx_entry *e, const char *key);

/* Copy a field's plaintext into out (NUL-terminated), decrypting if protected.
 * Caller wipes out (mbedtls_platform_zeroize) right after use. */
kdbx_err kdbx_reveal(const kdbx_db *db, const kdbx_field *f, char *out, size_t outsz);
