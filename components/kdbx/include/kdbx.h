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
    KDBX_ERR_EDIT,        /* edit refers to a missing item or is invalid (nothing written) */
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
    const char *autotype;   /* DefaultAutoTypeSequence, "" = inherit */
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
    const char *autotype;   /* AutoType/DefaultSequence, "" = inherit from groups */
    bool autotype_off;      /* AutoType/Enabled = False */
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
/* Entry's auto-type sequence: its own, else the nearest group's, else fallback. */
const char *kdbx_autotype(const kdbx_entry *e, const char *fallback);

/* Copy a field's plaintext into out (NUL-terminated), decrypting if protected.
 * Caller wipes out (mbedtls_platform_zeroize) right after use. */
kdbx_err kdbx_reveal(const kdbx_db *db, const kdbx_field *f, char *out, size_t outsz);

/* ---------------- editing ---------------- */

/* Provided by the platform: cryptographically secure random bytes. */
void cp_random(void *buf, size_t n);

typedef struct {
    const char *key, *value;  /* UTF-8; value is plaintext (caller wipes it after kdbx_save) */
    bool protect;
} kdbx_edit_field;

typedef enum {
    KDBX_EDIT_ENTRY,          /* create (create, parent) or update: strings/tags/expiry; old version -> History */
    KDBX_EDIT_ENTRY_MOVE,     /* to parent */
    KDBX_EDIT_ENTRY_DELETE,   /* permanent + DeletedObjects (kdbx_delete_entry() handles the recycle bin) */
    KDBX_EDIT_GROUP,          /* create (create, parent) or rename */
    KDBX_EDIT_GROUP_MOVE,     /* to parent */
    KDBX_EDIT_GROUP_DELETE,   /* permanent, with everything inside */
} kdbx_edit_op;

typedef struct {
    kdbx_edit_op op;
    uint8_t uuid[16];
    uint8_t parent[16];
    bool create;
    /* ENTRY: complete new set of strings (Title, UserName, Password, URL, Notes, custom) */
    const kdbx_edit_field *fields;
    size_t nfields;
    const char *tags;         /* NULL = "" */
    bool expires;
    int64_t expiry;           /* unix seconds */
    /* GROUP */
    const char *name;
    bool recycle_bin;         /* create: becomes the database's recycle bin */
} kdbx_edit;

void kdbx_new_uuid(uint8_t uuid[16]);
const kdbx_group *kdbx_root_group(const kdbx_db *db);
/* KeePass delete semantics: move to the recycle bin (creating it if needed) when
 * enabled and not already there, else delete permanently. Fills out[], returns count (<= 2). */
size_t kdbx_delete_entry(const kdbx_db *db, const kdbx_entry *e, kdbx_edit out[2]);
size_t kdbx_delete_group(const kdbx_db *db, const kdbx_group *g, kdbx_edit out[2]);

/* Safe save: re-reads path, applies edits while streaming into path.tmp (new seeds,
 * IV and inner stream key; unknown XML, history and attachments carried over),
 * re-opens path.tmp to verify, keeps the original as path.bak, renames.
 * newkey != NULL: new master key with a new KDF seed and `rounds` (0 = keep); runs the KDF.
 * now: unix seconds for modification times. *newdb: the saved database, re-opened. */
kdbx_err kdbx_save(const kdbx_db *db, const char *path, const kdbx_edit *edits, size_t nedits, int64_t now,
                   const kdbx_key *newkey, uint64_t rounds, kdbx_db **newdb);

enum { KDBX_AES256, KDBX_CHACHA20 };

/* New KDBX 4.0 database at path (must not exist): empty root group `name`,
 * recycle bin enabled, AES-KDF with `rounds`. Runs the KDF. *db: the new database. */
kdbx_err kdbx_create(const char *path, int cipher, uint64_t rounds, const kdbx_key *key, const char *name,
                     int64_t now, kdbx_db **db);

/* Write a new random KeePass XML v2 key file (32-byte key). */
kdbx_err kdbx_keyfile_create(FILE *f);

/* Finish an interrupted save (path missing, path.tmp complete). Call before listing files. */
void kdbx_recover(const char *path);
