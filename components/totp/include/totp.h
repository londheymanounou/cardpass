/* TOTP (RFC 6238 over RFC 4226). Parses KeePassXC `otp` (otpauth://) and
 * KeePass 2 `TimeOtp-*` fields. Holds the secret: totp_wipe() after use. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum { TOTP_SHA1, TOTP_SHA256, TOTP_SHA512 };

typedef struct {
    uint8_t key[128];
    size_t keylen;
    int digits;   /* 6..8 (5 for Steam) */
    int period;   /* seconds */
    int algo;
    bool steam;
} totp;

void totp_init(totp *t);                          /* defaults: SHA1, 6 digits, 30 s */
bool totp_from_uri(totp *t, const char *uri);     /* otpauth://totp/...?secret=... */
/* KeePass 2: call once per TimeOtp-* field (name, value). Unknown names ignored. */
bool totp_set_keepass(totp *t, const char *name, const char *value);
bool totp_valid(const totp *t);
/* out gets digits + NUL (>= 11 bytes). */
void totp_code(const totp *t, uint64_t unix_time, char *out);
int totp_remaining(const totp *t, uint64_t unix_time);
void totp_wipe(totp *t);

/* Exposed for tests. */
size_t totp_base32(const char *s, uint8_t *out, size_t outsz); /* 0 on error */
