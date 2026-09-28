#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/base64.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include "totp.h"

void totp_init(totp *t)
{
    memset(t, 0, sizeof *t);
    t->digits = 6;
    t->period = 30;
    t->algo = TOTP_SHA1;
}

void totp_wipe(totp *t)
{
    mbedtls_platform_zeroize(t, sizeof *t);
}

bool totp_valid(const totp *t)
{
    return t->keylen > 0 && t->period > 0 && (t->steam || (t->digits >= 6 && t->digits <= 8));
}

size_t totp_base32(const char *s, uint8_t *out, size_t outsz)
{
    uint32_t buf = 0;
    int bits = 0;
    size_t n = 0;
    for (; *s; s++) {
        int c = toupper((unsigned char)*s), v;
        if (c == '=' || c == ' ' || c == '-') continue;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= '2' && c <= '7') v = c - '2' + 26;
        else return 0;
        buf = buf << 5 | (uint32_t)v;
        if ((bits += 5) >= 8) {
            if (n == outsz) return 0;
            out[n++] = (uint8_t)(buf >> (bits -= 8));
        }
    }
    return n;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    c |= 0x20;
    return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

static int parse_algo(const char *v)
{
    /* "SHA1", "SHA256", "HMAC-SHA-256", ... */
    const char *d = v + strlen(v);
    while (d > v && isdigit((unsigned char)d[-1])) d--;
    int bits = atoi(d);
    return bits == 256 ? TOTP_SHA256 : bits == 512 ? TOTP_SHA512 : bits == 1 ? TOTP_SHA1 : -1;
}

/* Percent-decode src[0..n) into out (NUL-terminated). */
static bool pct_decode(const char *src, size_t n, char *out, size_t outsz)
{
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        int c = (unsigned char)src[i];
        if (c == '%' && i + 2 < n && hexval(src[i + 1]) >= 0 && hexval(src[i + 2]) >= 0) {
            c = hexval(src[i + 1]) << 4 | hexval(src[i + 2]);
            i += 2;
        } else if (c == '+') {
            c = ' ';
        }
        if (o + 1 >= outsz) return false;
        out[o++] = (char)c;
    }
    out[o] = 0;
    return true;
}

bool totp_from_uri(totp *t, const char *uri)
{
    char v[256];
    totp_init(t);
    if (strncmp(uri, "otpauth://totp/", 15)) return false;
    const char *q = strchr(uri, '?');
    bool ok = true;
    while (q && ok) {
        const char *k = q + 1, *eq = strchr(k, '='), *end = strchr(k, '&');
        if (!end) end = k + strlen(k);
        q = *end ? end : NULL;
        if (!eq || eq > end) continue;
        size_t kl = (size_t)(eq - k);
        if (!pct_decode(eq + 1, (size_t)(end - eq - 1), v, sizeof v)) { ok = false; break; }
        if (kl == 6 && !strncmp(k, "secret", 6)) ok = (t->keylen = totp_base32(v, t->key, sizeof t->key)) > 0;
        else if (kl == 6 && !strncmp(k, "period", 6)) t->period = atoi(v);
        else if (kl == 6 && !strncmp(k, "digits", 6)) t->digits = atoi(v);
        else if (kl == 9 && !strncmp(k, "algorithm", 9)) ok = (t->algo = parse_algo(v)) >= 0;
        else if (kl == 7 && !strncmp(k, "encoder", 7) && !strcmp(v, "steam")) { t->steam = true; t->digits = 5; }
    }
    mbedtls_platform_zeroize(v, sizeof v);
    if (!ok || !totp_valid(t)) { totp_wipe(t); return false; }
    return true;
}

bool totp_set_keepass(totp *t, const char *name, const char *value)
{
    if (strncmp(name, "TimeOtp-", 8)) return true;
    const char *n = name + 8;
    size_t len = strlen(value), olen = 0;
    if (!strcmp(n, "Secret")) {
        if (len > sizeof t->key) return false;
        memcpy(t->key, value, len);
        t->keylen = len;
    } else if (!strcmp(n, "Secret-Hex")) {
        size_t o = 0;
        int hi = -1;
        for (const char *s = value; *s; s++) {
            int h = hexval(*s);
            if (h < 0) { if (isspace((unsigned char)*s)) continue; return false; }
            if (hi < 0) { hi = h; continue; }
            if (o == sizeof t->key) return false;
            t->key[o++] = (uint8_t)(hi << 4 | h);
            hi = -1;
        }
        t->keylen = o;
    } else if (!strcmp(n, "Secret-Base32")) {
        if (!(t->keylen = totp_base32(value, t->key, sizeof t->key))) return false;
    } else if (!strcmp(n, "Secret-Base64")) {
        if (mbedtls_base64_decode(t->key, sizeof t->key, &olen, (const uint8_t *)value, len)) return false;
        t->keylen = olen;
    } else if (!strcmp(n, "Length")) {
        t->digits = atoi(value);
    } else if (!strcmp(n, "Period")) {
        t->period = atoi(value);
    } else if (!strcmp(n, "Algorithm")) {
        if ((t->algo = parse_algo(value)) < 0) return false;
    }
    return true;
}

void totp_code(const totp *t, uint64_t unix_time, char *out)
{
    static const mbedtls_md_type_t md[] = {MBEDTLS_MD_SHA1, MBEDTLS_MD_SHA256, MBEDTLS_MD_SHA512};
    uint8_t msg[8], mac[64];
    uint64_t counter = unix_time / (uint64_t)t->period;
    for (int i = 7; i >= 0; i--, counter >>= 8) msg[i] = (uint8_t)counter;
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(md[t->algo]);
    mbedtls_md_hmac(info, t->key, t->keylen, msg, 8, mac);
    int off = mac[mbedtls_md_get_size(info) - 1] & 0x0f;
    uint32_t bin = (uint32_t)(mac[off] & 0x7f) << 24 | mac[off + 1] << 16 | mac[off + 2] << 8 | mac[off + 3];
    mbedtls_platform_zeroize(mac, sizeof mac);

    if (t->steam) {
        static const char alpha[] = "23456789BCDFGHJKMNPQRTVWXY";
        for (int i = 0; i < 5; i++, bin /= 26) out[i] = alpha[bin % 26];
        out[5] = 0;
    } else {
        for (int i = t->digits - 1; i >= 0; i--, bin /= 10) out[i] = (char)('0' + bin % 10);
        out[t->digits] = 0;
    }
}

int totp_remaining(const totp *t, uint64_t unix_time)
{
    return t->period - (int)(unix_time % (uint64_t)t->period);
}
