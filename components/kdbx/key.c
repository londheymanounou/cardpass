/* Composite key: SHA-256(SHA-256(password) || keyfile_key). */
#include <ctype.h>
#include <string.h>
#include "mbedtls/base64.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"
#include "kdbx_priv.h"

#define KF_BUF 4096 /* XML key files are ~250 bytes; bigger files can only be "hash of anything" */

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    c |= 0x20;
    return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

/* Decode hex (whitespace skipped) into out[32]; exactly 32 bytes required. */
static bool hex32(const char *s, const char *end, uint8_t out[32])
{
    size_t n = 0;
    int hi = -1;
    for (; s < end; s++) {
        if (isspace((unsigned char)*s)) continue;
        int v = hexval(*s);
        if (v < 0 || n == 32) return false;
        if (hi < 0) hi = v;
        else { out[n++] = (uint8_t)(hi << 4 | v); hi = -1; }
    }
    return n == 32 && hi < 0;
}

/* Text between <tag ...> and </tag>; NULL if missing. */
static const char *xml_text(const char *buf, const char *tag, const char **end, const char **attrs)
{
    char open[16], close[16];
    snprintf(open, sizeof open, "<%s", tag);
    snprintf(close, sizeof close, "</%s>", tag);
    const char *s = strstr(buf, open);
    if (!s) return NULL;
    if (attrs) *attrs = s;
    s = strchr(s, '>');
    const char *e = s ? strstr(s, close) : NULL;
    if (!e) return NULL;
    *end = e;
    return s + 1;
}

/* KeePass XML key file v1 (base64) / v2 (hex + hash). 1 = ok, 0 = not XML, -1 = invalid. */
static int keyfile_xml(const char *buf, uint8_t out[32])
{
    const char *end, *attrs, *v = xml_text(buf, "Version", &end, NULL);
    if (!v) return 0;
    while (isspace((unsigned char)*v)) v++;
    const char *d = xml_text(buf, "Data", &end, &attrs);
    if (!d) return -1;
    if (v[0] == '1' && v[1] == '.') {
        while (d < end && isspace((unsigned char)*d)) d++;
        while (end > d && isspace((unsigned char)end[-1])) end--;
        size_t olen;
        return mbedtls_base64_decode(out, 32, &olen, (const uint8_t *)d, end - d) == 0 && olen == 32 ? 1 : -1;
    }
    if (v[0] == '2' && v[1] == '.') {
        if (!hex32(d, end, out)) return -1;
        const char *h = strstr(attrs, "Hash=\"");
        if (h && h < d) {
            uint8_t sum[32], want[4];
            h += 6;
            for (int i = 0; i < 4; i++) {
                int a = hexval(h[2 * i]), b = hexval(h[2 * i + 1]);
                if (a < 0 || b < 0) return -1;
                want[i] = (uint8_t)(a << 4 | b);
            }
            mbedtls_sha256(out, 32, sum, 0);
            if (memcmp(sum, want, 4)) return -1;
        }
        return 1;
    }
    return -1;
}

static kdbx_err keyfile_key(FILE *f, uint8_t out[32])
{
    char buf[KF_BUF + 1];
    uint8_t chunk[512];
    mbedtls_sha256_context sha;
    size_t total = 0, n;
    kdbx_err err = KDBX_OK;

    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    while ((n = fread(chunk, 1, sizeof chunk, f)) > 0) {
        mbedtls_sha256_update(&sha, chunk, n);
        if (total + n <= KF_BUF) memcpy(buf + total, chunk, n);
        total += n;
    }
    mbedtls_platform_zeroize(chunk, sizeof chunk);
    if (ferror(f)) { err = KDBX_ERR_KEYFILE; goto done; }

    if (total <= KF_BUF) {
        buf[total] = 0;
        const char *p = buf;
        while (isspace((unsigned char)*p)) p++;
        int r = *p == '<' && strlen(buf) == total ? keyfile_xml(buf, out) : 0;
        if (r < 0) { err = KDBX_ERR_KEYFILE; goto done; }
        if (r > 0) goto done;
        if (total == 32) { memcpy(out, buf, 32); goto done; }
        if (total == 64 && hex32(buf, buf + 64, out)) goto done;
    }
    mbedtls_sha256_finish(&sha, out);
done:
    mbedtls_sha256_free(&sha);
    mbedtls_platform_zeroize(buf, sizeof buf);
    return err;
}

kdbx_err kdbx_key_init(kdbx_key *k, const char *password, size_t pwlen, FILE *keyfile)
{
    uint8_t parts[64];
    size_t n = 0;
    kdbx_err err = KDBX_OK;

    if (password) {
        mbedtls_sha256((const uint8_t *)password, pwlen, parts, 0);
        n += 32;
    }
    if (keyfile) {
        if ((err = keyfile_key(keyfile, parts + n)) != KDBX_OK) goto done;
        n += 32;
    }
    mbedtls_sha256(parts, n, k->composite, 0);
done:
    mbedtls_platform_zeroize(parts, sizeof parts);
    return err;
}

void kdbx_key_wipe(kdbx_key *k)
{
    mbedtls_platform_zeroize(k, sizeof *k);
}

kdbx_err kdbx_keyfile_create(FILE *f)
{
    uint8_t key[32], sum[32];
    char hex[65];
    cp_random(key, 32);
    mbedtls_sha256(key, 32, sum, 0);
    for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "%02X", key[i]);
    int n = fprintf(f,
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<KeyFile>\n    <Meta>\n        <Version>2.0</Version>\n"
                    "    </Meta>\n    <Key>\n        <Data Hash=\"%02X%02X%02X%02X\">\n"
                    "            %.8s %.8s %.8s %.8s\n            %.8s %.8s %.8s %.8s\n        </Data>\n    </Key>\n</KeyFile>\n",
                    sum[0], sum[1], sum[2], sum[3], hex, hex + 8, hex + 16, hex + 24, hex + 32, hex + 40, hex + 48, hex + 56);
    mbedtls_platform_zeroize(key, sizeof key);
    mbedtls_platform_zeroize(hex, sizeof hex);
    return n > 0 && !ferror(f) ? KDBX_OK : KDBX_ERR_IO;
}
