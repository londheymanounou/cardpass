/* TOTP: RFC 6238 appendix B vectors + field parsing.
 *   test_totp            run tests
 *   test_totp --now URI  print the current code (compare with `keepassxc-cli show -t`) */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "totp.h"

static int failures;
#define CHECK(c, ...) do { if (!(c)) { failures++; printf("FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

int main(int argc, char **argv)
{
    totp t;
    char code[16];

    if (argc == 3 && !strcmp(argv[1], "--now")) {
        if (!totp_from_uri(&t, argv[2])) return 1;
        totp_code(&t, (uint64_t)time(NULL), code);
        printf("%s\n", code);
        totp_wipe(&t);
        return 0;
    }

    static const struct { uint64_t time; const char *code[3]; } rfc[] = {
        {59, {"94287082", "46119246", "90693936"}},
        {1111111109, {"07081804", "68084774", "25091201"}},
        {1111111111, {"14050471", "67062674", "99943326"}},
        {1234567890, {"89005924", "91819424", "93441116"}},
        {2000000000, {"69279037", "90698825", "38618901"}},
        {20000000000ULL, {"65353130", "77737706", "47863826"}},
    };
    static const char *seeds[3] = {
        "12345678901234567890",
        "12345678901234567890123456789012",
        "1234567890123456789012345678901234567890123456789012345678901234",
    };
    static const char *algos[3] = {"HMAC-SHA-1", "HMAC-SHA-256", "HMAC-SHA-512"};

    for (int a = 0; a < 3; a++) {
        totp_init(&t);
        CHECK(totp_set_keepass(&t, "TimeOtp-Secret", seeds[a]), "secret");
        CHECK(totp_set_keepass(&t, "TimeOtp-Length", "8"), "len");
        CHECK(totp_set_keepass(&t, "TimeOtp-Algorithm", algos[a]), "algo");
        for (size_t i = 0; i < sizeof rfc / sizeof *rfc; i++) {
            totp_code(&t, rfc[i].time, code);
            CHECK(!strcmp(code, rfc[i].code[a]), "%s t=%llu: %s != %s", algos[a], (unsigned long long)rfc[i].time, code, rfc[i].code[a]);
        }
        totp_wipe(&t);
    }

    /* Same key via otpauth:// (base32 of "12345678901234567890") */
    CHECK(totp_from_uri(&t, "otpauth://totp/Ex:alice%40x.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&issuer=Ex"), "uri");
    totp_code(&t, 59, code);
    CHECK(!strcmp(code, "94287082"), "uri code %s", code);
    CHECK(totp_remaining(&t, 59) == 1 && totp_remaining(&t, 60) == 30, "remaining");

    CHECK(totp_from_uri(&t, "otpauth://totp/x?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq&algorithm=SHA256&period=60"), "lower");
    CHECK(t.algo == TOTP_SHA256 && t.period == 60 && t.digits == 6 && t.keylen == 20, "params");
    CHECK(totp_from_uri(&t, "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&encoder=steam") && t.steam, "steam");
    totp_code(&t, 0, code);
    CHECK(strlen(code) == 5, "steam len");

    /* KeePass 2 encodings of the same key */
    const char *enc[][2] = {
        {"TimeOtp-Secret-Hex", "3132333435363738393031323334353637383930"},
        {"TimeOtp-Secret-Base32", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"},
        {"TimeOtp-Secret-Base64", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA="},
    };
    for (int i = 0; i < 3; i++) {
        totp_init(&t);
        CHECK(totp_set_keepass(&t, enc[i][0], enc[i][1]) && totp_set_keepass(&t, "TimeOtp-Length", "8"), "%s", enc[i][0]);
        totp_code(&t, 1234567890, code);
        CHECK(!strcmp(code, "89005924"), "%s -> %s", enc[i][0], code);
    }

    /* Rejects */
    CHECK(!totp_from_uri(&t, "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP"), "hotp accepted");
    CHECK(!totp_from_uri(&t, "otpauth://totp/x?secret=JBSW!Y3DP"), "bad base32 accepted");
    CHECK(!totp_from_uri(&t, "otpauth://totp/x?issuer=a"), "no secret accepted");
    CHECK(!totp_from_uri(&t, "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=12"), "12 digits accepted");
    CHECK(!totp_from_uri(&t, "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5"), "md5 accepted");

    totp_wipe(&t);
    printf("totp: %d failures\n", failures);
    return failures != 0;
}
