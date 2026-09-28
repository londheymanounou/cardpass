/* Host implementation of the platform RNG (the device uses esp_fill_random). */
#include <stddef.h>
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
void cp_random(void *buf, size_t n) { BCryptGenRandom(NULL, buf, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG); }
#else
#include <sys/random.h>
void cp_random(void *buf, size_t n)
{
    for (unsigned char *p = buf; n;) {
        ssize_t r = getrandom(p, n, 0);
        if (r > 0) p += r, n -= (size_t)r;
    }
}
#endif
