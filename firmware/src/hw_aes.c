/* AES-KDF accelerator. On the ESP32-S3 mbedtls_aes_crypt_ecb() sends every 16-byte block through a GDMA transfer
 * (descriptors, cache sync, interrupt): far slower than the AES engine itself, and the KDF does two of them per
 * round, millions of rounds. Here the engine is used in plain block mode (write 4 words, start, wait, read 4
 * words) with the key loaded once per chunk. The hardware lock is held only inside one call and released
 * between chunks, with a one-tick delay about once a second so the idle task (watchdog) and everyone else get to run.
 * hw_aes_selftest() compares the result with the portable loop before the accelerator is used at all: a wrong
 * KDF output would silently write databases nothing can open. */
#include <string.h>
#include "aes/esp_aes.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "hal/aes_hal.h"
#include "hal/aes_ll.h"
#include "hw.h"
#include "mbedtls/platform_util.h"

bool hw_aes_kdf_accel(const uint8_t seed[32], uint8_t b[32], uint64_t n)
{
    uint32_t w[8];
    memcpy(w, b, 32);
    esp_aes_acquire_hardware();
    aes_hal_setkey(seed, 32, ESP_AES_ENCRYPT);
    aes_ll_dma_enable(false);                              /* plain block mode, no DMA */
    for (uint64_t i = 0; i < n; i++) {
        aes_hal_transform_block(w, w);
        aes_hal_transform_block(w + 4, w + 4);
    }
    memcpy(b, w, 32);                                      /* the result */
    uint32_t zero[4] = {0, 0, 0, 0};
    aes_hal_transform_block(zero, zero);                   /* the data registers still hold the last chain value: overwrite them */
    esp_aes_release_hardware();
    mbedtls_platform_zeroize(w, sizeof w);
    hw_yield_if_due();                                     /* not after every chunk: the rounds benchmark stays honest */
    return true;
}

bool hw_aes_selftest(void)
{
    uint8_t seed[32], in[32], a[32], b[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 11 + 3), in[i] = (uint8_t)(200 - i * 5);
    kdbx_set_kdf_accel(NULL);
    kdbx_aes_kdf(seed, 300, in, a);                        /* portable loop */
    kdbx_set_kdf_accel(hw_aes_kdf_accel);
    kdbx_aes_kdf(seed, 300, in, b);                        /* accelerated */
    kdbx_set_kdf_accel(NULL);
    bool ok = !memcmp(a, b, 32);
    mbedtls_platform_zeroize(seed, sizeof seed);
    mbedtls_platform_zeroize(in, sizeof in);
    mbedtls_platform_zeroize(a, sizeof a);
    mbedtls_platform_zeroize(b, sizeof b);
    return ok;
}
