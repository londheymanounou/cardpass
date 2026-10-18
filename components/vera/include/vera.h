/* VeraCrypt volume reader/writer: a file-hosted standard or hidden volume, AES-256-XTS, PBKDF2-HMAC-SHA512 (500000 iterations,
 * no PIM, no keyfiles), 512-byte sectors. Other ciphers/hashes and system encryption are refused.
 * Portable (mbedTLS only): the platform supplies the raw container file through vera_io. Only data sectors are ever
 * written; the volume header is never touched. Keys live in `vera` and are wiped by vera_close(). */
#ifndef VERA_H
#define VERA_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "mbedtls/aes.h"

#define VERA_SECTOR 512

enum { VERA_OK = 0, VERA_ERR_IO = 1, VERA_ERR_PASSWORD = 2, VERA_ERR_UNSUPPORTED = 3 };

typedef struct {
    int (*read)(void *io, uint64_t off, void *buf, size_t n);          /* 0 = ok */
    int (*write)(void *io, uint64_t off, const void *buf, size_t n);   /* 0 = ok; may be NULL (read-only) */
    void *io;
} vera_io;

typedef struct {
    vera_io io;
    mbedtls_aes_context enc, dec, tweak;   /* XTS key 1 (both directions) and key 2 (tweak) */
    uint64_t data_off, nsec;               /* byte offset of the data area in the file, sectors in the volume */
    bool hidden;                           /* opened with the hidden volume's password */
} vera;

/* Derive the header key from `pw`, decrypt and check the header, set up the data keys. The standard volume's header is
 * tried first, then the hidden volume's (a wrong password therefore costs two key derivations). progress(arg, 0..100) runs
 * during each (slow) derivation. VERA_ERR_PASSWORD also means "not a VeraCrypt volume". */
int vera_open(vera *v, const vera_io *io, const uint8_t *pw, size_t pwlen, void (*progress)(void *, int), void *arg);
void vera_close(vera *v);                                              /* wipes the keys */
uint64_t vera_sectors(const vera *v);
bool vera_hidden(const vera *v);                                       /* the hidden volume was opened */
int vera_read(vera *v, uint64_t sector, uint32_t count, void *buf);    /* 0 = ok */
int vera_write(vera *v, uint64_t sector, uint32_t count, const void *buf);

#endif
