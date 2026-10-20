#ifndef CARDPASS_QEMU   /* the qemu env has no SD card to hold a container */
/* A VeraCrypt container on the SD card, mounted as a second FAT drive at HW_VC_MOUNT: FatFs reads and writes sectors
 * through vera.c, which decrypts/encrypts them on the way. Nothing decrypted ever reaches the SD card: the card only
 * sees the container file's ciphertext. Mounted only between hw_vc_mount() and hw_vc_unmount() (lock wipes the keys). */
#include <stdio.h>
#include "diskio_impl.h"
#include "esp_vfs_fat.h"
#include "ff.h"
#include "hw.h"
#include "vera.h"

static FILE *file;
static vera vol;
static bool vol_open, read_only, registered;
static BYTE pdrv = FF_DRV_NOT_USED;
static char drive[3];

/* fseek takes a 32-bit offset here: past 2 GiB it would wrap and read or write the wrong place */
static bool off_ok(uint64_t off) { return off <= 0x7FFFFFFFu; }

static int io_read(void *io, uint64_t off, void *buf, size_t n)
{
    (void)io;
    return !off_ok(off) || fseek(file, (long)off, SEEK_SET) || fread(buf, 1, n, file) != n;
}

static int io_write(void *io, uint64_t off, const void *buf, size_t n)
{
    (void)io;
    return !off_ok(off) || fseek(file, (long)off, SEEK_SET) || fwrite(buf, 1, n, file) != n;
}

static DSTATUS d_init(BYTE p) { (void)p; return read_only ? STA_PROTECT : 0; }
static DSTATUS d_status(BYTE p) { (void)p; return read_only ? STA_PROTECT : 0; }
static DRESULT d_read(BYTE p, BYTE *b, DWORD sector, UINT count) { (void)p; return vera_read(&vol, sector, count, b) ? RES_ERROR : RES_OK; }
static DRESULT d_write(BYTE p, const BYTE *b, DWORD sector, UINT count) { (void)p; return vera_write(&vol, sector, count, b) ? RES_ERROR : RES_OK; }

static DRESULT d_ioctl(BYTE p, BYTE cmd, void *buf)
{
    (void)p;
    switch (cmd) {
    case CTRL_SYNC: return fflush(file) ? RES_ERROR : RES_OK;
    case GET_SECTOR_COUNT: *(DWORD *)buf = (DWORD)vera_sectors(&vol); return RES_OK;
    case GET_SECTOR_SIZE: *(WORD *)buf = VERA_SECTOR; return RES_OK;
    case GET_BLOCK_SIZE: *(DWORD *)buf = 1; return RES_OK;
    }
    return RES_PARERR;
}

void hw_vc_unmount(void)
{
    if (registered) {
        f_mount(NULL, drive, 0);                       /* flushes through CTRL_SYNC while the keys still exist */
        esp_vfs_fat_unregister_path(HW_VC_MOUNT);
        registered = false;
    }
    if (pdrv != FF_DRV_NOT_USED) ff_diskio_unregister(pdrv), pdrv = FF_DRV_NOT_USED;
    if (vol_open) vera_close(&vol), vol_open = false;
    if (file) fclose(file), file = NULL;
}

int hw_vc_mount(const char *path, const uint8_t *pw, size_t pwlen, bool allow_outer_write, void (*progress)(void *, int), void *arg)
{
    static const ff_diskio_impl_t impl = {d_init, d_status, d_read, d_write, d_ioctl};
    hw_vc_unmount();
    if (!hw_sd_mount()) return 2;
    read_only = false;
    if (!(file = fopen(path, "r+b"))) {
        read_only = true;                              /* write-protected card or file: browse only */
        if (!(file = fopen(path, "rb"))) return 2;
    }
    vera_io io = {io_read, read_only ? NULL : io_write, NULL};
    int r = vera_open(&vol, &io, pw, pwlen, progress, arg);
    if (r) {
        hw_vc_unmount();
        return r == VERA_ERR_IO ? 2 : r == VERA_ERR_PASSWORD ? 1 : 3;
    }
    vol_open = true;
    if (!vera_hidden(&vol) && !allow_outer_write) {      /* a write to a standard volume can destroy a hidden one inside it */
        read_only = true;
        vol.io.write = NULL;
    }
    FATFS *fs = NULL;
    esp_vfs_fat_conf_t cfg = {.base_path = HW_VC_MOUNT, .fat_drive = drive, .max_files = 3};
    if (ff_diskio_get_drive(&pdrv) != ESP_OK) { pdrv = FF_DRV_NOT_USED; hw_vc_unmount(); return 4; }
    drive[0] = (char)('0' + pdrv);
    drive[1] = ':';
    drive[2] = 0;
    ff_diskio_register(pdrv, &impl);
    if (esp_vfs_fat_register_cfg(&cfg, &fs) != ESP_OK) { hw_vc_unmount(); return 4; }
    registered = true;
    if (f_mount(fs, drive, 1) != FR_OK) { hw_vc_unmount(); return 4; }   /* not FAT/FAT32 inside */
    return read_only ? 5 : 0;
}
#endif
