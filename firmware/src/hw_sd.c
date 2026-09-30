#include <stdlib.h>
#include <sys/stat.h>
#include "driver/sdspi_host.h"
#include "driver/spi_master.h"
#include "esp_vfs_fat.h"
#include "hw.h"
#include "sdmmc_cmd.h"

/* Pins verified on a real ADV in the sibling firmware. */
#define PIN_SCK 40
#define PIN_MISO 39
#define PIN_MOSI 14
#define PIN_CS 12

static sdmmc_card_t *card;
static bool bus_up;

bool hw_sd_mount(void)
{
    if (card) return true;
    if (!bus_up) {
        spi_bus_config_t bus = {.mosi_io_num = PIN_MOSI, .miso_io_num = PIN_MISO, .sclk_io_num = PIN_SCK, .quadwp_io_num = -1,
                                .quadhd_io_num = -1, .max_transfer_sz = 4096};
        if (spi_bus_initialize(SPI3_HOST, &bus, SPI_DMA_CH_AUTO) != ESP_OK) return false;
        bus_up = true;
    }
    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    host.slot = SPI3_HOST;
    host.max_freq_khz = 20000;
    sdspi_device_config_t slot = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot.gpio_cs = PIN_CS;
    slot.host_id = SPI3_HOST;
    esp_vfs_fat_mount_config_t mc = {.format_if_mount_failed = false, .max_files = 4, .allocation_unit_size = 16 * 1024};
    if (esp_vfs_fat_sdspi_mount(HW_SD_ROOT, &host, &slot, &mc, &card) != ESP_OK) { card = NULL; return false; }
    mkdir(HW_DB_DIR, 0777);
    return true;
}

void hw_sd_unmount(void)
{
    if (!card) return;
    esp_vfs_fat_sdcard_unmount(HW_SD_ROOT, card);
    card = NULL;
}

bool hw_sd_ok(void) { return card != NULL; }

static sdmmc_card_t *raw_card;
static sdmmc_host_t raw_host;

sdmmc_card_t *hw_sd_raw_open(void)
{
    if (raw_card || card || !bus_up) return raw_card;
    raw_host = (sdmmc_host_t)SDSPI_HOST_DEFAULT();
    raw_host.max_freq_khz = 20000;
    sdspi_device_config_t slot = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot.gpio_cs = PIN_CS;
    slot.host_id = SPI3_HOST;
    sdspi_dev_handle_t h;
    if (raw_host.init() != ESP_OK) return NULL;
    if (sdspi_host_init_device(&slot, &h) != ESP_OK) return NULL;
    raw_host.slot = h;
    sdmmc_card_t *c = calloc(1, sizeof *c);
    if (!c || sdmmc_card_init(&raw_host, c) != ESP_OK) {
        sdspi_host_remove_device(h);
        free(c);
        return NULL;
    }
    raw_card = c;
    return raw_card;
}

void hw_sd_raw_close(void)
{
    if (!raw_card) return;
    sdspi_host_remove_device(raw_host.slot);
    free(raw_card);
    raw_card = NULL;
}
