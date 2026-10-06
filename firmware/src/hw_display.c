#ifndef CARDPASS_QEMU   /* replaced by hw_qemu.c in the qemu env */
#include <string.h>
#include "driver/ledc.h"
#include "driver/spi_master.h"
#include "esp_heap_caps.h"
#include "esp_lcd_panel_io.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "hw.h"
#include "mbedtls/platform_util.h"
#include "ui.h"

/* ST7789V2, 135x240 window in a 240x320 RAM. Values from M5GFX's Cardputer(ADV) autodetect. */
#define PIN_MOSI 35
#define PIN_SCLK 36
#define PIN_DC 34
#define PIN_CS 37
#define PIN_RST 33
#define PIN_BL 38
#define OFFSET_X 40   /* landscape: RAM row offset 40 becomes x */
#define OFFSET_Y 52   /* RAM column offset 52 becomes y */

static esp_lcd_panel_io_handle_t io;
/* Pipeline: two DMA strip buffers, so the CPU draws strip n+1 while the SPI sends strip n (frame time = the slower of
 * the two, not their sum). Every strip of the 16-row grid keeps a 64-bit hash of what the panel shows; a strip that
 * comes out identical is not sent at all (hashing ~1920 words is microseconds, sending is ~1.5 ms at 40 MHz). The
 * column window is set once; consecutive strips continue with RAMWRC instead of re-addressing. */
#define NBUF 2
#define NSTRIPS ((UI_H + HW_STRIP_H - 1) / HW_STRIP_H)
#define HW_LCD_PCLK_HZ (40 * 1000 * 1000)   /* M5GFX's value. MOSI/SCLK are on IO_MUX pins: 80 MHz may work, unverified */
static SemaphoreHandle_t freed;              /* counts buffers whose DMA is finished */
static uint16_t *bufs[NBUF];
static int cur;
static uint64_t shown[NSTRIPS];              /* 0 = unknown: always send */
static int next_row = -1;                    /* the panel's write pointer, if the last strip sent ended there */

static bool on_done(esp_lcd_panel_io_handle_t h, esp_lcd_panel_io_event_data_t *e, void *ctx)
{
    BaseType_t woke = pdFALSE;
    xSemaphoreGiveFromISR(freed, &woke);
    return woke == pdTRUE;
}

static void cmd(uint8_t c, const uint8_t *d, size_t n) { esp_lcd_panel_io_tx_param(io, c, d, n); }
static void cmd1(uint8_t c, uint8_t v) { cmd(c, &v, 1); }

void hw_display_init(void)
{
    spi_bus_config_t bus = {.mosi_io_num = PIN_MOSI, .miso_io_num = -1, .sclk_io_num = PIN_SCLK, .quadwp_io_num = -1,
                            .quadhd_io_num = -1, .max_transfer_sz = UI_W * HW_STRIP_H * 2 + 16};
    spi_bus_initialize(SPI2_HOST, &bus, SPI_DMA_CH_AUTO);
    freed = xSemaphoreCreateCounting(NBUF, NBUF);
    esp_lcd_panel_io_spi_config_t ioc = {.cs_gpio_num = PIN_CS, .dc_gpio_num = PIN_DC, .spi_mode = 0, .pclk_hz = HW_LCD_PCLK_HZ,
                                         .trans_queue_depth = 2, .on_color_trans_done = on_done, .lcd_cmd_bits = 8,
                                         .lcd_param_bits = 8};
    esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)SPI2_HOST, &ioc, &io);
    for (int i = 0; i < NBUF; i++) bufs[i] = heap_caps_malloc(UI_W * HW_STRIP_H * 2, MALLOC_CAP_DMA);

    gpio_config_t rst = {.pin_bit_mask = 1ULL << PIN_RST, .mode = GPIO_MODE_OUTPUT};
    gpio_config(&rst);
    gpio_set_level(PIN_RST, 0);
    vTaskDelay(pdMS_TO_TICKS(20));
    gpio_set_level(PIN_RST, 1);
    vTaskDelay(pdMS_TO_TICKS(120));

    cmd(0x01, NULL, 0);                 /* SWRESET */
    vTaskDelay(pdMS_TO_TICKS(120));
    cmd(0x11, NULL, 0);                 /* SLPOUT */
    vTaskDelay(pdMS_TO_TICKS(120));
    cmd1(0x3A, 0x55);                   /* 16 bit colour */
    cmd1(0x36, 0x60);                   /* MADCTL: landscape (MX|MV), RGB */
    cmd(0x21, NULL, 0);                 /* INVON (this panel needs it) */
    cmd(0x13, NULL, 0);                 /* NORON */
    cmd(0x29, NULL, 0);                 /* DISPON */
    uint16_t x0 = OFFSET_X, x1 = OFFSET_X + UI_W - 1;   /* the column window never changes: set it once */
    uint8_t ca[4] = {(uint8_t)(x0 >> 8), (uint8_t)x0, (uint8_t)(x1 >> 8), (uint8_t)x1};
    cmd(0x2A, ca, 4);

    ledc_timer_config_t t = {.speed_mode = LEDC_LOW_SPEED_MODE, .duty_resolution = LEDC_TIMER_8_BIT, .timer_num = LEDC_TIMER_0,
                             .freq_hz = 512, .clk_cfg = LEDC_AUTO_CLK};
    ledc_timer_config(&t);
    ledc_channel_config_t ch = {.gpio_num = PIN_BL, .speed_mode = LEDC_LOW_SPEED_MODE, .channel = LEDC_CHANNEL_0,
                                .timer_sel = LEDC_TIMER_0, .duty = 0, .hpoint = 0};
    ledc_channel_config(&ch);
}

uint16_t *hw_display_strip(void)
{
    xSemaphoreTake(freed, portMAX_DELAY);    /* a buffer whose previous transfer is done */
    return bufs[cur];
}

static uint64_t strip_hash(const uint16_t *px, int n, int y0)
{
    uint64_t h = 1469598103934665603ULL ^ (uint64_t)y0;
    const uint32_t *w = (const uint32_t *)px;
    for (int i = 0; i < n / 2; i++) h = (h ^ w[i]) * 1099511628211ULL;
    return h | 1;                            /* never 0 (= unknown) */
}

void hw_display_brightness(int pct)
{
    if (pct < 0) pct = 0;
    if (pct > 100) pct = 100;
    ledc_set_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0, (uint32_t)(pct * 255 / 100));
    ledc_update_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0);
}

void hw_display_fade(int pct, int ms)
{
    static bool installed;
    if (!installed) { ledc_fade_func_install(0); installed = true; }
    if (pct < 0) pct = 0;
    if (pct > 100) pct = 100;
    ledc_set_fade_with_time(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0, (uint32_t)(pct * 255 / 100), (uint32_t)ms);
    ledc_fade_start(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0, LEDC_FADE_NO_WAIT);
}

void hw_display_sleep(bool on)
{
    cmd(on ? 0x28 : 0x29, NULL, 0);     /* DISPOFF / DISPON */
    if (on) hw_display_brightness(0);
}

void hw_display_push(int y0, int h, uint16_t *px)
{
    int k = y0 / HW_STRIP_H;
    uint64_t hs = strip_hash(px, UI_W * h, y0);
    if (k >= 0 && k < NSTRIPS && shown[k] == hs) {    /* the panel already shows exactly this */
        xSemaphoreGive(freed);
        next_row = -1;
        return;
    }
    if (k >= 0 && k < NSTRIPS) shown[k] = hs;
    for (int i = 0; i < UI_W * h; i++) px[i] = (uint16_t)(px[i] << 8 | px[i] >> 8);   /* panel wants big-endian */
    int op = 0x3C;                                     /* RAMWRC: continue where the last strip ended */
    if (y0 != next_row) {
        uint16_t ys = (uint16_t)(OFFSET_Y + y0), ye = (uint16_t)(OFFSET_Y + UI_H - 1);
        uint8_t ra[4] = {(uint8_t)(ys >> 8), (uint8_t)ys, (uint8_t)(ye >> 8), (uint8_t)ye};
        cmd(0x2B, ra, 4);                              /* waits for queued strips itself (esp_lcd) */
        op = 0x2C;
    }
    esp_lcd_panel_io_tx_color(io, op, px, (size_t)UI_W * h * 2);   /* queued: returns while the DMA runs */
    next_row = y0 + h;
    cur = (cur + 1) % NBUF;
}

/* The hashes fingerprint what was on screen (a revealed password, say): an offline guessing oracle in a RAM dump.
 * Called when the database closes: wiped, and every strip is sent again. */
void hw_display_forget(void)
{
    mbedtls_platform_zeroize(shown, sizeof shown);
    next_row = -1;
}

#endif
