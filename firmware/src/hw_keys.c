#ifndef CARDPASS_QEMU   /* replaced by hw_qemu.c in the qemu env */
/* Cardputer keyboard, both models in one binary: hw_keys_init() looks for the ADV's TCA8418 and falls back to the
 * original's matrix.
 *
 * ADV: TCA8418 matrix controller on the internal I2C bus (SDA 8, SCL 9, address 0x34, INT on GPIO 11). Event byte:
 * bit7 = pressed, (byte & 0x7F) - 1 = row * 10 + col, remapped to the 4 x 14 key layout of the Cardputer.
 * The controller's FIFO is ~10 deep and an overflow can wedge INT low: every poll drains up to
 * 12 events, and INT held low for 400 ms triggers a re-init.
 *
 * Original: a 74HC138 (select lines on GPIO 8, 9, 11) drives 8 matrix lines and 7 inputs (GPIO 13, 15, 3-7) read the
 * keys, as in M5Cardputer's IOMatrix reader. The whole matrix is scanned on every poll. */
#include <string.h>
#include "app.h"
#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "driver/rtc_io.h"
#include "esp_rom_sys.h"
#include "esp_sleep.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "hw.h"

#define PIN_SDA 8
#define PIN_SCL 9
#define PIN_INT 11
#define ADDR 0x34
#define WEDGE_MS 400
#define DRAIN_MAX 12

enum { REG_CFG = 0x01, REG_INT_STAT = 0x02, REG_KEY_EVENT_A = 0x04, REG_GPIO_INT_STAT_1 = 0x11,
       REG_GPIO_INT_EN_1 = 0x1A, REG_KP_GPIO_1 = 0x1D, REG_GPI_EM_1 = 0x20, REG_GPIO_DIR_1 = 0x23, REG_GPIO_INT_LVL_1 = 0x26 };

static i2c_master_bus_handle_t bus;
static i2c_master_dev_handle_t dev;
static bool og;                       /* original Cardputer: matrix on GPIOs, no TCA8418 */
static const int OG_SEL[3] = {8, 9, 11};
static const int OG_IN[7] = {13, 15, 3, 4, 5, 6, 7};

static void wr(uint8_t reg, uint8_t v)
{
    uint8_t b[2] = {reg, v};
    i2c_master_transmit(dev, b, 2, 50);
}
static uint8_t rd(uint8_t reg)
{
    uint8_t v = 0;
    i2c_master_transmit_receive(dev, &reg, 1, &v, 1, 50);
    return v;
}

static void controller_init(void)
{
    for (int i = 0; i < 3; i++) {
        wr((uint8_t)(REG_GPIO_DIR_1 + i), 0x00);      /* all GPIO pins inputs */
        wr((uint8_t)(REG_GPI_EM_1 + i), 0xFF);        /* all pins generate key events */
        wr((uint8_t)(REG_GPIO_INT_LVL_1 + i), 0x00);
        wr((uint8_t)(REG_GPIO_INT_EN_1 + i), 0xFF);
    }
    wr(REG_KP_GPIO_1, 0x7F);                          /* matrix: 7 rows ... */
    wr(REG_KP_GPIO_1 + 1, 0xFF);                      /* ... 8 columns */
    while (rd(REG_KEY_EVENT_A)) {}                    /* flush */
    for (int i = 0; i < 3; i++) rd((uint8_t)(REG_GPIO_INT_STAT_1 + i));
    wr(REG_INT_STAT, 3);
    wr(REG_CFG, (uint8_t)(rd(REG_CFG) | 0x02 | 0x01)); /* GPI + key event interrupts */
}

static void og_select(int line)
{
    for (int i = 0; i < 3; i++) gpio_set_level((gpio_num_t)OG_SEL[i], line >> i & 1);
}

static void og_init(void)
{
    for (int i = 0; i < 3; i++) {
        gpio_reset_pin((gpio_num_t)OG_SEL[i]);
        gpio_set_direction((gpio_num_t)OG_SEL[i], GPIO_MODE_OUTPUT);
    }
    for (int i = 0; i < 7; i++) {
        gpio_reset_pin((gpio_num_t)OG_IN[i]);
        gpio_set_direction((gpio_num_t)OG_IN[i], GPIO_MODE_INPUT);
        gpio_set_pull_mode((gpio_num_t)OG_IN[i], GPIO_PULLUP_ONLY);
    }
    og_select(0);
}

void hw_keys_init(void)
{
    i2c_master_bus_config_t bc = {.i2c_port = I2C_NUM_0, .sda_io_num = PIN_SDA, .scl_io_num = PIN_SCL,
                                  .clk_source = I2C_CLK_SRC_DEFAULT, .glitch_ignore_cnt = 7,
                                  .flags.enable_internal_pullup = true};
    i2c_new_master_bus(&bc, &bus);
    bool adv = false;
    for (int i = 0; i < 5 && !adv; i++) {              /* a few tries: a slow TCA8418 must not make an ADV look like an original */
        adv = i2c_master_probe(bus, ADDR, 50) == ESP_OK;
        if (!adv) vTaskDelay(pdMS_TO_TICKS(20));
    }
    if (!adv) {                                        /* the original Cardputer: GPIO 8/9 are matrix selects */
        i2c_del_master_bus(bus);
        bus = NULL;
        og = true;
        og_init();
        return;
    }
    i2c_device_config_t dc = {.dev_addr_length = I2C_ADDR_BIT_LEN_7, .device_address = ADDR, .scl_speed_hz = 400000};
    i2c_master_bus_add_device(bus, &dc, &dev);
    gpio_config_t g = {.pin_bit_mask = 1ULL << PIN_INT, .mode = GPIO_MODE_INPUT, .pull_up_en = GPIO_PULLUP_ENABLE};
    gpio_config(&g);
    controller_init();
}

/* ---- key layout: x = 0..13, y = 0..3, [normal, shifted]; negative = special ---- */
enum { KF_FN = 1, KF_SHIFT, KF_CTRL, KF_OPT, KF_ALT, KF_BS, KF_TAB, KF_ENTER };
typedef struct { int16_t n, s; } keydef;
#define S(a, b) {a, b}
#define SP(k) {-(k), -(k)}
static const keydef MAP[4][14] = {
    {S('`', '~'), S('1', '!'), S('2', '@'), S('3', '#'), S('4', '$'), S('5', '%'), S('6', '^'), S('7', '&'), S('8', '*'),
     S('9', '('), S('0', ')'), S('-', '_'), S('=', '+'), SP(KF_BS)},
    {SP(KF_TAB), S('q', 'Q'), S('w', 'W'), S('e', 'E'), S('r', 'R'), S('t', 'T'), S('y', 'Y'), S('u', 'U'), S('i', 'I'),
     S('o', 'O'), S('p', 'P'), S('[', '{'), S(']', '}'), S(92, '|')},
    {SP(KF_FN), SP(KF_SHIFT), S('a', 'A'), S('s', 'S'), S('d', 'D'), S('f', 'F'), S('g', 'G'), S('h', 'H'),
     S('j', 'J'), S('k', 'K'), S('l', 'L'), S(';', ':'), S(39, 34), SP(KF_ENTER)},
    {SP(KF_CTRL), SP(KF_OPT), SP(KF_ALT), S('z', 'Z'), S('x', 'X'), S('c', 'C'), S('v', 'V'),
     S('b', 'B'), S('n', 'N'), S('m', 'M'), S(',', '<'), S('.', '>'), S('/', '?'), S(' ', ' ')},
};

static uint64_t held;                 /* bit (y * 14 + x) */
static uint32_t sent[56];             /* code delivered at press, repeated at release */
static uint32_t rep_key, rep_next;
static uint32_t int_low_since;

static bool is_mod(int v) { return v == -KF_FN || v == -KF_SHIFT || v == -KF_CTRL || v == -KF_OPT || v == -KF_ALT; }
static bool pressed(int x, int y) { return held >> (y * 14 + x) & 1; }

/* app key code for a pressed position, honouring the modifiers held right now and Settings -> Arrows */
static uint32_t translate(int x, int y)
{
    bool fn = pressed(0, 2), shift = pressed(1, 2);
    int v = shift ? MAP[y][x].s : MAP[y][x].n;
    if (!hw_keys_fn_arrows() && !shift && (v == ';' || v == ',' || v == '.' || v == '/')) {
        if (fn) return (uint32_t)v;      /* direct arrows: fn types the character */
        return v == ';' ? K_UP : v == ',' ? K_LEFT : v == '.' ? K_DOWN : K_RIGHT;
    }
    if (fn) { /* fn + ; , . / = arrows, fn + ` = esc, fn + bksp = delete */
        if (v == ';' || v == ':') return K_UP;
        if (v == ',' || v == '<') return K_LEFT;
        if (v == '.' || v == '>') return K_DOWN;
        if (v == '/' || v == '?') return K_RIGHT;
        if (v == '`' || v == '~') return K_ESC;
        if (v == -KF_BS) return K_BACKSPACE | K_FN;
        return (uint32_t)(v < 0 ? 0 : MAP[y][x].n) | K_FN;
    }
    switch (v) {
    case -KF_BS: return K_BACKSPACE;
    case -KF_TAB: return K_TAB;
    case -KF_ENTER: return K_ENTER;
    default: return v < 0 ? 0 : (uint32_t)v;
    }
}

static bool repeats(uint32_t k) { return k == K_UP || k == K_DOWN || k == K_LEFT || k == K_RIGHT || k == K_BACKSPACE; }

void hw_keys_flush(void)
{
    if (og) return;
    while (rd(REG_KEY_EVENT_A)) {}
    for (int i = 0; i < 3; i++) rd((uint8_t)(REG_GPIO_INT_STAT_1 + i));
    wr(REG_INT_STAT, 3);
}

/* one key went down or up at layout position (x, y) */
static void key_event(int x, int y, bool down, void (*on_key)(uint32_t, bool), uint32_t now_ms)
{
    int bit = y * 14 + x;
    if (down) {
        held |= 1ULL << bit;
        if (is_mod(MAP[y][x].n)) return;
        uint32_t k = translate(x, y);
        sent[bit] = k;
        if (k) {
            on_key(k, true);
            if (repeats(k)) rep_key = k, rep_next = now_ms + 450;
        }
    } else {
        held &= ~(1ULL << bit);
        if (sent[bit]) {
            on_key(sent[bit], false);
            if (rep_key == sent[bit]) rep_key = 0;
            sent[bit] = 0;
        }
    }
}

/* the whole matrix as a held bitmap (bit y * 14 + x), laid out like M5Cardputer's IOMatrix reader:
 * line i of the 74HC138 and input j give x = 2j + (i < 4), y = 3 - (i & 3) */
static uint64_t og_scan(void)
{
    uint64_t m = 0;
    for (int i = 0; i < 8; i++) {
        og_select(i);
        esp_rom_delay_us(10);
        for (int j = 0; j < 7; j++)
            if (!gpio_get_level((gpio_num_t)OG_IN[j])) m |= 1ULL << ((3 - (i & 3)) * 14 + 2 * j + (i < 4));
    }
    og_select(0);
    return m;
}

static void og_poll(void (*on_key)(uint32_t, bool), uint32_t now_ms)
{
    static uint64_t last;
    uint64_t now = og_scan();
    if (now != last) { last = now; return; }              /* debounce: a change counts once two scans agree */
    for (int bit = 0; bit < 56; bit++)                    /* releases first, so fn is let go before the next press */
        if ((held >> bit & 1) && !(now >> bit & 1)) key_event(bit % 14, bit / 14, false, on_key, now_ms);
    for (int bit = 0; bit < 56; bit++)
        if (!(held >> bit & 1) && (now >> bit & 1)) key_event(bit % 14, bit / 14, true, on_key, now_ms);
}

void hw_keys_poll(void (*on_key)(uint32_t, bool), uint32_t now_ms)
{
    if (og) {
        og_poll(on_key, now_ms);
    } else if (gpio_get_level(PIN_INT)) {
        int_low_since = 0;
    } else {
        if (!int_low_since) int_low_since = now_ms ? now_ms : 1;
        for (int n = 0; n < DRAIN_MAX; n++) {
            uint8_t ev = rd(REG_KEY_EVENT_A);
            if (!ev) break;
            int code = (ev & 0x7F) - 1, row = code / 10, col = code % 10;
            int x = row * 2 + (col > 3), y = (col + 4) % 4;
            if (x > 13 || y > 3) continue;
            key_event(x, y, ev & 0x80, on_key, now_ms);
        }
        wr(REG_INT_STAT, 1);
        if (gpio_get_level(PIN_INT) == 0 && now_ms - int_low_since > WEDGE_MS) { /* wedged: rebuild */
            controller_init();
            int_low_since = 0;
            held = 0;
            memset(sent, 0, sizeof sent);
            rep_key = 0;
        }
    }
    if (rep_key && (int32_t)(now_ms - rep_next) >= 0) { /* auto-repeat arrows and backspace */
        on_key(rep_key, true);
        rep_next = now_ms + 70;
    }
}

/* Deep sleep for a dead battery. ADV: any key pulls the TCA8418's INT low. Original: the matrix has no interrupt line,
 * so matrix line 0 is held selected and a key on it (space, z, c, b, m, "." or opt), or the G0 button, wakes it. */
void hw_keys_wake_setup(void)
{
    if (!og) {
        esp_sleep_enable_ext1_wakeup(1ULL << PIN_INT, ESP_EXT1_WAKEUP_ANY_LOW);
        return;
    }
    uint64_t mask = 1ULL << 0;
    for (int i = 0; i < 3; i++) {
        gpio_set_level((gpio_num_t)OG_SEL[i], 0);
        gpio_hold_en((gpio_num_t)OG_SEL[i]);
    }
    gpio_deep_sleep_hold_en();
    for (int i = 0; i < 7; i++) {
        mask |= 1ULL << OG_IN[i];
        rtc_gpio_pullup_en((gpio_num_t)OG_IN[i]);
        rtc_gpio_pulldown_dis((gpio_num_t)OG_IN[i]);
    }
    esp_sleep_enable_ext1_wakeup(mask, ESP_EXT1_WAKEUP_ANY_LOW);
}
#endif
