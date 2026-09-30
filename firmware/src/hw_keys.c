/* Cardputer ADV keyboard: TCA8418 matrix controller on the internal I2C bus (SDA 8, SCL 9,
 * address 0x34, INT on GPIO 11). Event byte: bit7 = pressed, (byte & 0x7F) - 1 = row * 10 + col,
 * remapped to the 4 x 14 key layout of the Cardputer.
 *
 * The controller's FIFO is ~10 deep and an overflow can wedge INT low: every poll drains up to
 * 12 events, and INT held low for 400 ms triggers a re-init. */
#include <string.h>
#include "app.h"
#include "driver/gpio.h"
#include "driver/i2c_master.h"
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

void hw_keys_init(void)
{
    i2c_master_bus_config_t bc = {.i2c_port = I2C_NUM_0, .sda_io_num = PIN_SDA, .scl_io_num = PIN_SCL,
                                  .clk_source = I2C_CLK_SRC_DEFAULT, .glitch_ignore_cnt = 7,
                                  .flags.enable_internal_pullup = true};
    i2c_new_master_bus(&bc, &bus);
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

/* app key code for a pressed position, honouring the modifiers held right now */
static uint32_t translate(int x, int y)
{
    bool fn = pressed(0, 2), shift = pressed(1, 2);
    int v = shift ? MAP[y][x].s : MAP[y][x].n;
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
    while (rd(REG_KEY_EVENT_A)) {}
    for (int i = 0; i < 3; i++) rd((uint8_t)(REG_GPIO_INT_STAT_1 + i));
    wr(REG_INT_STAT, 3);
}

void hw_keys_poll(void (*on_key)(uint32_t, bool), uint32_t now_ms)
{
    if (gpio_get_level(PIN_INT)) {
        int_low_since = 0;
    } else {
        if (!int_low_since) int_low_since = now_ms ? now_ms : 1;
        for (int n = 0; n < DRAIN_MAX; n++) {
            uint8_t ev = rd(REG_KEY_EVENT_A);
            if (!ev) break;
            bool down = ev & 0x80;
            int code = (ev & 0x7F) - 1, row = code / 10, col = code % 10;
            int x = row * 2 + (col > 3), y = (col + 4) % 4;
            if (x > 13 || y > 3) continue;
            int bit = y * 14 + x;
            if (down) {
                held |= 1ULL << bit;
                if (is_mod(MAP[y][x].n)) continue;
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
