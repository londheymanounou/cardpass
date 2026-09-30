/* Device settings (plan: stored in NVS or an SD file; never anything from the database). */
#pragma once
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    bool light, large_font, reveal_toggle;
    int autolock_s, brightness, typing_delay_ms, tz_minutes, weak_bits, expiry_days;
    char layout[24];
    char autotype[96];     /* default auto-type sequence */
    char last_db[64];      /* file name only, to preselect in the picker */
} cp_settings;

void cp_settings_default(cp_settings *s);
void cp_settings_parse(cp_settings *s, const char *text);            /* defaults + whatever is valid */
size_t cp_settings_format(const cp_settings *s, char *out, size_t n); /* 0 if it does not fit */
