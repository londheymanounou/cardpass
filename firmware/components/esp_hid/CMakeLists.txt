# ESP-IDF 5.5's esp_hid, device side on NimBLE only, overriding the IDF component (project components win).
# One fix in src/nimble_hidd.c (search "CardPass"): the BLE HID device could not be started a second time
# per boot, because ble_svc_hid's slots and nimble_hidd's service_index were never reset on deinit.
# Re-check against upstream when the IDF version changes.
idf_component_register(SRCS "src/esp_hidd.c" "src/esp_hid_common.c" "src/nimble_hidd.c"
                       INCLUDE_DIRS "include"
                       PRIV_INCLUDE_DIRS "private"
                       REQUIRES esp_event bt)
target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-format")
