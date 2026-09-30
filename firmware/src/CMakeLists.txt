idf_component_register(
    SRCS main.c hw_display.c hw_keys.c hw_sd.c hw_misc.c hw_usb.c hw_wifi.c
    INCLUDE_DIRS .
    REQUIRES esp_wifi esp_netif esp_event lwip espressif__esp_tinyusb kdbx ui totp gen search typing strength fido qr
             esp_lcd driver esp_driver_spi esp_driver_i2c esp_driver_gpio esp_driver_ledc esp_adc
             fatfs sdmmc nvs_flash esp_timer bootloader_support esp_hw_support)
