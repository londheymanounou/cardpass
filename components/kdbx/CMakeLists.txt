idf_component_register(
    SRCS kdbx.c key.c xml_index.c save.c argon2.c yxml/yxml.c
    INCLUDE_DIRS include
    PRIV_INCLUDE_DIRS . yxml
    REQUIRES mbedtls esp_rom)
