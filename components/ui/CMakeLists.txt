idf_component_register(
    SRCS gfx.c app.c app_edit.c app_tools.c font_data.c settings.c
    INCLUDE_DIRS include
    PRIV_INCLUDE_DIRS .
    REQUIRES kdbx search strength totp typing gen qr)
