idf_component_register(
    SRCS gfx.c app.c app_edit.c app_tools.c app_fido.c app_time.c app_anim.c app_account.c app_groups.c app_view.c font_data.c settings.c
    INCLUDE_DIRS include
    PRIV_INCLUDE_DIRS .
    REQUIRES kdbx search strength totp typing gen qr fido)
