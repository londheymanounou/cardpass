cmake_minimum_required(VERSION 3.20)
project(cardpass_host C)
set(CMAKE_C_STANDARD 11)

include(FetchContent)
# Same mbedTLS major/minor as ESP-IDF 5.x
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(mbedtls
    URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2
    URL_HASH SHA256=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6)
# tinfl only (the device uses the copy in ROM)
FetchContent_Declare(miniz
    URL https://github.com/richgel999/miniz/releases/download/3.1.2/miniz-3.1.2.zip
    SOURCE_SUBDIR none)
FetchContent_MakeAvailable(mbedtls miniz)

option(SANITIZE "Build with AddressSanitizer + UBSan" OFF)
if(SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

set(KDBX ../../components/kdbx)
add_library(kdbx STATIC ${KDBX}/kdbx.c ${KDBX}/key.c ${KDBX}/xml_index.c ${KDBX}/save.c ${KDBX}/yxml/yxml.c ${miniz_SOURCE_DIR}/miniz.c host_random.c)
target_include_directories(kdbx PUBLIC ${KDBX}/include ${KDBX} ${KDBX}/yxml ${miniz_SOURCE_DIR})
target_link_libraries(kdbx PUBLIC mbedcrypto $<$<PLATFORM_ID:Windows>:bcrypt>)
target_compile_definitions(kdbx PRIVATE MINIZ_NO_ARCHIVE_APIS MINIZ_NO_STDIO)
set_source_files_properties(${KDBX}/kdbx.c ${KDBX}/key.c ${KDBX}/xml_index.c ${KDBX}/save.c PROPERTIES COMPILE_OPTIONS "-Wall;-Wextra")

add_executable(test_kdbx test_kdbx.c)
target_link_libraries(test_kdbx kdbx)

enable_testing()
add_test(NAME kdbx COMMAND test_kdbx ${CMAKE_CURRENT_SOURCE_DIR}/../../testdata)

add_library(totp STATIC ../../components/totp/totp.c)
target_include_directories(totp PUBLIC ../../components/totp/include)
target_link_libraries(totp PUBLIC mbedcrypto)
add_executable(test_totp test_totp.c)
target_link_libraries(test_totp totp)
add_test(NAME totp COMMAND test_totp)

add_library(gen STATIC ../../components/gen/gen.c ../../components/gen/wordlist.c)
target_include_directories(gen PUBLIC ../../components/gen/include)
add_executable(test_gen test_gen.c)
target_link_libraries(test_gen gen m)
add_test(NAME gen COMMAND test_gen)

add_library(search STATIC ../../components/search/search.c)
target_include_directories(search PUBLIC ../../components/search/include)
target_link_libraries(search PUBLIC kdbx)
add_executable(test_search test_search.c)
target_link_libraries(test_search search)
add_test(NAME search COMMAND test_search ${CMAKE_CURRENT_SOURCE_DIR}/../../testdata)

add_executable(test_save test_save.c)
target_link_libraries(test_save kdbx)
add_test(NAME save COMMAND test_save ${CMAKE_CURRENT_SOURCE_DIR}/../../testdata ${CMAKE_CURRENT_BINARY_DIR}/save_work)

add_library(typing STATIC ../../components/typing/layouts.c ../../components/typing/autotype.c)
target_include_directories(typing PUBLIC ../../components/typing/include)
add_executable(test_typing test_typing.c)
target_link_libraries(test_typing typing)
add_test(NAME typing COMMAND test_typing)

add_library(strength STATIC ../../components/strength/strength.c)
target_include_directories(strength PUBLIC ../../components/strength/include)
target_link_libraries(strength PUBLIC gen m)
add_executable(test_strength test_strength.c)
target_link_libraries(test_strength strength)
add_test(NAME strength COMMAND test_strength)

# RAM budget report (not a pass/fail test): run build/mem_probe
add_executable(mem_probe mem_probe.c)
target_link_libraries(mem_probe kdbx "-Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free")

add_library(fido STATIC ../../components/fido/cbor.c ../../components/fido/ctap.c ../../components/fido/ctaphid.c)
target_include_directories(fido PUBLIC ../../components/fido/include)
target_link_libraries(fido PUBLIC kdbx)
add_executable(test_fido test_fido.c)
target_link_libraries(test_fido fido)
add_test(NAME fido COMMAND test_fido ${CMAKE_CURRENT_SOURCE_DIR}/../../testdata ${CMAKE_CURRENT_BINARY_DIR})

add_library(ui STATIC ../../components/ui/gfx.c ../../components/ui/app.c ../../components/ui/app_edit.c ../../components/ui/app_tools.c ../../components/ui/font_data.c ../../components/ui/settings.c ../../components/qr/qrcodegen.c)
target_include_directories(ui PUBLIC ../../components/ui/include ../../components/qr)
target_link_libraries(ui PUBLIC kdbx search strength totp typing gen)
add_executable(render render.c)
target_link_libraries(render ui)
add_test(NAME render COMMAND render ${CMAKE_CURRENT_SOURCE_DIR}/../../testdata ${CMAKE_CURRENT_BINARY_DIR}/renders)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/renders)

add_executable(test_settings test_settings.c)
target_link_libraries(test_settings ui)
add_test(NAME settings COMMAND test_settings)
