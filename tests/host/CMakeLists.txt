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
add_library(kdbx STATIC ${KDBX}/kdbx.c ${KDBX}/key.c ${KDBX}/xml_index.c ${KDBX}/yxml/yxml.c ${miniz_SOURCE_DIR}/miniz.c)
target_include_directories(kdbx PUBLIC ${KDBX}/include ${KDBX} ${KDBX}/yxml ${miniz_SOURCE_DIR})
target_link_libraries(kdbx PUBLIC mbedcrypto)
target_compile_definitions(kdbx PRIVATE MINIZ_NO_ARCHIVE_APIS MINIZ_NO_STDIO)
set_source_files_properties(${KDBX}/kdbx.c ${KDBX}/key.c ${KDBX}/xml_index.c PROPERTIES COMPILE_OPTIONS "-Wall;-Wextra")

add_executable(test_kdbx test_kdbx.c)
target_link_libraries(test_kdbx kdbx)

enable_testing()
add_test(NAME kdbx COMMAND test_kdbx ${CMAKE_CURRENT_SOURCE_DIR}/../../testdata)
