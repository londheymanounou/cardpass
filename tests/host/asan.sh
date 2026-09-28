#!/bin/sh
# ASan + LeakSanitizer + UBSan run (Linux/WSL gcc). Needs the mbedTLS/miniz
# sources fetched by a prior CMake configure of tests/host (build/_deps).
set -e
cd "$(dirname "$0")"
D=build/_deps
K=../../components/kdbx
out=build/test_kdbx_asan
[ -f $out ] && [ -z "$(find $K test_kdbx.c -newer $out -name '*.[ch]')" ] || \
gcc -std=c11 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all \
    -DMINIZ_NO_ARCHIVE_APIS -DMINIZ_NO_STDIO -I$K/include -I$K -I$K/yxml -I$D/miniz-src -I$D/mbedtls-src/include \
    test_kdbx.c $K/kdbx.c $K/key.c $K/xml_index.c $K/yxml/yxml.c $D/miniz-src/miniz.c \
    $D/mbedtls-src/library/*.c -o $out
ASAN_OPTIONS=detect_leaks=1 $out ../../testdata
