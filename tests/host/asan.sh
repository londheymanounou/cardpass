#!/bin/sh
# ASan + LeakSanitizer + UBSan run of all host tests (Linux/WSL gcc). Needs the
# mbedTLS/miniz sources fetched by a prior CMake configure of tests/host (build/_deps).
set -e
cd "$(dirname "$0")"
D=build/_deps
C=../../components
B=build/asan
mkdir -p $B
CFLAGS="-std=gnu11 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all
  -DMINIZ_NO_ARCHIVE_APIS -DMINIZ_NO_STDIO -I$C/kdbx/include -I$C/kdbx -I$C/kdbx/yxml -I$C/totp/include
  -I$C/gen/include -I$C/search/include -I$C/typing/include -I$C/strength/include -I$C/fido/include -I$C/fido -I$D/miniz-src -I$D/mbedtls-src/include"

# libraries, compiled once
if [ ! -f $B/libdeps.a ]; then
    (cd $B && gcc $CFLAGS -I../../$D/miniz-src -I../../$D/mbedtls-src/include -c \
        ../../$D/miniz-src/miniz.c ../../$D/mbedtls-src/library/*.c) || exit 1
    ar rcs $B/libdeps.a $B/*.o && rm -f $B/*.o
fi
KDBX="$C/kdbx/kdbx.c $C/kdbx/key.c $C/kdbx/xml_index.c $C/kdbx/save.c $C/kdbx/yxml/yxml.c"

run() { name=$1; shift; gcc $CFLAGS "$@" $B/libdeps.a -lm -o $B/$name && echo "== $name" && ASAN_OPTIONS=detect_leaks=1 $B/$name $ARGS; }
ARGS=../../testdata run test_kdbx test_kdbx.c $KDBX host_random.c
ARGS= run test_totp test_totp.c $C/totp/totp.c
ARGS= run test_gen test_gen.c $C/gen/gen.c $C/gen/wordlist.c
ARGS=../../testdata run test_search test_search.c $C/search/search.c $KDBX host_random.c
ARGS="../../testdata $B/save_work" run test_save test_save.c $KDBX host_random.c
ARGS= run test_typing test_typing.c $C/typing/layouts.c $C/typing/autotype.c
ARGS= run test_strength test_strength.c $C/strength/strength.c $C/gen/gen.c $C/gen/wordlist.c
FIDO="$C/fido/cbor.c $C/fido/ctap.c $C/fido/ctaphid.c"
ARGS="../../testdata $B" run test_fido test_fido.c $KDBX host_random.c $FIDO
ARGS="../../testdata ${FUZZ_ITERS:-3000}" run fuzz fuzz.c $FIDO $KDBX $C/search/search.c $C/strength/strength.c $C/gen/gen.c $C/gen/wordlist.c $C/totp/totp.c $C/typing/layouts.c $C/typing/autotype.c
UI="$C/ui/gfx.c $C/ui/app.c $C/ui/app_edit.c $C/ui/app_tools.c $C/ui/app_fido.c $C/ui/app_time.c $C/ui/font_data.c $C/ui/settings.c $C/qr/qrcodegen.c -I$C/ui/include -I$C/qr"
mkdir -p $B/renders
ARGS="../../testdata $B/renders" run render render.c $UI $KDBX host_random.c $C/search/search.c $C/strength/strength.c $C/gen/gen.c $C/gen/wordlist.c $C/totp/totp.c $C/typing/layouts.c $C/typing/autotype.c $FIDO
ARGS= run test_settings test_settings.c $C/ui/settings.c -I$C/ui/include
