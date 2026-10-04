#!/bin/sh
# Secret-residue + leak test (Linux/WSL gcc, NO sanitizers: it scans the real process memory).
# Needs the mbedTLS/miniz sources fetched by a prior CMake configure of tests/host (build/_deps).
set -e
cd "$(dirname "$0")"
D=build/_deps
C=../../components
B=build/plain
mkdir -p $B
CFLAGS="-std=gnu11 -g -O1 -fno-omit-frame-pointer -DMINIZ_NO_ARCHIVE_APIS -DMINIZ_NO_STDIO
  -I$C/kdbx/include -I$C/kdbx -I$C/kdbx/yxml -I$C/totp/include -I$C/gen/include -I$C/search/include -I$C/typing/include
  -I$C/strength/include -I$C/fido/include -I$C/fido -I$D/miniz-src -I$D/mbedtls-src/include"
if [ ! -f $B/libdeps.a ]; then
    (cd $B && gcc $CFLAGS -I../../$D/miniz-src -I../../$D/mbedtls-src/include -c \
        ../../$D/miniz-src/miniz.c ../../$D/mbedtls-src/library/*.c) || exit 1
    ar rcs $B/libdeps.a $B/*.o && rm -f $B/*.o
fi
KDBX="$C/kdbx/kdbx.c $C/kdbx/key.c $C/kdbx/xml_index.c $C/kdbx/save.c $C/kdbx/yxml/yxml.c"
FIDO="$C/fido/cbor.c $C/fido/ctap.c $C/fido/ctaphid.c"
UI="$C/ui/gfx.c $C/ui/app.c $C/ui/app_edit.c $C/ui/app_tools.c $C/ui/app_fido.c $C/ui/app_bt.c $C/ui/app_splash.c $C/ui/app_browse.c $C/ui/app_time.c $C/ui/app_anim.c $C/ui/app_account.c $C/ui/app_groups.c $C/ui/app_view.c $C/ui/font_data.c $C/ui/settings.c $C/qr/qrcodegen.c -I$C/ui/include -I$C/qr"
gcc $CFLAGS memscan.c $UI $KDBX host_random.c $C/search/search.c $C/strength/strength.c $C/gen/gen.c $C/gen/wordlist.c $C/totp/totp.c $C/typing/layouts.c $C/typing/autotype.c $FIDO $B/libdeps.a -lm -o $B/memscan
$B/memscan
