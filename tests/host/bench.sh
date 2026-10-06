#!/bin/sh
# Rendering benchmark (Linux/WSL gcc -O2): the renderer as shipped, then with its fast paths off (-DUI_NAIVE).
set -e
cd "$(dirname "$0")"
D=build/_deps
C=../../components
B=build/plain
mkdir -p $B
CFLAGS="-std=gnu11 -O2 -DMINIZ_NO_ARCHIVE_APIS -DMINIZ_NO_STDIO -I$C/kdbx/include -I$C/kdbx -I$C/kdbx/yxml -I$C/totp/include
  -I$C/gen/include -I$C/search/include -I$C/typing/include -I$C/strength/include -I$C/fido/include -I$C/fido -I$D/miniz-src -I$D/mbedtls-src/include"
[ -f $B/libdeps.a ] || { echo "run memscan.sh once first (builds $B/libdeps.a)"; exit 1; }
KDBX="$C/kdbx/kdbx.c $C/kdbx/key.c $C/kdbx/xml_index.c $C/kdbx/save.c $C/kdbx/argon2.c $C/kdbx/yxml/yxml.c"
FIDO="$C/fido/cbor.c $C/fido/ctap.c $C/fido/ctaphid.c"
UI="$C/ui/app.c $C/ui/app_edit.c $C/ui/app_tools.c $C/ui/app_fido.c $C/ui/app_bt.c $C/ui/app_splash.c $C/ui/app_browse.c $C/ui/app_time.c $C/ui/app_anim.c $C/ui/app_account.c $C/ui/app_groups.c $C/ui/app_view.c $C/ui/font_data.c $C/ui/font_br.c $C/ui/theme_br.c $C/ui/logo_data.c $C/ui/settings.c $C/qr/qrcodegen.c -I$C/ui/include -I$C/qr"
REST="$KDBX host_random.c $C/search/search.c $C/strength/strength.c $C/gen/gen.c $C/gen/wordlist.c $C/totp/totp.c $C/typing/layouts.c $C/typing/autotype.c $FIDO $B/libdeps.a -lm"
gcc $CFLAGS bench.c $C/ui/gfx.c $UI $REST -o $B/bench
gcc $CFLAGS -DUI_NAIVE bench.c $C/ui/gfx.c $UI $REST -o $B/bench_naive
echo "== fast paths on";  $B/bench ../../testdata
echo "== fast paths off"; $B/bench_naive ../../testdata
