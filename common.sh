#!/bin/sh

set -e

LIBRIOT_TARGET="libriot"
LIBRIOT_BINARY="$LIBRIOT_TARGET.a"

BRZESZCZOT_TARGET="brzeszczot"
BRZESZCZOT_BINARY="$BRZESZCZOT_TARGET.exe"

ROOT="$(dirname $0)"

BIN="$ROOT/bin"
DEP="$ROOT/dep"
OBJ="$ROOT/obj"

SRC="$ROOT/src"
INC="$ROOT/include"
LIB="$ROOT/lib"

[ -d "$BIN" ] || mkdir "$BIN"
[ -d "$DEP" ] || mkdir "$DEP"
[ -d "$OBJ" ] || mkdir "$OBJ"

COMMON_FLAGS="-Wall -Wextra -Wpedantic -ggdb -O0"
CFLAGS="-std=c17 $COMMON_FLAGS"
CXXFLAGS="-std=c++20 $COMMON_FLAGS"
CPPFLAGS="-I$INC -I$DEP/include -I$DEP/include/ritobin"
LDFLAGS="-static -L$BIN -lriot -L$DEP/lib -lglfw3 -limgui -lopengl32 -lgdi32 -lshell32 -Wl,-O2 -Wl,--as-needed"

EXEC() {
	[ $DRYRUN ] && echo "$@" || ( [ $VERBOSE ] && echo "$@"; $@ )
}
