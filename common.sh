#!/bin/sh

set -e

TARGET="brzeszczot"
TARGET_EXECUTABLE="$TARGET.exe"

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

CFLAGS="-std=c++20 -Wall -Wextra -Wpedantic -ggdb -O2"
CPPFLAGS="-I$INC -I$DEP/include -I$DEP/include/ritobin"
LDFLAGS="-static -L$DEP/lib -lglfw3 -limgui -lritobin_lib -lopengl32 -lgdi32 -lshell32 -Wl,-O2 -Wl,--as-needed"

EXEC() {
	[ $DRYRUN ] && echo "$@" || ( [ $VERBOSE ] && echo "$@"; $@ )
}
