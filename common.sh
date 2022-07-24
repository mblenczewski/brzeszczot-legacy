#!/bin/sh

set -e

TARGET="brzeszczot.exe"

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

CFLAGS="-std=c++14 -Wall -Wextra -Wpedantic -ggdb -O2"
CPPFLAGS="-I$INC -I$DEP/include"
LDFLAGS="-L$DEP/lib -lglfw3 -limgui -lopengl32 -lgdi32 -lshell32 -Wl,-O2 -Wl,--as-needed"

EXEC() {
	[ $DRYRUN ] && echo "$@" || ( [ $VERBOSE ] && echo "$@"; $@ )
}
