#!/bin/sh

. "$(dirname $0)/common.sh"

"$ROOT/deps.sh"

"$ROOT/clean.sh"

SOURCES="
	src/unity.cpp
"

for __src in $SOURCES; do
	EXEC mkdir -p "$(dirname $OBJ/$TARGET/$__src)"
	EXEC c++ -o "$OBJ/$TARGET/$__src.o" -c "$__src" $CFLAGS $CPPFLAGS
done

OBJECTS="$(find $OBJ/$TARGET -name '*.o' -type f)"
EXEC c++ -o "$BIN/$TARGET_EXECUTABLE" $OBJECTS $CFLAGS $CPPFLAGS $LDFLAGS
