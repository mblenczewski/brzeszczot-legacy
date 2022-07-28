#!/bin/sh

. "$(dirname $0)/common.sh"

"$ROOT/deps.sh"

"$ROOT/clean.sh"

LIBRIOT_SOURCES="
	src/libriot_unity.c
"

for __src in $LIBRIOT_SOURCES; do
	EXEC mkdir -p "$(dirname $OBJ/$LIBRIOT_TARGET/$__src)"
	EXEC cc -o "$OBJ/$LIBRIOT_TARGET/$__src.o" -c "$__src" $CFLAGS $CPPFLAGS
done

LIBRIOT_OBJECTS="$(find $OBJ/$LIBRIOT_TARGET -name '*.o' -type f)"
EXEC ar -rcs "$BIN/$LIBRIOT_BINARY" $LIBRIOT_OBJECTS

BRZESZCZOT_SOURCES="
	src/brzeszczot_unity.cpp
"

for __src in $BRZESZCZOT_SOURCES; do
	EXEC mkdir -p "$(dirname $OBJ/$BRZESZCZOT_TARGET/$__src)"
	EXEC c++ -o "$OBJ/$BRZESZCZOT_TARGET/$__src.o" -c "$__src" $CXXFLAGS $CPPFLAGS
done

BRZESZCZOT_OBJECTS="$(find $OBJ/$BRZESZCZOT_TARGET -name '*.o' -type f)"
EXEC c++ -o "$BIN/$BRZESZCZOT_BINARY" $BRZESZCZOT_OBJECTS $CXXFLAGS $CPPFLAGS $LDFLAGS
