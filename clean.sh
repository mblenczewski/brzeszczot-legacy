#!/bin/sh

. "$(dirname $0)/common.sh"

EXEC rm -rf "$OBJ/$LIBRIOT_TARGET"
EXEC rm -f "$BIN/$LIBRIOT_BINARY"
EXEC rm -rf "$OBJ/$BRZESZCZOT_TARGET"
EXEC rm -f "$BIN/$BRZESZCZOT_BINARY"
