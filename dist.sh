#!/bin/sh

. "$(dirname $0)/common.sh"

"$ROOT/build.sh"

EXEC strip "$BIN/$TARGET"
