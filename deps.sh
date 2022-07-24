#!/bin/sh

. "$(dirname $0)/common.sh"

LIB_CFLAGS="-ggdb -Og"
LIB_CPPFLAGS=""

LIB_CMAKE_OPTS="-DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX=$DEP -DBUILD_SHARED_LIBS=OFF"

if [ ! -f "$DEP/built-deps.flag" ]; then
	EXEC rm -rf "$DEP/lib" "$DEP/include" "$OBJ/imgui" "$OBJ/glfw"

	EXEC git submodule update --init --recursive

	EXEC mkdir -p "$DEP/lib" "$DEP/include"

	## build and install glfw
	EXEC cmake -S "$LIB/glfw" -B "$OBJ/glfw" $LIB_CMAKE_OPTS -DGLFW_BUILD_EXAMPLES=OFF -DGLFW_BUILD_TESTS=OFF -DGLFW_BUILD_DOCS=OFF -DGLFW_BUILD_WIN32=ON
	EXEC cmake --build "$OBJ/glfw"
	EXEC cmake --install "$OBJ/glfw"

	## build and install imgui
	IMGUI_SOURCES="
		$LIB/imgui/imgui.cpp
		$LIB/imgui/imgui_demo.cpp
		$LIB/imgui/imgui_draw.cpp
		$LIB/imgui/imgui_tables.cpp
		$LIB/imgui/imgui_widgets.cpp
		$LIB/imgui/backends/imgui_impl_glfw.cpp
		$LIB/imgui/backends/imgui_impl_opengl3.cpp
	"

	for __src in $IMGUI_SOURCES; do
		EXEC mkdir -p "$(dirname $OBJ/imgui/$__src)"
		EXEC c++ -o "$OBJ/imgui/$__src.o" -c "$__src" $LIB_CFLAGS $LIB_CPPFLAGS -I"$LIB/imgui" -I"$LIB/imgui/backends" -I"$DEP/include"
	done

	EXEC ar -rcs "$DEP/lib/libimgui.a" "$(find $OBJ/imgui -name '*.o' -type f 2>/dev/null)"

	IMGUI_HEADERS="
		imgui.h
		imconfig.h
		backends/imgui_impl_glfw.h
		backends/imgui_impl_opengl3.h
	"

	for __hdr in $IMGUI_HEADERS; do
		EXEC mkdir -p "$(dirname $DEP/include/$__hdr)"
		EXEC cp "$LIB/imgui/$__hdr" "$DEP/include/$__hdr"
	done

	## build and install ritobin
	EXEC cmake -S "$LIB/ritobin" -B "$OBJ/ritobin" $LIB_CMAKE_OPTS
	EXEC cmake --build "$OBJ/ritobin"
	EXEC cmake --install "$OBJ/ritobin"

	cp "$OBJ/ritobin/ritobin_lib/libritobin_lib.a" "$DEP/lib/libritobin_lib.a"

	RITOBIN_HEADERS="
		ritobin/bin_hash.hpp
		ritobin/bin_io.hpp
		ritobin/bin_morph.hpp
		ritobin/bin_numconv.hpp
		ritobin/bin_strconv.hpp
		ritobin/bin_types.hpp
		ritobin/bin_types_helper.hpp
		ritobin/bin_unhash.hpp
	"

	for __hdr in $RITOBIN_HEADERS; do
		EXEC mkdir -p "$(dirname $DEP/include/$__hdr)"
		EXEC cp "$LIB/ritobin/ritobin_lib/src/$__hdr" "$DEP/include/$__hdr"
	done

	EXEC touch "$DEP/built-deps.flag"
fi
