#ifndef BRZESZCZOT_HPP
#define BRZESZCZOT_HPP

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <string>

#define TARGET_NAME "brzeszczot"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef float f32;
typedef double f64;

#define errlog(...) fprintf(stderr, __VA_ARGS__);

#include "brzeszczot/io.hpp"

#endif /* BRZESZCZOT_HPP */
