#ifndef BRZESZCZOT_H
#define BRZESZCZOT_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t b32;

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

struct str_t {
	char *ptr;
	size_t len;
};

#endif /* BRZESZCZOT_H */
