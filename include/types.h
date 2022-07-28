#ifndef TYPES_H
#define TYPES_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef int32_t b32;

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
	char *str;
	size_t len;
};

#define STR_FROM_CSTR(cstr) { .str = (cstr), .len = strlen(cstr), }
#define STR_FROM_CSTR_LIT(cstr) { .str = (cstr), .len = sizeof(cstr) - sizeof('\0'), }

#endif /* TYPES_H */
