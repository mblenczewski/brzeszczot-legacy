#ifndef TYPES_H
#define TYPES_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define ARRLEN(arr) (sizeof(arr) / sizeof((arr)[0]))
#define MAX(a, b) ((a) < (b) ? (b) : (a))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define BITS_SET(v, m) (((v) & (m)) == (m))

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

struct mem_t {
	u8 *ptr;
	size_t len;
};

#define MEM_FROM_SLICE(mem, off) { .ptr = (mem).ptr + (off), .len = (mem)
#define MEM_FROM_PTR(_ptr, _len) { .ptr = (_ptr), .len = (_len), }
#define MEM_FROM_ARR(_arr) MEM_FROM_PTR(_arr, sizeof(_arr) / sizeof(_arr[0]))

struct str_t {
	char *str;
	size_t len;
};

#define STR_FROM_CSTR(cstr) { .str = (cstr), .len = strlen(cstr), }

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* TYPES_H */
