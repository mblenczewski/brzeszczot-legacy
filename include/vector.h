#ifndef VECTOR_H
#define VECTOR_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "debug.h"
#include "types.h"

#ifndef global
#define global
#endif /* global */

#ifndef internal
#define internal static
#endif /* internal */

#define VECTOR_DECL(visibility, type, name)					\
typedef struct {								\
	type *vs;								\
	size_t cap, len;							\
} name;										\
										\
visibility b32									\
name##_try_alloc(name *out, size_t capacity);					\
visibility b32									\
name##_try_realloc(name *self, size_t capacity);				\
visibility void									\
name##_free(name *self);							\
										\
visibility b32									\
name##_try_push(name *self, type *val);						\
visibility b32									\
name##_try_pop(name *self, type *out);

#define VECTOR_IMPL(visibility, type, name)					\
visibility b32									\
name##_try_alloc(name *out, size_t capacity) {					\
	assert(out);								\
										\
	if ((UINT_MAX / sizeof(type)) < capacity) return false;			\
										\
	type *buf = malloc(capacity * sizeof(type));				\
	if (!buf) return false;							\
										\
	out->vs = buf;								\
	out->cap = capacity;							\
	out->len = 0;								\
										\
	return true;								\
}										\
										\
visibility b32									\
name##_try_realloc(name *self, size_t capacity) {				\
	assert(self);								\
										\
	if ((UINT_MAX / sizeof(type)) < capacity) return false;			\
										\
	type *buf = realloc(self->vs, capacity * sizeof(type));			\
	if (!buf) return false;							\
										\
	self->vs = buf;								\
	self->cap = capacity;							\
										\
	return true;								\
}										\
										\
visibility void									\
name##_free(name *self) {							\
	assert(self);								\
										\
	free(self->vs);								\
}										\
										\
visibility b32									\
name##_try_push(name *self, type *val) {					\
	assert(self);								\
	assert(val);								\
										\
	if (self->len == self->cap &&						\
		!name##_try_realloc(self, self->cap * 2) &&			\
		!name##_try_realloc(self, self->cap + 1)) {			\
		return false;							\
	}									\
										\
	self->vs[self->len++] = *val;						\
										\
	return true;								\
}										\
										\
visibility b32									\
name##_try_pop(name *self, type *out) {						\
	assert(self);								\
	assert(out);								\
										\
	if (self->len == 0) return false;					\
										\
	*out = self->vs[--(self->len)];						\
										\
	return true;								\
}

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* VECTOR_H */
