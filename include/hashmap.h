#ifndef HASHMAP_H
#define HASHMAP_H

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

enum hashmap_cell_state {
	HASHMAP_CELL_STATE_EMPTY,
	HASHMAP_CELL_STATE_IN_USE,
	HASHMAP_CELL_STATE_DELETED,
};

enum hashmap_result {
	HASHMAP_RESULT_OK,
	HASHMAP_RESULT_OLD_VALUE,
	HASHMAP_RESULT_NOT_FOUND,
};

#define HASHMAP_DECL(visibility, key_t, val_t, name)				\
typedef struct {								\
	enum hashmap_cell_state state;						\
	key_t key;								\
	val_t val;								\
} name##_cell;									\
										\
typedef struct {								\
	name##_cell *cells;							\
	size_t cap, len;							\
	double load;								\
} name;										\
										\
visibility b32									\
name##_try_alloc(name *out, size_t capacity);					\
visibility b32									\
name##_try_realloc(name *self, size_t capacity);				\
visibility void									\
name##_free(name *self);							\
										\
visibility enum hashmap_result							\
name##_try_update(name *self, key_t *key, val_t *val, val_t *out);		\
visibility enum hashmap_result							\
name##_try_get(name *self, key_t *key, val_t *out);				\
visibility enum hashmap_result							\
name##_try_del(name *self, key_t *key, val_t *out);

#define HASHMAP_IMPL(visibility, key_t, val_t, name, key_hash_fn, key_comp_fn)	\
visibility b32									\
name##_try_alloc(name *out, size_t capacity) {					\
	assert(out);								\
										\
	if (UINT_MAX / sizeof(name##_cell) < capacity) return false;		\
										\
	name##_cell *buf = malloc(capacity * sizeof(name##_cell));		\
	if (!buf) return false;							\
										\
	out->cells = buf;							\
	out->cap = capacity;							\
	out->len = 0;								\
	out->load = 0.0;							\
										\
	return true;								\
}										\
										\
visibility b32									\
name##_try_realloc(name *self, size_t capacity) {				\
	assert(self);								\
										\
	if (UINT_MAX / sizeof(name##_cell) < capacity || self->len < capacity)	\
		return false;							\
										\
	name tmp;								\
	if (!name##_try_alloc(&tmp, capacity)) return false;			\
										\
	for (size_t i = 0; i < self->cap; i++) {				\
		name##_cell *cell = &self->cells[i];				\
										\
		if (cell->state == HASHMAP_CELL_STATE_IN_USE)			\
			name##_try_update(&tmp, &cell->key, &cell->val, NULL);	\
	}									\
										\
	*self = tmp;								\
										\
	return true;								\
}										\
										\
visibility void									\
name##_free(name *self) {							\
	assert(self);								\
										\
	free(self->cells);							\
}										\
										\
visibility enum hashmap_result							\
name##_try_update(name *self, key_t *key, val_t *val, val_t *out) {		\
	assert(self);								\
	assert(key);								\
	assert(val);								\
										\
	u64 hash = key_hash_fn(key);						\
	for (size_t off = 0; off < self->cap; off++) {				\
		size_t idx = (hash + off) % self->cap;				\
										\
		name##_cell *cell = &self->cells[idx];				\
										\
		if (cell->state == HASHMAP_CELL_STATE_EMPTY			\
			|| cell->state == HASHMAP_CELL_STATE_DELETED) {		\
			self->load = (self->len++ / (double)self->cap);		\
										\
			cell->state = HASHMAP_CELL_STATE_IN_USE;		\
			cell->key = *key;					\
			cell->val = *val;					\
										\
			return HASHMAP_RESULT_OK;				\
		}								\
										\
		if (cell->state == HASHMAP_CELL_STATE_IN_USE			\
			&& key_comp_fn(key, &cell->key) == 0) {			\
			if (out) *out = cell->val;				\
										\
			cell->val = *val;					\
										\
			if (out) return HASHMAP_RESULT_OLD_VALUE;		\
										\
			return HASHMAP_RESULT_OK;				\
		}								\
	}									\
										\
	return HASHMAP_RESULT_NOT_FOUND;					\
}										\
										\
visibility enum hashmap_result							\
name##_try_get(name *self, key_t *key, val_t *out) {				\
	assert(self);								\
	assert(key);								\
	assert(out);								\
										\
	u64 hash = key_hash_fn(key);						\
	for (size_t off = 0; off < self->cap; off++) {				\
		size_t idx = (hash + off) % self->cap;				\
										\
		name##_cell *cell = &self->cells[idx];				\
										\
		if (cell->state == HASHMAP_CELL_STATE_EMPTY)			\
			return HASHMAP_RESULT_NOT_FOUND;			\
										\
		if (cell->state == HASHMAP_CELL_STATE_IN_USE			\
			&& key_comp_fn(key, &cell->key) == 0) {			\
			*out = cell->val;					\
										\
			return HASHMAP_RESULT_OK;				\
		}								\
	}									\
										\
	return HASHMAP_RESULT_NOT_FOUND;					\
}										\
										\
visibility enum hashmap_result							\
name##_try_del(name *self, key_t *key, val_t *out) {				\
	assert(self);								\
	assert(key);								\
										\
	u64 hash = key_hash_fn(key);						\
	for (size_t off = 0; off < self->cap; off++) {				\
		size_t idx = (hash + off) % self->cap;				\
										\
		name##_cell *cell = &self->cells[idx];				\
										\
		if (cell->state == HASHMAP_CELL_STATE_EMPTY)			\
			return HASHMAP_RESULT_NOT_FOUND;			\
										\
		if (cell->state == HASHMAP_CELL_STATE_IN_USE			\
			&& key_comp_fn(key, &cell->key) == 0) {			\
			if (out) *out = cell->val;				\
										\
			cell->state = HASHMAP_CELL_STATE_DELETED;		\
										\
			self->load = (--self->len / (double)self->cap);		\
										\
			return HASHMAP_RESULT_OK;				\
		}								\
	}									\
										\
	return HASHMAP_RESULT_NOT_FOUND;					\
}

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* HASHMAP_H */
