#include "libriot.h"

static inline size_t
str_hash_fn(struct str_t *key) {
	assert(key);

	/* implementation of djb2: http://www.cse.yorku.ca/~oz/hash.html */

	u32 hash = 5381;

	while (key->len--) hash = ((hash << 5) + hash) ^ *(key->str++);

	return hash;
}

static inline int
str_comp_fn(struct str_t *a, struct str_t *b) {
	assert(a);
	assert(b);

	return strncmp(a->str, b->str, (a->len > b->len) ? b->len : a->len);
}

HASHMAP_IMPL(global, struct str_t, struct riot_bin_node, map_str_to_riot_bin_node, str_hash_fn, str_comp_fn)
