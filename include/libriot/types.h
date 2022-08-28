#ifndef LIBRIOT_TYPES_H
#define LIBRIOT_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "libriot.h"

#define RIOT_BIN_NODE_TYPE_COMPLEX_FLAG 0x80

enum __attribute__((packed)) riot_bin_node_type {
	RIOT_BIN_NODE_TYPE_NONE		= 0,

	/* arithmetic and primitive types */
	RIOT_BIN_NODE_TYPE_B8		= 1,
	RIOT_BIN_NODE_TYPE_I8		= 2,
	RIOT_BIN_NODE_TYPE_U8		= 3,
	RIOT_BIN_NODE_TYPE_I16		= 4,
	RIOT_BIN_NODE_TYPE_U16		= 5,
	RIOT_BIN_NODE_TYPE_I32		= 6,
	RIOT_BIN_NODE_TYPE_U32		= 7,
	RIOT_BIN_NODE_TYPE_I64		= 8,
	RIOT_BIN_NODE_TYPE_U64		= 9,
	RIOT_BIN_NODE_TYPE_F32		= 10,
	RIOT_BIN_NODE_TYPE_VEC2		= 11,
	RIOT_BIN_NODE_TYPE_VEC3		= 12,
	RIOT_BIN_NODE_TYPE_VEC4		= 13,
	RIOT_BIN_NODE_TYPE_MAT4		= 14,
	RIOT_BIN_NODE_TYPE_RGBA		= 15,
	RIOT_BIN_NODE_TYPE_STR		= 16,
	RIOT_BIN_NODE_TYPE_HASH		= 17,
	RIOT_BIN_NODE_TYPE_FILE		= 18,

	/* complex types */
	RIOT_BIN_NODE_TYPE_LIST		= 0 | RIOT_BIN_NODE_TYPE_COMPLEX_FLAG,
	RIOT_BIN_NODE_TYPE_LIST2	= 1 | RIOT_BIN_NODE_TYPE_COMPLEX_FLAG,
	RIOT_BIN_NODE_TYPE_PTR		= 2 | RIOT_BIN_NODE_TYPE_COMPLEX_FLAG,
	RIOT_BIN_NODE_TYPE_EMBED	= 3 | RIOT_BIN_NODE_TYPE_COMPLEX_FLAG,
	RIOT_BIN_NODE_TYPE_LINK		= 4 | RIOT_BIN_NODE_TYPE_COMPLEX_FLAG,
	RIOT_BIN_NODE_TYPE_OPTION	= 5 | RIOT_BIN_NODE_TYPE_COMPLEX_FLAG,
	RIOT_BIN_NODE_TYPE_MAP		= 6 | RIOT_BIN_NODE_TYPE_COMPLEX_FLAG,
	RIOT_BIN_NODE_TYPE_FLAG		= 7 | RIOT_BIN_NODE_TYPE_COMPLEX_FLAG,
};

struct riot_bin_vec2 {
	f32 vs[2];
};

struct riot_bin_vec3 {
	f32 vs[3];
};

struct riot_bin_vec4 {
	f32 vs[4];
};

struct riot_bin_mat4 {
	f32 vs[16];
};

struct riot_bin_rgba {
	u8 vs[4];
};

struct riot_bin_str {
	u16 len;
	char *ptr;
};

struct riot_bin_node;
struct riot_bin_field;
struct riot_bin_pair;

struct riot_bin_node_list {
	enum riot_bin_node_type type;
	u32 count;
	struct riot_bin_node *items;
};

struct riot_bin_node_option {
	enum riot_bin_node_type type;
	struct riot_bin_node *item;
};

struct riot_bin_node_map {
	enum riot_bin_node_type key_type, val_type;
	u32 count;
	struct riot_bin_pair *items;
};

struct riot_bin_field_list {
	hashes_fnv1a_val_t name_hash;
	u16 count;
	struct riot_bin_field *items;
};

struct riot_bin_node {
	enum riot_bin_node_type type;
	union {
		/* generic member data pointer */
		u8 raw_data;

		/* primitive members */
		u8 node_bool, node_flag;
		s8 node_i8;
		u8 node_u8;
		s16 node_i16;
		u16 node_u16;
		s32 node_i32;
		u32 node_u32;
		s64 node_i64;
		u64 node_u64;
		f32 node_f32;
		struct riot_bin_vec2 node_vec2;
		struct riot_bin_vec3 node_vec3;
		struct riot_bin_vec4 node_vec4;
		struct riot_bin_mat4 node_mat4;
		struct riot_bin_rgba node_rgba;
		struct riot_bin_str node_str;
		hashes_fnv1a_val_t node_hash, node_link;
		hashes_xxh64_val_t node_file;

		/* complex members */
		struct riot_bin_node_list node_list;
		struct riot_bin_node_option node_option;
		struct riot_bin_node_map node_map;
		struct riot_bin_field_list node_ptr, node_embed;
	};
};

struct riot_bin_field {
	hashes_fnv1a_val_t name_hash;
	struct riot_bin_node val;
};

struct riot_bin_pair {
	struct riot_bin_node key, val;
};

struct riot_bin_alloc_info {
	size_t strings_len, nodes_count, fields_count, pairs_count;
};

struct riot_bin_mem_pool {
	char *strings, *strings_head;
	struct riot_bin_node *nodes, *nodes_head;
	struct riot_bin_field *fields, *fields_head;
	struct riot_bin_pair *pairs, *pairs_head;
	struct riot_bin_alloc_info alloc_info;
};

HASHMAP_DECL(global, struct str_t, struct riot_bin_node, map_str_to_riot_bin_node)

struct riot_bin {
	map_str_to_riot_bin_node sections;
	struct riot_bin_mem_pool mem_pool;
};

static inline void
riot_bin_free(struct riot_bin *self) {
	assert(self);

	map_str_to_riot_bin_node_free(&self->sections);
	free(self->mem_pool.strings);
	free(self->mem_pool.nodes);
	free(self->mem_pool.fields);
	free(self->mem_pool.pairs);
}

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* LIBRIOT_TYPES_H */
