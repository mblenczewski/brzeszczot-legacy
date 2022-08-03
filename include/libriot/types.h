#ifndef LIBRIOT_TYPES_H
#define LIBRIOT_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "libriot.h"

union vec2 {
	f32 vals[2];
	struct vec2_elements {
		f32 x, y;
	};
};

union vec3 {
	f32 vals[3];
	struct vec3_elements {
		f32 x, y, z;
	};
};

union vec4 {
	f32 vals[4];
	struct vec4_elements {
		f32 x, y, z, w;
	};
};

union mat4 {
	f32 vals[16];
};

struct rgba {
	f32 r, g, b, a;
};

enum riot_bin_node_type {
	RIOT_BIN_NODE_TYPE_NONE	= 0,
	RIOT_BIN_NODE_TYPE_B32	= 1,
	RIOT_BIN_NODE_TYPE_I8	= 2,
	RIOT_BIN_NODE_TYPE_U8	= 3,
	RIOT_BIN_NODE_TYPE_I16	= 4,
	RIOT_BIN_NODE_TYPE_U16	= 5,
	RIOT_BIN_NODE_TYPE_I32	= 6,
	RIOT_BIN_NODE_TYPE_U32	= 7,
	RIOT_BIN_NODE_TYPE_I64	= 8,
	RIOT_BIN_NODE_TYPE_U64	= 9,
	RIOT_BIN_NODE_TYPE_F32	= 10,
	RIOT_BIN_NODE_TYPE_VEC2	= 11,
	RIOT_BIN_NODE_TYOE_VEC3	= 12,
	RIOT_BIN_NODE_TYPE_VEC4	= 13,
	RIOT_BIN_NODE_TYPE_MAT4	= 14,
	RIOT_BIN_NODE_TYPE_RGBA	= 15,
	RIOT_BIN_NODE_TYPE_STR	= 16,
	RIOT_BIN_NODE_TYPE_HASH	= 17,
	RIOT_BIN_NODE_TYPE_FILE	= 18,
	RIOT_BIN_NODE_TYPE_LIST	= 0x80 | 0,
	RIOT_BIN_NODE_TYPE_LIST2 = 0x80 | 1,
	RIOT_BIN_NODE_TYPE_PTR	= 0x80 | 2,
	RIOT_BIN_NODE_TYPE_EMBED = 0x80 | 3,
	RIOT_BIN_NODE_TYPE_LINK	= 0x80 | 4,
	RIOT_BIN_NODE_TYPE_OPTION = 0x80 | 5,
	RIOT_BIN_NODE_TYPE_MAP	= 0x80 | 6,
	RIOT_BIN_NODE_TYPE_FLAG	= 0x80 | 7,
};

struct riot_bin_hash_fnv1a {
	hashes_fnv1a_val_t val;
	struct str_t src;
};

struct riot_bin_hash_xxh64 {
	hashes_xxh64_val_t val;
	struct str_t src;
};

struct riot_bin_node;
struct riot_bin_field;
struct riot_bin_pair;

VECTOR_DECL(global, struct riot_bin_node, vec_riot_bin_node)
VECTOR_DECL(global, struct riot_bin_field, vec_riot_bin_field)
VECTOR_DECL(global, struct riot_bin_pair, vec_riot_bin_pair)

struct riot_bin_node_list {
	enum riot_bin_node_type type;
	vec_riot_bin_node items;
};

struct riot_bin_field_list {
	struct riot_bin_hash_fnv1a name;
	vec_riot_bin_field item;
};

struct riot_bin_node_map {
	enum riot_bin_node_type key_type, val_type;
	vec_riot_bin_pair items;
};

struct riot_bin_node {
	enum riot_bin_node_type type;
	union {
		b32 node_bool, node_flag;
		s8 node_i8;
		u8 node_u8;
		s16 node_i16;
		u16 node_u16;
		s32 node_i32;
		u32 node_u32;
		s64 node_i64;
		u64 node_u64;
		f32 node_f32;
		union vec2 node_vec2;
		union vec3 node_vec3;
		union vec4 node_vec4;
		union mat4 node_mat4;
		struct rgba node_rgba;
		struct str_t node_string;
		struct riot_bin_hash_fnv1a node_hash, node_link;
		struct riot_bin_hash_xxh64 node_file;
		struct riot_bin_node_list node_list, node_list2, node_option;
		struct riot_bin_field_list node_pointer, node_embed;
		struct riot_bin_node_map node_map;
	};
};

struct riot_bin_field {
	struct riot_bin_hash_fnv1a key;
	struct riot_bin_node val;
};

struct riot_bin_pair {
	struct riot_bin_node key, val;
};

HASHMAP_DECL(global, struct str_t, struct riot_bin_node, map_str_to_riot_bin_node)

struct riot_bin {
	map_str_to_riot_bin_node sections;
};

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* LIBRIOT_TYPES_H */
