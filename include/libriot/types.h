#ifndef LIBRIOT_TYPES_H
#define LIBRIOT_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "libriot.h"

struct vec2 {
	f32 vs[2];
};

struct vec3 {
	f32 vs[3];
};

struct vec4 {
	f32 vs[4];
};

struct mat4 {
	f32 vs[16];
};

struct rgba {
	u8 vs[4];
};

enum __attribute__((packed)) riot_bin_node_type {
	RIOT_BIN_NODE_TYPE_NONE	= 0,
	RIOT_BIN_NODE_TYPE_B8	= 1,
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
	RIOT_BIN_NODE_TYPE_VEC3	= 12,
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

struct riot_bin_node;
struct riot_bin_field;
struct riot_bin_pair;

struct riot_bin_node_list {
	enum riot_bin_node_type type;
	struct riot_bin_node *items;
	u32 count;
};

struct riot_bin_node_option {
	enum riot_bin_node_type type;
	struct riot_bin_node *item;
};

struct riot_bin_field_list {
	hashes_fnv1a_val_t name_hash;
	struct riot_bin_field *items;
	u16 count;
};

struct riot_bin_pair_map {
	enum riot_bin_node_type key_type, val_type;
	struct riot_bin_pair *items;
	u32 count;
};

struct riot_bin_node {
	enum riot_bin_node_type type;
	union {
		u8 raw_data;
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
		struct vec2 node_vec2;
		struct vec3 node_vec3;
		struct vec4 node_vec4;
		struct mat4 node_mat4;
		struct rgba node_rgba;
		struct str_t node_str;
		hashes_fnv1a_val_t node_hash, node_link;
		hashes_xxh64_val_t node_file;
		struct riot_bin_node_list node_list;
		struct riot_bin_node_option node_option;
		struct riot_bin_field_list node_ptr, node_embed;
		struct riot_bin_pair_map node_map;
	};
};

struct riot_bin_field {
	hashes_fnv1a_val_t name_hash;
	struct riot_bin_node val;
};

struct riot_bin_pair {
	struct riot_bin_node key, val;
};

HASHMAP_DECL(global, struct str_t, struct riot_bin_node, map_str_to_riot_bin_node)

struct riot_bin {
	map_str_to_riot_bin_node sections;
};

static inline enum riot_bin_node_type
riot_bin_raw_type_to_node_type(u8 raw) {
	switch (raw) {
		case RIOT_BIN_NODE_TYPE_NONE:	return RIOT_BIN_NODE_TYPE_NONE;
		case RIOT_BIN_NODE_TYPE_B8:	return RIOT_BIN_NODE_TYPE_B8;
		case RIOT_BIN_NODE_TYPE_I8:	return RIOT_BIN_NODE_TYPE_I8;
		case RIOT_BIN_NODE_TYPE_U8:	return RIOT_BIN_NODE_TYPE_U8;
		case RIOT_BIN_NODE_TYPE_I16:	return RIOT_BIN_NODE_TYPE_I16;
		case RIOT_BIN_NODE_TYPE_U16:	return RIOT_BIN_NODE_TYPE_U16;
		case RIOT_BIN_NODE_TYPE_I32:	return RIOT_BIN_NODE_TYPE_I32;
		case RIOT_BIN_NODE_TYPE_U32:	return RIOT_BIN_NODE_TYPE_U32;
		case RIOT_BIN_NODE_TYPE_I64:	return RIOT_BIN_NODE_TYPE_I64;
		case RIOT_BIN_NODE_TYPE_U64:	return RIOT_BIN_NODE_TYPE_U64;
		case RIOT_BIN_NODE_TYPE_F32:	return RIOT_BIN_NODE_TYPE_F32;
		case RIOT_BIN_NODE_TYPE_VEC2:	return RIOT_BIN_NODE_TYPE_VEC2;
		case RIOT_BIN_NODE_TYPE_VEC3:	return RIOT_BIN_NODE_TYPE_VEC3;
		case RIOT_BIN_NODE_TYPE_VEC4:	return RIOT_BIN_NODE_TYPE_VEC4;
		case RIOT_BIN_NODE_TYPE_MAT4:	return RIOT_BIN_NODE_TYPE_MAT4;
		case RIOT_BIN_NODE_TYPE_RGBA:	return RIOT_BIN_NODE_TYPE_RGBA;
		case RIOT_BIN_NODE_TYPE_STR:	return RIOT_BIN_NODE_TYPE_STR;
		case RIOT_BIN_NODE_TYPE_HASH:	return RIOT_BIN_NODE_TYPE_HASH;
		case RIOT_BIN_NODE_TYPE_FILE:	return RIOT_BIN_NODE_TYPE_FILE;
		case RIOT_BIN_NODE_TYPE_LIST:	return RIOT_BIN_NODE_TYPE_LIST;
		case RIOT_BIN_NODE_TYPE_LIST2:	return RIOT_BIN_NODE_TYPE_LIST2;
		case RIOT_BIN_NODE_TYPE_PTR:	return RIOT_BIN_NODE_TYPE_PTR;
		case RIOT_BIN_NODE_TYPE_EMBED:	return RIOT_BIN_NODE_TYPE_EMBED;
		case RIOT_BIN_NODE_TYPE_LINK:	return RIOT_BIN_NODE_TYPE_LINK;
		case RIOT_BIN_NODE_TYPE_OPTION:	return RIOT_BIN_NODE_TYPE_OPTION;
		case RIOT_BIN_NODE_TYPE_MAP:	return RIOT_BIN_NODE_TYPE_MAP;
		case RIOT_BIN_NODE_TYPE_FLAG:	return RIOT_BIN_NODE_TYPE_FLAG;
		default:			return RIOT_BIN_NODE_TYPE_NONE;
	}
}

static inline u8
riot_bin_node_type_to_raw_type(enum riot_bin_node_type type) {
	return (u8)type;
}

static inline size_t
riot_bin_node_type_to_size(enum riot_bin_node_type type) {
	switch (type) {
		case RIOT_BIN_NODE_TYPE_NONE:	return 0;
		case RIOT_BIN_NODE_TYPE_B8:	return sizeof(u8);
		case RIOT_BIN_NODE_TYPE_I8:	return sizeof(s8);
		case RIOT_BIN_NODE_TYPE_U8:	return sizeof(u8);
		case RIOT_BIN_NODE_TYPE_I16:	return sizeof(s16);
		case RIOT_BIN_NODE_TYPE_U16:	return sizeof(u16);
		case RIOT_BIN_NODE_TYPE_I32:	return sizeof(s32);
		case RIOT_BIN_NODE_TYPE_U32:	return sizeof(u32);
		case RIOT_BIN_NODE_TYPE_I64:	return sizeof(s64);
		case RIOT_BIN_NODE_TYPE_U64:	return sizeof(u64);
		case RIOT_BIN_NODE_TYPE_F32:	return sizeof(f32);
		case RIOT_BIN_NODE_TYPE_VEC2:	return sizeof(struct vec2);
		case RIOT_BIN_NODE_TYPE_VEC3:	return sizeof(struct vec3);
		case RIOT_BIN_NODE_TYPE_VEC4:	return sizeof(struct vec4);
		case RIOT_BIN_NODE_TYPE_MAT4:	return sizeof(struct mat4);
		case RIOT_BIN_NODE_TYPE_RGBA:	return sizeof(struct rgba);
		case RIOT_BIN_NODE_TYPE_STR:	return 0;
		case RIOT_BIN_NODE_TYPE_HASH:	return sizeof(hashes_fnv1a_val_t);
		case RIOT_BIN_NODE_TYPE_FILE:	return sizeof(hashes_xxh64_val_t);
		case RIOT_BIN_NODE_TYPE_LIST:	return 0;
		case RIOT_BIN_NODE_TYPE_LIST2:	return 0;
		case RIOT_BIN_NODE_TYPE_PTR:	return 0;
		case RIOT_BIN_NODE_TYPE_EMBED:	return 0;
		case RIOT_BIN_NODE_TYPE_LINK:	return sizeof(hashes_fnv1a_val_t);
		case RIOT_BIN_NODE_TYPE_OPTION:	return 0;
		case RIOT_BIN_NODE_TYPE_MAP:	return 0;
		case RIOT_BIN_NODE_TYPE_FLAG:	return sizeof(u8);
		default:			return 0;
	}
}

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* LIBRIOT_TYPES_H */
