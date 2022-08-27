#ifndef LIBRIOT_TYPE_HELPERS_H
#define LIBRIOT_TYPE_HELPERS_H

#include "libriot/types.h"

static inline enum riot_bin_node_type
riot_bin_raw_type_to_node_type(u8 raw) {
	/* handling legacy complex types */
	if (raw >= RIOT_BIN_NODE_TYPE_FILE && raw < RIOT_BIN_NODE_TYPE_COMPLEX_FLAG) {
		raw -= RIOT_BIN_NODE_TYPE_FILE; /* remove primitive offset */
		raw |= RIOT_BIN_NODE_TYPE_COMPLEX_FLAG; /* mark as complex type */
	}

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
		case RIOT_BIN_NODE_TYPE_LIST2:	return RIOT_BIN_NODE_TYPE_LIST;
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
	if (type == RIOT_BIN_NODE_TYPE_LIST2)
		type = RIOT_BIN_NODE_TYPE_LIST;

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
		case RIOT_BIN_NODE_TYPE_VEC2:	return sizeof(struct riot_bin_vec2);
		case RIOT_BIN_NODE_TYPE_VEC3:	return sizeof(struct riot_bin_vec3);
		case RIOT_BIN_NODE_TYPE_VEC4:	return sizeof(struct riot_bin_vec4);
		case RIOT_BIN_NODE_TYPE_MAT4:	return sizeof(struct riot_bin_mat4);
		case RIOT_BIN_NODE_TYPE_RGBA:	return sizeof(struct riot_bin_rgba);
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

static inline b32
riot_bin_node_type_is_primitive(enum riot_bin_node_type type) {
	return !BITS_SET(type, RIOT_BIN_NODE_TYPE_COMPLEX_FLAG);
}

static inline b32
riot_bin_node_type_is_container(enum riot_bin_node_type type) {
	return type == RIOT_BIN_NODE_TYPE_LIST || type == RIOT_BIN_NODE_TYPE_OPTION || type == RIOT_BIN_NODE_TYPE_MAP;
}

#endif /* LIBRIOT_TYPE_HELPERS_H */
