#ifndef LIBRIOT_TYPES_H
#define LIBRIOT_TYPES_H

#include "libriot.h"

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
	u32 val;
	struct str_t src;
};

/* default value as recommended by: http://isthe.com/chongo/tech/comp/fnv/ */
#define FNV1A_DEFAULT_SEED 0x811C9DC5

static inline u32 riot_bin_hash_fnv1a_calc(struct str_t src, u32 seed) {
	assert(src.str);

	/* implementation of:
	 *   https://create.stephan-brumme.com/fnv-hash/
	 */

	const u32 FNV1A_PRIME = 0x01000193;

	u32 hash = seed;

	while (src.len--) hash = (*src.str++ ^ hash) * FNV1A_PRIME;

	return hash;
}

struct riot_bin_hash_xxh64 {
	u64 val;
	struct str_t src;
};

static inline u64 riot_bin_hash_xxh64_calc(struct str_t src, u64 seed) {
	assert(src.str);

	/* implementation of:
	 *   https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md#xxh64-algorithm-description
	 */

	/* primes for good dispersal of hash in address space */
	const u64 PRIME1 = 0x9E3779B185EBCA87ULL;
	const u64 PRIME2 = 0xC2B2AE3D27D4EB4FULL;
	const u64 PRIME3 = 0x165667B19E3779F9ULL;
	const u64 PRIME4 = 0x85EBCA77C2B2AE63ULL;
	const u64 PRIME5 = 0x27D4EB2F165667C5ULL;

	/* rotate x `bits` places to the left, should compile to a single CPU instruction (ROL) */
	#define ROL(x, bits) (((x) << (bits)) | ((x) >> (64 - (bits))))

	/* core hash step of a single accumulator  */
	#define ROUND(acc, input) (ROL((acc) + ((input) * PRIME2), 31) * PRIME1)

	/* core hash step of a 32-byte stripe (processes each of the 4 accumulators */
	#define ROUND4(stripe, acc0, acc1, acc2, acc3)				\
	{									\
		(acc0) = ROUND(acc0, stripe[0]);				\
		(acc1) = ROUND(acc1, stripe[1]);				\
		(acc2) = ROUND(acc2, stripe[2]);				\
		(acc3) = ROUND(acc3, stripe[3]);				\
	}

	/* merges two accumulator values */
	#define MERGE_ACC(acc, input) ((((acc) ^ ROUND(0, (input))) * PRIME1) + PRIME4)

	u64 hash;

	/* ===================================================================
	 * STEP 1 : Initialisation of accumulators
	 * ===================================================================
	 */

	/* if we don't have enough bytes to use the accumulators, then simply
	 * initialise the hash from the seed and skip to the single-lane mixing
	 * phase
	 */
	if (src.len < 32) {
		hash = seed + PRIME5;
		goto hash_mixing;
	}

	/* initialise the 4 unique lane accumulators
	 */
	u64 acc0 = seed + PRIME1 + PRIME2;
	u64 acc1 = seed + PRIME2;
	u64 acc2 = seed;
	u64 acc3 = seed - PRIME1;

	u8 const *data = (u8*)src.str;
	u8 const *stop = (u8*)src.str + src.len;

	/* ===================================================================
	 * STEP 2 : Process stripes
	 * ===================================================================
	 */

	/* process all 32-byte stripes */
	for (; data + 32 <= stop; data += 32) {
		u64 const *stripe = (u64*)data;
		ROUND4(stripe, acc0, acc1, acc2, acc3); 
	}

	/* ===================================================================
	 * STEP 3 : Merge accumulators into single u64 hash
	 * ===================================================================
	 */

	hash = ROL(acc0, 1) + ROL(acc1, 7) + ROL(acc2, 12) + ROL(acc3, 18);
	hash = MERGE_ACC(hash, acc0);
	hash = MERGE_ACC(hash, acc1);
	hash = MERGE_ACC(hash, acc2);
	hash = MERGE_ACC(hash, acc3);

	/* ===================================================================
	 * STEP 4 : Mixing in total input length
	 * ===================================================================
	 */

hash_mixing:
	hash += src.len;

	/* ===================================================================
	 * STEP 5 : Consume remaining input
	 * ===================================================================
	 */

	/* process all single lanes left */
	for (; data + 8 <= stop; data += 8) {
		u64 const lane = *(u64*)data;
		hash = (ROL(hash ^ ROUND(0, lane), 27) * PRIME1) + PRIME4;
	}

	/* process any half-lane found */
	if (data + 4 <= stop) {
		u32 const half_lane = *(u32*)data;
		hash = (ROL(hash ^ (half_lane * PRIME1), 23) * PRIME2) + PRIME3;
		data  += 4;
	}

	/* take care of remaining 0..3 bytes, eat 1 byte per step */
	while (data != stop) {
		u8 const byte = *data++;
		hash = ROL(hash ^ (byte * PRIME5), 11) * PRIME1;
	}

	/* ===================================================================
	 * STEP 6 : Final mix and output
	 * ===================================================================
	 */

	hash ^= hash >> 33;
	hash *= PRIME2;
	hash ^= hash >> 29;
	hash *= PRIME3;
	hash ^= hash >> 32;

	return hash;
}

struct riot_bin_node;
struct riot_bin_field;
struct riot_bin_pair;

VECTOR_DECL(global, struct riot_bin_node, vec_riot_bin_node)
VECTOR_DECL(global, struct riot_bin_field, vec_riot_bin_field)
VECTOR_DECL(global, struct riot_bin_pair, vec_riot_bin_pair)

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
		union {
			f32 vals[2];
			struct {
				f32 x, y;
			};
		} node_vec2;
		union {
			f32 vals[3];
			struct {
				f32 x, y, z;
			};
		} node_vec3;
		union {
			f32 vals[4];
			struct {
				f32 x, y, z, w;
			};
		} node_vec4;
		union {
			f32 vals[16];
		} node_mat4;
		struct {
			f32 r, b, g, a;
		} node_rgba;
		struct str_t node_string;
		struct riot_bin_hash_fnv1a node_hash, node_link;
		struct riot_bin_hash_xxh64 node_file;
		struct {
			enum riot_bin_node_type type;
			vec_riot_bin_node items;
		} node_list, node_list2, node_option;
		struct {
			struct riot_bin_hash_fnv1a name;
			vec_riot_bin_field items;
		} node_pointer, node_embed;
		struct {
			enum riot_bin_node_type key_type, val_type;
			vec_riot_bin_pair items;
		} node_map;
	};
};

struct riot_bin_field {
	struct riot_bin_hash_fnv1a key;
	struct riot_bin_node val;
};

struct riot_bin_pair {
	struct riot_bin_node key, val;
};

#endif /* LIBRIOT_TYPES_H */
