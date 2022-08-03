#ifndef HASHES_H
#define HASHES_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "types.h"

/* default value as recommended by: http://isthe.com/chongo/tech/comp/fnv/ */
#define HASHES_FNV1A_DEFAULT_SEED 0x811C9DC5

typedef u32 hashes_fnv1a_val_t;

static inline hashes_fnv1a_val_t
hashes_fnv1a(void *buf, size_t len, hashes_fnv1a_val_t seed) {
	assert(buf);

	/* implementation of:
	 *   https://create.stephan-brumme.com/fnv-hash/
	 */

	const u32 FNV1A_PRIME = 0x01000193;

	u32 hash = seed;
	u8 *src = (u8*)buf;

	while (len--) hash = (*src++ ^ hash) * FNV1A_PRIME;

	return hash;
}

typedef u64 hashes_xxh64_val_t;

static inline hashes_xxh64_val_t
hashes_xxh64(void *buf, size_t len, hashes_xxh64_val_t seed) {
	assert(buf);

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

	u64 hash, acc0, acc1, acc2, acc3;
	u8 const *data = (u8*)buf, *stop = data + len;

	/* ===================================================================
	 * STEP 1 : Initialisation of accumulators
	 * ===================================================================
	 */

	/* if we don't have enough bytes to use the accumulators, then simply
	 * initialise the hash from the seed and skip to the single-lane mixing
	 * phase
	 */
	if (len < 32) {
		hash = seed + PRIME5;
		goto hash_mixing;
	}

	/* initialise the 4 unique lane accumulators
	 */
	acc0 = seed + PRIME1 + PRIME2;
	acc1 = seed + PRIME2;
	acc2 = seed;
	acc3 = seed - PRIME1;

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
	hash += len;

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

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* HASHES_H */
