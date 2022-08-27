#ifndef LIBRIOT_IO_H
#define LIBRIOT_IO_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "libriot.h"

struct stream_t {
	struct mem_t buf;
	size_t cur;
};

enum riot_io_error {
	RIOT_IO_ERROR_OK,
	RIOT_IO_ERROR_EOF,
	RIOT_IO_ERROR_ALLOC,
	RIOT_IO_ERROR_CORRUPT,
	_RIOT_IO_ERROR_COUNT,
};

extern char const *_RIOT_IO_ERROR_NAME_MAP[_RIOT_IO_ERROR_COUNT];

static inline char const *
riot_io_error_str(enum riot_io_error val) {
	assert(val);
	assert(val < _RIOT_IO_ERROR_COUNT);

	return _RIOT_IO_ERROR_NAME_MAP[val];
}

#define STREAM_ERRLOG(stream) errlog("%s@%zu/%zu: ", __func__, (stream).cur, (stream).buf.len);

static inline b32
riot_bin_stream_has_input(struct stream_t *stream) {
	return stream->cur < stream->buf.len;
}

static inline enum riot_io_error
riot_bin_stream_try_skip(struct stream_t *stream, size_t len) {
	assert(stream);

	if (stream->buf.len < stream->cur + len) {
		STREAM_ERRLOG(*stream);
		dbglog("Tried to skip %zu bytes\n", len);
		return RIOT_IO_ERROR_EOF;
	}

	stream->cur += len;

	return RIOT_IO_ERROR_OK;
}

static inline enum riot_io_error
riot_bin_stream_try_read(struct stream_t *stream, void *buf, size_t len) {
	assert(stream);
	assert(stream->buf.ptr);
	assert(buf);

	if (stream->buf.len < stream->cur + len) {
		STREAM_ERRLOG(*stream);
		dbglog("Tried to read %zu bytes\n", len);
		return RIOT_IO_ERROR_EOF;
	}

	memcpy(buf, stream->buf.ptr + stream->cur, len);
	stream->cur += len;

	return RIOT_IO_ERROR_OK;
}

#define RIOT_IO_CHUNK_SIZE 8192

static inline enum riot_io_error
riot_bin_stream_try_write(struct stream_t *stream, void *buf, size_t len) {
	assert(stream);
	assert(stream->buf.ptr);
	assert(buf);

	if (stream->cur + len >= stream->buf.len) {
		size_t new_len = stream->buf.len + MAX(RIOT_IO_CHUNK_SIZE, len);
		u8 *new_buf = (u8*)realloc(stream->buf.ptr, new_len * sizeof(u8));
		if (!new_buf) return RIOT_IO_ERROR_ALLOC;

		stream->buf.ptr = new_buf;
		stream->buf.len = new_len;
	}

	memcpy(stream->buf.ptr + stream->cur, buf, len);
	stream->cur += len;

	return RIOT_IO_ERROR_OK;
}

/* ===========================================================================
 * RIOT INIBIN Format
 * ===========================================================================
 * | -------------------------------------------------------------------------- |
 * | PTCH Header : optional							|
 * | | ================================================================ |	|
 * | | PTCH Magic : 4 bytes, chr8[4]					|	|
 * | | Unknown Bytes : 8 bytes, u64 (flags? size? metadata?)		|	|
 * | -------------------------------------------------------------------------- |
 * | PROP Magic : 4 bytes, chr8[4]						|
 * | Version : 4 bytes, u32							|
 * | -------------------------------------------------------------------------- |
 * | Linked Files : v2+								|
 * | | ================================================================ |	|
 * | | Count : 4 bytes, u32						|	|
 * | | Strings : riot_bin_str[Count]					|	|
 * | -------------------------------------------------------------------------- |
 * | Prop Entries : v1+								|
 * | | ================================================================ |	|
 * | | Count : 4 bytes, u32						|	|
 * | | Entry Name Hashes : fnv1a_u32[Count]				|	|
 * | | Entries[Count]							|	|
 * | | | ====================================================== |	|	|
 * | | | Length : 4 bytes, u32					|	|	|
 * | | | Name Hash : 4 bytes, fnv1a_u32				|	|	|
 * | | | Count : 2 bytes, u16					|	|	|
 * | | | Items : riot_bin_node_field[Count]			|	|	|
 * | | | | ============================================ |	|	|	|
 * | | | | Name Hash : 4 bytes, fnv1a_u32		|	|	|	|
 * | | | | Type : 1 byte, u8				|	|	|	|
 * | | | | Value : riot_bin_node<Type>			|	|	|	|
 * | -------------------------------------------------------------------------- |
 * | Patch Entries : v3+, only if PTCH Header present				|
 * | | ================================================================	|	|
 * | | Count : 4 bytes, u32						|	|
 * | | Entries[Count]							|	|
 * | | | ======================================================	|	|	|
 * | | | Name Hash : 4 bytes, fnv1a_u32				|	|	|
 * | | | Length : 4 bytes, u32					|	|	|
 * | | | Type : 1 byte, u8					|	|	|
 * | | | String : riot_bin_str					|	|	|
 * | | | Value : riot_bin_node<Type>				|	|	|
 * | -------------------------------------------------------------------------- |
 *
 * riot_bin_str:
 * | -------------------------------------------------------------------------- |
 * | Size : 2 bytes, u16							|
 * | Chars : chr8[Size]								|
 * | --------------------------------------------------------------------------	|
 *
 * riot_bin_node Tagged Union:
 * primitives:
 *   b8, u8, s8, u16, s16, u32, s32, u64, s64, f32, fvec2, fvec3, fvec4,
 *   fmat4x4, rgba, fnv1a_u32, xxh64_u64, riot_bin_str, flag_b8
 * pseudo-containers:
 *   ptr, embed:
 *   | ------------------------------------------------------------------------	|
 *   | Name Hash : 4 bytes, fnv1a_u32						|
 *   | Size : 4 bytes, u32							|
 *   | Count : 2 bytes, u16							|
 *   | Items : riot_bin_field[Count]						|
 *   | | ==============================================================	|	|
 *   | | Name Hash : 4 bytes, fnv1a_u32					|	|
 *   | | Type : 1 byte, u8						|	|
 *   | | Value : riot_bin_node<Type>					|	|
 *   | ------------------------------------------------------------------------	|
 * containers:
 *   option:
 *   | ------------------------------------------------------------------------	|
 *   | Type : 1 byte, u8							|
 *   | Count : 1 byte, u8							|
 *   | Value : riot_bin_node<Type>, optional (present only if Count == 1)	|
 *   | ------------------------------------------------------------------------	|
 *   list, list2:
 *   | ------------------------------------------------------------------------	|
 *   | Type : 1 byte, u8							|
 *   | Size : 4 bytes, u32							|
 *   | Count : 4 bytes, u32							|
 *   | Items : riot_bin_node<Type>[Count]					|
 *   | ------------------------------------------------------------------------	|
 *   map:
 *   | ------------------------------------------------------------------------	|
 *   | Key Type : 1 byte, u8							|
 *   | Val Type : 1 byte, u8							|
 *   | Size : 4 bytes, u32							|
 *   | Count : 4 bytes, u32							|
 *   | Items : riot_bin_pair[Count]						|
 *   | | ==============================================================	|	|
 *   | | Key : riot_bin_node<Key Type>					|	|
 *   | | Val : riot_bin_node<Val Type>					|	|
 *   | ------------------------------------------------------------------------	|
 */

enum riot_io_error
riot_bin_try_size(struct mem_t buf, struct riot_bin_alloc_info *out);

enum riot_io_error
riot_bin_try_read(struct mem_t buf, struct riot_bin *out);

enum riot_io_error
riot_bin_try_write(struct riot_bin const *src, struct mem_t *out);

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* LIBRIOT_IO_H */
