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

extern char const *RIOT_IO_ERROR_NAME_MAP[_RIOT_IO_ERROR_COUNT];

#define STREAM_ERRLOG(stream) dbglog("@%zu/%zu: ", (stream).cur, (stream).buf.len);

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
 * Magic (PTCH or PROP) (4 bytes)
 * ---
 * Linked List Entries
 * ---
 * Prop Entries
 * ---
 * Patch Entries
 */

enum riot_io_error
riot_bin_try_read(struct mem_t buf, struct riot_bin *out);

enum riot_io_error
riot_bin_try_write(struct riot_bin const *src, struct mem_t *out);

/* ===========================================================================
 * ritobin JSON Format
 * ===========================================================================
 */

enum riot_io_error
riot_json_try_read(struct str_t buf, struct riot_bin *out);

enum riot_io_error
riot_json_try_write(struct riot_bin const *src, struct str_t *out);

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* LIBRIOT_IO_H */
