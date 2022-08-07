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
};

static inline enum riot_io_error
riot_bin_stream_try_skip(struct stream_t *stream, size_t len) {
	assert(stream);

	if (stream->buf.len - stream->cur < len) return RIOT_IO_ERROR_EOF;

	stream->cur += len;

	return RIOT_IO_ERROR_OK;
}

static inline enum riot_io_error
riot_bin_stream_try_read(struct stream_t *stream, void *buf, size_t len) {
	assert(stream);
	assert(buf);

	if (stream->buf.len - stream->cur < len) return RIOT_IO_ERROR_EOF;

	memcpy(buf, stream->buf.ptr + stream->cur, len);
	stream->cur += len;

	return RIOT_IO_ERROR_OK;
}

enum riot_io_error
riot_bin_try_read(struct mem_t buf, struct riot_bin *out);

enum riot_io_error
riot_bin_try_write(struct riot_bin const *src, struct mem_t *out);

enum riot_io_error
riot_json_try_read(struct str_t buf, struct riot_bin *out);

enum riot_io_error
riot_json_try_write(struct riot_bin const *src, struct str_t *out);

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* LIBRIOT_IO_H */
