#ifndef LIBRIOT_IO_H
#define LIBRIOT_IO_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "libriot.h"

enum riot_bin_reader_error {
	RIOT_BIN_READER_ERROR_REMAINING_INPUT = -3,
	RIOT_BIN_READER_ERROR_TRUNCATED_INPUT = -2,
	RIOT_BIN_READER_ERROR_BAD_MAGIC = -1,
	RIOT_BIN_READER_ERROR_OK = 0,
	RIOT_BIN_READER_ERROR_MALLOC = 1,
};

enum riot_bin_writer_error {
	RIOT_BIN_WRITER_ERROR_OK,
};

enum riot_json_reader_error {
	RIOT_JSON_READER_ERROR_OK,
};

enum riot_json_writer_error {
	RIOT_JSON_WRITER_ERROR_OK,
};

static inline b32
riot_bin_read_stream(struct mem_t stream, size_t *cur, void *buf, size_t len) {
	assert(stream.ptr);
	assert(cur);
	assert(buf);

	if (stream.len - *cur < len) return false;

	memcpy(buf, stream.ptr + *cur, len);

	*cur += len;

	return true;
}

enum riot_bin_reader_error
riot_bin_try_read(struct mem_t buf, struct riot_bin *out);
enum riot_bin_writer_error
riot_bin_try_write(struct riot_bin const *src, struct mem_t *out);

enum riot_json_reader_error
riot_json_try_read(struct str_t buf, struct riot_bin *out);
enum riot_json_writer_error
riot_json_try_write(struct riot_bin const *src, struct str_t *out);

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* LIBRIOT_IO_H */
