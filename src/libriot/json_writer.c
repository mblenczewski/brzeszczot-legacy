#include "libriot/io.h"

enum riot_json_writer_error
riot_json_try_write(struct riot_bin const *src, struct str_t *out) {
	assert(src);
	assert(out);

	return RIOT_JSON_WRITER_ERROR_OK;
}
