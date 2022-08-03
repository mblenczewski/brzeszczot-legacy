#include "libriot/io.h"

enum riot_json_reader_error
riot_json_try_read(struct str_t src, struct riot_bin *out) {
	assert(src.str);
	assert(out);

	return RIOT_JSON_READER_ERROR_OK;
}
