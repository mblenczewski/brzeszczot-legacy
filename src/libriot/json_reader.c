#include "libriot/io.h"

enum riot_io_error
riot_json_try_read(struct str_t src, struct riot_bin *out) {
	assert(src.str);
	assert(out);

	return RIOT_IO_ERROR_OK;
}
