#include "libriot/io.h"

enum riot_bin_writer_error
riot_bin_try_write(struct riot_bin const *src, struct mem_t *out) {
	assert(src);
	assert(out);

	return RIOT_BIN_WRITER_ERROR_OK;
}
