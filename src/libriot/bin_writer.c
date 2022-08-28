#include "libriot/io.h"

enum riot_io_error
riot_bin_try_write(struct riot_bin const *src, struct mem_t *out) {
	assert(src);
	assert(out);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	struct mem_t buf = {0};

	*out = buf;

failure:
	return err;
}
