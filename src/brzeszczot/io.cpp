#include "brzeszczot/io.hpp"

static size_t
read_bin_file(char const *filepath, u8 **out) {
	assert(filepath);
	assert(out);

	FILE *f = fopen(filepath, "rb");
	if (!f) return 0;

	u8 *buf = NULL;
	size_t len = 0, total_read = 0, curr_read = 0;
	fseek(f, 0, SEEK_END);
	if (!(len = ftell(f))) goto failure;
	fseek(f, 0, SEEK_SET);

	buf = (u8*)malloc(len * sizeof(u8));
	if (!buf) goto failure;

	do {
		total_read += (curr_read = fread(buf + total_read, sizeof(u8), len - total_read, f));
	} while (curr_read && total_read < len);

	*out = buf;

	fclose(f);

	return len;

failure:
	fclose(f);

	return 0;
}

static size_t
write_bin_file(char const *filepath, u8 *buf, size_t len) {
	assert(filepath);
	assert(buf);

	FILE *f = fopen(filepath, "wb");
	if (!f) return 0;

	size_t total_written = 0, curr_written = 0;
	do {
		total_written += (curr_written = fwrite(buf + total_written, sizeof(u8), len - total_written, f));
	} while (curr_written && total_written < len);

	fclose(f);

	return total_written;
}

bool
brzeszczot::try_read_bin_file(char const *filepath, struct riot_bin *out) {
	assert(filepath);
	assert(out);

	u8 *buf;
	size_t len;
	if (!(len = read_bin_file(filepath, &buf))) {
		errlog("Failed to read in file '%s' in binary mode\n", filepath);
		return false;
	}

	struct mem_t src = {
		.ptr = buf,
		.len = len,
	};

	enum riot_io_error result = riot_bin_try_read(src, out);
	if (result)
		errlog("Failed to parse bin file due to '%s'\n", riot_io_error_str(result));

	free(buf);

	return result == RIOT_IO_ERROR_OK;
}

bool
brzeszczot::try_write_bin_file(char const *filepath, struct riot_bin *out) {
	assert(filepath);
	assert(out);

	return false;
}
