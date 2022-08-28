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

	struct mem_t buf;
	if (!(buf.len = read_bin_file(filepath, &buf.ptr))) {
		errlog("Failed to read in file '%s' in binary mode\n", filepath);
		return false;
	}

	enum riot_io_error result = riot_bin_try_read(buf, out);
	if (result) {
		errlog("Failed to parse bin file due to '%s'\n", riot_io_error_str(result));
	}

	free(buf.ptr);

	return result == RIOT_IO_ERROR_OK;
}

bool
brzeszczot::try_write_bin_file(char const *filepath, struct riot_bin *bin) {
	assert(filepath);
	assert(bin);

	struct mem_t buf;
	enum riot_io_error result = riot_bin_try_write(bin, &buf);
	if (result != RIOT_IO_ERROR_OK) {
		errlog("Failed to serialise bin file due to '%s'\n", riot_io_error_str(result));
		return false;
	}

	size_t written = write_bin_file(filepath, buf.ptr, buf.len);
	if (written != buf.len) {
		errlog("Failed to write serialised bin file to '%s' (%zu bytes out of %zu)\n", filepath, written, buf.len);
	}

	free(buf.ptr);

	return written == buf.len;
}
