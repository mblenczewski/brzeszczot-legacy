#include "brzeszczot/io.hpp"

static size_t
read_bin_file(char const *filepath, u8 **out) {
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

static bool
try_read_file_bin(char const *filepath, struct riot_bin *out) {
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

	bool result = riot_bin_try_read(src, out) == RIOT_IO_ERROR_OK;

	free(buf);

	return result;
}

static bool
try_read_file_json(char const *filepath, struct riot_bin *out) {
	assert(filepath);
	assert(out);

	assert(sizeof(char) == sizeof(u8));

	u8 *buf;
	size_t len;
	if (!(len = read_bin_file(filepath, &buf))) {
		errlog("Failed to read in file '%s' in json mode\n", filepath);
		return false;
	}

	char *str = (char*)realloc(buf, (len + 1) * sizeof(char));
	if (!str) { free(buf); return false; }
	str[len] = '\0';

	struct str_t src = {
		.str = str,
		.len = len,
	};

	bool result = riot_json_try_read(src, out) == RIOT_IO_ERROR_OK;

	free(str);

	return result;
}

bool brzeszczot::try_read_file(char const *filepath, struct riot_bin *out) {
	assert(out);

	char const *extension = strrchr(filepath, '.');
	if (strcmp(extension, ".bin") == 0) {
		dbglog("Attempting to parse file '%s' in binary mode\n", filepath);
		return try_read_file_bin(filepath, out);
	} else if (strcmp(extension, ".json") == 0) {
		dbglog("Attempting to parse file '%s' in json mode\n", filepath);
		return try_read_file_json(filepath, out);
	} else {
		// TODO: use magic value to pick the correct reader to read
		// the inibin file

		errlog("Failed to recognise the extension: '%s', and magic number not recognised\n", extension);
	}

	return false;
}
