#include "libriot/io.h"

static struct str_t _patch_magic = STR_FROM_CSTR_LIT("PTCH");
static struct str_t _prop_magic = STR_FROM_CSTR_LIT("PROP");

static enum riot_bin_reader_error
riot_bin_try_read_linked_list();

static enum riot_bin_reader_error
riot_bin_try_read_entries();

static enum riot_bin_reader_error
riot_bin_try_read_patches();

enum riot_bin_reader_error
riot_bin_try_read(struct mem_t buf, struct riot_bin *out) {
	assert(buf.ptr);
	assert(out);

	enum riot_bin_reader_error err = RIOT_BIN_READER_ERROR_OK;

	u8 magic[4];
	struct riot_bin_node *node = NULL;
	struct str_t key;

	size_t cur = 0;

	if (!riot_bin_read_stream(buf, &cur, magic, _patch_magic.len))
		return RIOT_BIN_READER_ERROR_BAD_MAGIC;

	/* if our first magic identifier is that of a patch, we need to skip
	 * the next 8 bytes and try again (at which point we should see the
	 * prop magic identifier
	 */
	if (memcmp(magic, _patch_magic.str, _patch_magic.len) == 0) {
		cur += 8;

		key.str = "type";
		key.len = strlen(key.str);

		node = malloc(sizeof(struct riot_bin_node));
		if (!node) return RIOT_BIN_READER_ERROR_MALLOC;
		node->type = RIOT_BIN_NODE_TYPE_STR;
		memcpy(&node->node_string, &_patch_magic, sizeof(_patch_magic));

		assert(map_str_to_riot_bin_node_try_update(&out->sections, &key, node, NULL));

		if (!riot_bin_read_stream(buf, &cur, magic, _prop_magic.len))
			return RIOT_BIN_READER_ERROR_BAD_MAGIC;
	}

	/* if we don't successfully read the prop magic identifier then we have
	 * a corrupted bin file
	 */
	if (!memcmp(magic, _prop_magic.str, _prop_magic.len) == 0)
		return RIOT_BIN_READER_ERROR_BAD_MAGIC;

	key.str = "type";
	key.len = strlen(key.str);

	node = malloc(sizeof(struct riot_bin_node));
	if (!node) return RIOT_BIN_READER_ERROR_MALLOC;
	node->type = RIOT_BIN_NODE_TYPE_STR;
	memcpy(&node->node_string, &_prop_magic, sizeof(_prop_magic));

	assert(map_str_to_riot_bin_node_try_update(&out->sections, &key, node, NULL));

	u32 version;
	if (!riot_bin_read_stream(buf, &cur, &version, sizeof(version)))
		return RIOT_BIN_READER_ERROR_TRUNCATED_INPUT;

	key.str = "version";
	key.len = strlen(key.str);

	node = malloc(sizeof(struct riot_bin_node));
	if (!node) return RIOT_BIN_READER_ERROR_MALLOC;
	node->type = RIOT_BIN_NODE_TYPE_U32;
	node->node_u32 = version;

	assert(map_str_to_riot_bin_node_try_update(&out->sections, &key, node, NULL));

	if (version >= 2)
		if (!(err = riot_bin_try_read_linked_list())) return err;

	if (!(err = riot_bin_try_read_entries())) return err;

	if (version >= 3)
		if (!(err = riot_bin_try_read_patches())) return err;

	/* if there is any remaining input then we have mis-handled the input
	 * or we have corrupted input
	 */
	if (cur != buf.len) return RIOT_BIN_READER_ERROR_REMAINING_INPUT;

	return RIOT_BIN_READER_ERROR_OK;
}

static enum riot_bin_reader_error
riot_bin_try_read_linked_list() {
	return RIOT_BIN_READER_ERROR_OK;
}

static enum riot_bin_reader_error
riot_bin_try_read_entries() {
	return RIOT_BIN_READER_ERROR_OK;
}

static enum riot_bin_reader_error
riot_bin_try_read_patches() {
	return RIOT_BIN_READER_ERROR_OK;
}
