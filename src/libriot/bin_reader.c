#include "libriot/io.h"

#define READER_ASSERT(cond, errno, cleanup, ...)				\
if (!(cond)) {									\
	STREAM_ERRLOG(*stream);							\
	errlog("%s: ", riot_io_error_str(errno));				\
	errlog(__VA_ARGS__);							\
	errlog("\n");								\
	err = errno;								\
	goto cleanup;								\
}

static enum riot_io_error
riot_bin_stream_try_size_node(struct stream_t *stream, enum riot_bin_node_type type, struct riot_bin_alloc_info *alloc_info);

static enum riot_io_error
riot_bin_try_size_linked_files(struct stream_t *stream, struct riot_bin_alloc_info *alloc_info);

static enum riot_io_error
riot_bin_try_size_entries(struct stream_t *stream, struct riot_bin_alloc_info *alloc_info);

static enum riot_io_error
riot_bin_try_size_patches(struct stream_t *stream, struct riot_bin_alloc_info *alloc_info);

enum riot_io_error
riot_bin_try_size(struct mem_t buf, struct riot_bin_alloc_info *out) {
	assert(buf.ptr);
	assert(out);

	struct stream_t _stream = {
		.buf = buf,
		.cur = 0,
	}, *stream = &_stream;

	struct str_t patch_magic = STR_FROM_CSTR("PTCH");
	struct str_t prop_magic = STR_FROM_CSTR("PROP");

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	u8 magic[4] = {0};
	b32 has_patches = false;

	struct riot_bin_alloc_info alloc_info = {
		.nodes_count = 0,
		.fields_count = 0,
		.pairs_count = 0,
	};

	err = riot_bin_stream_try_read(stream, magic, patch_magic.len);
	READER_ASSERT(!err, err, failure, "Failed to read magic value!")

	/* if we read the patch magic, then we need to skip ahead 8 bytes to
	 * skip past the unknown 8 bytes remaining in the patch header and
	 * re-read the magic (as we expect the PROP magic identifier)
	 */ 
	if (memcmp(magic, patch_magic.str, patch_magic.len) == 0) {
		has_patches = true;

		err = riot_bin_stream_try_skip(stream, 8);
		READER_ASSERT(!err, err, failure, "Failed to skip past patch header!")

		err = riot_bin_stream_try_read(stream, magic, prop_magic.len);
		READER_ASSERT(!err, err, failure, "Failed to read magic value!")
	}

	/* if we don't successfully read the patch magic identifier or
	 * the prop magic identifier then we have a corrupted bin file
	 */
	if (memcmp(magic, prop_magic.str, prop_magic.len) != 0) {
		READER_ASSERT(false, RIOT_IO_ERROR_CORRUPT, failure, "Invalid magic value read!");
	}

	u32 version = 0;
	err = riot_bin_stream_try_read(stream, &version, sizeof(version));
	READER_ASSERT(!err, err, failure, "Failed to read version identifier!")

	if (version >= 2) {
		err = riot_bin_try_size_linked_files(stream, &alloc_info);
		READER_ASSERT(!err, err, failure, "Failed to size linked files!")
	}

	err = riot_bin_try_size_entries(stream, &alloc_info);
	READER_ASSERT(!err, err, failure, "Failed to size prop entries!")

	if (version >= 3 && has_patches) {
		err = riot_bin_try_size_patches(stream, &alloc_info);
		READER_ASSERT(!err, err, failure, "Failed to size patch entries!");
	}

	READER_ASSERT(!riot_bin_stream_has_input(stream), RIOT_IO_ERROR_CORRUPT, failure, "Stream input remaining!")

	*out = alloc_info;

failure:
	return err;
}

static inline enum riot_io_error
riot_bin_try_size_linked_files(struct stream_t *stream, struct riot_bin_alloc_info *alloc_info) {
	assert(stream);
	assert(alloc_info);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	u32 count = 0;
	err = riot_bin_stream_try_read(stream, &count, sizeof(count));
	READER_ASSERT(!err, err, failure, "Failed to read number of linked files!")

	if (!count) return err;

	for (u32 i = 0; i < count; i++) {
		err = riot_bin_stream_try_size_node(stream, RIOT_BIN_NODE_TYPE_STR, alloc_info);
		READER_ASSERT(!err, err, failure, "Failed to size linked files %u!", i)
	}

failure:
	return err;
}

static enum riot_io_error
riot_bin_try_size_entry(struct stream_t *stream, struct riot_bin_alloc_info *alloc_info) {
	assert(stream);
	assert(alloc_info);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	u32 size = 0;
	err = riot_bin_stream_try_read(stream, &size, sizeof(size));
	READER_ASSERT(!err, err, failure, "Failed to read total size of prop entry embed!")

	size_t prev_cur = stream->cur;

	err = riot_bin_stream_try_skip(stream, sizeof(hashes_fnv1a_val_t));
	READER_ASSERT(!err, err, failure, "Failed to skip prop entry embed name hash!")

	u16 count = 0; 
	err = riot_bin_stream_try_read(stream, &count, sizeof(count));
	READER_ASSERT(!err, err, failure, "Failed to read count of prop entry embed fields!")

	for (u16 i = 0; i < count; i++) {
		err = riot_bin_stream_try_skip(stream, sizeof(hashes_fnv1a_val_t));
		READER_ASSERT(!err, err, failure, "Failed to skip prop entry embed's field %u name hash!", i)

		u8 raw_type;
		err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type));
		READER_ASSERT(!err, err, failure, "Failed to read prop entry embed's field %u type!", i)

		enum riot_bin_node_type type = riot_bin_raw_type_to_node_type(raw_type);
		err = riot_bin_stream_try_size_node(stream, type, alloc_info);
		READER_ASSERT(!err, err, failure, "Failed to size prop entry embed's field %u value!", i)
	}

	READER_ASSERT(stream->cur - prev_cur == size, RIOT_IO_ERROR_CORRUPT, failure,
			"Prop entry embed parsing failed (%zu bytes read, %u bytes expected)!", stream->cur - prev_cur, size)

	alloc_info->fields_count += count;

failure:
	return err;
}

static inline enum riot_io_error
riot_bin_try_size_entries(struct stream_t *stream, struct riot_bin_alloc_info *alloc_info) {
	assert(stream);
	assert(alloc_info);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	u32 count = 0;
	err = riot_bin_stream_try_read(stream, &count, sizeof(count));
	READER_ASSERT(!err, err, failure, "Failed to read number of prop entries!")

	if (!count) return err;

	err = riot_bin_stream_try_skip(stream, count * sizeof(hashes_fnv1a_val_t));
	READER_ASSERT(!err, err, failure, "Failed to skip over prop entry name hashes!")

	for (u32 i = 0; i < count; i++) {
		err = riot_bin_try_size_entry(stream, alloc_info);
		READER_ASSERT(!err, err, failure, "Failed to size embed entry %u!", i)
	}

	alloc_info->pairs_count += count;

failure:
	return err;
}

static enum riot_io_error
riot_bin_try_size_patch(struct stream_t *stream, struct riot_bin_alloc_info *alloc_info) {
	assert(stream);
	assert(alloc_info);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	err = riot_bin_stream_try_skip(stream, sizeof(hashes_fnv1a_val_t));
	READER_ASSERT(!err, err, failure, "Failed to skip patch entry embed name hash!")

	u32 size = 0;
	err = riot_bin_stream_try_read(stream, &size, sizeof(size));
	READER_ASSERT(!err, err, failure, "Failed to read total size of patch entry embed!")

	size_t prev_cur = stream->cur;

	u8 raw_type;
	err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type));
	READER_ASSERT(!err, err, failure, "Failed to read raw type of patch entry embed value!");

	enum riot_bin_node_type type = riot_bin_raw_type_to_node_type(raw_type);

	err = riot_bin_stream_try_size_node(stream, RIOT_BIN_NODE_TYPE_STR, alloc_info);
	READER_ASSERT(!err, err, failure, "Failed to size patch entry embed path!")

	err = riot_bin_stream_try_size_node(stream, type, alloc_info);
	READER_ASSERT(!err, err, failure, "Failed to size patch entry embed value!")

	READER_ASSERT(stream->cur - prev_cur == size, RIOT_IO_ERROR_ALLOC, failure,
			"Patch entry embed parsing failed (%zu bytes read, %u bytes expected)!", stream->cur - prev_cur, size)

	alloc_info->fields_count += 2;

failure:
	return err;
}

static inline enum riot_io_error
riot_bin_try_size_patches(struct stream_t *stream, struct riot_bin_alloc_info *alloc_info) {
	assert(stream);
	assert(alloc_info);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	u32 count = 0;
	err = riot_bin_stream_try_read(stream, &count, sizeof(count));
	READER_ASSERT(!err, err, failure, "Failed to read number of patches!")

	if (!count) return err;

	for (u32 i = 0; i < count; i++) {
		err = riot_bin_try_size_patch(stream, alloc_info);
		READER_ASSERT(!err, err, failure, "Failed to size patch %u!", i)
	}

	alloc_info->pairs_count += count;

failure:
	return err;
}

static inline b32
riot_bin_try_add_section(struct riot_bin *bin, struct str_t *key, struct riot_bin_node *val) {
	assert(bin);
	assert(key);
	assert(val);

	enum hashmap_result result = HASHMAP_RESULT_OK;

	result = map_str_to_riot_bin_node_try_update(&bin->sections, key, val, NULL);
	if (result) return false;

	if (bin->sections.load > 0.5) {
		result = map_str_to_riot_bin_node_try_realloc(&bin->sections, bin->sections.cap * 2);
		if (result) return false;
	}

	return true;
}

static enum riot_io_error
riot_bin_stream_try_read_node(struct stream_t *stream, enum riot_bin_node_type type, struct riot_bin_node *out, struct riot_bin_mem_pool *pool);

static enum riot_io_error
riot_bin_try_read_linked_files(struct stream_t *stream, struct riot_bin *out);

static enum riot_io_error
riot_bin_try_read_entries(struct stream_t *stream, struct riot_bin *out);

static enum riot_io_error
riot_bin_try_read_patches(struct stream_t *stream, struct riot_bin *out);

enum riot_io_error
riot_bin_try_read(struct mem_t buf, struct riot_bin *out) {
	assert(buf.ptr);
	assert(out);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	struct riot_bin bin = {0};
	if (!map_str_to_riot_bin_node_try_alloc(&bin.sections, 8)) {
		errlog("Failed to allocate riot bin hashmap\n");
		return 1;
	}

	struct str_t key;
	struct str_t patch_magic = STR_FROM_CSTR("PTCH");
	struct str_t prop_magic = STR_FROM_CSTR("PROP");
	struct riot_bin_node node;

	struct stream_t _stream = {
		.buf = buf,
		.cur = 0,
	}, *stream = &_stream;

	/* calculate the allocation requirements in terms of number of nodes,
	 * fields, and pairs so that all required memory can be allocated
	 * ahead of time in 3 separate blocks. this means that all memory can
	 * be easily deallocated when it is finished with and the parser does
	 * not have to worry about allocation potentially failing halfway
	 * through and having to step back and undo all previous allocations
	 */
	err = riot_bin_try_size(buf, &bin.mem_pool.alloc_info);
	READER_ASSERT(!err, err, failure, "Failed to calculate allocation requirements for bin repr!")

	assert(bin.mem_pool.alloc_info.nodes_count);
	assert(bin.mem_pool.alloc_info.fields_count);
	assert(bin.mem_pool.alloc_info.pairs_count);

	dbglog("Arena-allocated Nodes: %zu\n", bin.mem_pool.alloc_info.nodes_count);
	dbglog("Arena-allocated Fields: %zu\n", bin.mem_pool.alloc_info.fields_count);
	dbglog("Arena-allocated Pairs: %zu\n", bin.mem_pool.alloc_info.pairs_count);

	bin.mem_pool.nodes = malloc(bin.mem_pool.alloc_info.nodes_count * sizeof(struct riot_bin_node));
	READER_ASSERT(bin.mem_pool.nodes, RIOT_IO_ERROR_ALLOC, failure, "Failed to allocate nodes for bin repr!")

	bin.mem_pool.fields = malloc(bin.mem_pool.alloc_info.fields_count * sizeof(struct riot_bin_field));
	READER_ASSERT(bin.mem_pool.fields, RIOT_IO_ERROR_ALLOC, failure, "Failed to allocate fields for bin repr!")

	bin.mem_pool.pairs = malloc(bin.mem_pool.alloc_info.pairs_count * sizeof(struct riot_bin_pair));
	READER_ASSERT(bin.mem_pool.pairs, RIOT_IO_ERROR_ALLOC, failure, "Failed to allocate pairs for bin repr!")
	
	bin.mem_pool.nodes_head = bin.mem_pool.nodes;
	bin.mem_pool.fields_head = bin.mem_pool.fields;
	bin.mem_pool.pairs_head = bin.mem_pool.pairs;

	/* the initial header of the inibin file depends on a magic identifier.
	 * if this identifier is equal to PTCH, then an 8-byte unknown field is
	 * present and the inibin contains a trailing list of patches which
	 * must be read. after reading the PTCH header (or if it was not
	 * present) the PROP magic identifier must be present, otherwise the
	 * file is in an unknown format or corrupted
	 */
	u8 magic[4] = {0};
	b32 has_patches = false;

	key.str = "type";
	key.len = strlen(key.str);

	node.type = RIOT_BIN_NODE_TYPE_STR;

	err = riot_bin_stream_try_read(stream, magic, patch_magic.len);
	READER_ASSERT(!err, err, failure, "Failed to read magic value!")

	if (memcmp(magic, patch_magic.str, patch_magic.len) == 0) {
		dbglog("Read PTCH magic (have patch header and trailer)\n");

		node.node_str.ptr = patch_magic.str;
		node.node_str.len = patch_magic.len;

		READER_ASSERT(riot_bin_try_add_section(&bin, &key, &node), RIOT_IO_ERROR_ALLOC, failure, "Failed to add %s section to bin repr!", key.str)
		has_patches = true;

		u64 unknown = 0;
		err = riot_bin_stream_try_read(stream, &unknown, sizeof(unknown));
		READER_ASSERT(!err, err, failure, "Failed to read unknown bytes!")

		dbglog("Unknown bytes: %llu\n", unknown);

		err = riot_bin_stream_try_read(stream, magic, prop_magic.len);
		READER_ASSERT(!err, err, failure, "Failed to read magic value!")
	}

	/* if we do not have the PROP magic identifier, our file is corrupt
	 * or has an unknown format
	 */
	if (memcmp(magic, prop_magic.str, prop_magic.len) != 0) {
		/* if we don't successfully read the patch magic identifier or
		 * the prop magic identifier then we have a corrupted bin file
		 */
		READER_ASSERT(false, RIOT_IO_ERROR_CORRUPT, failure, "Invalid magic value read!");
	}

	node.node_str.ptr = prop_magic.str;
	node.node_str.len = prop_magic.len;

	READER_ASSERT(riot_bin_try_add_section(&bin, &key, &node), RIOT_IO_ERROR_ALLOC, failure, "Failed to add %s section to bin repr!", key.str)

	/* we need to parse the version identifier of the current file so that
	 * we can correctly parse out the included sections
	 */
	u32 version = 0;
	err = riot_bin_stream_try_read(stream, &version, sizeof(version));
	READER_ASSERT(!err, err, failure, "Failed to read INIBIN version!")

	dbglog("INIBIN version: %u\n", version);
	assert(version > 0);

	key.str = "version";
	key.len = strlen(key.str);

	node.type = RIOT_BIN_NODE_TYPE_U32;
	node.node_u32 = version;

	READER_ASSERT(riot_bin_try_add_section(&bin, &key, &node), RIOT_IO_ERROR_ALLOC, failure, "Failed to add %s section to bin repr!", key.str)

	if (version >= 2) {
		err = riot_bin_try_read_linked_files(stream, &bin);
		READER_ASSERT(!err, err, failure, "Failed to read linked files!")
	}

	err = riot_bin_try_read_entries(stream, &bin);
	READER_ASSERT(!err, err, failure, "Failed to read prop entries!")

	if (version >= 3 && has_patches) {
		err = riot_bin_try_read_patches(stream, &bin);
		READER_ASSERT(!err, err, failure, "Failed to read patch entries!");
	}

	READER_ASSERT(!riot_bin_stream_has_input(stream), RIOT_IO_ERROR_CORRUPT, failure, "Stream input remaining!")

	*out = bin;

	return err;

failure:
	riot_bin_free(&bin);

	return err;
}

static enum riot_io_error
riot_bin_try_read_linked_files(struct stream_t *stream, struct riot_bin *bin) {
	assert(stream);
	assert(bin);

	dbglog("Reading linked files\n");

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	struct str_t key = STR_FROM_CSTR("linked");
	struct riot_bin_node list = {
		.type = RIOT_BIN_NODE_TYPE_LIST,
		.node_list = {
			.type = RIOT_BIN_NODE_TYPE_STR,
		},
	};

	err = riot_bin_stream_try_read(stream, &list.node_list.count, sizeof(list.node_list.count));
	READER_ASSERT(!err, err, failure, "Failed to read number of linked files!")

	dbglog("Linked files: %u\n", list.node_list.count);

	if (!list.node_list.count)
		goto success;

	list.node_list.items = bin->mem_pool.nodes_head;
	bin->mem_pool.nodes_head += list.node_list.count;

	for (u32 i = 0; i < list.node_list.count; i++) {
		struct riot_bin_node *elem = &list.node_list.items[i];

		err = riot_bin_stream_try_read_node(stream, RIOT_BIN_NODE_TYPE_STR, elem, &bin->mem_pool);
		READER_ASSERT(!err, err, failure, "Failed to read linked files %u!", i)
	}

success:
	READER_ASSERT(riot_bin_try_add_section(bin, &key, &list), RIOT_IO_ERROR_ALLOC, failure, "Failed to add %s section to bin repr!", key.str)

failure:
	return err;
}

static enum riot_io_error
riot_bin_try_read_entry(struct stream_t *stream, hashes_fnv1a_val_t *name_hash, struct riot_bin_field_list *embed, struct riot_bin_mem_pool *pool) {
	assert(stream);
	assert(name_hash);
	assert(embed);
	assert(pool);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	u32 size = 0;
	err = riot_bin_stream_try_read(stream, &size, sizeof(size));
	READER_ASSERT(!err, err, failure, "Failed to read total size of prop entry embed!")

	size_t prev_cur = stream->cur;

	err = riot_bin_stream_try_read(stream, name_hash, sizeof(*name_hash));
	READER_ASSERT(!err, err, failure, "Failed to read prop entry embed name hash!")

	err = riot_bin_stream_try_read(stream, &embed->count, sizeof(embed->count));
	READER_ASSERT(!err, err, failure, "Failed to read count of prop entry embed fields!")

	embed->items = pool->fields_head;
	pool->fields_head += embed->count;

	for (u16 i = 0; i < embed->count; i++) {
		struct riot_bin_field *elem = &embed->items[i];

		err = riot_bin_stream_try_read(stream, &elem->name_hash, sizeof(elem->name_hash));
		READER_ASSERT(!err, err, failure, "Failed to read prop entry embed's field %u name hash!", i)

		u8 raw_type;
		err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type));
		READER_ASSERT(!err, err, failure, "Failed to read prop entry embed's field %u type!", i)

		enum riot_bin_node_type type = riot_bin_raw_type_to_node_type(raw_type);
		err = riot_bin_stream_try_read_node(stream, type, &elem->val, pool);
		READER_ASSERT(!err, err, failure, "Failed to read prop entry embed's field %u value!", i)
	}

	READER_ASSERT(stream->cur - prev_cur == size, RIOT_IO_ERROR_CORRUPT, failure,
			"Prop entry embed parsing failed (%zu bytes read, %u bytes expected)!", stream->cur - prev_cur, size)

failure:
	return err;
}

static enum riot_io_error
riot_bin_try_read_entries(struct stream_t *stream, struct riot_bin *bin) {
	assert(stream);
	assert(bin);

	dbglog("Reading prop entries\n");

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	struct str_t key = STR_FROM_CSTR("entries");
	struct riot_bin_node map = {
		.type = RIOT_BIN_NODE_TYPE_MAP,
		.node_map = {
			.key_type = RIOT_BIN_NODE_TYPE_HASH,
			.val_type = RIOT_BIN_NODE_TYPE_EMBED,
		},
	};

	err = riot_bin_stream_try_read(stream, &map.node_map.count, sizeof(map.node_map.count));
	READER_ASSERT(!err, err, failure, "Failed to read number of prop entries!")

	dbglog("Prop entries: %u\n", map.node_map.count);

	if (!map.node_map.count) goto success;

	hashes_fnv1a_val_t *entry_name_hashes = (hashes_fnv1a_val_t*)&stream->buf.ptr[stream->cur];
	err = riot_bin_stream_try_skip(stream, map.node_map.count * sizeof(hashes_fnv1a_val_t));
	READER_ASSERT(!err, err, failure, "Failed to skip over prop entry name hashes!")

	map.node_map.items = bin->mem_pool.pairs_head;
	bin->mem_pool.pairs_head += map.node_map.count;

	for (u32 i = 0; i < map.node_map.count; i++) {
		hashes_fnv1a_val_t entry_name_hash = entry_name_hashes[i];

		struct riot_bin_pair *elem = &map.node_map.items[i];
		elem->key.type = RIOT_BIN_NODE_TYPE_HASH;
		elem->val.type = RIOT_BIN_NODE_TYPE_EMBED;
		elem->val.node_embed.name_hash = entry_name_hash;

		err = riot_bin_try_read_entry(stream, &elem->key.node_hash, &elem->val.node_embed, &bin->mem_pool);
		READER_ASSERT(!err, err, failure, "Failed to read embed entry %u!", i)
	}

success:
	READER_ASSERT(riot_bin_try_add_section(bin, &key, &map), RIOT_IO_ERROR_ALLOC, failure, "Failed to add %s section to bin repr!", key.str)

failure:
	return err;
}

static enum riot_io_error
riot_bin_try_read_patch(struct stream_t *stream, hashes_fnv1a_val_t *name_hash, struct riot_bin_field_list *embed, struct riot_bin_mem_pool *pool) {
	assert(stream);
	assert(name_hash);
	assert(embed);
	assert(pool);

	hashes_fnv1a_val_t path_name_hash = hashes_fnv1a("path", 4, HASHES_FNV1A_DEFAULT_SEED);
	hashes_fnv1a_val_t value_name_hash = hashes_fnv1a("value", 5, HASHES_FNV1A_DEFAULT_SEED);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	err = riot_bin_stream_try_read(stream, name_hash, sizeof(*name_hash));
	READER_ASSERT(!err, err, failure, "Failed to read patch entry embed name hash!")

	u32 size = 0;
	err = riot_bin_stream_try_read(stream, &size, sizeof(size));
	READER_ASSERT(!err, err, failure, "Failed to read total size of patch entry embed!")

	size_t prev_cur = stream->cur;

	embed->items = pool->fields_head;
	pool->fields_head += 2;

	embed->items[0].name_hash = path_name_hash;
	struct riot_bin_node *path = &embed->items[0].val;

	embed->items[1].name_hash = value_name_hash;
	struct riot_bin_node *value = &embed->items[1].val;

	u8 raw_type;
	err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type));
	READER_ASSERT(!err, err, failure, "Failed to read raw type of patch entry embed value!");

	enum riot_bin_node_type type = riot_bin_raw_type_to_node_type(raw_type);

	err = riot_bin_stream_try_read_node(stream, RIOT_BIN_NODE_TYPE_STR, path, pool);
	READER_ASSERT(!err, err, failure, "Failed to read patch entry embed path!")

	err = riot_bin_stream_try_read_node(stream, type, value, pool);
	READER_ASSERT(!err, err, failure, "Failed to read patch entry embed value!")

	READER_ASSERT(stream->cur - prev_cur == size, RIOT_IO_ERROR_ALLOC, failure,
			"Patch entry embed parsing failed (%zu bytes read, %u bytes expected)!", stream->cur - prev_cur, size)

failure:
	return err;
}

static enum riot_io_error
riot_bin_try_read_patches(struct stream_t *stream, struct riot_bin *bin) {
	assert(stream);
	assert(bin);

	dbglog("Reading prop patches\n");

	hashes_fnv1a_val_t patch_name_hash = hashes_fnv1a("patch", 5, HASHES_FNV1A_DEFAULT_SEED);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	struct str_t key = STR_FROM_CSTR("patches");
	struct riot_bin_node map = {
		.type = RIOT_BIN_NODE_TYPE_MAP,
		.node_map = {
			.key_type = RIOT_BIN_NODE_TYPE_HASH,
			.val_type = RIOT_BIN_NODE_TYPE_EMBED,
		},
	};

	err = riot_bin_stream_try_read(stream, &map.node_map.count, sizeof(map.node_map.count));
	READER_ASSERT(!err, err, failure, "Failed to read number of patches!")

	if (!map.node_map.count) goto success;

	map.node_map.items = bin->mem_pool.pairs_head;
	bin->mem_pool.pairs_head += map.node_map.count;
	
	for (u32 i = 0; i < map.node_map.count; i++) {
		struct riot_bin_pair *elem = &map.node_map.items[i];
		elem->key.type = RIOT_BIN_NODE_TYPE_HASH;
		elem->val.type = RIOT_BIN_NODE_TYPE_EMBED;
		elem->val.node_embed.name_hash = patch_name_hash;

		err = riot_bin_try_read_patch(stream, &elem->key.node_hash, &elem->val.node_embed, &bin->mem_pool);
		READER_ASSERT(!err, err, failure, "Failed to read patch %u!", i)
	}

success:
	READER_ASSERT(riot_bin_try_add_section(bin, &key, &map), RIOT_IO_ERROR_ALLOC, failure, "Failed to add %s section to bin repr!", key.str)

failure:
	return err;
}

/* ===========================================================================
 * Sizing Helpers
 * ===========================================================================
 */
static enum riot_io_error
riot_bin_stream_try_size_str(struct stream_t *stream) {
	assert(stream);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	u16 len = 0;
	err = riot_bin_stream_try_read(stream, &len, sizeof(len));
	READER_ASSERT(!err, err, failure, "Failed to read string length!")
	
	err = riot_bin_stream_try_skip(stream, len);
	READER_ASSERT(!err, err, failure, "Failed to skip string bytes!")
	
failure:
	return err;
}

static enum riot_io_error
riot_bin_stream_try_size_ptr(struct stream_t *stream, struct riot_bin_alloc_info *alloc_info) {
	assert(stream);
	assert(alloc_info);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	hashes_fnv1a_val_t name_hash = 0;
	err = riot_bin_stream_try_read(stream, &name_hash, sizeof(name_hash));
	READER_ASSERT(!err, err, failure, "Failed to read ptr name hash!")

	/* if the hash is empty, we have a null pointer and so we can skip this
	 * node (err == RIOT_IO_ERROR_OK)
	 */
	if (name_hash == 0)
		return err;

	u32 size = 0;
	err = riot_bin_stream_try_read(stream, &size, sizeof(size));
	READER_ASSERT(!err, err, failure, "Failed to read the total size")

	size_t prev_cur = stream->cur;

	u16 count = 0;
	err = riot_bin_stream_try_read(stream, &count, sizeof(count));
	READER_ASSERT(!err, err, failure, "Failed to read number of elements after pointer!")

	for (u16 i = 0; i < count; i++) {
		err = riot_bin_stream_try_skip(stream, sizeof(hashes_fnv1a_val_t));
		READER_ASSERT(!err, err, failure, "Failed to skip ptr element %u name hash!", i)

		u8 raw_type;
		err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type));
		READER_ASSERT(!err, err, failure, "Failed to read ptr element %u type!", i)

		enum riot_bin_node_type type = riot_bin_raw_type_to_node_type(raw_type);
		err = riot_bin_stream_try_size_node(stream, type, alloc_info);
		READER_ASSERT(!err, err, failure, "Failed to size ptr element %u!", i)
	}

	READER_ASSERT(stream->cur - prev_cur == size, RIOT_IO_ERROR_CORRUPT, failure,
			"Ptr parsing failed (%zu bytes read, %u bytes expected)!", stream->cur - prev_cur, size)

	alloc_info->fields_count += count;

failure:
	return err;
}

static enum riot_io_error
riot_bin_stream_try_size_embed(struct stream_t *stream, struct riot_bin_alloc_info *alloc_info) {
	assert(stream);
	assert(alloc_info);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	err = riot_bin_stream_try_skip(stream, sizeof(hashes_fnv1a_val_t));
	READER_ASSERT(!err, err, failure, "Failed to skip embed name hash!")

	u32 size = 0;
	err = riot_bin_stream_try_read(stream, &size, sizeof(size));
	READER_ASSERT(!err, err, failure, "Failed to read total size of embed!")

	size_t prev_cur = stream->cur;

	u16 count = 0;
	err = riot_bin_stream_try_read(stream, &count, sizeof(count));
	READER_ASSERT(!err, err, failure, "Failed to read number of elements in embed!")

	for (u16 i = 0; i < count; i++) {
		err = riot_bin_stream_try_skip(stream, sizeof(hashes_fnv1a_val_t));
		READER_ASSERT(!err, err, failure, "Failed to skip embed element %u name hash!", i)

		u8 raw_type;
		err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type));
		READER_ASSERT(!err, err, failure, "Failed to read embed element %u raw type!", i)

		enum riot_bin_node_type type = riot_bin_raw_type_to_node_type(raw_type);
		err = riot_bin_stream_try_size_node(stream, type, alloc_info);
		READER_ASSERT(!err, err, failure, "Failed to size embed element %u!", i)
	}

	READER_ASSERT(stream->cur - prev_cur == size, RIOT_IO_ERROR_CORRUPT, failure,
			"Embed parsing failed (%zu bytes read, %u bytes expected)!", stream->cur - prev_cur, size)

	alloc_info->fields_count += count;

failure:
	return err;
}

static enum riot_io_error
riot_bin_stream_try_size_list(struct stream_t *stream, struct riot_bin_alloc_info *alloc_info) {
	assert(stream);
	assert(alloc_info);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	u8 raw_type = RIOT_BIN_NODE_TYPE_NONE;
	err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type));
	READER_ASSERT(!err, err, failure, "Failed to read list element type!")

	enum riot_bin_node_type type = riot_bin_raw_type_to_node_type(raw_type);
	READER_ASSERT(!riot_bin_node_type_is_container(type), RIOT_IO_ERROR_CORRUPT, failure, "List cannot contain other container types")

	u32 size = 0;
	err = riot_bin_stream_try_read(stream, &size, sizeof(size));
	READER_ASSERT(!err, err, failure, "Failed to read total size of list!")

	size_t prev_cur = stream->cur;

	u32 count = 0;
	err = riot_bin_stream_try_read(stream, &count, sizeof(count));
	READER_ASSERT(!err, err, failure, "Failed to read number of elements in list!")

	for (u32 i = 0; i < count; i++) {
		err = riot_bin_stream_try_size_node(stream, type, alloc_info);
		READER_ASSERT(!err, err, failure, "Failed to read list element %u", i)
	}

	READER_ASSERT(stream->cur - prev_cur == size, RIOT_IO_ERROR_CORRUPT, failure,
			"List parsing failed (%zu bytes read, %u bytes expected)!", stream->cur - prev_cur, size)

failure:
	return err;
}

static enum riot_io_error
riot_bin_stream_try_size_option(struct stream_t *stream, struct riot_bin_alloc_info *alloc_info) {
	assert(stream);
	assert(alloc_info);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	u8 raw_type = RIOT_BIN_NODE_TYPE_NONE;
	err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type));
	READER_ASSERT(!err, err, failure, "Failed to read option item type!")

	enum riot_bin_node_type type = riot_bin_raw_type_to_node_type(raw_type);
	READER_ASSERT(!riot_bin_node_type_is_container(type), RIOT_IO_ERROR_CORRUPT, failure, "Option cannot contain other container types!")

	u8 has_item = 0;
	err = riot_bin_stream_try_read(stream, &has_item, sizeof(has_item));
	READER_ASSERT(!err, err, failure, "Failed to read option item presence flag!")

	/* if the option has no value, we can simply skip it
	 */
	if (!has_item) return err;

	err = riot_bin_stream_try_size_node(stream, type, alloc_info);
	READER_ASSERT(!err, err, failure, "Failed to size option item!")

failure:
	return err;
}

static enum riot_io_error
riot_bin_stream_try_size_map(struct stream_t *stream, struct riot_bin_alloc_info *alloc_info) {
	assert(stream);
	assert(alloc_info);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	u8 raw_key_type = RIOT_BIN_NODE_TYPE_NONE, raw_val_type = RIOT_BIN_NODE_TYPE_NONE;
	err = riot_bin_stream_try_read(stream, &raw_key_type, sizeof(raw_key_type));
	READER_ASSERT(!err, err, failure, "Failed to read map key type!")

	err = riot_bin_stream_try_read(stream, &raw_val_type, sizeof(raw_val_type));
	READER_ASSERT(!err, err, failure, "Failed to read map val type!")

	enum riot_bin_node_type key_type = riot_bin_raw_type_to_node_type(raw_key_type);
	READER_ASSERT(riot_bin_node_type_is_primitive(key_type), RIOT_IO_ERROR_CORRUPT, failure, "Map keys must be primitive!")

	enum riot_bin_node_type val_type = riot_bin_raw_type_to_node_type(raw_val_type);
	READER_ASSERT(!riot_bin_node_type_is_container(val_type), RIOT_IO_ERROR_CORRUPT, failure, "Map vals must not be containers!")

	u32 size = 0;
	err = riot_bin_stream_try_read(stream, &size, sizeof(size));
	READER_ASSERT(!err, err, failure, "Failed to read map total size!")

	size_t prev_cur = stream->cur;

	u32 count = 0;
	err = riot_bin_stream_try_read(stream, &count, sizeof(count));
	READER_ASSERT(!err, err, failure, "Failed to read number of elements in map!")

	for (u32 i = 0; i < count; i++) {
		err = riot_bin_stream_try_size_node(stream, key_type, alloc_info);
		READER_ASSERT(!err, err, failure, "Failed to size map key %u", i)

		err = riot_bin_stream_try_size_node(stream, val_type, alloc_info);
		READER_ASSERT(!err, err, failure, "Failed to size map val %u", i)
	}

	READER_ASSERT(stream->cur - prev_cur == size, RIOT_IO_ERROR_CORRUPT, failure,
			"Map parsing failed (%zu bytes read, %u bytes expected)!", stream->cur - prev_cur, size)

	alloc_info->pairs_count += count;

failure:
	return err;
}

static enum riot_io_error
riot_bin_stream_try_size_node(struct stream_t *stream, enum riot_bin_node_type type, struct riot_bin_alloc_info *alloc_info) {
	assert(stream);
	assert(alloc_info);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	switch (type) {
		/* handle arithmetic types with a known size by simply reading
		 * however many bytes are required into the union data. this
		 * assumes that the union elements all alias to the first
		 * memory location
		 */
		case RIOT_BIN_NODE_TYPE_B8:
		case RIOT_BIN_NODE_TYPE_I8:
		case RIOT_BIN_NODE_TYPE_U8:
		case RIOT_BIN_NODE_TYPE_I16:
		case RIOT_BIN_NODE_TYPE_U16:
		case RIOT_BIN_NODE_TYPE_I32:
		case RIOT_BIN_NODE_TYPE_U32:
		case RIOT_BIN_NODE_TYPE_I64:
		case RIOT_BIN_NODE_TYPE_U64:
		case RIOT_BIN_NODE_TYPE_F32:
		case RIOT_BIN_NODE_TYPE_VEC2:
		case RIOT_BIN_NODE_TYPE_VEC3:
		case RIOT_BIN_NODE_TYPE_VEC4:
		case RIOT_BIN_NODE_TYPE_MAT4:
		case RIOT_BIN_NODE_TYPE_RGBA:
		case RIOT_BIN_NODE_TYPE_HASH:
		case RIOT_BIN_NODE_TYPE_FILE:
		case RIOT_BIN_NODE_TYPE_LINK:
		case RIOT_BIN_NODE_TYPE_FLAG:
			err = riot_bin_stream_try_skip(stream, riot_bin_node_type_to_size(type));
			READER_ASSERT(!err, err, failure, "Failed to skip bytes for primitive node of type %u!", type)
			break;

		/* complex types require special-case handling, as they usually
		 * handle some kind of memory allocation which can fail
		 */
		case RIOT_BIN_NODE_TYPE_STR:
			err = riot_bin_stream_try_size_str(stream);
			READER_ASSERT(!err, err, failure, "Failed to size string node!")
			break;

		case RIOT_BIN_NODE_TYPE_LIST:
		case RIOT_BIN_NODE_TYPE_LIST2:
			err = riot_bin_stream_try_size_list(stream, alloc_info);
			READER_ASSERT(!err, err, failure, "Failed to size list node!")
			break;

		case RIOT_BIN_NODE_TYPE_PTR:
			err = riot_bin_stream_try_size_ptr(stream, alloc_info);
			READER_ASSERT(!err, err, failure, "Failed to size ptr node!")
			break;

		case RIOT_BIN_NODE_TYPE_EMBED:
			err = riot_bin_stream_try_size_embed(stream, alloc_info);
			READER_ASSERT(!err, err, failure, "Failed to size embed node!")
			break;

		case RIOT_BIN_NODE_TYPE_OPTION:
			err = riot_bin_stream_try_size_option(stream, alloc_info);
			READER_ASSERT(!err, err, failure, "Failed to size option node!")
			break;

		case RIOT_BIN_NODE_TYPE_MAP:
			err = riot_bin_stream_try_size_map(stream, alloc_info);
			READER_ASSERT(!err, err, failure, "Failed to size map node!")
			break;

		/* an unknown type was encountered, which should never happen
		 */
		default:
			READER_ASSERT(false, RIOT_IO_ERROR_CORRUPT, failure, "Unknown node type %u encountered!", type)
			break;
	}

	alloc_info->nodes_count++;

failure:
	return err;
}

/* ===========================================================================
 * Reading Helpers
 * ===========================================================================
 */
static enum riot_io_error
riot_bin_stream_try_read_str(struct stream_t *stream, struct riot_bin_node *out) {
	assert(stream);
	assert(out);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	err = riot_bin_stream_try_read(stream, &out->node_str.len, sizeof(out->node_str.len));
	READER_ASSERT(!err, err, failure, "Failed to read string length!")

	out->node_str.ptr = (char*)&stream->buf.ptr[stream->cur];

	err = riot_bin_stream_try_skip(stream, out->node_str.len);
	READER_ASSERT(!err, err, failure, "Failed to skip string bytes!")

	return err;

failure:
	return err;
}

static enum riot_io_error
riot_bin_stream_try_read_ptr(struct stream_t *stream, struct riot_bin_node *out, struct riot_bin_mem_pool *pool) {
	assert(stream);
	assert(out);
	assert(pool);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	err = riot_bin_stream_try_read(stream, &out->node_ptr.name_hash, sizeof(out->node_ptr.name_hash));
	READER_ASSERT(!err, err, failure, "Failed to read ptr name hash!")

	/* if the hash is empty, we have a null pointer and so we can skip this
	 * node (err == RIOT_IO_ERROR_OK)
	 */
	if (out->node_ptr.name_hash == 0)
		return err;

	u32 size = 0;
	err = riot_bin_stream_try_read(stream, &size, sizeof(size));
	READER_ASSERT(!err, err, failure, "Failed to read the total size")

	size_t prev_cur = stream->cur;

	err = riot_bin_stream_try_read(stream, &out->node_ptr.count, sizeof(out->node_ptr.count));
	READER_ASSERT(!err, err, failure, "Failed to read number of elements after pointer!")

	out->node_ptr.items = pool->fields_head;
	pool->fields_head += out->node_ptr.count;

	for (u16 i = 0; i < out->node_ptr.count; i++) {
		struct riot_bin_field *elem = &out->node_ptr.items[i];

		err = riot_bin_stream_try_read(stream, &elem->name_hash, sizeof(elem->name_hash));
		READER_ASSERT(!err, err, failure, "Failed to read ptr element %u name hash!", i)

		u8 raw_type;
		err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type));
		READER_ASSERT(!err, err, failure, "Failed to read ptr element %u type!", i)

		enum riot_bin_node_type type = riot_bin_raw_type_to_node_type(raw_type);
		err = riot_bin_stream_try_read_node(stream, type, &elem->val, pool);
		READER_ASSERT(!err, err, failure, "Failed to read ptr element %u!", i)
	}

	READER_ASSERT(stream->cur - prev_cur == size, RIOT_IO_ERROR_CORRUPT, failure,
			"Ptr parsing failed (%zu bytes read, %u bytes expected)!", stream->cur - prev_cur, size)

failure:
	return err;
}

static enum riot_io_error
riot_bin_stream_try_read_embed(struct stream_t *stream, struct riot_bin_node *out, struct riot_bin_mem_pool *pool) {
	assert(stream);
	assert(out);
	assert(pool);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	err = riot_bin_stream_try_read(stream, &out->node_embed.name_hash, sizeof(out->node_embed.name_hash));
	READER_ASSERT(!err, err, failure, "Failed to read embed name hash!")

	u32 size = 0;
	err = riot_bin_stream_try_read(stream, &size, sizeof(size));
	READER_ASSERT(!err, err, failure, "Failed to read total size of embed!")

	size_t prev_cur = stream->cur;

	err = riot_bin_stream_try_read(stream, &out->node_embed.count, sizeof(out->node_embed.count));
	READER_ASSERT(!err, err, failure, "Failed to read number of elements in embed!")

	out->node_embed.items = pool->fields_head;
	pool->fields_head += out->node_embed.count;

	for (u16 i = 0; i < out->node_embed.count; i++) {
		struct riot_bin_field *elem = &out->node_embed.items[i];

		err = riot_bin_stream_try_read(stream, &elem->name_hash, sizeof(elem->name_hash));
		READER_ASSERT(!err, err, failure, "Failed to read embed element %u name hash!", i)

		u8 raw_type;
		err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type));
		READER_ASSERT(!err, err, failure, "Failed to read embed element %u raw type!", i)

		enum riot_bin_node_type type = riot_bin_raw_type_to_node_type(raw_type);
		err = riot_bin_stream_try_read_node(stream, type, &elem->val, pool);
		READER_ASSERT(!err, err, failure, "Failed to read embed element %u!", i)
	}

	READER_ASSERT(stream->cur - prev_cur == size, RIOT_IO_ERROR_CORRUPT, failure,
			"Embed parsing failed (%zu bytes read, %u bytes expected)!", stream->cur - prev_cur, size)

failure:
	return err;
}


static enum riot_io_error
riot_bin_stream_try_read_list(struct stream_t *stream, struct riot_bin_node *out, struct riot_bin_mem_pool *pool) {
	assert(stream);
	assert(out);
	assert(pool);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	u8 raw_type = RIOT_BIN_NODE_TYPE_NONE;
	err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type));
	READER_ASSERT(!err, err, failure, "Failed to read list element type!")

	out->node_list.type = riot_bin_raw_type_to_node_type(raw_type);
	READER_ASSERT(!riot_bin_node_type_is_container(out->node_list.type), RIOT_IO_ERROR_CORRUPT, failure, "List cannot contain other container types")

	u32 size = 0;
	err = riot_bin_stream_try_read(stream, &size, sizeof(size));
	READER_ASSERT(!err, err, failure, "Failed to read total size of list!")

	size_t prev_cur = stream->cur;

	err = riot_bin_stream_try_read(stream, &out->node_list.count, sizeof(out->node_list.count));
	READER_ASSERT(!err, err, failure, "Failed to read number of elements in list!")

	out->node_list.items = pool->nodes_head;
	pool->nodes_head += out->node_list.count;

	for (u32 i = 0; i < out->node_list.count; i++) {
		struct riot_bin_node *elem = &out->node_list.items[i];

		err = riot_bin_stream_try_read_node(stream, out->node_list.type, elem, pool);
		READER_ASSERT(!err, err, failure, "Failed to read list element %u", i)
	}

	READER_ASSERT(stream->cur - prev_cur == size, RIOT_IO_ERROR_CORRUPT, failure,
			"List parsing failed (%zu bytes read, %u bytes expected)!", stream->cur - prev_cur, size)

failure:
	return err;
}

static enum riot_io_error
riot_bin_stream_try_read_option(struct stream_t *stream, struct riot_bin_node *out, struct riot_bin_mem_pool *pool) {
	assert(stream);
	assert(out);
	assert(pool);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	u8 raw_type = RIOT_BIN_NODE_TYPE_NONE;
	err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type));
	READER_ASSERT(!err, err, failure, "Failed to read option item type!")

	out->node_option.type = riot_bin_raw_type_to_node_type(raw_type);
	READER_ASSERT(!riot_bin_node_type_is_container(out->node_option.type), RIOT_IO_ERROR_CORRUPT, failure, "Option cannot contain other container types!")

	u8 has_item = 0;
	err = riot_bin_stream_try_read(stream, &has_item, sizeof(has_item));
	READER_ASSERT(!err, err, failure, "Failed to read option item presence flag!")

	/* if the option has no value, we can simply skip it
	 */
	if (!has_item) return err;

	out->node_option.item = pool->nodes_head;
	pool->nodes_head += 1;

	err = riot_bin_stream_try_read_node(stream, out->node_option.type, out->node_option.item, pool);
	READER_ASSERT(!err, err, failure, "Failed to read option item!")

failure:
	return err;
}

static enum riot_io_error
riot_bin_stream_try_read_map(struct stream_t *stream, struct riot_bin_node *out, struct riot_bin_mem_pool *pool) {
	assert(stream);
	assert(out);
	assert(pool);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	u8 raw_key_type = RIOT_BIN_NODE_TYPE_NONE, raw_val_type = RIOT_BIN_NODE_TYPE_NONE;
	err = riot_bin_stream_try_read(stream, &raw_key_type, sizeof(raw_key_type));
	READER_ASSERT(!err, err, failure, "Failed to read map key type!")

	err = riot_bin_stream_try_read(stream, &raw_val_type, sizeof(raw_val_type));
	READER_ASSERT(!err, err, failure, "Failed to read map val type!")

	out->node_map.key_type = riot_bin_raw_type_to_node_type(raw_key_type);
	READER_ASSERT(riot_bin_node_type_is_primitive(out->node_map.key_type), RIOT_IO_ERROR_CORRUPT, failure, "Map keys must be primitive!")

	out->node_map.val_type = riot_bin_raw_type_to_node_type(raw_val_type);
	READER_ASSERT(!riot_bin_node_type_is_container(out->node_map.val_type), RIOT_IO_ERROR_CORRUPT, failure, "Map vals must not be containers!")

	u32 size = 0;
	err = riot_bin_stream_try_read(stream, &size, sizeof(size));
	READER_ASSERT(!err, err, failure, "Failed to read map total size!")

	size_t prev_cur = stream->cur;

	err = riot_bin_stream_try_read(stream, &out->node_map.count, sizeof(out->node_map.count));
	READER_ASSERT(!err, err, failure, "Failed to read number of elements in map!")

	out->node_map.items = pool->pairs_head;
	pool->pairs_head += out->node_map.count;

	for (u32 i = 0; i < out->node_map.count; i++) {
		struct riot_bin_pair *elem = &out->node_map.items[i];

		err = riot_bin_stream_try_read_node(stream, out->node_map.key_type, &elem->key, pool);
		READER_ASSERT(!err, err, failure, "Failed to read map key %u", i)

		err = riot_bin_stream_try_read_node(stream, out->node_map.val_type, &elem->val, pool);
		READER_ASSERT(!err, err, failure, "Failed to read map val %u", i)
	}

	READER_ASSERT(stream->cur - prev_cur == size, RIOT_IO_ERROR_CORRUPT, failure,
			"Map parsing failed (%zu bytes read, %u bytes expected)!", stream->cur - prev_cur, size)

failure:
	return err;
}

static enum riot_io_error
riot_bin_stream_try_read_node(struct stream_t *stream, enum riot_bin_node_type type, struct riot_bin_node *out, struct riot_bin_mem_pool *pool) {
	assert(stream);
	assert(out);
	assert(pool);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	out->type = type;

	switch (type) {
		/* handle arithmetic types with a known size by simply reading
		 * however many bytes are required into the union data. this
		 * assumes that the union elements all alias to the first
		 * memory location
		 */
		case RIOT_BIN_NODE_TYPE_B8:
		case RIOT_BIN_NODE_TYPE_I8:
		case RIOT_BIN_NODE_TYPE_U8:
		case RIOT_BIN_NODE_TYPE_I16:
		case RIOT_BIN_NODE_TYPE_U16:
		case RIOT_BIN_NODE_TYPE_I32:
		case RIOT_BIN_NODE_TYPE_U32:
		case RIOT_BIN_NODE_TYPE_I64:
		case RIOT_BIN_NODE_TYPE_U64:
		case RIOT_BIN_NODE_TYPE_F32:
		case RIOT_BIN_NODE_TYPE_VEC2:
		case RIOT_BIN_NODE_TYPE_VEC3:
		case RIOT_BIN_NODE_TYPE_VEC4:
		case RIOT_BIN_NODE_TYPE_MAT4:
		case RIOT_BIN_NODE_TYPE_RGBA:
		case RIOT_BIN_NODE_TYPE_HASH:
		case RIOT_BIN_NODE_TYPE_FILE:
		case RIOT_BIN_NODE_TYPE_LINK:
		case RIOT_BIN_NODE_TYPE_FLAG:
			err = riot_bin_stream_try_read(stream, &out->raw_data, riot_bin_node_type_to_size(type));
			READER_ASSERT(!err, err, failure, "Failed to read primitive node of type %u!", type)
			break;

		/* complex types require special-case handling, as they usually
		 * handle some kind of memory allocation which can fail
		 */
		case RIOT_BIN_NODE_TYPE_STR:
			err = riot_bin_stream_try_read_str(stream, out);
			READER_ASSERT(!err, err, failure, "Failed to read string node!")
			break;

		case RIOT_BIN_NODE_TYPE_LIST:
		case RIOT_BIN_NODE_TYPE_LIST2:
			err = riot_bin_stream_try_read_list(stream, out, pool);
			READER_ASSERT(!err, err, failure, "Failed to read list node!")
			break;

		case RIOT_BIN_NODE_TYPE_PTR:
			err = riot_bin_stream_try_read_ptr(stream, out, pool);
			READER_ASSERT(!err, err, failure, "Failed to read ptr node!")
			break;

		case RIOT_BIN_NODE_TYPE_EMBED:
			err = riot_bin_stream_try_read_embed(stream, out, pool);
			READER_ASSERT(!err, err, failure, "Failed to read embed node!")
			break;

		case RIOT_BIN_NODE_TYPE_OPTION:
			err = riot_bin_stream_try_read_option(stream, out, pool);
			READER_ASSERT(!err, err, failure, "Failed to read option node!")
			break;

		case RIOT_BIN_NODE_TYPE_MAP:
			err = riot_bin_stream_try_read_map(stream, out, pool);
			READER_ASSERT(!err, err, failure, "Failed to read map node!")
			break;

		/* an unknown type was encountered, which should never happen
		 */
		default:
			READER_ASSERT(false, RIOT_IO_ERROR_CORRUPT, failure, "Unknown node type %u encountered!", type)
			break;
	}

failure:
	return err;
}
