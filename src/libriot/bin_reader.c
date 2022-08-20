#include "libriot/io.h"

#define READER_ASSERT(cond, errno, cleanup, ...)				\
if (!(cond)) {									\
	STREAM_ERRLOG(*stream);							\
	errlog("%s: ", RIOT_IO_ERROR_NAME_MAP[errno]);				\
	errlog(__VA_ARGS__);							\
	errlog("\n");								\
	err = errno;								\
	goto cleanup;								\
}

static enum riot_io_error
riot_bin_stream_try_read_node(struct stream_t *stream, enum riot_bin_node_type type, struct riot_bin_node *out);

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

	struct stream_t _stream = {
		.buf = buf,
		.cur = 0,
	}, *stream = &_stream;

	struct str_t patch_magic = STR_FROM_CSTR("PTCH");
	struct str_t prop_magic = STR_FROM_CSTR("PROP");

	assert(patch_magic.len == 4);
	assert(prop_magic.len == 4);

	enum riot_io_error err = RIOT_IO_ERROR_OK;
	enum hashmap_result map_result = HASHMAP_RESULT_OK;

	u8 magic[4] = {0};
	struct str_t key;
	struct riot_bin_node node;

	b32 has_patches = false;

	key.str = "type";
	key.len = strlen(key.str);

	node.type = RIOT_BIN_NODE_TYPE_STR;

	err = riot_bin_stream_try_read(stream, magic, patch_magic.len);
	READER_ASSERT(!err, err, failure, "Failed to read magic value!")

	if (memcmp(magic, patch_magic.str, patch_magic.len) == 0) {
		/* if our first magic identifier is that of a patch, we need to
		 * skip the next 8 bytes and try again (at which point we
		 * should see the prop magic identifier)
		 */
		dbglog("Read PTCH magic!\n");

		node.node_str.ptr = patch_magic.str;
		node.node_str.len = patch_magic.len;

		// TODO: return meaningful error
		map_result = map_str_to_riot_bin_node_try_update(&out->sections, &key, &node, NULL);
		assert(map_result == HASHMAP_RESULT_OK);
		has_patches = true;

		u64 unknown = 0;
		err = riot_bin_stream_try_read(stream, &unknown, sizeof(unknown));
		READER_ASSERT(!err, err, failure, "Failed to read unknown bytes!")

		dbglog("Unknown bytes: %llu\n", unknown);

		err = riot_bin_stream_try_read(stream, magic, prop_magic.len);
		READER_ASSERT(!err, err, failure, "Failed to read magic value!")
	}

	if (memcmp(magic, prop_magic.str, prop_magic.len) == 0) {
		/* if our first magic identiier is that of a prop, we don't
		 * need to do anything else
		 */
		dbglog("Read PROP magic!\n");

		node.node_str.ptr = prop_magic.str;
		node.node_str.len = prop_magic.len;

		// TODO: return meaningful error
		map_result = map_str_to_riot_bin_node_try_update(&out->sections, &key, &node, NULL);
		assert(map_result == HASHMAP_RESULT_OK);
	} else {
		/* if we don't successfully read the patch magic identifier or
		 * the prop magic identifier then we have a corrupted bin file
		 */
		READER_ASSERT(false, RIOT_IO_ERROR_CORRUPT, failure, "Invalid magic value read!");
	}

	u32 version = 0;
	err = riot_bin_stream_try_read(stream, &version, sizeof(version));
	READER_ASSERT(!err, err, failure, "Failed to read INIBIN version!")

	dbglog("INIBIN version: %u\n", version);
	assert(version > 0);

	key.str = "version";
	key.len = strlen(key.str);

	node.type = RIOT_BIN_NODE_TYPE_U32;
	node.node_u32 = version;

	// TODO: return meaningful error
	map_result = map_str_to_riot_bin_node_try_update(&out->sections, &key, &node, NULL);
	assert(map_result == HASHMAP_RESULT_OK);

	if (version >= 2) {
		err = riot_bin_try_read_linked_files(stream, out);
		READER_ASSERT(!err, err, failure, "Failed to read linked files!")
	}

	err = riot_bin_try_read_entries(stream, out);
	READER_ASSERT(!err, err, failure, "Failed to read prop entries!")

	if (version >= 3 && has_patches && riot_bin_stream_has_input(stream)) {
		err = riot_bin_try_read_patches(stream, out);
		READER_ASSERT(!err, err, failure, "Failed to read patch entries!");
	}

	/* if there is any remaining input then we have corrupted input
	 */
	READER_ASSERT(stream->cur == stream->buf.len, RIOT_IO_ERROR_CORRUPT, failure, "Stream input remaining!")

failure:
	if (err != RIOT_IO_ERROR_OK)
		dbglog("Failed to read bin file: %s\n", RIOT_IO_ERROR_NAME_MAP[err]); 

	return err;
}

static enum riot_io_error
riot_bin_try_read_linked_files(struct stream_t *stream, struct riot_bin *out) {
	assert(stream);
	assert(out);

	dbglog("Reading linked files\n");

	enum riot_io_error err = RIOT_IO_ERROR_OK;
	enum hashmap_result map_result = HASHMAP_RESULT_OK;

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

	// TODO: switch to bump allocator
	list.node_list.items = malloc(list.node_list.count * sizeof(struct riot_bin_node));
	READER_ASSERT(list.node_list.items, RIOT_IO_ERROR_ALLOC, failure,
			"Failed to allocate %u items of size %zu!", list.node_list.count, sizeof(struct riot_bin_node))

	for (u32 i = 0; i < list.node_list.count; i++) {
		struct riot_bin_node *elem = &list.node_list.items[i];

		err = riot_bin_stream_try_read_node(stream, RIOT_BIN_NODE_TYPE_STR, elem);
		READER_ASSERT(!err, err, failure_alloc, "Failed to read linked files %u!", i)
	}

success:
	// TODO: return meaningful error
	map_result = map_str_to_riot_bin_node_try_update(&out->sections, &key, &list, NULL);
	assert(map_result == HASHMAP_RESULT_OK);

	return err;

failure_alloc:
	free(list.node_list.items);
failure:
	return err;
}

static enum riot_io_error
riot_bin_try_read_entry(struct stream_t *stream, hashes_fnv1a_val_t *name_hash, struct riot_bin_field_list *embed) {
	assert(stream);
	assert(name_hash);
	assert(embed);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	u32 size = 0;
	err = riot_bin_stream_try_read(stream, &size, sizeof(size));
	READER_ASSERT(!err, err, failure, "Failed to read total size of prop entry embed!")

	size_t prev_cur = stream->cur;

	err = riot_bin_stream_try_read(stream, name_hash, sizeof(*name_hash));
	READER_ASSERT(!err, err, failure, "Failed to read prop entry embed name hash!")

	err = riot_bin_stream_try_read(stream, &embed->count, sizeof(embed->count));
	READER_ASSERT(!err, err, failure, "Failed to read count of prop entry embed fields!")

	// TODO: switch to bump allocator
	embed->items = malloc(embed->count * sizeof(struct riot_bin_field));
	READER_ASSERT(embed->items, RIOT_IO_ERROR_ALLOC, failure,
			"Failed to allocate %u items of size %zu!", embed->count, sizeof(struct riot_bin_field))

	u16 i;
	for (i = 0; i < embed->count; i++) {
		struct riot_bin_field *elem = &embed->items[i];

		err = riot_bin_stream_try_read(stream, &elem->name_hash, sizeof(elem->name_hash));
		READER_ASSERT(!err, err, failure_alloc, "Failed to read prop entry embed's field %u name hash!", i)

		u8 raw_type;
		err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type));
		READER_ASSERT(!err, err, failure_alloc, "Failed to read prop entry embed's field %u type!", i)

		enum riot_bin_node_type type = riot_bin_raw_type_to_node_type(raw_type);
		err = riot_bin_stream_try_read_node(stream, type, &elem->val);
		READER_ASSERT(!err, err, failure_alloc, "Failed to read prop entry embed's field %u value!", i)
	}

	READER_ASSERT(stream->cur - prev_cur == size, RIOT_IO_ERROR_CORRUPT, failure_alloc,
			"Prop entry embed parsing failed (%zu bytes read, %u bytes expected)!", stream->cur - prev_cur, size)

	return err;

failure_alloc:
	/* free dirty allocated embed entries */
	for (u16 j = 0; j < i; j++) {
		riot_bin_node_free(&embed->items[j].val);
	}

	free(embed->items);
failure:
	return err;
}

static enum riot_io_error
riot_bin_try_read_entries(struct stream_t *stream, struct riot_bin *out) {
	assert(stream);
	assert(out);

	dbglog("Reading prop entries\n");

	enum riot_io_error err = RIOT_IO_ERROR_OK;
	enum hashmap_result map_result = HASHMAP_RESULT_OK;

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

	// TODO: switch to bump allocator
	map.node_map.items = malloc(map.node_map.count * sizeof(struct riot_bin_pair));
	READER_ASSERT(map.node_map.items, RIOT_IO_ERROR_ALLOC, failure,
			"Failed to allocate %u items of size %zu!", map.node_map.count, sizeof(struct riot_bin_pair))

	u32 i;
	for (i = 0; i < map.node_map.count; i++) {
		hashes_fnv1a_val_t entry_name_hash = entry_name_hashes[i];

		struct riot_bin_pair *elem = &map.node_map.items[i];
		elem->key.type = RIOT_BIN_NODE_TYPE_HASH;
		elem->val.type = RIOT_BIN_NODE_TYPE_EMBED;
		elem->val.node_embed.name_hash = entry_name_hash;

		err = riot_bin_try_read_entry(stream, &elem->key.node_hash, &elem->val.node_embed);
		READER_ASSERT(!err, err, failure_alloc, "Failed to read embed entry %u!", i)
	}

success:
	// TODO: return meaningful error
	map_result = map_str_to_riot_bin_node_try_update(&out->sections, &key, &map, NULL);
	assert(map_result == HASHMAP_RESULT_OK);

	return err;

failure_alloc:
	/* free dirty allocated embeds */
	for (u32 j = 0; j < i; j++) {
		riot_bin_node_free(&map.node_map.items[j].key);
		riot_bin_node_free(&map.node_map.items[j].val);
	}

	free(map.node_map.items);
failure:
	return err;
}

static enum riot_io_error
riot_bin_try_read_patch(struct stream_t *stream, hashes_fnv1a_val_t *name_hash, struct riot_bin_field_list *embed) {
	assert(stream);
	assert(name_hash);
	assert(embed);

	hashes_fnv1a_val_t path_name_hash = hashes_fnv1a("path", 4, HASHES_FNV1A_DEFAULT_SEED);
	hashes_fnv1a_val_t value_name_hash = hashes_fnv1a("value", 5, HASHES_FNV1A_DEFAULT_SEED);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	err = riot_bin_stream_try_read(stream, name_hash, sizeof(*name_hash));
	READER_ASSERT(!err, err, failure, "Failed to read patch entry embed name hash!")
		goto failure;

	u32 size = 0;
	err = riot_bin_stream_try_read(stream, &size, sizeof(size));
	READER_ASSERT(!err, err, failure, "Failed to read total size of patch entry embed!")

	size_t prev_cur = stream->cur;

	embed->items = malloc(2 * sizeof(struct riot_bin_field));
	READER_ASSERT(embed->items, RIOT_IO_ERROR_ALLOC, failure, "Failed to allocate %u items of size %zu!", 2, sizeof(struct riot_bin_field))

	embed->items[0].name_hash = path_name_hash;
	struct riot_bin_node *path = &embed->items[0].val;

	embed->items[1].name_hash = value_name_hash;
	struct riot_bin_node *value = &embed->items[1].val;

	u8 raw_type;
	err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type));
	READER_ASSERT(!err, err, failure_alloc, "Failed to read raw type of patch entry embed value!");

	enum riot_bin_node_type type = riot_bin_raw_type_to_node_type(raw_type);

	err = riot_bin_stream_try_read_node(stream, RIOT_BIN_NODE_TYPE_STR, path);
	READER_ASSERT(!err, err, failure_alloc, "Failed to read patch entry embed path!")

	err = riot_bin_stream_try_read_node(stream, type, value);
	READER_ASSERT(!err, err, failure_alloc, "Failed to read patch entry embed value!")

	READER_ASSERT(stream->cur - prev_cur == size, RIOT_IO_ERROR_ALLOC, failure_alloc,
			"Patch entry embed parsing failed (%zu bytes read, %u bytes expected)!", stream->cur - prev_cur, size)

	return err;

failure_alloc:
	// TODO: free dirty allocated embed entries
	riot_bin_node_free(path);
	riot_bin_node_free(value);

	free(embed->items);
failure:
	return err;
}

static enum riot_io_error
riot_bin_try_read_patches(struct stream_t *stream, struct riot_bin *out) {
	assert(stream);
	assert(out);

	dbglog("Reading prop patches\n");

	hashes_fnv1a_val_t patch_name_hash = hashes_fnv1a("patch", 5, HASHES_FNV1A_DEFAULT_SEED);

	enum riot_io_error err = RIOT_IO_ERROR_OK;
	enum hashmap_result map_result = HASHMAP_RESULT_OK;

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

	// TODO: switch to bump allocator
	map.node_map.items = malloc(map.node_map.count * sizeof(struct riot_bin_pair));
	READER_ASSERT(map.node_map.items, RIOT_IO_ERROR_ALLOC, failure,
			"Failed to allocate %u items of size %zu!", map.node_map.count, sizeof(struct riot_bin_pair))

	u32 i;
	for (i = 0; i < map.node_map.count; i++) {
		struct riot_bin_pair *elem = &map.node_map.items[i];
		elem->key.type = RIOT_BIN_NODE_TYPE_HASH;
		elem->val.type = RIOT_BIN_NODE_TYPE_EMBED;
		elem->val.node_embed.name_hash = patch_name_hash;

		err = riot_bin_try_read_patch(stream, &elem->key.node_hash, &elem->val.node_embed);
		READER_ASSERT(!err, err, failure_alloc, "Failed to read patch %u!", i)
	}

success:
	// TODO: return meaningful error
	map_result = map_str_to_riot_bin_node_try_update(&out->sections, &key, &map, NULL);
	assert(map_result == HASHMAP_RESULT_OK);

	return err;

failure_alloc:
	/* free dirty allocated embeds */
	for (u32 j = 0; j < i; j++) {
		riot_bin_node_free(&map.node_map.items[j].key);
		riot_bin_node_free(&map.node_map.items[j].val);
	}

	free(map.node_map.items);
failure:
	return err;
}

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
riot_bin_stream_try_read_ptr(struct stream_t *stream, struct riot_bin_node *out) {
	assert(stream);
	assert(out);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	err = riot_bin_stream_try_read(stream, &out->node_ptr.name_hash, sizeof(out->node_ptr.name_hash));
	READER_ASSERT(!err, err, failure, "Failed to reach ptr name hash!")

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

	// TODO: switch to bump allocator
	out->node_ptr.items = malloc(out->node_ptr.count * sizeof(struct riot_bin_field));
	READER_ASSERT(out->node_ptr.items, RIOT_IO_ERROR_ALLOC, failure,
			"Failed to allocate %u items of size %zu\n", out->node_ptr.count, sizeof(struct riot_bin_field))

	u16 i;
	for (i = 0; i < out->node_ptr.count; i++) {
		struct riot_bin_field *elem = &out->node_ptr.items[i];

		err = riot_bin_stream_try_read(stream, &elem->name_hash, sizeof(elem->name_hash));
		READER_ASSERT(!err, err, failure_alloc, "Failed to read ptr element %u name hash!", i)

		u8 raw_type;
		err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type));
		READER_ASSERT(!err, err, failure_alloc, "Failed to read ptr element %u type!", i)

		enum riot_bin_node_type type = riot_bin_raw_type_to_node_type(raw_type);
		err = riot_bin_stream_try_read_node(stream, type, &elem->val);
		READER_ASSERT(!err, err, failure_alloc, "Failed to read ptr element %u!", i)
	}

	READER_ASSERT(stream->cur - prev_cur == size, RIOT_IO_ERROR_CORRUPT, failure_alloc,
			"Ptr parsing failed (%zu bytes read, %u bytes expected)!", stream->cur - prev_cur, size)

	return err;

failure_alloc:
	/* free dirty allocated items */
	for (u16 j = 0; j < i; j++) {
		riot_bin_node_free(&out->node_ptr.items[j].val);
	}

	free(out->node_ptr.items);
failure:
	return err;
}

static enum riot_io_error
riot_bin_stream_try_read_embed(struct stream_t *stream, struct riot_bin_node *out) {
	assert(stream);
	assert(out);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	err = riot_bin_stream_try_read(stream, &out->node_embed.name_hash, sizeof(out->node_embed.name_hash));
	READER_ASSERT(!err, err, failure, "Failed to read embed name hash!")

	u32 size = 0;
	err = riot_bin_stream_try_read(stream, &size, sizeof(size));
	READER_ASSERT(!err, err, failure, "Failed to read total size of embed!")

	size_t prev_cur = stream->cur;

	err = riot_bin_stream_try_read(stream, &out->node_embed.count, sizeof(out->node_embed.count));
	READER_ASSERT(!err, err, failure, "Failed to read number of elements in embed!")

	// TODO: switch to bump allocator
	out->node_embed.items = malloc(out->node_embed.count * sizeof(struct riot_bin_field));
	READER_ASSERT(out->node_embed.items, RIOT_IO_ERROR_ALLOC, failure,
			"Failed to allocate %u items of size %zu\n", out->node_embed.count, sizeof(struct riot_bin_field))

	u16 i;
	for (i = 0; i < out->node_embed.count; i++) {
		struct riot_bin_field *elem = &out->node_embed.items[i];

		err = riot_bin_stream_try_read(stream, &elem->name_hash, sizeof(elem->name_hash));
		READER_ASSERT(!err, err, failure_alloc, "Failed to read embed element %u name hash!", i)

		u8 raw_type;
		err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type));
		READER_ASSERT(!err, err, failure_alloc, "Failed to read embed element %u raw type!", i)

		enum riot_bin_node_type type = riot_bin_raw_type_to_node_type(raw_type);
		err = riot_bin_stream_try_read_node(stream, type, &elem->val);
		READER_ASSERT(!err, err, failure_alloc, "Failed to read embed element %u!", i)
	}

	READER_ASSERT(stream->cur - prev_cur == size, RIOT_IO_ERROR_CORRUPT, failure_alloc,
			"Embed parsing failed (%zu bytes read, %u bytes expected)!", stream->cur - prev_cur, size)

	return err;

failure_alloc:
	/* free dirty allocated embed item */
	for (u16 j = 0; j < i; i++) {
		riot_bin_node_free(&out->node_embed.items[j].val);
	}

	free(out->node_ptr.items);
failure:
	return err;
}


static enum riot_io_error
riot_bin_stream_try_read_list(struct stream_t *stream, struct riot_bin_node *out) {
	assert(stream);
	assert(out);

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

	// TODO: switch to bump allocation?
	out->node_list.items = malloc(out->node_list.count * sizeof(struct riot_bin_node));
	READER_ASSERT(out->node_list.items, RIOT_IO_ERROR_ALLOC, failure,
			"Failed to allocate %u items of size %zu!", out->node_list.count, sizeof(struct riot_bin_node))

	for (u32 i = 0; i < out->node_list.count; i++) {
		struct riot_bin_node *elem = &out->node_list.items[i];

		err = riot_bin_stream_try_read_node(stream, out->node_list.type, elem);
		READER_ASSERT(!err, err, failure_alloc, "Failed to read list element %u", i)
	}

	READER_ASSERT(stream->cur - prev_cur == size, RIOT_IO_ERROR_CORRUPT, failure_alloc,
			"List parsing failed (%zu bytes read, %u bytes expected)!", stream->cur - prev_cur, size)

	return err;

failure_alloc:
	free(out->node_list.items);
failure:
	return err;
}

static enum riot_io_error
riot_bin_stream_try_read_option(struct stream_t *stream, struct riot_bin_node *out) {
	assert(stream);
	assert(out);

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

	// TODO: switch to bump allocator
	out->node_option.item = malloc(sizeof(struct riot_bin_node));
	READER_ASSERT(out->node_option.item, RIOT_IO_ERROR_ALLOC, failure,
			"Failed to allocate %u items of size %zu\n", has_item, sizeof(struct riot_bin_node));

	err = riot_bin_stream_try_read_node(stream, out->node_option.type, out->node_option.item);
	READER_ASSERT(!err, err, failure_alloc, "Failed to read option item!")

	return err;

failure_alloc:
	free(out->node_option.item);
failure:
	return err;
}

static enum riot_io_error
riot_bin_stream_try_read_map(struct stream_t *stream, struct riot_bin_node *out) {
	assert(stream);
	assert(out);

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

	// TODO: switch to bump allocation
	out->node_map.items = malloc(out->node_map.count * sizeof(struct riot_bin_pair));
	READER_ASSERT(out->node_map.items, RIOT_IO_ERROR_ALLOC, failure,
			"Failed to allocate %u items of size %zu\n", out->node_map.count, sizeof(struct riot_bin_pair))

	u32 i;
	for (i = 0; i < out->node_map.count; i++) {
		struct riot_bin_pair *elem = &out->node_map.items[i];

		err = riot_bin_stream_try_read_node(stream, out->node_map.key_type, &elem->key);
		READER_ASSERT(!err, err, failure_alloc, "Failed to read map key %u", i)

		err = riot_bin_stream_try_read_node(stream, out->node_map.val_type, &elem->val);
		READER_ASSERT(!err, err, failure_alloc, "Failed to read map val %u", i)
	}

	READER_ASSERT(stream->cur - prev_cur == size, RIOT_IO_ERROR_CORRUPT, failure_alloc,
			"Map parsing failed (%zu bytes read, %u bytes expected)!", stream->cur - prev_cur, size)

	return err;

failure_alloc:
	for (u32 j = 0; j < i; j++) {
		riot_bin_node_free(&out->node_map.items[j].key);
		riot_bin_node_free(&out->node_map.items[j].val);
	}

	free(out->node_map.items);
failure:
	return err;
}

static enum riot_io_error
riot_bin_stream_try_read_node(struct stream_t *stream, enum riot_bin_node_type type, struct riot_bin_node *out) {
	assert(stream);
	assert(out);

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
			err = riot_bin_stream_try_read_list(stream, out);
			READER_ASSERT(!err, err, failure, "Failed to read list node!")
			break;

		case RIOT_BIN_NODE_TYPE_PTR:
			err = riot_bin_stream_try_read_ptr(stream, out);
			READER_ASSERT(!err, err, failure, "Failed to read ptr node!")
			break;

		case RIOT_BIN_NODE_TYPE_EMBED:
			err = riot_bin_stream_try_read_embed(stream, out);
			READER_ASSERT(!err, err, failure, "Failed to read embed node!")
			break;

		case RIOT_BIN_NODE_TYPE_OPTION:
			err = riot_bin_stream_try_read_option(stream, out);
			READER_ASSERT(!err, err, failure, "Failed to read option node!")
			break;

		case RIOT_BIN_NODE_TYPE_MAP:
			err = riot_bin_stream_try_read_map(stream, out);
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
