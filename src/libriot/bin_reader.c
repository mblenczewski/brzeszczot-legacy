#include "libriot/io.h"

static enum riot_io_error
riot_bin_stream_try_read_node(struct stream_t *stream, enum riot_bin_node_type type, struct riot_bin_node *out);

static enum riot_io_error
riot_bin_try_read_linked_list(struct stream_t *stream, struct riot_bin *out);

static enum riot_io_error
riot_bin_try_read_entries(struct stream_t *stream, struct riot_bin *out);

static enum riot_io_error
riot_bin_try_read_patches(struct stream_t *stream, struct riot_bin *out);

enum riot_io_error
riot_bin_try_read(struct mem_t buf, struct riot_bin *out) {
	assert(buf.ptr);
	assert(out);

	struct stream_t stream = {
		.buf = buf,
		.cur = 0,
	};

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

	if ((err = riot_bin_stream_try_read(&stream, magic, patch_magic.len)))
		goto failure;

	if (memcmp(magic, patch_magic.str, patch_magic.len) == 0) {
		/* if our first magic identifier is that of a patch, we need to
		 * skip the next 8 bytes and try again (at which point we
		 * should see the prop magic identifier)
		 */
		dbglog("Read PTCH magic!\n");

		node.node_str.str = patch_magic.str;
		node.node_str.len = patch_magic.len;

		has_patches = true;

		u64 unknown = 0;
		if ((err = riot_bin_stream_try_read(&stream, &unknown, sizeof(unknown))))
			goto failure;

		dbglog("Unknown bytes: %llu\n", unknown);

		if ((err = riot_bin_stream_try_read(&stream, magic, prop_magic.len)))
			goto failure;
	} else if (memcmp(magic, prop_magic.str, prop_magic.len) == 0) {
		/* if our first magic identiier is that of a prop, we don't
		 * need to do anything else
		 */
		dbglog("Read PROP magic!\n");

		node.node_str.str = prop_magic.str;
		node.node_str.len = prop_magic.len;
	} else {
		/* if we don't successfully read the patch magic identifier or
		 * the prop magic identifier then we have a corrupted bin file
		 */
		err = RIOT_IO_ERROR_CORRUPT;
		goto failure;
	}

	// TODO: return meaningful error
	map_result = map_str_to_riot_bin_node_try_update(&out->sections, &key, &node, NULL);
	assert(map_result == HASHMAP_RESULT_OK);

	u32 version = 0;
	if ((err = riot_bin_stream_try_read(&stream, &version, sizeof(version))))
		goto failure;

	dbglog("INIBIN version: %u\n", version);
	assert(version > 0);

	key.str = "version";
	key.len = strlen(key.str);

	node.type = RIOT_BIN_NODE_TYPE_U32;
	node.node_u32 = version;

	// TODO: return meaningful error
	map_result = map_str_to_riot_bin_node_try_update(&out->sections, &key, &node, NULL);
	assert(map_result == HASHMAP_RESULT_OK);

	if (version >= 2)
		if ((err = riot_bin_try_read_linked_list(&stream, out)))
			goto failure;

	if ((err = riot_bin_try_read_entries(&stream, out)))
		goto failure;

	if (has_patches)
		if ((err = riot_bin_try_read_patches(&stream, out)))
			goto failure;

	/* if there is any remaining input then we have corrupted input
	 */
	if (stream.cur != stream.buf.len)
		err = RIOT_IO_ERROR_CORRUPT;

failure:
	if (err != RIOT_IO_ERROR_OK)
		dbglog("Failed to read bin file: %s\n", RIOT_IO_ERROR_NAME_MAP[err]); 

	return err;
}

static enum riot_io_error
riot_bin_try_read_linked_list(struct stream_t *stream, struct riot_bin *out) {
	assert(stream);
	assert(out);

	dbglog("Reading linked list of entries\n");

	enum riot_io_error err = RIOT_IO_ERROR_OK;
	enum hashmap_result map_result = HASHMAP_RESULT_OK;

	struct str_t key = STR_FROM_CSTR("linked");
	struct riot_bin_node list = {
		.type = RIOT_BIN_NODE_TYPE_LIST,
		.node_list = {
			.type = RIOT_BIN_NODE_TYPE_STR,
		},
	};

	u32 count = 0;
	if ((err = riot_bin_stream_try_read(stream, &count, sizeof(count))))
		goto failure;

	if (!count) {
		dbglog("No linked list entries!\n");
		return err;
	}

	dbglog("Linked entries: %u\n", count);

	// TODO: switch to bump allocator
	if (!(list.node_list.items = malloc(count * sizeof(struct riot_bin_node)))) {
		STREAM_ERRLOG(*stream);
		dbglog("Failed to allocate %u items of size %zu\n", count, sizeof(struct riot_bin_node));
		err = RIOT_IO_ERROR_ALLOC;
		goto failure;
	}

	for (size_t i = 0; i < count; i++) {
		struct riot_bin_node *elem = &list.node_list.items[i];
		if ((err = riot_bin_stream_try_read_node(stream, RIOT_BIN_NODE_TYPE_STR, elem)))
			goto failure_alloc;
	}

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
	if ((err = riot_bin_stream_try_read(stream, &size, sizeof(size))))
		goto failure;

	size_t prev_cur = stream->cur;

	if ((err = riot_bin_stream_try_read(stream, name_hash, sizeof(*name_hash))))
		goto failure;

	u16 count = 0;
	if ((err = riot_bin_stream_try_read(stream, &count, sizeof(count))))
		goto failure;

	// TODO: switch to bump allocator
	if (!(embed->items = malloc(count * sizeof(struct riot_bin_field)))) {
		STREAM_ERRLOG(*stream);
		dbglog("Failed to allocate %u items of size %zu\n", count, sizeof(struct riot_bin_field));
		err = RIOT_IO_ERROR_ALLOC;
		goto failure;
	}

	u16 i;
	for (i = 0; i < count; i++) {
		struct riot_bin_field *elem = &embed->items[i];

		if ((err = riot_bin_stream_try_read(stream, &elem->name_hash, sizeof(elem->name_hash))))
			goto failure_alloc;

		u8 raw_type;
		if ((err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type))))
			goto failure_alloc;

		enum riot_bin_node_type type = riot_bin_raw_type_to_node_type(raw_type);
		if ((err = riot_bin_stream_try_read_node(stream, type, &elem->val)))
			goto failure_alloc;
	}

	if (stream->cur - prev_cur != size)
		err = RIOT_IO_ERROR_CORRUPT;

	return err;

failure_alloc:
	for (u16 j = 0; j < i; j++) {
		// TODO: free dirty allocated embed entries
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

	u32 count = 0;
	if ((err = riot_bin_stream_try_read(stream, &count, sizeof(count))))
		goto failure;

	if (!count) {
		dbglog("No prop entries!\n");
		return err;
	}

	hashes_fnv1a_val_t *entry_name_hashes = (hashes_fnv1a_val_t*)&stream->buf.ptr[stream->cur];
	if ((err = riot_bin_stream_try_skip(stream, count * sizeof(hashes_fnv1a_val_t))))
		goto failure;

	// TODO: switch to bump allocator
	if (!(map.node_map.items = malloc(count * sizeof(struct riot_bin_pair)))) {
		STREAM_ERRLOG(*stream);
		dbglog("Failed to allocate %u items of size %zu\n", count, sizeof(struct riot_bin_pair));
		err = RIOT_IO_ERROR_ALLOC;
		goto failure;
	}

	map.node_map.count = count;

	u32 i;
	for (i = 0; i < count; i++) {
		hashes_fnv1a_val_t entry_name_hash = entry_name_hashes[i];

		struct riot_bin_pair *elem = &map.node_map.items[i];
		elem->key.type = RIOT_BIN_NODE_TYPE_HASH;
		elem->val.type = RIOT_BIN_NODE_TYPE_EMBED;
		elem->val.node_embed.name_hash = entry_name_hash;

		if ((err = riot_bin_try_read_entry(stream, &elem->key.node_hash, &elem->val.node_embed)))
			goto failure_alloc;
	}

	// TODO: return meaningful error
	map_result = map_str_to_riot_bin_node_try_update(&out->sections, &key, &map, NULL);
	assert(map_result == HASHMAP_RESULT_OK);

	return err;

failure_alloc:
	for (u32 j = 0; j < i; j++) {
		// TODO: free dirty allocated embeds
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

	if ((err = riot_bin_stream_try_read(stream, name_hash, sizeof(*name_hash))))
		goto failure;

	u32 size = 0;
	if ((err = riot_bin_stream_try_read(stream, &size, sizeof(size))))
		goto failure;

	size_t prev_cur = stream->cur;

	if (!(embed->items = malloc(2 * sizeof(struct riot_bin_field)))) {
		STREAM_ERRLOG(*stream);
		dbglog("Failed to allocate %u items of size %zu\n", 2, sizeof(struct riot_bin_field));
		err = RIOT_IO_ERROR_ALLOC;
		goto failure;
	}

	embed->items[0].name_hash = path_name_hash;
	struct riot_bin_node *path = &embed->items[0].val;

	embed->items[1].name_hash = value_name_hash;
	struct riot_bin_node *value = &embed->items[1].val;

	u8 raw_type;
	if ((err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type))))
		goto failure_alloc;

	enum riot_bin_node_type type = riot_bin_raw_type_to_node_type(raw_type);

	if ((err = riot_bin_stream_try_read_node(stream, RIOT_BIN_NODE_TYPE_STR, path)))
		goto failure_alloc;

	if ((err = riot_bin_stream_try_read_node(stream, type, value)))
		goto failure_alloc;

	if (stream->cur - prev_cur != size)
		err = RIOT_IO_ERROR_CORRUPT;

	return err;

failure_alloc:
	// TODO: free dirty allocated embed entries

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

	u32 count = 0;
	if ((err = riot_bin_stream_try_read(stream, &count, sizeof(count))))
		goto failure;

	if (!count) {
		dbglog("No patch entries!\n");
		return err;
	}

	// TODO: switch to bump allocator
	if (!(map.node_map.items = malloc(count * sizeof(struct riot_bin_pair)))) {
		STREAM_ERRLOG(*stream);
		dbglog("Failed to allocate %u items of size %zu\n", count, sizeof(struct riot_bin_pair));
		err = RIOT_IO_ERROR_ALLOC;
		goto failure;
	}

	u32 i;
	for (i = 0; i < count; i++) {
		struct riot_bin_pair *elem = &map.node_map.items[i];
		elem->key.type = RIOT_BIN_NODE_TYPE_HASH;
		elem->val.type = RIOT_BIN_NODE_TYPE_EMBED;
		elem->val.node_embed.name_hash = patch_name_hash;

		if ((err = riot_bin_try_read_patch(stream, &elem->key.node_hash, &elem->val.node_embed)))
			goto failure_alloc;
	}

	// TODO: return meaningful error
	map_result = map_str_to_riot_bin_node_try_update(&out->sections, &key, &map, NULL);
	assert(map_result == HASHMAP_RESULT_OK);

	return err;

failure_alloc:
	for (u32 j = 0; j < i; j++) {
		// TODO: free dirty allocated embeds
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

	u16 len = 0;
	if ((err = riot_bin_stream_try_read(stream, &len, sizeof(len))))
		goto failure;

	out->node_str.len = len;
	out->node_str.str = (char*)&stream->buf.ptr[stream->cur];

	err = riot_bin_stream_try_skip(stream, len);

failure:
	return err;
}

static enum riot_io_error
riot_bin_stream_try_read_list(struct stream_t *stream, struct riot_bin_node *out) {
	assert(stream);
	assert(out);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	u8 raw_type = RIOT_BIN_NODE_TYPE_NONE;
	if ((err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type))))
		goto failure;

	out->node_list.type = riot_bin_raw_type_to_node_type(raw_type);
	// TODO: assert that the read type is not a container type

	u32 size = 0, count = 0;
	if ((err = riot_bin_stream_try_read(stream, &size, sizeof(size))))
		goto failure;

	size_t prev_cur = stream->cur;

	if ((err = riot_bin_stream_try_read(stream, &count, sizeof(count))))
		goto failure;

	// TODO: switch to bump allocation?
	if (!(out->node_list.items = malloc(count * sizeof(struct riot_bin_node)))) {
		STREAM_ERRLOG(*stream);
		dbglog("Failed to allocate %u items of size %zu\n", count, sizeof(struct riot_bin_node));
		err = RIOT_IO_ERROR_ALLOC;
		goto failure;
	}

	for (u32 i = 0; i < count; i++) {
		struct riot_bin_node *elem = &out->node_list.items[i];

		if ((err = riot_bin_stream_try_read_node(stream, out->node_list.type, elem)))
			goto failure_alloc;
	}

	// TODO: logging error location?
	if (stream->cur - prev_cur != size)
		 err = RIOT_IO_ERROR_CORRUPT;

	return err;

failure_alloc:
	free(out->node_list.items);
failure:
	return err;
}

static enum riot_io_error
riot_bin_stream_try_read_ptr(struct stream_t *stream, struct riot_bin_node *out) {
	assert(stream);
	assert(out);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	if ((err = riot_bin_stream_try_read(stream, &out->node_ptr.name_hash, sizeof(out->node_ptr.name_hash))))
		goto failure;

	/* if the hash is empty, we have a null pointer and so we can skip this
	 * node (err == RIOT_IO_ERROR_OK)
	 */
	if (out->node_ptr.name_hash == 0)
		goto failure;

	u32 size = 0;
	if ((err = riot_bin_stream_try_read(stream, &size, sizeof(size))))
		goto failure;

	size_t prev_cur = stream->cur;

	u16 count = 0;
	if ((err = riot_bin_stream_try_read(stream, &count, sizeof(count))))
		goto failure;

	// TODO: switch to bump allocator
	if (!(out->node_ptr.items = malloc(count * sizeof(struct riot_bin_field)))) {
		STREAM_ERRLOG(*stream);
		dbglog("Failed to allocate %u items of size %zu\n", count, sizeof(struct riot_bin_field));
		err = RIOT_IO_ERROR_ALLOC;
		goto failure;
	}

	for (u16 i = 0; i < count; i++) {
		struct riot_bin_field *elem = &out->node_ptr.items[i];

		if ((err = riot_bin_stream_try_read(stream, &elem->name_hash, sizeof(elem->name_hash))))
			goto failure_alloc;

		u8 raw_type;
		if ((err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type))))
			goto failure_alloc;

		enum riot_bin_node_type type = riot_bin_raw_type_to_node_type(raw_type);
		if ((err = riot_bin_stream_try_read_node(stream, type, &elem->val)))
			goto failure_alloc;
	}

	if (stream->cur - prev_cur != size)
		err = RIOT_IO_ERROR_CORRUPT;

	return err;

failure_alloc:
	free(out->node_ptr.items);
failure:
	return err;
}

static enum riot_io_error
riot_bin_stream_try_read_embed(struct stream_t *stream, struct riot_bin_node *out) {
	assert(stream);
	assert(out);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	if ((err = riot_bin_stream_try_read(stream, &out->node_ptr.name_hash, sizeof(out->node_ptr.name_hash))))
		goto failure;

	u32 size = 0;
	if ((err = riot_bin_stream_try_read(stream, &size, sizeof(size))))
		goto failure;

	size_t prev_cur = stream->cur;

	u16 count = 0;
	if ((err = riot_bin_stream_try_read(stream, &count, sizeof(count))))
		goto failure;

	// TODO: switch to bump allocator
	if (!(out->node_embed.items = malloc(count * sizeof(struct riot_bin_field)))) {
		STREAM_ERRLOG(*stream);
		dbglog("Failed to allocate %u items of size %zu\n", count, sizeof(struct riot_bin_field));
		err = RIOT_IO_ERROR_ALLOC;
		goto failure;
	}

	for (u16 i = 0; i < count; i++) {
		struct riot_bin_field *elem = &out->node_embed.items[i];

		if ((err = riot_bin_stream_try_read(stream, &elem->name_hash, sizeof(elem->name_hash))))
			goto failure_alloc;

		u8 raw_type;
		if ((err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type))))
			goto failure_alloc;

		enum riot_bin_node_type type = riot_bin_raw_type_to_node_type(raw_type);
		if ((err = riot_bin_stream_try_read_node(stream, type, &elem->val)))
			goto failure_alloc;
	}

	if (stream->cur - prev_cur != size)
		err = RIOT_IO_ERROR_CORRUPT;

	return err;

failure_alloc:
	free(out->node_ptr.items);
failure:
	return err;
}

static enum riot_io_error
riot_bin_stream_try_read_option(struct stream_t *stream, struct riot_bin_node *out) {
	assert(stream);
	assert(out);

	enum riot_io_error err = RIOT_IO_ERROR_OK;

	u8 raw_type = RIOT_BIN_NODE_TYPE_NONE;
	if ((err = riot_bin_stream_try_read(stream, &raw_type, sizeof(raw_type))))
		goto failure;

	out->node_option.type = riot_bin_raw_type_to_node_type(raw_type);
	// TODO: ensure that the type is not a container type

	u8 count = 0;
	if ((err = riot_bin_stream_try_read(stream, &count, sizeof(count))))
		goto failure;

	/* if the option has no value, we can simply skip it
	 */
	if (!count)
		goto failure;

	// TODO: switch to bump allocator
	if (!(out->node_option.item = malloc(sizeof(struct riot_bin_node)))) {
		STREAM_ERRLOG(*stream);
		dbglog("Failed to allocate %u items of size %zu\n", count, sizeof(struct riot_bin_node));
		err = RIOT_IO_ERROR_ALLOC;
		goto failure;
	}

	if ((err = riot_bin_stream_try_read_node(stream, out->node_option.type, out->node_option.item)))
		goto failure_alloc;

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
	if ((err = riot_bin_stream_try_read(stream, &raw_key_type, sizeof(raw_key_type))))
		goto failure;

	if ((err = riot_bin_stream_try_read(stream, &raw_val_type, sizeof(raw_val_type))))
		goto failure;

	out->node_map.key_type = riot_bin_raw_type_to_node_type(raw_key_type);
	out->node_map.val_type = riot_bin_raw_type_to_node_type(raw_val_type);
	// TODO: ensure that both types are not container types

	u32 size = 0, count = 0;
	if ((err = riot_bin_stream_try_read(stream, &size, sizeof(size))))
		goto failure;

	size_t prev_cur = stream->cur;

	if ((err = riot_bin_stream_try_read(stream, &count, sizeof(count))))
		goto failure;

	// TODO: switch to bump allocation
	if (!(out->node_map.items = malloc(count * sizeof(struct riot_bin_pair)))) {
		STREAM_ERRLOG(*stream);
		dbglog("Failed to allocate %u items of size %zu\n", count, sizeof(struct riot_bin_pair));
		err = RIOT_IO_ERROR_ALLOC;
		goto failure;
	}

	for (u32 i = 0; i < count; i++) {
		struct riot_bin_pair *elem = &out->node_map.items[i];

		if ((err = riot_bin_stream_try_read_node(stream, out->node_map.key_type, &elem->key)))
			goto failure_alloc;

		if ((err = riot_bin_stream_try_read_node(stream, out->node_map.val_type, &elem->val)))
			goto failure_alloc;
	}

	if (stream->cur - prev_cur != size)
		err = RIOT_IO_ERROR_CORRUPT;

	return err;

failure_alloc:
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
	size_t size = riot_bin_node_type_to_size(type);

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
			if ((err = riot_bin_stream_try_read(stream, &out->raw_data, size)))
				goto failure;
			break;

		/* complex types require special-case handling, as they usually
		 * handle some kind of memory allocation which can fail
		 */
		case RIOT_BIN_NODE_TYPE_STR:
			if ((err = riot_bin_stream_try_read_str(stream, out)))
				goto failure;
			break;

		case RIOT_BIN_NODE_TYPE_LIST:
		case RIOT_BIN_NODE_TYPE_LIST2:
			if ((err = riot_bin_stream_try_read_list(stream, out)))
				goto failure;
			break;

		case RIOT_BIN_NODE_TYPE_PTR:
			if ((err = riot_bin_stream_try_read_ptr(stream, out)))
				goto failure;
			break;

		case RIOT_BIN_NODE_TYPE_EMBED:
			if ((err = riot_bin_stream_try_read_embed(stream, out)))
				goto failure;
			break;

		case RIOT_BIN_NODE_TYPE_OPTION:
			if ((err = riot_bin_stream_try_read_option(stream, out)))
				goto failure;
			break;

		case RIOT_BIN_NODE_TYPE_MAP:
			if ((err = riot_bin_stream_try_read_map(stream, out)))
				goto failure;
			break;

		/* an unknown type was encountered, which should never happen
		 */
		default:
			assert(0);
			break;
	}

failure:
	return err;
}
