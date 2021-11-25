// Copyright (c) Microsoft Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/btf.h>

#include "btfgen.h"
#include "hashmap.h"

#include "stolen.h"

static inline __u32 btf_type_info(int kind, int vlen, int kflag)
{
	return (kflag << 31) | (kind << 24) | vlen;
}

static bool core_relo_is_field_based(enum bpf_core_relo_kind kind)
{
	switch (kind) {
	case BPF_FIELD_BYTE_OFFSET:
	case BPF_FIELD_BYTE_SIZE:
	case BPF_FIELD_EXISTS:
	case BPF_FIELD_SIGNED:
	case BPF_FIELD_LSHIFT_U64:
	case BPF_FIELD_RSHIFT_U64:
		return true;
	default:
		return false;
	}
}

static bool core_relo_is_type_based(enum bpf_core_relo_kind kind)
{
	switch (kind) {
	case BPF_TYPE_ID_LOCAL:
	case BPF_TYPE_ID_TARGET:
	case BPF_TYPE_EXISTS:
	case BPF_TYPE_SIZE:
		return true;
	default:
		return false;
	}
}

static bool core_relo_is_enumval_based(enum bpf_core_relo_kind kind)
{
	switch (kind) {
	case BPF_ENUMVAL_EXISTS:
	case BPF_ENUMVAL_VALUE:
		return true;
	default:
		return false;
	}
}

struct btf_reloc_member {
	struct btf_member *member;
	int idx;
};

struct btf_reloc_type {
	struct btf_type *type;
	unsigned int id;

	struct hashmap *members;
};

struct btf_reloc_info {
	struct hashmap *types;
	struct hashmap *ids_map;

	struct btf *src_btf;
};

static size_t bpf_reloc_info_hash_fn(const void *key, void *ctx)
{
	return (size_t)key;
}

static bool bpf_reloc_info_equal_fn(const void *k1, const void *k2, void *ctx)
{
	return k1 == k2;
}

static void *uint_as_hash_key(int x) {
	return (void *)(uintptr_t)x;
}

void bpf_reloc_type_free(struct btf_reloc_type *type) {
	struct hashmap_entry *entry;
	int i;

	if (IS_ERR_OR_NULL(type))
		return;

	if (!IS_ERR_OR_NULL(type->members)) {
		hashmap__for_each_entry(type->members, entry, i) {
			free(entry->value);
		}
		hashmap__free(type->members);
	}

	free(type);
}

struct btf_reloc_info *btfgen_reloc_info_new(const char *targ_btf_path) {
	struct btf_reloc_info *info;
	struct btf *src_btf;
	struct hashmap *ids_map;
	struct hashmap *types;

	info = calloc(1, sizeof(*info));
	if (!info)
		return ERR_PTR(-ENOMEM);

	src_btf = btf__parse(targ_btf_path, NULL);
	if (libbpf_get_error(src_btf)) {
		btfgen_reloc_info_free(info);
		return (void *) src_btf;
	}

	info->src_btf = src_btf;

	ids_map = hashmap__new(bpf_reloc_info_hash_fn, bpf_reloc_info_equal_fn, NULL);
	if (IS_ERR(ids_map)) {
		btfgen_reloc_info_free(info);
		return (void *) ids_map;
	}

	info->ids_map = ids_map;

	types = hashmap__new(bpf_reloc_info_hash_fn, bpf_reloc_info_equal_fn, NULL);
	if (IS_ERR(types)) {
		btfgen_reloc_info_free(info);
		return (void *) types;
	}

	info->types = types;

	return info;
}

void btfgen_reloc_info_free(struct btf_reloc_info *info) {
	struct hashmap_entry *entry;
	int i;

	if (!info)
		return;

	hashmap__free(info->ids_map);

	if (!IS_ERR_OR_NULL(info->types)) {
		hashmap__for_each_entry(info->types, entry, i) {
			bpf_reloc_type_free(entry->value);
		}
		hashmap__free(info->types);
	}

	btf__free(info->src_btf);
	free(info);
}

/* Return id for type in new btf instance */
static unsigned int btf_reloc_id_get(struct btf_reloc_info *info, unsigned int old) {
	uintptr_t new = 0;

	/* deal with BTF_KIND_VOID */
	if (old == 0)
		return 0;

	if (!hashmap__find(info->ids_map, uint_as_hash_key(old), (void **)&new)) {
		/* return id for void as it's possible that the ID we're looking for is
		 * the type of a pointer that we're not adding.
		 */
		return 0;
	}

	return (unsigned int)(uintptr_t)new;
}

/* Add new id map to the list of mappings */
static int btf_reloc_id_add(struct btf_reloc_info *info, unsigned int old, unsigned int new) {
	return hashmap__add(info->ids_map, uint_as_hash_key(old), uint_as_hash_key(new));
}

/*
 * Put type in the list. If the type already exists it's returned, otherwise a
 * new one is created and added to the list. This is called recursively adding
 * all the types that are needed for the current one.
 */
static struct btf_reloc_type *btf_reloc_put_type(struct btf *btf,
						 struct btf_reloc_info *info,
						 struct btf_type *btf_type,
						 unsigned int id) {
	struct btf_reloc_type *reloc_type, *tmp;
	struct btf_array *array;
	unsigned int child_id;
	int err;

	/* check if we already have this type */
	if (hashmap__find(info->types, uint_as_hash_key(id), (void **) &reloc_type)) {
		return reloc_type;
	}

	/* do nothing. void is implicit in BTF */
	if (id == 0)
		return NULL;

	reloc_type = calloc(1, sizeof(*reloc_type));
	if (!reloc_type)
		return ERR_PTR(-ENOMEM);

	reloc_type->type = btf_type;
	reloc_type->id = id;

	/* append this type to the relocation type's list before anything else */
	err = hashmap__add(info->types, uint_as_hash_key(reloc_type->id), reloc_type);
	if (err)
		return ERR_PTR(err);

	/* complex types might need further processing */
	switch (btf_kind(reloc_type->type)) {
	/* already processed */
	case BTF_KIND_UNKN:
	case BTF_KIND_INT:
	case BTF_KIND_FLOAT:
	/* processed by callee */
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
	/* doesn't need resolution. If the data of the pointer is used
	 * then it'll added by the caller in another relocation.
	 */
	case BTF_KIND_PTR:
		break;
	/* needs resolution */
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_TYPEDEF:
		child_id = btf_type->type;
		btf_type = (struct btf_type *) btf__type_by_id(btf, child_id);
		 if (!btf_type)
			return ERR_PTR(-EINVAL);

		tmp = btf_reloc_put_type(btf, info, btf_type, child_id);
		if (IS_ERR(tmp))
			return tmp;
		break;
	/* needs resolution */
	case BTF_KIND_ARRAY:
		array = btf_array(reloc_type->type);

		/* add type for array type */
		btf_type = (struct btf_type *) btf__type_by_id(btf, array->type);
		tmp = btf_reloc_put_type(btf, info, btf_type, array->type);
		if (IS_ERR(tmp))
			return tmp;

		/* add type for array's index type */
		btf_type = (struct btf_type *) btf__type_by_id(btf, array->index_type);
		tmp = btf_reloc_put_type(btf, info, btf_type, array->index_type);
		if (IS_ERR(tmp))
			return tmp;

		break;
	/* tells if some other type needs to be handled */
	default:
		printf("unsupported relocation: %d\n", reloc_type->id);
		return ERR_PTR(-EINVAL);
	}

	return reloc_type;
}

/* Return pointer to btf_reloc_type by id */
static struct btf_reloc_type *btf_reloc_get_type(struct btf_reloc_info *info, int id) {
	struct btf_reloc_type *type = NULL;

	if (!hashmap__find(info->types, uint_as_hash_key(id), (void **)&type))
		return ERR_PTR(-ENOENT);

	return type;
}

static int bpf_reloc_type_add_member(struct btf_reloc_info *info,
				     struct btf_reloc_type *reloc_type,
				     struct btf_member *btf_member, int idx) {
	int err;
	struct btf_reloc_member *reloc_member;

	/* create new members hashmap for this relocation type if needed */
	if (reloc_type->members == NULL) {
		struct hashmap *tmp = hashmap__new(bpf_reloc_info_hash_fn,
						   bpf_reloc_info_equal_fn,
						   NULL);
		if (IS_ERR(tmp))
			return PTR_ERR(tmp);

		reloc_type->members = tmp;
	}
	/* add given btf_member as a member of the parent relocation_type's type */
	reloc_member = calloc(1, sizeof(*reloc_member));
	if (!reloc_member)
		return -ENOMEM;
	reloc_member->member = btf_member;
	reloc_member->idx = idx;
	/* add given btf_member as member to given relocation type */
	err = hashmap__add(reloc_type->members, uint_as_hash_key(reloc_member->idx), reloc_member);
	if (err) {
		free(reloc_member);
		if (err != -EEXIST)
			return err;
	}

	return 0;
}

static int btf_reloc_info_gen_field(struct btf_reloc_info *info, struct bpf_core_relo_spec *targ_spec) {
	struct btf *btf = (struct btf *) info->src_btf;
	struct btf_reloc_type *reloc_type;
	struct btf_member *btf_member;
	struct btf_type *btf_type;
	struct btf_array *array;
	unsigned int id;
	int idx, err;

	btf_type = (struct btf_type *) btf__type_by_id(btf, targ_spec->root_type_id);

	/* create reloc type for root type */
	reloc_type = btf_reloc_put_type(btf, info, btf_type, targ_spec->root_type_id);
	if (IS_ERR(reloc_type))
		return PTR_ERR(reloc_type);

	/* add types for complex types (arrays, unions, structures) */
	for (int i = 1; i < targ_spec->spec_len; i++) {

		/* skip typedefs and mods */
		while (btf_is_mod(btf_type) || btf_is_typedef(btf_type)) {
			id = btf_type->type;
			reloc_type = btf_reloc_get_type(info, id);
			if (IS_ERR(reloc_type))
				return PTR_ERR(reloc_type);
			btf_type = (struct btf_type *) btf__type_by_id(btf, id);
		}

		switch (btf_kind(btf_type)) {
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
			idx = targ_spec->spec[i];
			btf_member = btf_members(btf_type) + idx;
			btf_type =  (struct btf_type *) btf__type_by_id(btf, btf_member->type);

			/* add member to relocation type */
			err = bpf_reloc_type_add_member(info, reloc_type, btf_member, idx);
			if (err)
				return err;
			/* add relocation type */
			reloc_type = btf_reloc_put_type(btf, info, btf_type, btf_member->type);
			if (IS_ERR(reloc_type))
				return PTR_ERR(reloc_type);
			break;
		case BTF_KIND_ARRAY:
			array = btf_array(btf_type);
			reloc_type = btf_reloc_get_type(info, array->type);
			if (IS_ERR(reloc_type))
				return PTR_ERR(reloc_type);
			btf_type = (struct btf_type *) btf__type_by_id(btf, array->type);
			break;
		default:
			//printf("spec type wasn't handled: %s\n", btf_kind_str(btf_type));
			printf("spec type wasn't handled\n");
			return 1;
		}
	}

	return 0;
}

static int btf_reloc_info_gen_type(struct btf_reloc_info *info, struct bpf_core_relo_spec *targ_spec) {
	printf("untreated type based relocation\n");
	return -EOPNOTSUPP;
}

static int btf_reloc_info_gen_enumval(struct btf_reloc_info *info, struct bpf_core_relo_spec *targ_spec) {
	printf("untreated enumval based relocation\n");
	return -EOPNOTSUPP;
}

static int btf_reloc_info_gen(struct btf_reloc_info *info, struct bpf_core_relo_result *res) {

	if (core_relo_is_type_based(res->relo_kind))
		return btf_reloc_info_gen_type(info, &res->targ_spec);

	if (core_relo_is_enumval_based(res->relo_kind))
		return btf_reloc_info_gen_enumval(info, &res->targ_spec);

	if (core_relo_is_field_based(res->relo_kind))
		return btf_reloc_info_gen_field(info, &res->targ_spec);

	return -EINVAL;
}

int btfgen_obj_reloc_info_gen(struct btf_reloc_info *reloc_info, struct bpf_object *obj) {
	struct bpf_core_relo_result *relos;
	struct bpf_program *prog;
	int err;
	bool poisoned = false;

	bpf_object__for_each_program(prog, obj) {
		relos = (struct bpf_core_relo_result *) bpf_program__core_relos(prog);
		int n = bpf_program__core_relos_cnt(prog);

		for (int i = 0; i < n; i++) {
			if (relos[i].poison) {
				poisoned = true;
				continue;
			}

			err = btf_reloc_info_gen(reloc_info, &relos[i]);
			if (err)
				goto out;
		}
	}

out:
	if (poisoned)
		return -ENOEXEC;

	return err;
}

struct btf *btfgen_reloc_info_get_btf(struct btf_reloc_info *info) {
	struct hashmap_entry *entry;
	struct btf *btf_new;
	int err, i;

	btf_new = btf__new_empty();
	if (IS_ERR(btf_new)) {
		printf("failed to allocate btf structure\n");
		return btf_new;
	}

	/* first pass: add all types and add their new ids to the ids map */
	hashmap__for_each_entry(info->types, entry, i) {
		struct btf_reloc_type *reloc_type = entry->value;
		struct btf_type *btf_type = reloc_type->type;
		int new_id;

		/* add members for struct and union */
		if (btf_is_struct(btf_type) || btf_is_union(btf_type)) {
			struct hashmap_entry *member_entry;
			struct btf_type *btf_type_cpy;
			int nmembers, bkt, index;
			size_t new_size;

			nmembers = reloc_type->members ? hashmap__size(reloc_type->members) : 0;
			new_size = sizeof(struct btf_type) + nmembers * sizeof(struct btf_member);

			btf_type_cpy = malloc(new_size);
			if (!btf_type_cpy) {
				err = -ENOMEM;
				goto out;
			}

			/* copy header */
			memcpy(btf_type_cpy, btf_type, sizeof(*btf_type_cpy));

			/* copy only members that are needed */
			index = 0;
			if (nmembers > 0) {
				hashmap__for_each_entry(reloc_type->members, member_entry, bkt) {
					struct btf_reloc_member *reloc_member;
					struct btf_member *btf_member;

					reloc_member = member_entry->value;
					btf_member = btf_members(btf_type) + reloc_member->idx;

					memcpy(btf_members(btf_type_cpy) + index, btf_member, sizeof(struct btf_member));

					index++;
				}
			}

			/* set new vlen */
			btf_type_cpy->info = btf_type_info(btf_kind(btf_type_cpy), nmembers, btf_kflag(btf_type_cpy));

			err = btf__add_type(btf_new, info->src_btf, btf_type_cpy);
			free(btf_type_cpy);
		} else {
			err = btf__add_type(btf_new, info->src_btf, btf_type);
		}

		if (err < 0)
			goto out;

		new_id = err;

		/* add ID mapping */
		err = btf_reloc_id_add(info, reloc_type->id, new_id);
		if (err)
			goto out;
	}

	/* second pass: fix up type ids */
	for (int i = 0; i <= btf__get_nr_types(btf_new); i++) {
		struct btf_member *btf_member;
		struct btf_type *btf_type;
		struct btf_param *params;
		struct btf_array *array;

		btf_type = (struct btf_type *) btf__type_by_id(btf_new, i);

		switch (btf_kind(btf_type)) {
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
			for (int i = 0; i < btf_vlen(btf_type); i++) {
				btf_member = btf_members(btf_type) + i;
				btf_member->type = btf_reloc_id_get(info, btf_member->type);
			}
			break;
		case BTF_KIND_PTR:
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_FUNC:
		case BTF_KIND_VAR:
			btf_type->type = btf_reloc_id_get(info, btf_type->type);
			break;
		case BTF_KIND_ARRAY:
			array = btf_array(btf_type);
			array->index_type = btf_reloc_id_get(info, array->index_type);
			array->type = btf_reloc_id_get(info, array->type);
			break;
		case BTF_KIND_FUNC_PROTO:
			btf_type->type = btf_reloc_id_get(info, btf_type->type);
			params = btf_params(btf_type);
			for (int i = 0; i < btf_vlen(btf_type); i++) {
				params[i].type = btf_reloc_id_get(info, params[i].type);
			}
			break;
		}
	}

	/* deduplicate generated BTF */
	struct btf_dedup_opts dedup_opts = {};
	err = btf__dedup(btf_new, NULL, &dedup_opts);
	if (err) {
		printf("error calling btf__dedup()\n");
		goto out;
	}

	return btf_new;

out:
	btf__free(btf_new);
	return ERR_PTR(err);
}
