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

#include <argp.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/btf.h>

#include <btfgen2.h>
#include <err.h>
#include <hashmap.h>
#include <stolen.h>

#define OBJ_KEY 260
#define MAX_OBJECTS 128

struct env {
	const char *outputdir;
	const char *inputdir;
	const char *obj[MAX_OBJECTS];
	int obj_index;
	bool verbose;
};

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "display libbpf debug messages" },
	{ "outputdir", 'o', "outputdir", 0, "dir to output the result BTF files" },
	{ "inputdir", 'i', "inputdir", 0, "dir with source BTF files to use" },
	{ "object", OBJ_KEY,  "object", 0, "path of object file to generate BTFs for" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct env *env = state->input;
	switch (key) {
	case 'v':
		env->verbose = true;
		break;
	case 'o':
		env->outputdir = arg;
		break;
	case 'i':
		env->inputdir = arg;
		break;
	case OBJ_KEY:
		env->obj[env->obj_index++] = arg;
		break;
	case ARGP_KEY_END:
		if (env->outputdir == NULL || env->inputdir == NULL || env->obj_index == 0)
			argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int verbose_print(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
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

static void bpf_reloc_type_free(struct btf_reloc_type *type) {
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

void bpf_reloc_info__free(struct btf_reloc_info *info) {
	struct hashmap_entry *entry;
	int i;

	if (!info)
		return;

	btf__free(info->src_btf);

	hashmap__free(info->ids_map);

	if (!IS_ERR_OR_NULL(info->types)) {
		hashmap__for_each_entry(info->types, entry, i) {
			bpf_reloc_type_free(entry->value);
		}
		hashmap__free(info->types);
	}

	free(info);
}

struct btf_reloc_info *bpf_reloc_info__new(const char *targ_btf_path) {
	struct btf_reloc_info *info = NULL;
	struct btf *src_btf = NULL;
	struct hashmap *ids_map = NULL;
	struct hashmap *types = NULL;

	info = calloc(1, sizeof(*info));
	if (!info)
		return ERR_PTR(-ENOMEM);

	src_btf = btf__parse(targ_btf_path, NULL);
	if (libbpf_get_error(src_btf)) {
		bpf_reloc_info__free(info);
		return (void *) src_btf;
	}

	info->src_btf = src_btf;

	ids_map = hashmap__new(bpf_reloc_info_hash_fn, bpf_reloc_info_equal_fn, NULL);
	if (IS_ERR(ids_map)) {
		bpf_reloc_info__free(info);
		return (void *) ids_map;
	}

	info->ids_map = ids_map;

	types = hashmap__new(bpf_reloc_info_hash_fn, bpf_reloc_info_equal_fn, NULL);
	if (IS_ERR(types)) {
		bpf_reloc_info__free(info);
		return (void *) types;
	}

	info->types = types;

	return info;
}

int bpf_object__reloc_info_gen(struct btf_reloc_info *info, struct bpf_object *obj)
{
	//obj->reloc_info = info;
	//return bpf_object__relocate_core(obj, NULL);
	return 0;
}

static int btf_reloc_info_gen_field(struct btf_reloc_info *info, struct bpf_core_spec *targ_spec) {
	struct btf *btf = (struct btf *) targ_spec->btf;
	struct btf_reloc_type *reloc_type;
	struct btf_member *btf_member;
	struct btf_type *btf_type;
	struct btf_array *array;
	unsigned int id;
	int idx, err;

	btf_type = btf_type_by_id(btf, targ_spec->root_type_id);

	/*
	// create reloc type for root type
	reloc_type = btf_reloc_put_type(btf, info, btf_type, targ_spec->root_type_id);
	if (IS_ERR(reloc_type))
		return PTR_ERR(reloc_type);

	// add types for complex types (arrays, unions, structures)
	for (int i = 1; i < targ_spec->raw_len; i++) {

		// skip typedefs and mods
		while (btf_is_mod(btf_type) || btf_is_typedef(btf_type)) {
			id = btf_type->type;
			reloc_type = btf_reloc_get_type(info, id);
			if (IS_ERR(reloc_type))
				return PTR_ERR(reloc_type);
			btf_type = (struct btf_type*) btf__type_by_id(btf, id);
		}

		switch (btf_kind(btf_type)) {
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
			idx = targ_spec->raw_spec[i];
			btf_member = btf_members(btf_type) + idx;
			btf_type = btf_type_by_id(btf, btf_member->type);

			// add member to relocation type
			err = bpf_reloc_type_add_member(info, reloc_type, btf_member, idx);
			if (err)
				return err;
			// add relocation type
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
			pr_warn("spec type wasn't handled: %s\n", btf_kind_str(btf_type));
			return 1;
		}
	}
	*/

	return 0;
}

int generate_btf(const char *src_btf, const char *dst_btf, const char *objspaths[]) {
	struct btf_reloc_info *reloc_info;
	struct btf *btf_new;
	int err;

	reloc_info = bpf_reloc_info__new(src_btf);
	err = libbpf_get_error(reloc_info);
	if (err) {
		printf("failed to allocate info structure\n");
		goto out;
	}

	for (int i = 0; objspaths[i] != NULL; i++) {
		printf("processing %s object\n", objspaths[i]);

		struct bpf_object *obj = bpf_object__open(objspaths[i]);
		err = libbpf_get_error(obj);
		if (err) {
			printf("error opening object\n");
			goto out;
		}

		err = bpf_object__reloc_info_gen(reloc_info, obj);
		if (err) {
			bpf_object__close(obj);
			printf("failed to generate btf info for object\n");
			goto out;
		}

		bpf_object__close(obj);
	}

	/*
	btf_new = bpf_reloc_info__get_btf(reloc_info);
	err = libbpf_get_error(btf_new);
	if (err) {
		printf("error generating btf\n");
		goto out;
	}

	err = btf__save_to_file(btf_new, dst_btf);
	if (err) {
		printf("error saving btf file\n");
		goto out;
	}

out:
	if (!libbpf_get_error(btf_new))
		btf__free(btf_new);
	bpf_reloc_info__free(reloc_info);
	return err;
	*/

out:
	return 0;
}

int main(int argc, char **argv)
{
	struct dirent *dir;
	int err;
	DIR *d;

	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
	};

	static struct env env = {
		.obj_index = 0,
	};

	err = argp_parse(&argp, argc, argv, 0, NULL, &env);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	if (env.verbose) {
		libbpf_set_print(verbose_print);
	}

	d = opendir(env.inputdir);
	if (!d) {
		printf("error opening input dir\n");
		return -1;
	}

	while ((dir = readdir(d)) != NULL) {
		char src_btf_path[PATH_MAX];
		char dst_btf_path[PATH_MAX];

		if (dir->d_type != DT_REG)
			continue;

		/* ignore non BTF files */
		if (strncmp(dir->d_name + strlen(dir->d_name) - 4, ".btf", 4))
			continue;

		snprintf(src_btf_path, sizeof(src_btf_path), "%s/%s", env.inputdir, dir->d_name);
		snprintf(dst_btf_path, sizeof(dst_btf_path), "%s/%s", env.outputdir, dir->d_name);

		printf("generating btf from %s\n", src_btf_path);

		err = generate_btf(src_btf_path, dst_btf_path, env.obj);
		if (err) {
			printf("failed to generate btf for %s\n", src_btf_path);
			closedir(d);
			return 1;
		}
	}

	closedir(d);

	printf("done!\n");
	return 0;
}
