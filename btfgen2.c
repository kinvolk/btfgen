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

struct btf;

static void *uint_as_hash_key(int x) {
	return (void *)(uintptr_t)x;
}

/* generate bigger final BTF with all eBPF object used types (complete complex types) */
int generate_btf_01(const char *src_btf, const char *dst_btf, const char *objspaths[]) {

	long err;
	struct btf *temp;
	struct btf *targ_btf, *btf_obj;

	// src_btf == target kernel BTF information
	targ_btf = btf__parse_raw(src_btf);
	err = libbpf_get_error(targ_btf);
	if (err) {
		printf("error: could not parse src_btf: %s", src_btf);
		return -ENOENT;
	}

	for (int i = 0; objspaths[i] != NULL; i++) {
		printf("info: processing %s object\n", objspaths[i]);

		// btf_obj == eBPF objects BTF information
		btf_obj = btf__parse_elf(objspaths[i], NULL);
		err = libbpf_get_error(btf_obj);
		if (err) {
			printf("warning: could not parse btf_obj: %s\n", objspaths[i]);
			continue;
		}

		int n = btf__get_nr_types(btf_obj);
		for (int i = 0; i < n; i++) {
			const struct btf_type *t = btf__type_by_id(btf_obj, i);

			if (btf_is_struct(t)) {
				printf("achou\n");
			}
		}
	}

	return 0;
}

int add_btf_type_recursive(struct btf *dest, struct btf *src, int id, struct hashmap *ids_map) {
	uintptr_t new = 0;

	int new_id;

	if (hashmap__find(ids_map, uint_as_hash_key(id), (void **)&new)) {
		return 0;
	}

	struct btf_type *t = btf__type_by_id(src, id);
	struct btf_member *btf_member;
	struct btf_array *array;

	new_id = btf__add_type(dest, src, btf__type_by_id(src, id));
	hashmap__add(ids_map, uint_as_hash_key(id), uint_as_hash_key(new_id));

	/* add all types that dependend on it */
	switch (btf_kind(t)) {
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		for (int i = 0; i < btf_vlen(t); i++) {
			btf_member = btf_members(t) + i;
			add_btf_type_recursive(dest, src, btf_member->type, ids_map);
		}
		break;
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_TYPEDEF:
		add_btf_type_recursive(dest, src, t->type, ids_map);
		break;
	case BTF_KIND_ARRAY:
		array = btf_array(t);
		add_btf_type_recursive(dest, src, array->type, ids_map);
		add_btf_type_recursive(dest, src, array->index_type, ids_map);
	}

	return 0;
}

static size_t bpf_reloc_info_hash_fn(const void *key, void *ctx)
{
	return (size_t)key;
}

static bool bpf_reloc_info_equal_fn(const void *k1, const void *k2, void *ctx)
{
	return k1 == k2;
}

int find_type_id(struct btf *target_btf, const char *name) {
	int n, i;
	struct btf_type *t;

	n = btf__get_nr_types(target_btf);
	for (i = 0; i <= n; i++) {
		t = btf__type_by_id(target_btf, i);

		if (strcmp(btf__str_by_offset(target_btf, t->name_off), name) == 0) {
			return i;
		}
	}

	return 0;
}

int id_get(struct hashmap *ids_map, int old) {
	uintptr_t new = 0;

	if (old == 0)
		return 0;

	if (!hashmap__find(ids_map, uint_as_hash_key(old), (void **)&new)) {
		/* return id for void as it's possible that the ID we're looking for is
		 * the type of a pointer that we're not adding.
		 */
		return 0;
	}

	return (unsigned int)(uintptr_t)new;
}

/* bpf_object__relocate_core logic: we need the bpf_core_relos */
int bpf_object_relocate_core(struct bpf_object *obj, struct btf *kernel_btf, const char *target_path) {
	int i = 0;

	const struct btf_ext_info_sec *sec;
	const struct bpf_core_relo *rec;
	const struct btf_ext_info *seg;

	const char *sec_name;

	struct btf *local_btf = obj->btf;

	struct hashmap *ids_map = hashmap__new(bpf_reloc_info_hash_fn, bpf_reloc_info_equal_fn, NULL);
	struct btf *created_btf = btf__new_empty();

	int id;

	seg = &obj->btf_ext->core_relo_info;
	for_each_btf_ext_sec(seg, sec)
	{
		sec_name = btf__name_by_offset(obj->btf, sec->sec_name_off);
		if (str_is_empty(sec_name)) {
			printf("error: sec_name is empty\n");
			return -1;
		}
		printf("sec_name = %s\n", sec_name);

		printf("sec '%s': found %d CO-RE relocations\n", sec_name, sec->num_info);

		for_each_btf_ext_rec(seg, sec, i, rec)
		{
			// each rec, here, is a bpf_core_relo for us to discover types in target BTF
			// we can do something like bpf_core_find_cands
			printf("relocation of type %u. acc str %s\n",
				rec->type_id, btf__str_by_offset(local_btf, rec->access_str_off));

			struct btf_type *t = btf__type_by_id(local_btf, rec->type_id);
			const char *name = btf__str_by_offset(local_btf, t->name_off);
			printf("type name is: %s\n", name);

			id = find_type_id(kernel_btf, name);
			printf("matching type in targ btf is %d\n", id);

			add_btf_type_recursive(created_btf, kernel_btf, id, ids_map);
		}
	}

	/* fix up ids */
	for (int i = 0; i <= btf__get_nr_types(created_btf); i++) {
		struct btf_member *btf_member;
		struct btf_type *btf_type;
		struct btf_param *params;
		struct btf_array *array;

		btf_type = (struct btf_type *) btf__type_by_id(created_btf, i);

		switch (btf_kind(btf_type)) {
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
			for (int i = 0; i < btf_vlen(btf_type); i++) {
				btf_member = btf_members(btf_type) + i;
				btf_member->type = id_get(ids_map, btf_member->type);
			}
			break;
		case BTF_KIND_PTR:
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_FUNC:
		case BTF_KIND_VAR:
			btf_type->type = id_get(ids_map, btf_type->type);
			break;
		case BTF_KIND_ARRAY:
			array = btf_array(btf_type);
			array->index_type = id_get(ids_map, array->index_type);
			array->type = id_get(ids_map, array->type);
			break;
		case BTF_KIND_FUNC_PROTO:
			btf_type->type = id_get(ids_map, btf_type->type);
			params = btf_params(btf_type);
			for (int i = 0; i < btf_vlen(btf_type); i++) {
				params[i].type = id_get(ids_map, params[i].type);
			}
			break;
		}
	}

	btf__save_to_file(created_btf, target_path);

	return 0;
}

/* try to use .BTF.ext relocation information to generate final BTF */
int generate_btf_02(const char *src_btf, const char *dst_btf, const char *objspaths[]) {

	long err;
	struct btf *temp;
	struct btf *targ_btf, *btf_obj;

	// src_btf == target kernel BTF information
	targ_btf = btf__parse_raw(src_btf);
	err = libbpf_get_error(targ_btf);
	if (err) {
		printf("error: could not parse src_btf: %s", src_btf);
		return -ENOENT;
	}

	for (int i = 0; objspaths[i] != NULL; i++) {
		printf("processing %s object\n", objspaths[i]);

		struct bpf_object_open_opts opts = {};
		opts.sz = sizeof(struct bpf_object_open_opts);
		opts.btf_custom_path = strdup(src_btf);

		struct bpf_object *obj = bpf_object__open_file(objspaths[i], &opts);
		err = libbpf_get_error(obj);
		if (err) {
			printf("error: could not open ebpf object\n");
			return -ENOENT;
		}

		// here we would need to call a function to each bpf_core_relo inside .BTF.ext of obj
		bpf_object_relocate_core(obj, targ_btf, dst_btf);

		bpf_object__close(obj);
	}

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

		//err = generate_btf_01(src_btf_path, dst_btf_path, env.obj);
		err = generate_btf_02(src_btf_path, dst_btf_path, env.obj);
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
