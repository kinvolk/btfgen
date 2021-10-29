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

/* bpf_object__relocate_core logic: we need the bpf_core_relos */
int bpf_object_relocate_core(struct bpf_object *obj) {

	int i = 0;

	const struct btf_ext_info_sec *sec;
	const struct bpf_core_relo *rec;
	const struct btf_ext_info *seg;

	struct bpf_program *prog;

	const char *sec_name;

	seg = &obj->btf_ext->core_relo_info;
	for_each_btf_ext_sec(seg, sec)
	{
		sec_name = btf__name_by_offset(obj->btf, sec->sec_name_off);
		if (str_is_empty(sec_name)) {
			printf("error: sec_name is empty\n");
			return -1;
		}
		printf("sec_name = %s\n", sec_name);

		prog = NULL;
		for (i = 0; i < obj->nr_programs; i++) {
			prog = &obj->programs[i];
			if (strcmp(prog->sec_name, sec_name) == 0)
				break;
		}
		if (!prog) {
			printf("sec '%s': failed to find a BPF program\n", sec_name);
			return -ENOENT;
		}

		int sec_idx = prog->sec_idx;

		printf("sec '%s': found %d CO-RE relocations\n", sec_name, sec->num_info);

		for_each_btf_ext_rec(seg, sec, i, rec)
		{
			int insn_idx = rec->insn_off / BPF_INSN_SZ;
			// each rec, here, is a bpf_core_relo for us to discover types in target BTF
			// we can do something like bpf_core_find_cands
		}
	}

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
		bpf_object_relocate_core(obj);

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
