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

#include <argp.h>
#include <dirent.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <bpf/libbpf.h>
#include <bpf/btf.h>

#include "btfgen.h"

#define OBJ_KEY 260
#define MAX_OBJECTS 128

#define generate_err(x) {                                               \
	if (err && err == -ENOEXEC) {                                   \
		printf("WARN: generated btf (%s) is poisoned%s\n",      \
			x, env.nopoison ? " (deleting)" : "");          \
		if (env.nopoison)                                       \
			unlink(x);                                      \
	} else if (err) {                                               \
		printf("ERR : failed to generate btf for %s\n", x);     \
		return 1;                                               \
	}                                                               \
}

struct env {
	const char *output, *input;
	const char *obj[MAX_OBJECTS];
	int obj_index;
	bool verbose, nopoison;
	bool infile, outfile;
};

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "display libbpf debug messages" },
	{ "output", 'o', "output", 0, "dir to output the result BTF files" },
	{ "input", 'i', "input", 0, "dir with source BTF files to use" },
	{ "object", OBJ_KEY,  "object", 0, "path of object file to generate BTFs for" },
	{ "nopoison", 'p', NULL, 0, "do not save poisoned BTF files" },
	{},
};

static int is_file(const char *path) {
	struct stat st = {};

	if (stat(path, &st) < 0)
		return -1;

	switch (st.st_mode & S_IFMT) {
	case S_IFDIR:
		return 0;
	case S_IFREG:
		return 1;
	}

	return -1;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct env *env = state->input;
	switch (key) {
	case 'v':
		env->verbose = true;
		break;
	case 'p':
		env->nopoison = true;
		break;
	case 'o':
		env->output = arg;
		env->outfile = is_file(env->output);
		break;
	case 'i':
		env->input = arg;
		env->infile = is_file(env->input);
		break;
	case OBJ_KEY:
		env->obj[env->obj_index++] = arg;
		break;
	case ARGP_KEY_END:
		if (env->output == NULL || env->input == NULL || env->obj_index == 0)
			argp_usage(state);
		if (env->outfile < 0 || env->infile < 0) {
			printf("ERR : could not stat given argument\n");
			argp_usage(state);
		}
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

static int generate_btf(const char *src_btf, const char *dst_btf, const char *objspaths[]) {
	struct btf_reloc_info *reloc_info;
	struct bpf_object *obj;
	struct btf *btf_new = NULL;
	int err;
	bool poisoned = false;

	reloc_info = btfgen_reloc_info_new(src_btf);
	err = libbpf_get_error(reloc_info);
	if (err) {
		printf("ERR : failed to allocate info structure\n");
		goto out;
	}

	struct bpf_object_open_opts ops = {
		.sz = sizeof(ops),
		.btf_custom = reloc_info->src_btf,
		.record_core_relos = true,
	};

	for (int i = 0; objspaths[i] != NULL; i++) {
		printf("OBJ : %s\n", objspaths[i]);
		obj = bpf_object__open_file(objspaths[i], &ops);
		err = libbpf_get_error(obj);
		if (err) {
			printf("ERR : error opening object\n");
			goto out;
		}

		err = bpf_object__prepare(obj);
		if (err) {
			goto out;
		}

		err = btfgen_obj_reloc_info_gen(reloc_info, obj);
		if (err) {
			if (err != -ENOEXEC)
				goto out;
			poisoned = true;
		}

		bpf_object__close(obj);
	}

	btf_new = btfgen_reloc_info_get_btf(reloc_info);
	err = libbpf_get_error(btf_new);
	if (err) {
		printf("ERR : error generating btf\n");
		goto out;
	}

	// target btf
	printf("TBTF: %s\n", dst_btf);
	err = btf__save_raw(btf_new, dst_btf);
	if (err) {
		printf("ERR : error saving btf file\n");
		goto out;
	}

out:
	if (!libbpf_get_error(btf_new))
		btf__free(btf_new);
	btfgen_reloc_info_free(reloc_info);

	if (!err && poisoned)
		return -ENOEXEC;

	return err;
}

int main(int argc, char **argv)
{
	int err;
	char src_btf_path[PATH_MAX];
	char dst_btf_path[PATH_MAX];

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

	if (env.verbose)
		libbpf_set_print(verbose_print);

	// single BTF file

	if (env.infile) {
		printf("LBTF: %s\n", env.input);

		if (env.outfile) {
			err = generate_btf(env.input, env.output, env.obj);
			generate_err(env.output);
		} else {
			snprintf(dst_btf_path, sizeof(dst_btf_path), "%s/%s", env.output, basename(strdup(env.input)));
			err = generate_btf(env.input, dst_btf_path, env.obj);
			generate_err(dst_btf_path);
		}

		return 0;
	}

	if (env.outfile) {
		printf("ERR : can't have just one file as output\n");
		return 1;
	}

	// directory w/ BTF files

	DIR *d;
	struct dirent *dir;

	d = opendir(env.input);
	if (!d) {
		printf("ERR : error opening input dir\n");
		return -1;
	}

	while ((dir = readdir(d)) != NULL) {

		if (dir->d_type != DT_REG)
			continue;

		if (strncmp(dir->d_name + strlen(dir->d_name) - 4, ".btf", 4))
			continue;

		snprintf(src_btf_path, sizeof(src_btf_path), "%s/%s", env.input, dir->d_name);
		snprintf(dst_btf_path, sizeof(dst_btf_path), "%s/%s", env.output, dir->d_name);

		// local BTF
		printf("LBTF: %s\n", src_btf_path);

		err = generate_btf(src_btf_path, dst_btf_path, env.obj);
		generate_err(dst_btf_path);
	}

	closedir(d);

	printf("STAT: done!\n");
	return 0;
}
