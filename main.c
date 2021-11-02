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

#include <bpf/libbpf.h>
#include <bpf/btf.h>

#include "btfgen.h"

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

static int generate_btf(const char *src_btf, const char *dst_btf, const char *objspaths[]) {
	struct btf_reloc_info *reloc_info;
	struct bpf_object *obj;
	struct btf *btf_new;
	int err;

	struct bpf_object_open_opts ops = {
		.sz = sizeof(ops),
		.btf_custom_path = src_btf,
	};

	reloc_info = bpf_reloc_info__new(src_btf);
	err = libbpf_get_error(reloc_info);
	if (err) {
		printf("failed to allocate info structure\n");
		goto out;
	}

	for (int i = 0; objspaths[i] != NULL; i++) {
		printf("processing %s object\n", objspaths[i]);
		obj = bpf_object__open_file(objspaths[i], &ops);
		err = libbpf_get_error(obj);
		if (err) {
			printf("error opening object\n");
			goto out;
		}

        struct bpf_object_prepare_attr attr = {
            .obj = obj,
            .record_core_relos = true,
        };

        err = bpf_object__prepare_xattr(&attr);
        if (err) {
            goto out;
        }

		err = bpf_object__reloc_info_gen(reloc_info, obj);
		if (err) {
			goto out;
		}

		bpf_object__close(obj);
	}

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