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
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/btf.h>

#define OBJ_KEY 260
#define MAX_OBJECTS 128

static struct env {
	const char *outputdir;
	const char *inputdir;
	const char *obj[MAX_OBJECTS];
	int obj_index;
} env = {
	.obj_index = 0,
};

static const struct argp_option opts[] = {
	{ "outputdir", 'o', "outputdir", 0, "dir to output the result BTF files" },
	{ "inputdir", 'i', "inputdir", 0, "dir with source BTF files to use" },
	{ "object", OBJ_KEY,  "object", 0, "path of object file to generate BTFs for" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'o':
		env.outputdir = arg;
		break;
	case 'i':
		env.inputdir = arg;
		break;
	case OBJ_KEY:
		env.obj[env.obj_index++] = arg;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	/* Set up libbpf errors and debug info callback */
	//libbpf_set_print(libbpf_print_fn);

	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
	};

	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	DIR *d;
	struct dirent *dir;
	d = opendir(env.inputdir);
	if (!d) {
		printf("error opening input dir\n");
		return -1;
	}

	while ((dir = readdir(d)) != NULL) {
		char btf_path[1024];

		int len = strlen(dir->d_name);

		// ignore non BTF files
		if (strcmp(dir->d_name + len - 4, ".btf")) {
			continue;
		}

		snprintf(btf_path, sizeof(btf_path), "%s/%s", env.inputdir, dir->d_name);
		printf("opening %s\n", btf_path);

		// create info struct for each BTF source file
		struct btf_reloc_info *info = bpf_reloc_info_new(btf_path);
		if (info == NULL) {
			printf("failed to allocate info structure");
			return 1;
		}

		for (int i = 0; i < env.obj_index; i++) {
			printf("processing for %s\n", env.obj[i]);

			struct bpf_object *obj = bpf_object__open(env.obj[i]);
			if (libbpf_get_error(obj)) {
				printf("error opening object\n");
				return 1;
			}

			err = bpf_object__reloc_info_gen(info, obj);
			if (err) {
				printf("failed to generate btf info for object\n");
				return 1;
			}

			bpf_object__close(obj);
		}

		snprintf(btf_path, sizeof(btf_path), "%s/prefix-%s", env.outputdir, dir->d_name);

		//btf_reloc_info_dump(info);
		btf_reloc_info_save(info, btf_path);
		bpf_reloc_info_free(info);
	}

	closedir(d);

	printf("done!\n");
	return 0;
}
