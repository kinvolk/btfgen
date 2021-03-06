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

#include <bpf/libbpf.h>

struct hashmap;

struct btf_reloc_info {
	struct hashmap *types;
	struct hashmap *ids_map;

	struct btf *src_btf;
};

struct btf_reloc_info *btfgen_reloc_info_new(const char *targ_btf_path);
void btfgen_reloc_info_free(struct btf_reloc_info *info);
int btfgen_obj_reloc_info_gen(struct btf_reloc_info *reloc_info, struct bpf_object *obj);
struct btf *btfgen_reloc_info_get_btf(struct btf_reloc_info *info);
