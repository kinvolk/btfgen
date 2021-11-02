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

struct bpf_reloc_info;

struct btf_reloc_info *bpf_reloc_info__new(const char *targ_btf_path);
void bpf_reloc_info__free(struct btf_reloc_info *info);
int bpf_object__reloc_info_gen(struct btf_reloc_info *reloc_info, struct bpf_object *obj);
struct btf *bpf_reloc_info__get_btf(struct btf_reloc_info *info);
