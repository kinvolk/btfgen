#ifndef __STOLEN_H
#define __STOLEN_H

#include <btfgen2.h>
#include <stdbool.h>
#include <stddef.h>
#include <libelf.h>
#include <gelf.h>
#include <linux/types.h>

#define BPF_CORE_SPEC_MAX_LEN 64
#define BPF_OBJ_NAME_LEN 16U

/* bpf_core_relo_kind encodes which aspect of captured field/type/enum value
 * has to be adjusted by relocations.
 */
enum bpf_core_relo_kind {
	BPF_FIELD_BYTE_OFFSET = 0, /* field byte offset */
	BPF_FIELD_BYTE_SIZE = 1, /* field size in bytes */
	BPF_FIELD_EXISTS = 2, /* field existence in target kernel */
	BPF_FIELD_SIGNED = 3, /* field signedness (0 - unsigned, 1 - signed) */
	BPF_FIELD_LSHIFT_U64 = 4, /* bitfield-specific left bitshift */
	BPF_FIELD_RSHIFT_U64 = 5, /* bitfield-specific right bitshift */
	BPF_TYPE_ID_LOCAL = 6, /* type ID in local BPF object */
	BPF_TYPE_ID_TARGET = 7, /* type ID in target kernel */
	BPF_TYPE_EXISTS = 8, /* type existence in target kernel */
	BPF_TYPE_SIZE = 9, /* type size in bytes */
	BPF_ENUMVAL_EXISTS = 10, /* enum value existence in target kernel */
	BPF_ENUMVAL_VALUE = 11, /* enum value integer value */
};

/* represents BPF CO-RE field or array element accessor */
struct bpf_core_accessor {
	__u32 type_id; /* struct/union type or array element type */
	__u32 idx; /* field index or array index */
	const char *name; /* field name or NULL for array accessor */
};

struct bpf_core_spec {
	const struct btf *btf;
	/* high-level spec: named fields and array indices only */
	struct bpf_core_accessor spec[BPF_CORE_SPEC_MAX_LEN];
	/* original unresolved (no skip_mods_or_typedefs) root type ID */
	__u32 root_type_id;
	/* CO-RE relocation kind */
	enum bpf_core_relo_kind relo_kind;
	/* high-level spec length */
	int len;
	/* raw, low-level spec: 1-to-1 with accessor spec string */
	int raw_spec[BPF_CORE_SPEC_MAX_LEN];
	/* raw spec length */
	int raw_len;
	/* field bit offset represented by spec */
	__u32 bit_offset;
};


struct list_head {
	struct list_head *next, *prev;
};

struct btf {
	/* raw BTF data in native endianness */
	void *raw_data;
	/* raw BTF data in non-native endianness */
	void *raw_data_swapped;
	__u32 raw_size;
	/* whether target endianness differs from the native one */
	bool swapped_endian;

	/*
	 * When BTF is loaded from an ELF or raw memory it is stored
	 * in a contiguous memory block. The hdr, type_data, and, strs_data
	 * point inside that memory region to their respective parts of BTF
	 * representation:
	 *
	 * +--------------------------------+
	 * |  Header  |  Types  |  Strings  |
	 * +--------------------------------+
	 * ^          ^         ^
	 * |          |         |
	 * hdr        |         |
	 * types_data-+         |
	 * strs_data------------+
	 *
	 * If BTF data is later modified, e.g., due to types added or
	 * removed, BTF deduplication performed, etc, this contiguous
	 * representation is broken up into three independently allocated
	 * memory regions to be able to modify them independently.
	 * raw_data is nulled out at that point, but can be later allocated
	 * and cached again if user calls btf__get_raw_data(), at which point
	 * raw_data will contain a contiguous copy of header, types, and
	 * strings:
	 *
	 * +----------+  +---------+  +-----------+
	 * |  Header  |  |  Types  |  |  Strings  |
	 * +----------+  +---------+  +-----------+
	 * ^             ^            ^
	 * |             |            |
	 * hdr           |            |
	 * types_data----+            |
	 * strset__data(strs_set)-----+
	 *
	 *               +----------+---------+-----------+
	 *               |  Header  |  Types  |  Strings  |
	 * raw_data----->+----------+---------+-----------+
	 */
	struct btf_header *hdr;

	void *types_data;
	size_t types_data_cap; /* used size stored in hdr->type_len */

	/* type ID to `struct btf_type *` lookup index
	 * type_offs[0] corresponds to the first non-VOID type:
	 *   - for base BTF it's type [1];
	 *   - for split BTF it's the first non-base BTF type.
	 */
	__u32 *type_offs;
	size_t type_offs_cap;
	/* number of types in this BTF instance:
	 *   - doesn't include special [0] void type;
	 *   - for split BTF counts number of types added on top of base BTF.
	 */
	__u32 nr_types;
	/* if not NULL, points to the base BTF on top of which the current
	 * split BTF is based
	 */
	struct btf *base_btf;
	/* BTF type ID of the first type in this BTF instance:
	 *   - for base BTF it's equal to 1;
	 *   - for split BTF it's equal to biggest type ID of base BTF plus 1.
	 */
	int start_id;
	/* logical string offset of this BTF instance:
	 *   - for base BTF it's equal to 0;
	 *   - for split BTF it's equal to total size of base BTF's string section size.
	 */
	int start_str_off;

	/* only one of strs_data or strs_set can be non-NULL, depending on
	 * whether BTF is in a modifiable state (strs_set is used) or not
	 * (strs_data points inside raw_data)
	 */
	void *strs_data;
	/* a set of unique strings */
	struct strset *strs_set;
	/* whether strings are already deduplicated */
	bool strs_deduped;

	/* BTF object FD, if loaded into kernel */
	int fd;

	/* Pointer size (in bytes) for a target architecture of this BTF */
	int ptr_sz;
};

struct bpf_object {
	char name[BPF_OBJ_NAME_LEN];
	char license[64];
	__u32 kern_version;

	struct bpf_program *programs;
	size_t nr_programs;
	struct bpf_map *maps;
	size_t nr_maps;
	size_t maps_cap;

	char *kconfig;
	struct extern_desc *externs;
	int nr_extern;
	int kconfig_map_idx;
	int rodata_map_idx;

	bool loaded;
	bool has_subcalls;

	struct bpf_gen *gen_loader;

	/*
	 * Information when doing elf related work. Only valid if fd
	 * is valid.
	 */
	struct {
		int fd;
		const void *obj_buf;
		size_t obj_buf_sz;
		Elf *elf;
		GElf_Ehdr ehdr;
		Elf_Data *symbols;
		Elf_Data *data;
		Elf_Data *rodata;
		Elf_Data *bss;
		Elf_Data *st_ops_data;
		size_t shstrndx; /* section index for section name strings */
		size_t strtabidx;
		struct {
			GElf_Shdr shdr;
			Elf_Data *data;
		} *reloc_sects;
		int nr_reloc_sects;
		int maps_shndx;
		int btf_maps_shndx;
		__u32 btf_maps_sec_btf_id;
		int text_shndx;
		int symbols_shndx;
		int data_shndx;
		int rodata_shndx;
		int bss_shndx;
		int st_ops_shndx;
	} efile;
	/*
	 * All loaded bpf_object is linked in a list, which is
	 * hidden to caller. bpf_objects__<func> handlers deal with
	 * all objects.
	 */
	struct list_head list;

	struct btf *btf;
	struct btf_ext *btf_ext;

	/* Parse and load BTF vmlinux if any of the programs in the object need
	 * it at load time.
	 */
	struct btf *btf_vmlinux;
	/* Path to the custom BTF to be used for BPF CO-RE relocations as an
	 * override for vmlinux BTF.
	 */
	char *btf_custom_path;
	/* vmlinux BTF override for CO-RE relocations */
	struct btf *btf_vmlinux_override;
	/* Lazily initialized kernel module BTFs */
	struct module_btf *btf_modules;
	bool btf_modules_loaded;
	size_t btf_module_cnt;
	size_t btf_module_cap;

	void *priv;
	void (*bpf_object_clear_priv_t)(struct bpf_object *, void *);

	int *fd_array;
	size_t fd_array_cap;
	size_t fd_array_cnt;

	char path[];
};

struct btf_type *btf_type_by_id(struct btf *, __u32);
const struct btf_type *btf__type_by_id(const struct btf *, __u32);

#endif
