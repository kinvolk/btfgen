#ifndef __STOLEN_H
#define __STOLEN_H

#include <stdbool.h>
#include <libelf.h>
#include <gelf.h>
#include <bpf/bpf.h>

static inline bool str_is_empty(const char *s)
{
	return !s || !s[0];
}

struct list_head {
	struct list_head *next, *prev;
};

#define BPF_OBJ_NAME_LEN 16U

struct elf_state {
	int fd;
	const void *obj_buf;
	size_t obj_buf_sz;
	Elf *elf;
	Elf64_Ehdr *ehdr;
	Elf_Data *symbols;
	Elf_Data *st_ops_data;
	size_t shstrndx; /* section index for section name strings */
	size_t strtabidx;
	struct elf_sec_desc *secs;
	int sec_cnt;
	int maps_shndx;
	int btf_maps_shndx;
	__u32 btf_maps_sec_btf_id;
	int text_shndx;
	int symbols_shndx;
	int st_ops_shndx;
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

	bool loaded;
	bool has_subcalls;
	bool has_rodata;

	struct bpf_gen *gen_loader;

	/* Information when doing ELF related work. Only valid if efile.elf is not NULL */
	struct elf_state efile;
	/*
	 * All loaded bpf_object are linked in a list, which is
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

/* libbpf_internal.h */

struct btf_ext_info {
	/*
	 * info points to the individual info section (e.g. func_info and
	 * line_info) from the .BTF.ext. It does not include the __u32 rec_size.
	 */
	void *info;
	__u32 rec_size;
	__u32 len;
};

#define for_each_btf_ext_sec(seg, sec)					\
	for (sec = (seg)->info;						\
	     (void *)sec < (seg)->info + (seg)->len;			\
	     sec = (void *)sec + sizeof(struct btf_ext_info_sec) +	\
		   (seg)->rec_size * sec->num_info)

#define for_each_btf_ext_rec(seg, sec, i, rec)				\
	for (i = 0, rec = (void *)&(sec)->data;				\
	     i < (sec)->num_info;					\
	     i++, rec = (void *)rec + (seg)->rec_size)

struct btf_ext_header {
	__u16	magic;
	__u8	version;
	__u8	flags;
	__u32	hdr_len;

	__u32	func_info_off;
	__u32	func_info_len;
	__u32	line_info_off;
	__u32	line_info_len;

	__u32	core_relo_off;
	__u32	core_relo_len;
};

struct btf_ext {
	union {
		struct btf_ext_header *hdr;
		void *data;
	};
	struct btf_ext_info func_info;
	struct btf_ext_info line_info;
	struct btf_ext_info core_relo_info;
	__u32 data_size;
};

struct btf_ext_info_sec {
	__u32	sec_name_off;
	__u32	num_info;
	__u8	data[];
};

struct bpf_func_info_min {
	__u32   insn_off;
	__u32   type_id;
};

struct bpf_line_info_min {
	__u32	insn_off;
	__u32	file_name_off;
	__u32	line_off;
	__u32	line_col;
};

// libbpf.{h,c}

struct bpf_program {
	const struct bpf_sec_def *sec_def;
	char *sec_name;

	size_t sec_idx;
	size_t sec_insn_off;
	size_t sec_insn_cnt;

	size_t sub_insn_off;

	char *name;

	char *pin_name;

	struct bpf_insn *insns;

	size_t insns_cnt;

	struct reloc_desc *reloc_desc;
	int nr_reloc;
	int log_level;

	struct {
		int nr;
		int *fds;
	} instances;
	int (*bpf_program_prep_t)(void *, int, void *, int, void *);

	struct bpf_object *obj;
	void *priv;
	void (*bpf_program_clear_priv_t)(void *, void *);

	bool load;
	bool mark_btf_static;
	enum bpf_prog_type type;
	enum bpf_attach_type expected_attach_type;
	int prog_ifindex;
	__u32 attach_btf_obj_fd;
	__u32 attach_btf_id;
	__u32 attach_prog_fd;
	void *func_info;
	__u32 func_info_rec_size;
	__u32 func_info_cnt;

	void *line_info;
	__u32 line_info_rec_size;
	__u32 line_info_cnt;
	__u32 prog_flags;
};

#define BPF_INSN_SZ (sizeof(struct bpf_insn))

/* relo_core.h */

enum bpf_core_relo_kind {
	BPF_FIELD_BYTE_OFFSET = 0,	/* field byte offset */
	BPF_FIELD_BYTE_SIZE = 1,	/* field size in bytes */
	BPF_FIELD_EXISTS = 2,		/* field existence in target kernel */
	BPF_FIELD_SIGNED = 3,		/* field signedness (0 - unsigned, 1 - signed) */
	BPF_FIELD_LSHIFT_U64 = 4,	/* bitfield-specific left bitshift */
	BPF_FIELD_RSHIFT_U64 = 5,	/* bitfield-specific right bitshift */
	BPF_TYPE_ID_LOCAL = 6,		/* type ID in local BPF object */
	BPF_TYPE_ID_TARGET = 7,		/* type ID in target kernel */
	BPF_TYPE_EXISTS = 8,		/* type existence in target kernel */
	BPF_TYPE_SIZE = 9,		/* type size in bytes */
	BPF_ENUMVAL_EXISTS = 10,	/* enum value existence in target kernel */
	BPF_ENUMVAL_VALUE = 11,		/* enum value integer value */
};

struct bpf_core_relo {
	__u32   insn_off;
	__u32   type_id;
	__u32   access_str_off;
	enum bpf_core_relo_kind kind;
};

#endif
