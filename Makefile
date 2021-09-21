INCLUDES := -I libbpf_out/usr/include/ -I libbpf/include/uapi/

all: btfgen

LIBBPF_SRC := $(abspath ./libbpf/src)

libbpf_out/usr/lib64/libbpf.a: $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile)
	mkdir -p libbpf_out && cd $(LIBBPF_SRC) && make DESTDIR=../../libbpf_out install -j && cd ../..

btfgen: btfgen.c libbpf_out/usr/lib64/libbpf.a
	gcc -g -o btfgen $(INCLUDES) $^ -lelf -lz

clean:
	rm btfgen
