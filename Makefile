CC = gcc
BASEDIR := $(shell pwd)
INCLUDES := -I libbpf_out/usr/include/

all: btfgen

LIBBPF_SRC := $(abspath ./libbpf/src)

libbpf_out/usr/lib64/libbpf.a: $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile)
	mkdir -p $(BASEDIR)/libbpf_out && \
		cd $(LIBBPF_SRC) && \
		$(MAKE) DESTDIR=$(BASEDIR)/libbpf_out install && \
		$(MAKE) DESTDIR=$(BASEDIR)/libbpf_out install_uapi_headers && \
		cd ../..

btfgen: btfgen.c libbpf_out/usr/lib64/libbpf.a
	$(CC) -g -static -ggdb -gdwarf -O2 -o btfgen $(INCLUDES) $^ -lelf -lz

clean:
	$(MAKE) -C libbpf/src clean
	rm -rf btfgen libbpf_out
