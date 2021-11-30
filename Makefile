CC = gcc
BASEDIR := $(shell pwd)
INCLUDES := -I libbpf_out/usr/include/ -I /usr/include/ -I.

all: btfgen

LIBBPF_SRC := $(abspath ./libbpf/src)

libbpf_out/usr/lib64/libbpf.a: $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile)
	mkdir -p $(BASEDIR)/libbpf_out && \
		cd $(LIBBPF_SRC) && \
		$(MAKE) DESTDIR=$(BASEDIR)/libbpf_out install && \
		$(MAKE) DESTDIR=$(BASEDIR)/libbpf_out install_uapi_headers && \
		cd ../..

btfgen: main.c btfgen.c libbpf_out/usr/lib64/libbpf.a
	$(CC) -g -O2 -static -o btfgen $(INCLUDES) $^ -lelf -lz

.PHONY: debug
debug: main.c btfgen.c libbpf_out/usr/lib64/libbpf.a
	$(CC) -g -ggdb -gdwarf -fsanitize=address -O0 -fno-omit-frame-pointer -o btfgen $(INCLUDES) $^ -lelf -lz


.PHONY: clean-libbpf
clean-libbpf:
	$(MAKE) -C libbpf/src clean

clean:
	rm -rf btfgen libbpf_out
