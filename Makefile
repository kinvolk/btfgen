CC = clang
CFLAGS = -g -static -ggdb -gdwarf -O2
BASEDIR := $(shell pwd)
INCLUDES := -Iinclude -I libbpf_out/usr/include/

#all: btfgen btfgen2
all: btfgen2

LIBBPF_SRC := $(abspath ./libbpf/src)

libbpf_out/usr/lib64/libbpf.a: $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile)
	mkdir -p $(BASEDIR)/libbpf_out && \
		cd $(LIBBPF_SRC) && \
		$(MAKE) DESTDIR=$(BASEDIR)/libbpf_out install && \
		$(MAKE) DESTDIR=$(BASEDIR)/libbpf_out install_uapi_headers && \
		cd ../..

btfgen: btfgen.c libbpf_out/usr/lib64/libbpf.a
	$(CC) $(CFLAGS) btfgen $(INCLUDES) $^ -lelf -lz

btfgen2: btfgen2.c libbpf_out/usr/lib64/libbpf.a
	$(CC) $(CFLAGS) -c $(INCLUDES) hashmap.c
	$(CC) $(CFLAGS) -c $(INCLUDES) stolen.c
	$(CC) $(CFLAGS) -c $(INCLUDES) $^
	$(CC) $(CFLAGS) -o btfgen2 $(INCLUDES) stolen.o hashmap.o $^ -lelf -lz

clean:
	$(MAKE) -C libbpf/src clean
	rm -rf btfgen libbpf_out
