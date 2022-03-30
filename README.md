# **NOTE**

**This support has been merged into bpftool, please check https://kinvolk.io/blog/2022/03/btfgen-one-step-closer-to-truly-portable-ebpf-programs/ to learn more.**


# BTF GEN

BTF GEN is a utility program that generates the BTF information that is needed
for an eBPF program by using a set of kernel BTF files. This is useful to run
eBPF programs that use Compile Once - Run Everywhere in kernels that don't
expose BTF information (`CONFIG_DEBUG_INFO_BTF` not enabled). By using this
tool, a developer can ship the eBPF program and the BTF information needed to
run it on different kernels. The size of the BTF info for each kernel for a
specific program is some hundreds of bytes in most of the cases.

**Note: This is an experimental repository. We plan to upstream these changes to
libbpf and probably bpftool too.**

## How does it work?

The logic to calculate the BTF information that is needed for an eBPF program is
implemented in our libbpf [temporal
fork](https://github.com/kinvolk/libbpf/commits/btfgen). We decided to reuse all
the relocation logic existing already in libbpf to generate the data types that
an eBPF program requires.

This repository and our libbpf fork are just temporal PoCs until we start
upstreaming this support into libbpf and likely into bpftool too.

## How to install

Only compilation from source code is supported now

```
$ git clone git@github.com:kinvolk/btfgen.git --recursive
$ cd btfgen
$ make
$ ./btfgen --help
```

## How to use

1. Compile your eBPF programs using
   [CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html)
   to an object file.
2. Get a list of BTFs for the kernels you want to generate the information for.
   You can use [btfhub](https://github.com/aquasecurity/btfhub) or extract that
   information from the debugging packages for the different kernels. (Look into
   the [update.sh](https://github.com/aquasecurity/btfhub/blob/main/update.sh)
   script of btfhub to get more information about how to do it).
3. Execute btfgen to generate BTF for the different kernels.

```
./btfgen --inputdir=<dir where the kernel btfs are stored> \
          --outputdir=<dir where you want to save the generated BTFs> \
          --object=<path to bpf object> \
          --object=<path to another bpf object>
```
4. Deploy the generated BTF files to the target machine.
5. Install the correct BTF file according to the kernel of the target machine.
6. Run the executable that loads your eBPF program.

## Demo

This section provides more details about the usage of this utility. This section
shows how BTF gen can be used to run some of the BCC libbf-tools in machines
without `CONFIG_DEBUG_INFO_BTF` enabled.

### Prepare a root dir for this demo

```
$ mkdir /tmp/btfgendemo
```

### Download and compile BCC libbpf tools

```
$ cd /tmp/btfgendemo
$ git clone https://github.com/iovisor/bcc -b v0.21.0 --recursive
```

libbpf has a hardcoded list of paths to look for the kernel BTF information.
Let's add an additional path where we'll put the generated BTF file.

```
# /tmp/bcc.patch
diff --git a/src/btf.c b/src/btf.c
index b46760b..4f9dfbf 100644
@@ -4400,6 +4400,9 @@ struct btf *libbpf_find_kernel_btf(void)
 		const char *path_fmt;
 		bool raw_btf;
 	} locations[] = {
+		/* try custom path first*/
+		{ "/tmp/vmlinux.btf", true /* raw BTF */ },
+
 		/* try canonical vmlinux BTF through sysfs first */
 		{ "/sys/kernel/btf/vmlinux", true /* raw BTF */ },
 		/* fall back to trying to find vmlinux ELF on disk otherwise */
```

```
$ cd src/cc/libbpf/
$ git apply /tmp/bcc.patch
```

Compile the libbpf and the tools

```
$ cd ../../../libbpf-tools/
$ make
```

### Get BTF files for different kernels

In this case we use btfhub and only consider the files for Ubuntu Focal.

```
$ cd /tmp/btfgendemo
$ git clone https://github.com/aquasecurity/btfhub
$ cd btfhub/ubuntu/focal/x86_64/
$ for f in *.tar.xz; do tar -xf "$f"; done
$ ls -lh *.btf | head
```

As you can see, the size of the BTF file for each kernel is around 4 MB.

### Generate BTF for some BCC ebpf programs

```
$ OBJ1=/tmp/btfgendemo/bcc/libbpf-tools/.output/execsnoop.bpf.o
$ OBJ2=/tmp/btfgendemo/bcc/libbpf-tools/.output/opensnoop.bpf.o
$ OBJ3=/tmp/btfgendemo/bcc/libbpf-tools/.output/bindsnoop.bpf.o

$ mkdir /tmp/btfgendemo/btfs
$ ./btfgen --inputdir=/tmp/btfgendemo/btfhub/ubuntu/focal/x86_64/ \
            --outputdir=/tmp/btfgendemo/btfs \
            --obj=$OBJ1 --obj=$OBJ2 --obj=$OBJ3
```

### Test it out

Create a VM with Ubuntu Focal. The following Vagrantfile can be used:

```
# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"
  config.vm.synced_folder "/tmp/btfgendemo", "/btfgendemo", type: "sshfs"

  config.vm.provider "virtualbox" do |vb|
    # Display the VirtualBox GUI when booting the machine
    vb.gui = false

    vb.cpus = 8
    vb.memory = "8192"
  end
end
```

```
$ vagrant up
$ vagrant ssh
```

The following commands must be executed inside the VM

Let's check that the kernel doesn't have CONFIG_DEBUG_INFO_BTF enabled.

```
$ cat /boot/config-$(uname -r) | grep CONFIG_DEBUG_INFO_BTF
# CONFIG_DEBUG_INFO_BTF is not set
```

Let's try to run some of the tools before providing the BTF information.

```
$ sudo /btfgendemo/bcc/libbpf-tools/execsnoop
libbpf: failed to find valid kernel BTF
libbpf: Error loading vmlinux BTF: -3
libbpf: failed to load object 'execsnoop_bpf'
libbpf: failed to load BPF skeleton 'execsnoop_bpf': -3
failed to load BPF object: -3
```

As expected, the tool is failing because it's not able to find the BTF
information required to perform the CO-RE relocations.

Install the right BTF file for this kernel

```
$ cp /btfgendemo/btfs/prefix-$(uname -r).btf /tmp/vmlinux.btf
```

After this, the different tools work fine.

```
# try out the different BCC tools
$ sudo /btfgendemo/bcc/libbpf-tools/execsnoop
PCOMM            PID    PPID   RET ARGS
^C

$ sudo /btfgendemo/bcc/libbpf-tools/bindsnoop
PID     COMM             RET PROTO OPTS  IF   PORT  ADDR
^C

$ sudo /btfgendemo/bcc/libbpf-tools/opensnoop
PID    COMM              FD ERR PATH
^C
```

## Code of Conduct

This project follows the [Microsoft Code of Conduct](https://opensource.microsoft.com/codeofconduct).
