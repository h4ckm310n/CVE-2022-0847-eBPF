# CVE-2022-0847-eBPF
An eBPF program to detect and defense attacks on CVE-2022-0847. 

In the kernel space, the program detects **splice()** system calls, if such a system call contains a pipe as the output fd, and the flags of the pipe buffer is set to **PIPE_BUF_FLAG_CAN_MERGE** , then an event would be submitted. In the user space, the program kills the corresponding process that calls **splice()** , and overwrites **/proc/sys/vm/drop_caches** to clear page cache. 

Tested on Ubuntu Server 20.10 with kernel 5.8.0-25.

## Building

```bash
clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I/usr/src/linux-headers-5.8.0-25/include -I/usr/include -c ./splice.bpf.c -o splice.bpf.o
bpftool gen skeleton ./splice.bpf.o > splice.skel.h
clang -I/usr/include -c splice.c -o splice_epbf.o
clang splice_epbf.o -lbpf -lelf -lz -o splice_epbf
```

