# kvm hardware

## cpu extensions

- xcr0 support `0x1f`: `X87` `SSE` `AVX` `BNDREG` `BNDCSR` `opmask` -> `AVX-512` not supported

## !! watch cpu register initialization value
has to be the same as when linux runs it.


## to dynamic

strace -n ../ucvm/tests/hello-glibc-dyn 
```
[  59] execve("../ucvm/tests/hello-glibc-dyn", ["../ucvm/tests/hello-glibc-dyn"], 0x7ffe69eff838 /* 44 vars */) = 0
[  12] brk(NULL)                        = 0x55afec0c1000
[   9] mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f209477a000
[  21] access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)
[ 257] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
[   5] fstat(3, {st_mode=S_IFREG|0644, st_size=116634, ...}) = 0
[   9] mmap(NULL, 116634, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f209475d000
[   3] close(3)                         = 0
[ 257] openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
[   0] read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0p\236\2\0\0\0\0\0"..., 832) = 832
[  17] pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 840, 64) = 840
[   5] fstat(3, {st_mode=S_IFREG|0755, st_size=2003408, ...}) = 0
[  17] pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 840, 64) = 840
[   9] mmap(NULL, 2055800, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f2094567000
[   9] mmap(0x7f209458f000, 1462272, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x7f209458f000
[   9] mmap(0x7f20946f4000, 352256, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x18d000) = 0x7f20946f4000
[   9] mmap(0x7f209474a000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e2000) = 0x7f209474a000
[   9] mmap(0x7f2094750000, 52856, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f2094750000
[   3] close(3)                         = 0
[   9] mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f2094564000
[ 158] arch_prctl(ARCH_SET_FS, 0x7f2094564740) = 0
[ 218] set_tid_address(0x7f2094564a10)  = 14060
[ 273] set_robust_list(0x7f2094564a20, 24) = 0
[ 334] rseq(0x7f2094564680, 0x20, 0, 0x53053053) = 0
[  10] mprotect(0x7f209474a000, 16384, PROT_READ) = 0
[  10] mprotect(0x55afd3ed7000, 4096, PROT_READ) = 0
[  10] mprotect(0x7f20947b6000, 8192, PROT_READ) = 0
[ 302] prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
[  11] munmap(0x7f209475d000, 116634)   = 0
[   5] fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0x3), ...}) = 0
[ 318] getrandom("\x6b\xfc\x49\xcf\x94\x36\x13\x57", 8, GRND_NONBLOCK) = 8
[  12] brk(NULL)                        = 0x55afec0c1000
[  12] brk(0x55afec0e2000)              = 0x55afec0e2000
[   1] write(1, "ciao\n", 5ciao
)            = 5
[ 231] exit_group(0)                    = ?
[ 231] +++ exited with 0 +++
```