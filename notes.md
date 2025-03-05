# kvm hardware

## cpu extensions

- xcr0 support `0x1f`: `X87` `SSE` `AVX` `BNDREG` `BNDCSR` `opmask` -> `AVX-512` not supported

# tests

## hello-glibc

strace output and progress
```
execve("./tests/hello-glibc", ["./tests/hello-glibc"], 0x7ffcbb646c80 /* 43 vars */) = 0
brk(NULL)                               = 0x3c458000
brk(0x3c458d40)                         = 0x3c458d40
arch_prctl(ARCH_SET_FS, 0x3c4583c0)     = 0           
set_tid_address(0x3c458690)             = 49828     
set_robust_list(0x3c4586a0, 24)         = 0         
rseq(0x3c458340, 0x20, 0, 0x53053053)   = 0         
prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0    
readlinkat(AT_FDCWD, "/proc/self/exe", "/home/fabio/Documents/projects/u"..., 4096) = 53 
getrandom("\xc4\x50\xa2\x52\xb7\x00\x3c\x18", 8, GRND_NONBLOCK) = 8 (:>)
brk(NULL)                               = 0x3c458d40
brk(0x3c479d40)                         = 0x3c479d40
brk(0x3c47a000)                         = 0x3c47a000
mprotect(0x49f000, 20480, PROT_READ)    = 0
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0x3), ...}) = 0
write(1, "ciao\n", 5ciao
)                   = 5
exit_group(0)                           = ?
+++ exited with 0 +++
```