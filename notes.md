# kvm hardware

## cpu extensions

- xcr0 support `0x1f`: `X87` `SSE` `AVX` `BNDREG` `BNDCSR` `opmask` -> `AVX-512` not supported

# tests

## hello-glibc

strace output and progress
```
execve("./tests/hello-glibc", ["./tests/hello-glibc"], 0x7ffe689b6e08 /* 46 vars */) = 0
brk(NULL)                               = 0x4af000
brk(0x4afd40)                           = 0x4afd40
arch_prctl(ARCH_SET_FS, 0x4af3c0)       = 0
set_tid_address(0x4af690)               = 111188
set_robust_list(0x4af6a0, 24)           = 0
rseq(0x4af340, 0x20, 0, 0x53053053)     = 0
prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
readlinkat(AT_FDCWD, "/proc/self/exe", "/home/fabione/Documents/progetti"..., 4096) = 55
getrandom("\x08\x62\x35\x59\xad\x4f\x66\x34", 8, GRND_NONBLOCK) = 8 
brk(NULL)                               = 0x4afd40
brk(0x4d0d40)                           = 0x4d0d40
brk(0x4d1000)                           = 0x4d1000
mprotect(0x4a2000, 20480, PROT_READ)    = 0 
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0x2), ...}) = 0
write(1, "ciao\n", 5ciao
)                   = 5         (:>)
exit_group(0)                           = ?
+++ exited with 0 +++
```

# glibc problems

when running in ucvm:

```
__run_exit_handlers
	call_fini
		_fini
	40450f:       ff d0                   call   *%rax jump to 0x600 -> crash
```

should be:
```
__run_exit_handlers
	call_fini
		_fini
    call Clean I/0 o roba del genere
```