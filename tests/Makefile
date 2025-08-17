# Default target
all: hello-glibc hello hello-glibc-dyn test-syscall test-cpu test-io nothing-glibc test-vdso read_secrets cpu-privileges

nothing-glibc: nothing-glibc.c
	gcc -g -static -o nothing-glibc nothing-glibc.c

hello-glibc: hello-glibc.c
	gcc -g -static -o hello-glibc hello-glibc.c

hello-glibc-dyn: hello-glibc.c
	gcc -g -o hello-glibc-dyn hello-glibc.c

hello: hello.c syscall.h
	gcc -g -static -nostdlib -o hello hello.c 

test-syscall: test-syscall.c syscall.h
	gcc -static -nostdlib -o test-syscall test-syscall.c 

test-cpu: test-cpu.c syscall.h
	gcc -static -nostdlib -o test-cpu test-cpu.c 

test-io: test-io.c syscall.h
	gcc -static -nostdlib -o test-io test-io.c

read_secrets: read_secrets.c
	gcc -o read_secrets read_secrets.c

test-vdso: test-vdso.c
	gcc -o test-vdso test-vdso.c

cpu-privileges: cpu-privileges.c
	gcc -static -nostdlib -o cpu-privileges cpu-privileges.c

clean:
	rm -f hello-glibc hello hello-glibc-dyn test-syscall test-cpu nothing-glibc test-io test-vdso read_secrets cpu-privileges
.PHONY: all clean