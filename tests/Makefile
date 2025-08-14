# Default target
all: hello-glibc hello hello-glibc-dyn test-syscall test-cpu test-io nothing-glibc test-vdso

nothing-glibc: nothing-glibc.c
	gcc -g -static -o nothing-glibc nothing-glibc.c

hello-glibc: hello-glibc.c
	gcc -g -static -o hello-glibc hello-glibc.c

hello-glibc-dyn: hello-glibc.c
	gcc -g -o hello-glibc-dyn hello-glibc.c

hello: hello.c
	gcc -g -static -nostdlib -o hello hello.c 

test-syscall: test-syscall.c
	gcc -static -nostdlib -o test-syscall test-syscall.c 

test-cpu: test-cpu.c
	gcc -static -nostdlib -o test-cpu test-cpu.c 

test-io: test-io.c
	gcc -static -nostdlib -o test-io test-io.c

test-vdso: test-vdso.c
	gcc -o test-vdso test-vdso.c

clean:
	rm -f hello-glibc hello hello-glibc-dyn test-syscall test-cpu nothing-glibc test-io test-vdso


.PHONY: all clean