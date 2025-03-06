# Default target
all: hello-glibc hello hello-glibc-dyn

hello-glibc: hello-glibc.c
	gcc -g -static -o hello-glibc hello-glibc.c

hello-glibc-dyn: hello-glibc.c
	gcc -g -o hello-glibc-dyn hello-glibc.c

hello: hello.c
	gcc -g -static -nostdlib -o hello hello.c 

clean:
	rm -f hello-glibc hello

.PHONY: all clean