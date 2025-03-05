
#include "load_linux.h"
#include "vm.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
	if (argc < 2) {
		printf("Usage: %s <filename>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

    struct linux_proc linux_proc;
	linux_proc.argv = &argv[1];
	
	struct vm vm = vm_create();
    vm_init(&vm);
    vm_load_program(&vm, &linux_proc);
    vm_run(&vm, &linux_proc);
}