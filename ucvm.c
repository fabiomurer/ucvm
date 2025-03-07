
#include "load_linux.h"
#include "vm.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
	if (argc < 3) {
		printf("Usage: %s <debug|nodebug> <filename>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	bool debug = false;
	if (strcmp("debug", argv[1]) == 0) debug = true;
	else debug = false;
	

    struct linux_proc linux_proc;
	linux_proc.argv = &argv[2];
	
	struct vm vm = vm_create();
    vm_init(&vm);
    vm_load_program(&vm, &linux_proc);
	if (debug) {
		vm_set_debug(&vm, true);
	} else {
		while(true) {
			int exit_code = vm_run(&vm);
			vm_exit_handler(exit_code, &vm, &linux_proc);
		}
	}
}