#pragma once

#include <linux/kvm.h>
#include <stdbool.h>

#include "load_linux.h"

struct vm {
	int kvmfd;
	int vmfd;
	int vcpufd;
	struct kvm_run *run;
	void *memory;
	struct kvm_guest_debug guest_debug;
	bool debug_enabled;
};

struct vm vm_create(void);

void vm_init(struct vm *vm);

void vm_load_program(struct vm *vm, struct linux_proc *linux_proc);

int vm_run(struct vm *vm);

void vm_exit_handler(int exit_code, struct vm *vm, struct linux_proc *linux_proc);

void vm_set_debug(struct vm *vm, bool enable_debug);

void vm_set_debug_step(struct vm *vm, bool enable_step);
