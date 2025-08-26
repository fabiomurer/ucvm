#pragma once

#include <linux/kvm.h>
#include <stdbool.h>

#include "view_linux.h"
#include "vmm.h"

struct vm {
	int kvmfd;
	int vmfd;
	int vcpufd;
	struct kvm_cpuid2 *vcpu_cpuid;
	struct kvm_run *run;

	struct vmm vmm;

	struct linux_view linux_view;

	struct kvm_guest_debug guest_debug;
	bool debug_enabled;
};

struct vm vm_create(void);

void vm_init(struct vm *vm);

void vm_load_program(struct vm *vm, char **argv);

int vm_run(struct vm *vm);

void vm_exit_handler(int exit_code, struct vm *vm);

void vm_set_debug(struct vm *vm, bool enable_debug);

void vm_set_debug_step(struct vm *vm, bool enable_step);

void vm_page_fault_handler(struct vm *vm, uint64_t cr2);

struct kvm_regs *vm_get_regs(struct vm *vm);

struct kvm_sregs *vm_get_sregs(struct vm *vm);

struct kvm_vcpu_events *vm_get_vcpu_events(struct vm *vm);

void vm_set_regs(struct vm *vm);

void vm_set_sregs(struct vm *vm);
