#pragma once 

#include <linux/kvm.h>
#include "load_linux.h"

struct vm {
    int kvmfd;
    int vmfd;
    int vcpufd;
    struct kvm_run* run;
    void* memory;
};

struct vm vm_create(void);

void vm_init(struct vm* vm);

void vm_load_program(struct vm* vm, struct linux_proc* linux_proc);

void vm_run(struct vm* vm, struct linux_proc* linux_proc);