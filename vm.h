#pragma once 

#include <linux/kvm.h>

struct vm {
    int kvmfd;
    int vmfd;
    int vcpufd;
    struct kvm_run* run;
    void* memory;
};

struct vm vm_create(void);