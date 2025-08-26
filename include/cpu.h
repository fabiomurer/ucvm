#pragma once

#include "vmm.h"

void cpu_init(int vcpufd, struct kvm_cpuid2* vcpu_cpuid, struct vmm *vmm);

