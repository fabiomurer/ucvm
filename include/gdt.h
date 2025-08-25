#pragma once

#include <stdint.h>
#include "vmm.h"

extern struct kvm_segment gdt_code_segment;
extern struct kvm_segment gdt_data_segment;

void gdt_init(struct kvm_sregs2 *sregs, struct vmm *vmm);


