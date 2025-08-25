#pragma once
#include <stdint.h>
#include <linux/kvm.h>

#include "vmm.h"

// to call after vmm is initialized
void idt_init(struct kvm_sregs2 *sregs, struct vmm *vmm);
