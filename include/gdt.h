#pragma once

#include <stdint.h>
#include "vmm.h"

enum {
    GDT_IDX_CODE = 1,
    GDT_IDX_DATA = 2,
};

void gdt_init(struct kvm_sregs2 *sregs, struct vmm *vmm);

struct kvm_segment gdt_get_segment(int idx);


