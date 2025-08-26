#include "gdt.h"
#include "vmm.h"
#include <stdio.h>
#include "idt.h"
#include "utils.h"

enum {
    IDTENTRY_TYPE_INTERRUPT = 0xE,
    IDTENTRY_TYPE_TRAP = 0xF,
    IDTENTRY_TYPE_CALL = 0xC,
    IDTENTRY_TYPE_TASK = 0x5,
};

enum {
    IDTENTRY_NUM = 256
};


struct idt_entry {
	uint16_t offset_low;
	uint16_t selector;
	uint16_t ist : 3, zero0 : 5, type : 5, dpl : 2, p : 1;
	uint16_t offset_mid;
	uint32_t offset_high;
	uint32_t zero1;
} __attribute__((packed));

void idt_init(struct kvm_sregs2 *sregs, struct vmm *vmm)
{
    struct frame mem_idt = { 0 };
	if (vmm_get_free_frame(vmm, &mem_idt) != 0) {
		PANIC("get_free_frame");
	}

    vmm_map_addr(vmm, IDT_VADDR, mem_idt.guest_physical_addr);
	struct idt_entry *idt = (struct idt_entry *)mem_idt.host_virtual_addr;

    // Set up a template for a non-present interrupt gate.
	// Any attempt to use this gate will cause a #NP fault (Not Present)
	struct idt_entry entry = { 0 };
	entry.selector = gdt_get_segment(GDT_IDX_CODE).selector;
	entry.type = IDTENTRY_TYPE_INTERRUPT;
    entry.dpl = 0;
    entry.p = 0;

	// Fill the entire IDT with non-present gates.
	for (int i = 0; i < IDTENTRY_NUM; i++) {
		idt[i] = entry;
	}

	// Set the IDTR to point to our new table.
	sregs->idt.base = IDT_VADDR;
	sregs->idt.limit = (IDTENTRY_NUM * sizeof(struct idt_entry)) - 1;
}
