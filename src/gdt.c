
#include <linux/kvm.h>
#include <stdio.h>
#include "vmm.h"
#include "utils.h"
#include "gdt.h"

/*
GDT entry 8 bytes long -> 64 bits

## Global Descriptor Table
| Address 			 | Content
| ------------------ | -------
| GDTR Offset + 0 	| Null
| GDTR Offset + 8 	| Entry 1
| GDTR Offset + 16 	| Entry 2
| GDTR Offset + 24 	| Entry 3

## GDT entry

- (0-15)	limit0 always 0 in 64 bit mode
- (16-31)	base0  ...
- (32,39) 	base1

## access bytes (40,47)
- type 4 bit
    - A accessed bit CPU set it when segment is accessed unless set to 1 in
advance
    - RW code (write newer allowed) -> read if 1, data (read always allowed)
write if 1
    - DC for data->direction bit 0 := up, code-> 0 executed if cpu in dlp
    - E Executable bit, 1 := executable segment
Types available in Long Mode:
    0x2: LDT
    0x9: 64-bit TSS (Available)
    0xB: 64-bit TSS (Busy)

- s Descriptor type, 0 := system segment, 1 := code or data segment
- 2 bit dlp CPU Privilege level of the segment. (0 kernel-3 user)
- p present bit. Must be set (1) for any valid segment
- limit1

## flags
- avl reserved
- l long mode flag if 1 defines a 64-bit code segment, When set, DB = 0, other
type of segment = 0
- d (DB) size flag 0 16 bit segment 1 32 bit segment
- G If 0, the Limit is in 1 Byte blocks. If 1, the Limit is in 4 KiB blocks

- base2
*/

#define S_DATA_OR_CODE 0b1
#define S_SYSTEM 0b0
#define DLP_KERNEL 0b00
#define DLP_USER 0b11
#define P_VALID 0b1
#define P_INVALID 0b0
#define L_LONGMODE_CODE 0b1
#define L_OTHER 0b0
#define D_LONGMODE 0b0
#define G_4KIB 0b1

#define TYPE_A_ACCES_DONTSET 0b1
#define TYPE_RW_CODE_READ 0b10
#define TYPE_RW_DATA_WRITE 0b10
#define TYPE_DC_DATA_DIRECTION_UP 0b000
#define TYPE_DC_CODE_EXEC_IFDLP 0b000
#define TYPE_E_CODE 0b1000
#define TYPE_E_DATA 0b0000

#define AVL 0
#define RPL_USER 3

struct gdt_entry {
	uint64_t limit0;
	uint64_t base0;
	uint64_t base1 : 8, type : 4, s : 1, dpl : 2, p : 1;
	uint64_t limit1 : 4, avl : 1, l : 1, d : 1, g : 1, base2 : 8;
} __attribute__((packed));

const struct gdt_entry CODE_SEG = {
	.limit0 = 0xFFFF,
	.base0 = 0,
	.base1 = 0,
	.type = (TYPE_A_ACCES_DONTSET | TYPE_RW_CODE_READ | TYPE_DC_CODE_EXEC_IFDLP | TYPE_E_CODE),
	.s = S_DATA_OR_CODE,
	.dpl = DLP_KERNEL, // DLP_USER,
	.p = P_VALID,
	.limit1 = 0xF,
	.avl = AVL,
	.l = L_LONGMODE_CODE,
	.d = D_LONGMODE,
	.g = G_4KIB,
	.base2 = 0,
};

const struct gdt_entry DATA_SEG = {
	.limit0 = 0xFFFF,
	.base0 = 0,
	.base1 = 0,
	.type = 0x2 | 0x1,
	.s = S_DATA_OR_CODE,
	.dpl = DLP_KERNEL, // DLP_USER,
	.p = P_VALID,
	.limit1 = (TYPE_A_ACCES_DONTSET | TYPE_RW_DATA_WRITE | TYPE_E_DATA),
	.avl = AVL,
	.l = L_OTHER, // era L_LONGMODE_CODE ??
	.d = D_LONGMODE,
	.g = G_4KIB,
	.base2 = 0,
};

struct kvm_segment gdt_seg_from_desc(struct gdt_entry e, uint32_t idx)
{
	struct kvm_segment res = {
		.base = e.base0 | ((uint64_t)e.base1 << 16) | ((uint64_t)e.base2 << 24),
		.limit = (uint64_t)e.limit0 | ((uint64_t)e.limit1 << 16),
		.selector =
			(idx * sizeof(struct gdt_entry)), // | RPL_USER, //
							  // https://wiki.osdev.org/Segment_Selector
							  // RPL
		.type = e.type,
		.present = e.p,
		.dpl = e.dpl,
		.db = e.d,
		.s = e.s,
		.l = e.l,
		.g = e.g,
		.avl = e.avl,
		.padding = 0,
		.unusable = 0,
	};

	return res;
}

void gdt_init(struct kvm_sregs2 *sregs, struct vmm *vmm)
{
	// alloc one page for GDT
	struct frame mem_gdt = { 0 };
	if (vmm_get_free_frame(vmm, &mem_gdt) != 0) {
		PANIC("get_free_frame");
	}

	struct gdt_entry *gdt = (struct gdt_entry *)mem_gdt.host_virtual_addr;

	// set all to null, so first is null descriptor
	memset(gdt, 0, PAGE_SIZE);

	// one code segment
	gdt[1] = CODE_SEG;
	// one data segment
	gdt[2] = DATA_SEG;

	// start address of gdt in guest
	sregs->gdt.base = mem_gdt.guest_physical_addr;
	// size of the table (2 entry, 1 null)
	sregs->gdt.limit = (3 * sizeof(struct gdt_entry)) - 1;
}

struct kvm_segment gdt_get_segment(int idx)
{
	switch (idx) {
	case GDT_IDX_CODE:
		return gdt_seg_from_desc(CODE_SEG, GDT_IDX_CODE);
	case GDT_IDX_DATA:
		return gdt_seg_from_desc(DATA_SEG, GDT_IDX_DATA);
	default:
		PANIC("segment idx not valid");
	}
}
