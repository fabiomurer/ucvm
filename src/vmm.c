#include <linux/const.h>
#include <linux/kvm.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "vmm.h"
#include "utils.h"
#include "intrusive_dlist.h"

static void *guest_memory;
static struct frame pml4t_addr;

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

// reserved
#define AVL 0

struct __attribute__((packed)) seg_desc {
	uint16_t limit0;
	uint16_t base0;
	uint16_t base1 : 8, type : 4, s : 1, dpl : 2, p : 1;
	uint16_t limit1 : 4, avl : 1, l : 1, d : 1, g : 1, base2 : 8;
};

#define GDT_OFFSET 0x500
#define IDT_OFFSET 0x520

static const struct seg_desc CODE_SEG = {
	.limit0 = 0xFFFF,
	.base0 = 0,
	.base1 = 0,
	.type = (TYPE_A_ACCES_DONTSET | TYPE_RW_CODE_READ | TYPE_DC_CODE_EXEC_IFDLP | TYPE_E_CODE),
	.s = S_DATA_OR_CODE,
	.dpl = DLP_KERNEL,
	.p = P_VALID,
	.limit1 = 0xF,
	.avl = AVL,
	.l = L_LONGMODE_CODE,
	.d = D_LONGMODE,
	.g = G_4KIB,
	.base2 = 0,
};

static const struct seg_desc DATA_SEG = {
	.limit0 = 0xFFFF,
	.base0 = 0,
	.base1 = 0,
	.type = 0x2 | 0x1,
	.s = S_DATA_OR_CODE,
	.dpl = DLP_KERNEL,
	.p = P_VALID,
	.limit1 = (TYPE_A_ACCES_DONTSET | TYPE_RW_DATA_WRITE | TYPE_E_DATA),
	.avl = AVL,
	.l = L_OTHER, // era L_LONGMODE_CODE ??
	.d = D_LONGMODE,
	.g = G_4KIB,
	.base2 = 0,
};

static struct kvm_segment seg_from_desc(struct seg_desc e, uint32_t idx)
{
	struct kvm_segment res = {
		.base = e.base0 | ((uint64_t)e.base1 << 16) | ((uint64_t)e.base2 << 24),
		.limit = (uint64_t)e.limit0 | ((uint64_t)e.limit1 << 16),
		.selector = idx * 8,
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

static struct frame frames_pool[PAGE_NUMBER] = { 0 };

static DLIST_HEAD(free_frames_list);

void free_frames_list_init(void)
{
	for (size_t i = 0; i < PAGE_NUMBER; i++) {
		frames_pool[i].pfn = i;
		frames_pool[i].host_virtual_addr = (uint64_t)guest_memory + (i * PAGE_SIZE);
		frames_pool[i].guest_physical_addr = (uint64_t)GUEST_PHYS_ADDR + (i * PAGE_SIZE);

		dlist_init(&frames_pool[i].list);
		dlist_add_tail(&frames_pool[i].list, &free_frames_list);
	}
}

int get_free_pfn(size_t *pfn)
{
	struct dlist_head *node = dlist_pop(&free_frames_list);
	if (node != nullptr) {
		struct frame *frame = dlist_entry(node, struct frame, list);
		*pfn = frame->pfn;
		return 0;
	}

	// no free frames
	return -1;
}

int add_free_pfn(size_t pfn)
{
	// pfn not valid
	if (pfn >= PAGE_NUMBER) {
		return -1;
	}

	struct frame *frame = &frames_pool[pfn];
	if (!dlist_empty(&frame->list)) {
		dlist_push(&frame->list, &free_frames_list);
		return 0;
	}

	// frame with the pfn is already in a list
	return -1;
}

int get_free_frame(struct frame *frame)
{
	size_t pfn = 0;
	int err = get_free_pfn(&pfn);
	if (err != 0) {
		return err;
	}

	frame->pfn = frames_pool[pfn].pfn;
	frame->host_virtual_addr = frames_pool[pfn].host_virtual_addr;
	frame->guest_physical_addr = frames_pool[pfn].guest_physical_addr;
	return 0;
}

#define CRO_PROTECTED_MODE (1ULL << 0)
#define CR0_ENABLE_PAGING (1ULL << 31)
#define CR4_ENABLE_PAE (1ULL << 5)
#define CR4_ENABLE_PGE (1ULL << 7)

/*
bit 10

Description: Indicates whether long mode is active. This bit is read-only and is
set by the processor when entering long mode.
- Values:
    - 0: Long mode is not active
    - 1: Long mode is active
*/
#define EFER_LONG_MODE_ENABLED (1ULL << 8)
#define EFER_LONG_MODE_ACTIVE (1ULL << 10)

/*
bit 11

Description: Enables the no-execute page protection feature, which prevents code
execution from data pages.

- Values:
    -0: No-execute page protection is disabled
    - 1: No-execute page protection is enabled
*/
#define EFER_NO_EXECUTE_ENABLE (1ULL << 11)

void cpu_init_long(struct kvm_sregs2 *sregs, void *memory)
{
	guest_memory = memory;

	free_frames_list_init();

	// alloc one page for GDT (used) IDT (not used)
	if (get_free_frame(&pml4t_addr) != 0) {
		PANIC("get_free_frame");
	}
	struct frame mem_gdt = { 0 };
	if (get_free_frame(&mem_gdt) != 0) {
		PANIC("get_free_frame");
	}

	void *gdt_addr = (void *)(mem_gdt.host_virtual_addr + GDT_OFFSET);

	struct kvm_segment code_segment = seg_from_desc(CODE_SEG, 1);
	struct kvm_segment data_segment = seg_from_desc(DATA_SEG, 2);

	// null descriptor
	memset(gdt_addr, 0, 8);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"
	// one code segment
	memcpy(gdt_addr + 8, &CODE_SEG, 8);
	// one data segment
	memcpy(gdt_addr + 16, &DATA_SEG, 8);
#pragma GCC diagnostic pop

	// start address of gdt in guest
	sregs->gdt.base = GDT_OFFSET + mem_gdt.guest_physical_addr;
	// size of the table (2 entry, 1 null)
	sregs->gdt.limit = 3 * 8 - 1;

	// IDT (interrupt description table) initialization, all null not used
	memset((void *)(mem_gdt.host_virtual_addr + IDT_OFFSET), 0, 8);
	// start address of IDT in guest
	sregs->idt.base = IDT_OFFSET + mem_gdt.guest_physical_addr;
	// IDT size (one null)
	sregs->idt.limit = 7;

	sregs->cr0 |= CRO_PROTECTED_MODE | CR0_ENABLE_PAGING;
	sregs->cr3 = (uint64_t)pml4t_addr.guest_physical_addr;
	sregs->cr4 |= CR4_ENABLE_PAE | CR4_ENABLE_PGE;
	sregs->efer |= EFER_LONG_MODE_ENABLED | EFER_LONG_MODE_ACTIVE; // EFER_LONG_MODE_ENABLED??

	// initialize segments for long mode
	// code segment
	sregs->cs = code_segment;
	// data segment
	sregs->ds = data_segment;
	// stack segment
	sregs->ss = data_segment;
	// additional data and string operation
	sregs->es = data_segment;
	// thread-specific data structures
	sregs->fs = data_segment;
	// thread-specific data structures
	sregs->gs = data_segment;
}

#define PAGE_TABLE_LEVELS 4

#define SHIFT_LVL_0 39
#define SHIFT_LVL_1 30
#define SHIFT_LVL_2 21
#define SHIFT_LVL_3 12

#define PAGE_PRESENT (1ULL << 0)
#define PAGE_RW (1ULL << 1)

// cache
#define PAGE_PWT (1ULL << 3) /* Page Write Through */
#define PAGE_PCD (1ULL << 4) /* Page Cache Disable */
#define PAGE_PAT (1ULL << 7) /* Page Attribute Table */

#define PAGE_CACHE_WB 0			    /* Write-back PAT, PCD, PWT = 0 */
#define PAGE_CACHE_WT PAGE_PWT		    /* Write-through PWT=1*/
#define PAGE_CACHE_UC_MINUS PAGE_PCD	    /* Uncacheable minus PCD=1*/
#define PAGE_CACHE_UC (PAGE_PCD | PAGE_PWT) /* Uncacheable PWT,PCD=1*/

#define PAGE_FLAGS (PAGE_PRESENT | PAGE_RW | PAGE_CACHE_WB)
// ?
struct frame jump_next_frame(uint64_t gaddr)
{
	// rounds gaddr down to the nearest multiple of PAGE_SIZE
	gaddr = (gaddr / PAGE_SIZE) * PAGE_SIZE;
	struct frame frame = {
		.guest_physical_addr = gaddr,
		.host_virtual_addr = (uint64_t)guest_memory + (gaddr - GUEST_PHYS_ADDR),
	};

	return frame;
}

// set 4 level page table for address translation
void map_addr(uint64_t vaddr, uint64_t phys_addr)
{
#ifdef DEBUG
	printf("Mapping %lx to %lx\n", vaddr, phys_addr);
#endif

	size_t i = 0;
	struct frame cur_addr = pml4t_addr;
	const uint64_t ind[PAGE_TABLE_LEVELS] = {
		(vaddr & _AC(0xff8000000000, ULL)) >> SHIFT_LVL_0,
		(vaddr & _AC(0x7fc0000000, ULL)) >> SHIFT_LVL_1,
		(vaddr & _AC(0x3fe00000, ULL)) >> SHIFT_LVL_2,
		(vaddr & _AC(0x1FF000, ULL)) >> SHIFT_LVL_3,
	};

	// if not alligned
	if ((vaddr % PAGE_SIZE != 0) || (phys_addr % PAGE_SIZE != 0)) {
		PANIC("ALIGMENT PROBLEMS");
	}

	// map page walk
	for (i = 0; i < PAGE_TABLE_LEVELS; i++) {
		uint64_t *g_a =
			(uint64_t *)(cur_addr.host_virtual_addr + ind[i] * sizeof(uint64_t));

		// if last level
		if (i == PAGE_TABLE_LEVELS - 1) {
			// is alredy mapped (not 0)
			if (*g_a) {
				PANIC("PAGE ALREADY MAPPED");
			}
			// Last page. Just set it to the physicall address
			*g_a = (uint64_t)phys_addr | PAGE_FLAGS;
			break;
		}
		// if the part of the current level is not mapped, map it
		if (!*g_a) {
#ifdef DEBUG
			printf("Allocating level %zu\n", i);
#endif
			struct frame new_frame = { 0 };
			if (get_free_frame(&new_frame) != 0) {
				PANIC("get_free_frame");
			}
			*g_a = new_frame.guest_physical_addr | PAGE_FLAGS;
		}
		cur_addr = jump_next_frame(*g_a);
	}
}

uintptr_t map_page(uint64_t vaddr)
{
	struct frame frame = { 0 };
	int err = get_free_frame(&frame);
	if (err != 0) {
		PANIC("get_free_frame");
	}

	map_addr(vaddr, frame.guest_physical_addr);
	return frame.host_virtual_addr;
}
