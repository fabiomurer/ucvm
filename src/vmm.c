#include <linux/kvm.h>
#include <stddef.h>
#include <stdio.h>
#include "vmm.h"
#include "utils.h"
#include <sys/user.h>

static void *guest_memory;
static struct frame pml4t_addr;

#define GDTENTRY_SIZE 8
#define IDTENTRY_SIZE 8

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

static const struct seg_desc CODE_SEG = {
	.limit0 = 0xFFFF,
	.base0 = 0,
	.base1 = 0,
	.type = (TYPE_A_ACCES_DONTSET | TYPE_RW_CODE_READ | TYPE_DC_CODE_EXEC_IFDLP | TYPE_E_CODE),
	.s = S_DATA_OR_CODE,
	.dpl = DLP_KERNEL, //DLP_USER, 
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
	.dpl = DLP_KERNEL, //DLP_USER,
	.p = P_VALID,
	.limit1 = (TYPE_A_ACCES_DONTSET | TYPE_RW_DATA_WRITE | TYPE_E_DATA),
	.avl = AVL,
	.l = L_OTHER, // era L_LONGMODE_CODE ??
	.d = D_LONGMODE,
	.g = G_4KIB,
	.base2 = 0,
};

#define RPL_USER 3

static struct kvm_segment seg_from_desc(struct seg_desc e, uint32_t idx)
{
	struct kvm_segment res = {
		.base = e.base0 | ((uint64_t)e.base1 << 16) | ((uint64_t)e.base2 << 24),
		.limit = (uint64_t)e.limit0 | ((uint64_t)e.limit1 << 16),
		.selector = (idx * GDTENTRY_SIZE), // | RPL_USER, // https://wiki.osdev.org/Segment_Selector RPL
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

size_t guest_physical_addr_to_pfn(uint64_t guest_physical_addr)
{
	return (guest_physical_addr - GUEST_PHYS_ADDR) / PAGE_SIZE;
}

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

struct frame *get_frame_from_phys_addr(uint64_t phys_addr)
{
	size_t pfn = phys_addr / PAGE_SIZE;

	if (pfn >= PAGE_NUMBER) {
		PANIC("pfn too large");
	}

	return &frames_pool[pfn];
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

	// allocate one page for the pml4
	if (get_free_frame(&pml4t_addr) != 0) {
		PANIC("get_free_frame");
	}
	
	// GDT 
	// alloc one page for GDT
	struct frame mem_gdt = { 0 };
	if (get_free_frame(&mem_gdt) != 0) {
		PANIC("get_free_frame");
	}

	void *gdt_addr = (void *)mem_gdt.host_virtual_addr;

	struct kvm_segment code_segment = seg_from_desc(CODE_SEG, 1);
	struct kvm_segment data_segment = seg_from_desc(DATA_SEG, 2);

	// set all to null, so first is null descriptor
	memset(gdt_addr, 0, PAGE_SIZE);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"
	// one code segment
	memcpy(gdt_addr + GDTENTRY_SIZE, &CODE_SEG, GDTENTRY_SIZE);
	// one data segment
	memcpy(gdt_addr + ((ptrdiff_t)(2 * GDTENTRY_SIZE)), &DATA_SEG, GDTENTRY_SIZE);
#pragma GCC diagnostic pop

	// start address of gdt in guest
	sregs->gdt.base = mem_gdt.guest_physical_addr;
	// size of the table (2 entry, 1 null)
	sregs->gdt.limit = (3 * GDTENTRY_SIZE) - 1;

	
	// IDT
	// alloc one page for IDT

	/*
	// VECCHIO--------------
	struct frame mem_idt = { 0 };
	if (get_free_frame(&mem_idt) != 0) {
		PANIC("get_free_frame");
	}

	void *idt_addr = (void *)mem_idt.host_virtual_addr;

	// IDT (interrupt description table) initialization, all null not used TODO: understand if necessary
	memset(idt_addr, 0, PAGE_SIZE);

	sregs->idt.base = mem_gdt.guest_physical_addr;
	sregs->idt.limit = 0; // not used
	*/

	
	// NUOVO ----------------
	struct idt_entry {
		uint16_t offset_low;
		uint16_t selector;
		uint8_t  ist;
		uint8_t  type_attr; // Type and attributes (P, DPL, etc.)
		uint16_t offset_mid;
		uint32_t offset_high;
		uint32_t zero;
	} __attribute__((packed));

	// alloc one page for IDT
	struct frame mem_idt = { 0 };
	if (get_free_frame(&mem_idt) != 0) {
		PANIC("get_free_frame");
	}

	map_addr(mem_idt.guest_physical_addr, mem_idt.guest_physical_addr);
	struct idt_entry *idt = (struct idt_entry *)mem_idt.host_virtual_addr;

	// Set up a template for a non-present interrupt gate.
	// Any attempt to use this gate will cause a #NP fault (Not Present),
	// which triggers a KVM_EXIT_EXCEPTION to the VMM.
	struct idt_entry entry = { 0 };
	entry.selector = code_segment.selector; // Selector for the code segment
	// Type = 64-bit Interrupt Gate (0xE), DPL = 0, Present = 0
	entry.type_attr = 0x8E & ~0x80; // Clear the P bit (bit 7)

	// Fill the entire IDT with non-present gates.
	for (int i = 0; i < 256; i++) {
		idt[i] = entry;
	}

	// Set the IDTR to point to our new table.
	sregs->idt.base = mem_idt.guest_physical_addr;
	sregs->idt.limit = (256 * sizeof(struct idt_entry)) - 1;
	

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
#define PAGE_USER (1ULL << 2)

// cache
#define PAGE_PWT (1ULL << 3) /* Page Write Through */
#define PAGE_PCD (1ULL << 4) /* Page Cache Disable */
#define PAGE_PAT (1ULL << 7) /* Page Attribute Table */

#define PAGE_CACHE_WB 0			    /* Write-back PAT, PCD, PWT = 0 */
#define PAGE_CACHE_WT PAGE_PWT		    /* Write-through PWT=1*/
#define PAGE_CACHE_UC_MINUS PAGE_PCD	    /* Uncacheable minus PCD=1*/
#define PAGE_CACHE_UC (PAGE_PCD | PAGE_PWT) /* Uncacheable PWT,PCD=1*/

#define PAGE_FLAGS (PAGE_PRESENT | PAGE_RW | PAGE_CACHE_WB) // | PAGE_USER
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

/*
linear address (virtual)
9 PGD 9 PDU 9 PMD 9 PT 12 offset

NOTE:
*** Physical Address is is considering the pfn (
real pyhisical address *= PAGE_SIZE ()
)


https://blog.zolutal.io/understanding-paging/

~ PGD Entry ~                                                   Present ──────┐
							    Read/Write ──────┐|
						      User/Supervisor ──────┐||
						  Page Write Through ──────┐|||
					       Page Cache Disabled ──────┐ ||||
							 Accessed ──────┐| ||||
							 Ignored ──────┐|| ||||
						       Reserved ──────┐||| ||||
┌─ NX          ┌─ Reserved                             Ignored ──┬──┐ |||| ||||
|┌───────────┐ |┌──────────────────────────────────────────────┐ |  | |||| ||||
||  Ignored  | ||               PUD Physical Address           | |  | |||| ||||
||           | ||                                              | |  | |||| ||||
XXXX XXXX XXXX 0XXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX 0XXX XXXX
       56        48        40        32        24        16         8         0

~ PUD Entry, Page Size unset ~                                  Present ──────┐
							    Read/Write ──────┐|
						      User/Supervisor ──────┐||
						  Page Write Through ──────┐|||
					       Page Cache Disabled ──────┐ ||||
							 Accessed ──────┐| ||||
							 Ignored ──────┐|| ||||
						      Page Size ──────┐||| ||||
┌─ NX          ┌─ Reserved                             Ignored ──┬──┐ |||| ||||
|┌───────────┐ |┌──────────────────────────────────────────────┐ |  | |||| ||||
||  Ignored  | ||               PMD Physical Address           | |  | |||| ||||
||           | ||                                              | |  | |||| ||||
XXXX XXXX XXXX 0XXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX 0XXX XXXX
       56        48        40        32        24        16         8         0

~ PMD Entry, Page Size unset ~                                  Present ──────┐
							    Read/Write ──────┐|
						      User/Supervisor ──────┐||
						  Page Write Through ──────┐|||
					       Page Cache Disabled ──────┐ ||||
							 Accessed ──────┐| ||||
							 Ignored ──────┐|| ||||
						      Page Size ──────┐||| ||||
┌─ NX          ┌─ Reserved                             Ignored ──┬──┐ |||| ||||
|┌───────────┐ |┌──────────────────────────────────────────────┐ |  | |||| ||||
||  Ignored  | ||                PT Physical Address           | |  | |||| ||||
||           | ||                                              | |  | |||| ||||
XXXX XXXX XXXX 0XXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX 0XXX XXXX
       56        48        40        32        24        16         8         0

~ PT Entry ~                                                    Present ──────┐
							    Read/Write ──────┐|
						      User/Supervisor ──────┐||
						  Page Write Through ──────┐|||
					       Page Cache Disabled ──────┐ ||||
							 Accessed ──────┐| ||||
┌─── NX                                                    Dirty ──────┐|| ||||
|┌───┬─ Memory Protection Key              Page Attribute Table ──────┐||| ||||
||   |┌──────┬─── Ignored                               Global ─────┐ |||| ||||
||   ||      | ┌─── Reserved                          Ignored ───┬─┐| |||| ||||
||   ||      | |┌──────────────────────────────────────────────┐ | || |||| ||||
||   ||      | ||            4KB Page Physical Address         | | || |||| ||||
||   ||      | ||                                              | | || |||| ||||
XXXX XXXX XXXX 0XXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX
       56        48        40        32        24        16         8         0
*/

void get_indexes_array(uint64_t vaddr, uint64_t *indexes_array)
{
	indexes_array[0] = (vaddr & _AC(0xFF8000000000, ULL)) >> SHIFT_LVL_0;
	indexes_array[1] = (vaddr & _AC(0x7FC0000000, ULL)) >> SHIFT_LVL_1;
	indexes_array[2] = (vaddr & _AC(0x3FE00000, ULL)) >> SHIFT_LVL_2;
	indexes_array[3] = (vaddr & _AC(0x1FF000, ULL)) >> SHIFT_LVL_3;
}

#define PHYIS_ADDR_MASK 0x7FFFFFFFFF000

uint64_t get_phys_addr_from_pt_row(uint64_t pt_row)
{
	return (pt_row & PHYIS_ADDR_MASK);
}

#define NULL_PT_ROW 0ULL

void *host_virtual_addr_to_guest_physical_addr(uint64_t vaddr)
{
	uint64_t offset = vaddr % PAGE_SIZE;
	uint64_t indexes_array[PAGE_TABLE_LEVELS] = { 0 };
	get_indexes_array(vaddr, indexes_array);
	struct frame *current_pt_table = &pml4t_addr;

	for (int level = 0; level < PAGE_TABLE_LEVELS; level++) {
		uint64_t current_pt_row = *(uint64_t *)(current_pt_table->host_virtual_addr +
							(indexes_array[level] * sizeof(uint64_t)));
		uint64_t phys_addr = get_phys_addr_from_pt_row(current_pt_row);

		// if last level
		if (level == PAGE_TABLE_LEVELS - 1) {
			// not present
			if ((current_pt_row & PAGE_PRESENT) == 0) {
				return nullptr;
			}
			struct frame *f = get_frame_from_phys_addr(phys_addr);
			return (void *)(f->host_virtual_addr + offset);
		}

		// not allocated
		if (current_pt_row == NULL_PT_ROW) {
			return nullptr;
		}

		// jump to next page table
		current_pt_table = get_frame_from_phys_addr(phys_addr);
	}

	return nullptr;
}

void map_addr(uint64_t vaddr, uint64_t phys_addr)
{
#ifdef DEBUG
	printf("Mapping %lx to %lx\n", vaddr, phys_addr);
#endif

	// if not alligned
	if ((vaddr % PAGE_SIZE != 0) || (phys_addr % PAGE_SIZE != 0)) {
		PANIC("ALIGMENT PROBLEMS");
	}

	uint64_t indexes_array[PAGE_TABLE_LEVELS] = { 0 };
	get_indexes_array(vaddr, indexes_array);
	struct frame *current_pt_table = &pml4t_addr;

	for (int level = 0; level < PAGE_TABLE_LEVELS; level++) {
		uint64_t *current_pt_row = (uint64_t *)(current_pt_table->host_virtual_addr +
							(indexes_array[level] * sizeof(uint64_t)));

		// if last level
		if (level == PAGE_TABLE_LEVELS - 1) {
			// is alredy mapped (not 0)
			if (*current_pt_row != NULL_PT_ROW) {
				PANIC("PAGE ALREADY MAPPED");
			}
			// Last page. Just set it to the physicall address
			*current_pt_row = (uint64_t)phys_addr | PAGE_FLAGS;
			break;
		}

		// if the part of the current level is not mapped, map it
		if (*current_pt_row == NULL_PT_ROW) {
			struct frame new_frame = { 0 };
			if (get_free_frame(&new_frame) != 0) {
				PANIC("get_free_frame");
			}
			*current_pt_row = new_frame.guest_physical_addr | PAGE_FLAGS;
		}

		// jump to next page table
		uint64_t pt_row_addr = get_phys_addr_from_pt_row(*current_pt_row);
		current_pt_table = get_frame_from_phys_addr(pt_row_addr);
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

int unmap_addr(uint64_t vaddr)
{
	if (vaddr % PAGE_SIZE != 0) {
		PANIC("ALIGMENT PROBLEMS");
	}

	uint64_t indexes_array[PAGE_TABLE_LEVELS] = { 0 };
	get_indexes_array(vaddr, indexes_array);
	struct frame *current_pt_table = &pml4t_addr;

	for (int level = 0; level < PAGE_TABLE_LEVELS; level++) {
		uint64_t *current_pt_row = (uint64_t *)(current_pt_table->host_virtual_addr +
							(indexes_array[level] * sizeof(uint64_t)));
		uint64_t phys_addr = get_phys_addr_from_pt_row(*current_pt_row);

		// Check if the entry is present
		if ((*current_pt_row & PAGE_PRESENT) == 0) {
			return -1; // Indicate page was not mapped
		}

		// if last level
		if (level == PAGE_TABLE_LEVELS - 1) {
			// Found the PTE. Clear it to unmap the page.
#if DEBUG
			printf("Unmapping vaddr: %lx phys_addr:%lx\n", vaddr, phys_addr);
#endif
			// free used frame
			size_t pfn = guest_physical_addr_to_pfn(phys_addr);
			add_free_pfn(pfn);

			// unset it
			*current_pt_row = NULL_PT_ROW;

			return 0; // Successfully unmapped
		}

		// jump to next page table
		current_pt_table = get_frame_from_phys_addr(phys_addr);
	}
	return -1;
}

// TODO: make more performant by unmapping only the mapped pages
void unmap_range(uint64_t vaddr_start, size_t size)
{
	if (size == 0) {
		return;
	}

	// Align start address down to page boundary
	uint64_t vaddr = TRUNC_PG(vaddr_start);

	// Calculate end address (exclusive). Align up to the *next* page boundary
	uint64_t vaddr_last_byte = vaddr_start + size - 1;
	uint64_t vaddr_end = ROUND_PG(vaddr_last_byte);

	// Iterate through pages in the range
	while (vaddr < vaddr_end) {
		unmap_addr(vaddr); // can fail
		vaddr += PAGE_SIZE;
	}

	// there is no need to invalidate the TLB (tlb flush)
	// because this is done when the vm is stopped (exited)
	// when a vm enter is perform all the addresses of the
	// guest are invalidated.
}
