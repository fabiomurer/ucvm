#include "intrusive_dlist.h"
#include <linux/kvm.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "vmm.h"
#include "utils.h"
#include <sys/user.h>


size_t guest_physical_addr_to_pfn(uint64_t guest_physical_addr)
{
	return (guest_physical_addr - GUEST_PHYS_ADDR) / PAGE_SIZE;
}

void free_frames_list_init(struct vmm *vmm)
{
	dlist_init(&vmm->free_frames_list);

	for (size_t i = 0; i < PAGE_NUMBER; i++) {
		vmm->frames_pool[i].pfn = i;
		vmm->frames_pool[i].host_virtual_addr = (uint64_t)vmm->mem_host_virtual_addr + (i * PAGE_SIZE);
		vmm->frames_pool[i].guest_physical_addr = (uint64_t)GUEST_PHYS_ADDR + (i * PAGE_SIZE);

		dlist_init(&vmm->frames_pool[i].list);
		dlist_add_tail(&vmm->frames_pool[i].list, &vmm->free_frames_list);
	}
}

int get_free_pfn(struct vmm *vmm, size_t *pfn)
{
	struct dlist_head *node = dlist_pop(&vmm->free_frames_list);
	if (node != nullptr) {
		struct frame *frame = dlist_entry(node, struct frame, list);
		*pfn = frame->pfn;
		return 0;
	}

	// no free frames
	return -1;
}

int add_free_pfn(struct vmm *vmm, size_t pfn)
{
	// pfn not valid
	if (pfn >= PAGE_NUMBER) {
		return -1;
	}

	struct frame *frame = &vmm->frames_pool[pfn];
	if (!dlist_empty(&frame->list)) {
		dlist_push(&frame->list, &vmm->free_frames_list);
		return 0;
	}

	// frame with the pfn is already in a list
	return -1;
}

int vmm_get_free_frame(struct vmm *vmm, struct frame *frame)
{
	size_t pfn = 0;
	int err = get_free_pfn(vmm, &pfn);
	if (err != 0) {
		return err;
	}

	frame->pfn 					= vmm->frames_pool[pfn].pfn;
	frame->host_virtual_addr 	= vmm->frames_pool[pfn].host_virtual_addr;
	frame->guest_physical_addr 	= vmm->frames_pool[pfn].guest_physical_addr;
	return 0;
}

struct frame *get_frame_from_phys_addr(struct vmm *vmm, uint64_t phys_addr)
{
	size_t pfn = phys_addr / PAGE_SIZE;

	if (pfn >= PAGE_NUMBER) {
		PANIC("pfn too large");
	}

	return &vmm->frames_pool[pfn];
}

void vmm_init(struct vmm *vmm)
{
	free_frames_list_init(vmm);

	// allocate one page for the pml4
	if (vmm_get_free_frame(vmm, &vmm->pml4t_addr) != 0) {
		PANIC("get_free_frame");
	}
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
struct frame jump_next_frame(uint64_t gaddr, void* mem_host_virtual_addr)
{
	// rounds gaddr down to the nearest multiple of PAGE_SIZE
	gaddr = (gaddr / PAGE_SIZE) * PAGE_SIZE;
	struct frame frame = {
		.guest_physical_addr = gaddr,
		.host_virtual_addr = (uint64_t)mem_host_virtual_addr + (gaddr - GUEST_PHYS_ADDR),
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

void *vmm_host_virtual_addr_to_guest_physical_addr(struct vmm *vmm, uint64_t vaddr)
{
	uint64_t offset = vaddr % PAGE_SIZE;
	uint64_t indexes_array[PAGE_TABLE_LEVELS] = { 0 };
	get_indexes_array(vaddr, indexes_array);
	struct frame *current_pt_table = &vmm->pml4t_addr;

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
			struct frame *f = get_frame_from_phys_addr(vmm, phys_addr);
			return (void *)(f->host_virtual_addr + offset);
		}

		// not allocated
		if (current_pt_row == NULL_PT_ROW) {
			return nullptr;
		}

		// jump to next page table
		current_pt_table = get_frame_from_phys_addr(vmm, phys_addr);
	}

	return nullptr;
}

void vmm_map_addr(struct vmm *vmm, uint64_t vaddr, uint64_t phys_addr)
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
	struct frame *current_pt_table = &vmm->pml4t_addr;

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
			if (vmm_get_free_frame(vmm, &new_frame) != 0) {
				PANIC("get_free_frame");
			}
			*current_pt_row = new_frame.guest_physical_addr | PAGE_FLAGS;
		}

		// jump to next page table
		uint64_t pt_row_addr = get_phys_addr_from_pt_row(*current_pt_row);
		current_pt_table = get_frame_from_phys_addr(vmm, pt_row_addr);
	}
}

uintptr_t vmm_map_page(struct vmm *vmm, uint64_t vaddr)
{
	struct frame frame = { 0 };
	int err = vmm_get_free_frame(vmm, &frame);
	if (err != 0) {
		PANIC("get_free_frame");
	}

	vmm_map_addr(vmm, vaddr, frame.guest_physical_addr);
	return frame.host_virtual_addr;
}

int vmm_unmap_addr(struct vmm *vmm, uint64_t vaddr)
{
	if (vaddr % PAGE_SIZE != 0) {
		PANIC("ALIGMENT PROBLEMS");
	}

	uint64_t indexes_array[PAGE_TABLE_LEVELS] = { 0 };
	get_indexes_array(vaddr, indexes_array);
	struct frame *current_pt_table = &vmm->pml4t_addr;

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
			add_free_pfn(vmm, pfn);

			// unset it
			*current_pt_row = NULL_PT_ROW;

			return 0; // Successfully unmapped
		}

		// jump to next page table
		current_pt_table = get_frame_from_phys_addr(vmm, phys_addr);
	}
	return -1;
}

// TODO: make more performant by unmapping only the mapped pages
void vmm_unmap_range(struct vmm *vmm, uint64_t vaddr_start, size_t size)
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
		vmm_unmap_addr(vmm, vaddr); // can fail
		vaddr += PAGE_SIZE;
	}

	// there is no need to invalidate the TLB (tlb flush)
	// because this is done when the vm is stopped (exited)
	// when a vm enter is perform all the addresses of the
	// guest are invalidated.
}
