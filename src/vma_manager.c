#include "vma_manager.h"
#include "intrusive_dlist.h"
#include "utils.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> // For malloc, free
#include <assert.h>
#include <string.h>

// The head of the VMA list (sentinel node)
static DLIST_HEAD(vma_list);

// Helper to create a new VMA node
static struct vma *create_vma(uintptr_t start, uintptr_t end, bool is_free)
{
	struct vma *vma = (struct vma *)malloc(sizeof(struct vma));
	if (!vma) {
		PANIC_PERROR("Failed to allocate VMA node");
	}
	vma->start = start;
	vma->end = end;
	vma->is_free = is_free;
	dlist_init(&vma->node); // Initialize node before use
	return vma;
}

// Helper to find the VMA containing a given address
// Returns NULL if not found
static struct vma *find_vma_containing(uintptr_t addr)
{
	struct dlist_head *pos = nullptr;
	dlist_for_each(pos, &vma_list)
	{
		struct vma *vma = dlist_entry(pos, struct vma, node);
		if (addr >= vma->start && addr < vma->end) {
			return vma;
		}
	}
	return nullptr;
}

// Helper to find the VMA starting exactly at a given address
// Returns NULL if not found
static struct vma *find_vma_starting_at(uintptr_t start_addr)
{
	struct dlist_head *pos = nullptr;
	dlist_for_each(pos, &vma_list)
	{
		struct vma *vma = dlist_entry(pos, struct vma, node);
		if (vma->start == start_addr) {
			return vma;
		}
		if (vma->start > start_addr) {
			// List is sorted, no need to search further
			break;
		}
	}
	return nullptr;
}

// Helper to merge a free VMA with its adjacent free neighbors
static void merge_free_neighbors(struct vma *vma)
{
	if (!vma || !vma->is_free) {
		return;
	}

	// Merge with previous if it's free
	if (vma->node.prev != &vma_list) {
		struct vma *prev_v = dlist_entry(vma->node.prev, struct vma, node);
		if (prev_v->is_free && prev_v->end == vma->start) {
			prev_v->end = vma->end; // Extend previous VMA
			dlist_del(&vma->node);	// Remove current VMA
			free(vma);		// Free the node memory
			vma = prev_v; // Continue merging with the (now extended) previous VMA
		}
	}

	// Merge with next if it's free
	if (vma->node.next != &vma_list) {
		struct vma *next_v = dlist_entry(vma->node.next, struct vma, node);
		if (next_v->is_free && vma->end == next_v->start) {
			vma->end = next_v->end;	  // Extend current VMA
			dlist_del(&next_v->node); // Remove next VMA
			free(next_v);		  // Free the node memory
						  // No need to update 'v' pointer here
		}
	}
}

bool vma_init(uintptr_t start, uintptr_t end)
{
	// Ensure list is empty before initialization
	if (!dlist_empty(&vma_list)) {
		vma_destroy(); // Clear existing list if any
	}
	dlist_init(&vma_list); // Re-initialize sentinel just in case

	struct vma *initial_vma = create_vma(start, end, true);
	if (!initial_vma) {
		return false;
	}
	dlist_add_tail(&initial_vma->node, &vma_list); // Add the single free block
	return true;
}

void vma_destroy(void)
{
	struct dlist_head *pos = nullptr;
	struct dlist_head *n = nullptr;
	dlist_for_each_safe(pos, n, &vma_list)
	{
		struct vma *v = dlist_entry(pos, struct vma, node);
		dlist_del(&v->node); // Remove from list
		free(v);	     // Free the node memory
	}
	// Ensure the list head itself is reset
	dlist_init(&vma_list);
}

bool vma_find_free(size_t size, uintptr_t *out_addr)
{
	if (size == 0) {
		return false;
	}

	struct dlist_head *pos = nullptr;
	dlist_for_each(pos, &vma_list)
	{
		struct vma *v = dlist_entry(pos, struct vma, node);
		if (v->is_free && (v->end - v->start) >= size) {
			*out_addr = v->start;
			return true;
		}
	}
	return false; // No suitable block found
}

bool vma_find_free_reverse(size_t size, uintptr_t *out_addr)
{
	if (size == 0) {
		return false;
	}

	struct dlist_head *pos = nullptr;
	dlist_for_each_reverse(pos, &vma_list)
	{
		struct vma *v = dlist_entry(pos, struct vma, node);
		if (v->is_free && (v->end - v->start) >= size) {
			*out_addr = v->end - size;
			return true;
		}
	}
	return false; // No suitable block found
}

bool vma_find_free_hint(size_t size, uintptr_t hint, uintptr_t *out_addr)
{
	if (size == 0) {
		return false;
	}

	struct vma *v = find_vma_containing(hint);
	if (v == nullptr) {
		return false;
	}

	// exact match
	if (v->is_free && (v->end - hint) >= size) {
		*out_addr = hint;
		return true;
	}

	// if hint not free ignore it.
	return vma_find_free_reverse(size, out_addr);
}

bool vma_reserve(uintptr_t start, size_t size)
{
	if (size == 0) {
		return false;
	}
	uintptr_t end = start + size;

	struct vma *target_vma = find_vma_containing(start);

	// Check if found, is free, and contains the entire requested range
	if (!target_vma || !target_vma->is_free || end > target_vma->end) {
		return false; // Range invalid or not fully contained in a free block
	}

	// Case 1: Exact match - just change the flag
	if (target_vma->start == start && target_vma->end == end) {
		target_vma->is_free = false;
		return true;
	}

	// Case 2: Split required
	struct vma *reserved_vma = nullptr;
	struct vma *after_vma = nullptr;

	// Create the new reserved VMA
	reserved_vma = create_vma(start, end, false);
	if (!reserved_vma) {
		return false; // Allocation failed
	}

	// Does a free block remain *after* the reserved block?
	if (end < target_vma->end) {
		after_vma = create_vma(end, target_vma->end, true);
		if (!after_vma) {
			free(reserved_vma);
			return false; // Allocation failed
		}
	}

	// Does a free block remain *before* the reserved block?
	if (start > target_vma->start) {
		// Modify the original VMA to be the 'before' block
		target_vma->end = start;
		// Insert the new blocks after the modified original
		dlist_add(&reserved_vma->node, &target_vma->node);
		if (after_vma) {
			dlist_add(&after_vma->node, &reserved_vma->node);
		}
	} else {
		// Original VMA starts exactly where reserved starts. Replace original.
		// Insert the new reserved block *before* the original (which will be removed)
		dlist_add_tail(&reserved_vma->node, &target_vma->node); // Add before target
		if (after_vma) {
			// Insert the 'after' block *after* the new reserved block
			dlist_add(&after_vma->node, &reserved_vma->node);
		}
		// Remove the original VMA
		dlist_del(&target_vma->node);
		free(target_vma);
	}

	return true;
}

bool vma_delete(uintptr_t start, size_t size)
{
	if (size == 0) {
		return false;
	}
	uintptr_t end = start + size;

	struct vma *target_vma = find_vma_starting_at(start);

	// Check if found, is reserved, and size matches exactly
	if (!target_vma || target_vma->is_free || target_vma->end != end) {
		return false; // Not found, or not reserved, or size mismatch
	}

	// Mark as free
	target_vma->is_free = true;

	// Merge with neighbors if they are free
	merge_free_neighbors(target_vma);

	return true;
}

bool vma_expand(uintptr_t start, size_t old_size, size_t new_size)
{
	if (new_size <= old_size || new_size == 0 || old_size == 0) {
		return false;
	}

	uintptr_t old_end = start + old_size;
	uintptr_t new_end = start + new_size;

	struct vma *target_vma = find_vma_starting_at(start);

	// Check if found, is reserved, and old size matches
	if (!target_vma || target_vma->is_free || target_vma->end != old_end) {
		return false;
	}

	// Check the next VMA
	if (target_vma->node.next == &vma_list) {
		return false; // No next VMA to expand into
	}

	struct vma *next_vma = dlist_entry(target_vma->node.next, struct vma, node);

	// Check if next is free and large enough
	if (!next_vma->is_free || next_vma->end < new_end) {
		return false; // Next VMA is not free or not large enough
	}

	// Expansion is possible
	size_t expansion_needed = new_size - old_size;
	size_t next_vma_original_size = next_vma->end - next_vma->start;

	// Update target VMA's end
	target_vma->end = new_end;

	// Update or remove next VMA
	if (next_vma_original_size == expansion_needed) {
		// Next VMA is consumed entirely
		dlist_del(&next_vma->node);
		free(next_vma);
	} else {
		// Shrink next VMA from the start
		next_vma->start = new_end;
	}

	return true;
}

bool vma_shrink(uintptr_t start, size_t old_size, size_t new_size)
{
	if (new_size >= old_size || new_size == 0 || old_size == 0) {
		return false;
	}

	uintptr_t old_end = start + old_size;
	uintptr_t new_end = start + new_size;

	struct vma *target_vma = find_vma_starting_at(start);

	// Check if found, is reserved, and old size matches
	if (!target_vma || target_vma->is_free || target_vma->end != old_end) {
		return false;
	}

	// Create the new free VMA for the shrunk portion
	struct vma *shrunk_part = create_vma(new_end, old_end, true);
	if (!shrunk_part) {
		return false; // Allocation failed
	}

	// Update the original VMA's end
	target_vma->end = new_end;

	// Insert the new free VMA immediately after the target VMA
	dlist_add(&shrunk_part->node, &target_vma->node);

	// Try merging the newly created free VMA with the *next* one (if it exists and is free)
	merge_free_neighbors(shrunk_part);

	return true;
}

void vma_dump(void)
{
	struct dlist_head *pos = nullptr;
	printf("--- VMA Dump ---\n");
	if (dlist_empty(&vma_list)) {
		printf("  List is empty.\n");
		return;
	}
	int i = 0;
	dlist_for_each(pos, &vma_list)
	{
		struct vma *v = dlist_entry(pos, struct vma, node);
		printf("  [%d] Addr: %p, Start: 0x%lx, End: 0x%lx, Size: %lu, State: %s\n", i++,
		       (void *)v, v->start, v->end, (unsigned long)(v->end - v->start),
		       v->is_free ? "Free" : "Reserved");
	}
	printf("----------------\n");
}

// --- Example Usage (Optional - Compile separately or wrap in #ifdef) ---
/*
#include <stdio.h>

int main() {
    uintptr_t mem_start = 0x10000;
    size_t mem_size = 0x10000; // 64 KiB

    printf("Initializing VMA Manager...\n");
    if (!vma_init(mem_start, mem_size)) {
	return 1;
    }
    vma_dump();

    uintptr_t addr1;
    printf("\nFinding free space for 0x1000 bytes...\n");
    if (vma_find_free(0x1000, &addr1)) {
	printf("Found free space at 0x%lx. Reserving...\n", addr1);
	if (!vma_reserve(addr1, 0x1000)) {
	    printf("Failed to reserve!\n");
	}
    } else {
	printf("Could not find free space.\n");
    }
    vma_dump();

    printf("\nReserving specific range [0x12000, 0x13000)...\n");
    if (!vma_reserve(0x12000, 0x1000)) {
	 printf("Failed to reserve specific range!\n");
    }
     vma_dump();


    printf("\nReserving specific range [0x15000, 0x18000)...\n");
    if (!vma_reserve(0x15000, 0x3000)) {
	 printf("Failed to reserve specific range!\n");
    }
     vma_dump();

    printf("\nTrying to reserve overlapping range [0x12800, 0x13800)...\n");
    if (!vma_reserve(0x12800, 0x1000)) {
	 printf("Correctly failed to reserve overlapping range.\n");
    } else {
	 printf("Incorrectly reserved overlapping range!\n");
    }
     vma_dump();


    printf("\nExpanding VMA at 0x%lx from 0x1000 to 0x1800...\n", addr1);
    if (!vma_expand(addr1, 0x1000, 0x1800)) {
	printf("Failed to expand VMA at 0x%lx\n", addr1);
    }
    vma_dump();

     printf("\nShrinking VMA at 0x12000 from 0x1000 to 0x800...\n");
    if (!vma_shrink(0x12000, 0x1000, 0x800)) {
	printf("Failed to shrink VMA at 0x12000\n");
    }
    vma_dump();

    printf("\nDeleting VMA at 0x%lx (size 0x1800)...\n", addr1);
    if (!vma_delete(addr1, 0x1800)) {
	 printf("Failed to delete VMA at 0x%lx\n", addr1);
    }
    vma_dump();

     printf("\nDeleting VMA at 0x12000 (size 0x800)...\n");
    if (!vma_delete(0x12000, 0x800)) {
	 printf("Failed to delete VMA at 0x12000\n");
    }
    vma_dump();


    printf("\nCleaning up...\n");
    vma_destroy();
    vma_dump();

    return 0;
}
*/
