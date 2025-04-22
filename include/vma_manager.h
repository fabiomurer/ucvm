#pragma once

#include "intrusive_dlist.h"
#include <stdint.h> // For uintptr_t
#include <stdbool.h>
#include <stddef.h> // For size_t

// Structure to represent a Virtual Memory Area (VMA)
struct vma {
	uintptr_t start;	// Start address of the area
	uintptr_t end;		// End address of the area (exclusive: [start, end))
	bool is_free;		// Flag indicating if the area is free or reserved
	struct dlist_head node; // Intrusive list node
};

/**
 * @brief Initializes the VMA manager with a single free block covering the entire space.
 *
 * @return true on success, false on failure (e.g., allocation error).
 */
bool vma_init(uintptr_t start, uintptr_t end);

/**
 * @brief Cleans up the VMA manager, freeing all allocated VMA nodes.
 */
void vma_destroy(void);

/**
 * @brief Finds a contiguous free memory area of at least the specified size.
 * Uses a first-fit strategy.
 *
 * @param size The minimum size required.
 * @param out_addr Pointer to store the start address of the found free area.
 * @return true if a suitable free area is found, false otherwise.
 */
bool vma_find_free(size_t size, uintptr_t *out_addr);

/**
 * @brief Finds a contiguous free memory area of at least the specified size,
 *        starting the search from the end of the address space (reverse search).
 *
 * @param size The minimum size required (in bytes).
 * @param out_addr Pointer to store the start address of the found free area.
 * @return true if a suitable free area is found, false otherwise.
 */
 bool vma_find_free_reverse(size_t size, uintptr_t *out_addr);

 /**
  * @brief Finds a contiguous free memory area of at least the specified size,
  *        starting the search near a given hint address if possible.
  *
  * If the hint falls within a free VMA that is large enough to contain the requested
  * size, the function will return the block that starts at the hint address. If the hint
  * is not within a free block or the block is too small, the function will fall back to
  * a reverse search for a suitable block.
  *
  * @param size The minimum size required (in bytes).
  * @param hint The hint address to start the search near.
  * @param out_addr Pointer to store the start address of the found free area.
  * @return true if a suitable free area is found, false otherwise.
  */
 bool vma_find_free_hint(size_t size, uintptr_t hint, uintptr_t *out_addr);

/**
 * @brief Reserves a specific range of memory.
 * The range must currently be entirely within a single *free* VMA.
 *
 * @param start The starting address of the range to reserve.
 * @param size The size of the range to reserve.
 * @return true on success, false if the range is invalid, not free,
 *         or spans multiple VMAs, or on allocation error.
 */
bool vma_reserve(uintptr_t start, size_t size);

/**
 * @brief Deletes (frees) a specific range of memory.
 * The range must exactly match an existing *reserved* VMA.
 * Merges with adjacent free VMAs if possible.
 *
 * @param start The starting address of the range to delete.
 * @param size The size of the range to delete.
 * @return true on success, false if no matching reserved VMA is found
 *         or if the size doesn't match.
 */
bool vma_delete(uintptr_t start, size_t size);

/**
 * @brief Expands an existing reserved VMA.
 * Requires the immediately following VMA to be free and large enough.
 *
 * @param start The starting address of the reserved VMA to expand.
 * @param old_size The current size of the VMA.
 * @param new_size The desired new total size (must be > old_size).
 * @return true on success, false if the VMA is not found, not reserved,
 *         the next VMA is not suitable for expansion, or new_size <= old_size.
 */
bool vma_expand(uintptr_t start, size_t old_size, size_t new_size);

/**
 * @brief Shrinks an existing reserved VMA.
 * Creates a new free VMA for the released portion.
 *
 * @param start The starting address of the reserved VMA to shrink.
 * @param old_size The current size of the VMA.
 * @param new_size The desired new total size (must be > 0 and < old_size).
 * @return true on success, false if the VMA is not found, not reserved,
 *         or new_size is invalid, or on allocation error.
 */
bool vma_shrink(uintptr_t start, size_t old_size, size_t new_size);

/**
 * @brief Debugging function to print all VMAs in the list.
 */
void vma_dump(void);
