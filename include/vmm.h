#pragma once

#include <linux/kvm.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/user.h> // for PAGE_SIZE

#include "intrusive_dlist.h"

#define PAGE_NUMBER 10000
#define MEMORY_SIZE (PAGE_SIZE * PAGE_NUMBER)
#define MEMORY_SLOT 0
#define GUEST_PHYS_ADDR 0x0

#define ALIGN (PAGE_SIZE - 1)
// 4096 -> 8192 (4096*2)
#define ROUND_PG(x) (((x) + (ALIGN)) & ~(ALIGN))
// 4095 -> 0
#define TRUNC_PG(x) ((x) & ~(ALIGN))

struct frame {
	size_t pfn;
	uint64_t host_virtual_addr;
	uint64_t guest_physical_addr;
	struct dlist_head list;
};

void *host_virtual_addr_to_guest_physical_addr(uint64_t vaddr);

void map_addr(uint64_t vaddr, uint64_t phys_addr);

uintptr_t map_page(uint64_t vaddr);

int unmap_addr(uint64_t vaddr);

void unmap_range(uint64_t vaddr_start, size_t size);

void cpu_init_long(struct kvm_sregs2 *sregs, void *memory);
