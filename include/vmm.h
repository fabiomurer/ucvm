#pragma once

#include <linux/kvm.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/user.h> // for PAGE_SIZE

#include "intrusive_dlist.h"

// clang-format off
/*
linux virtual memory map with 4-level page table

Start addr 				Offset 		End addr 				Size 		VM area description
0000_0000_0000_0000 	0 			0000_7fff_ffff_ffff 	128 TiB 	user-space virtual memory
0000_8000_0000_0000 	+128 TiB 	ffff_7fff_ffff_ffff		~16M TiB 	non-canonical
ffff_8000_0000_0000 	-128 TiB 	ffff_ffff_ffff_ffff 	128 TiB 	kernel-space virtual memory

we can assume that the kernel space virtual memory is not touched by the userspace
*/
// clang-format on

#define LINUX_VM_USER_START 0x0000000000000000ULL
#define LINUX_VM_NONCANONICAL_START 0x0000800000000000ULL
#define LINUX_VM_KERNEL_START 0xffff800000000000ULL

#define IDT_VADDR LINUX_VM_KERNEL_START

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

struct vmm {
	void *mem_host_virtual_addr;
	struct frame pml4t_addr;

	struct frame frames_pool[PAGE_NUMBER];
	struct dlist_head free_frames_list;
};

void vmm_init(struct vmm *vmm);

int vmm_get_free_frame(struct vmm *vmm, struct frame *frame);

void *vmm_host_virtual_addr_to_guest_physical_addr(struct vmm *vmm, uint64_t vaddr);

void vmm_map_addr(struct vmm *vmm, uint64_t vaddr, uint64_t phys_addr);

uintptr_t vmm_map_page(struct vmm *vmm, uint64_t vaddr);

int vmm_unmap_addr(struct vmm *vmm, uint64_t vaddr);

void vmm_unmap_range(struct vmm *vmm, uint64_t vaddr_start, size_t size);
