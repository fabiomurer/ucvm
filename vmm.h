#pragma once

#include <stdint.h>
#include <stddef.h>
#include <linux/kvm.h>

#define PAGE_SIZE 4096
#define PAGE_NUMBER 4096
#define MEMORY_SIZE (PAGE_SIZE * PAGE_NUMBER)
#define MEMORY_SLOT 0
#define GUEST_PHYS_ADDR 0

#define ALIGN		(PAGE_SIZE - 1)
// 4096 -> 8192 (4096*2)
#define ROUND_PG(x)	(((x) + (ALIGN)) & ~(ALIGN))
// 4095 -> 0
#define TRUNC_PG(x)	((x) & ~(ALIGN))

struct memory_chunk {
	size_t size;
	uintptr_t host;
	uintptr_t guest;
};

struct memory_chunk get_free_memory_chunk(size_t pages_count);
struct memory_chunk alloc_pages(size_t pages_count);
struct memory_chunk alloc_memory(uint64_t guest_vaddr, size_t length);

void cpu_init_long(struct kvm_sregs2 *sregs, void* memory);