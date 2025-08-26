#pragma once
#define _GNU_SOURCE

#include "view_linux.h"
#include "vmm.h"

uint64_t syscall_munmap(struct linux_view *linux_view, struct vmm *vmm, uint64_t addr,
			uint64_t len);
