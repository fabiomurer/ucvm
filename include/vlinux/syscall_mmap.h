#pragma once
#define _GNU_SOURCE

#include "view_linux.h"

uint64_t syscall_mmap(struct linux_view *linux_view, void *addr, size_t lenght, int prot,
			     int flags, int fd, off_t offset);
