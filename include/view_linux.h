#pragma once

#define _GNU_SOURCE

#include <stdint.h>
#include <sys/types.h>
#include <sys/user.h>

struct linux_view {
	char **argv;
	pid_t pid;
	int memfd;
};

void create_linux_view(char **argv, struct linux_view *linux_view);

void linux_view_get_regs(struct linux_view *view, struct user_regs_struct *regs);

int linux_view_read_mem(struct linux_view *view, off64_t src, void *dest, size_t len);

int linux_view_write_mem(struct linux_view *view, off64_t dest, const void *src, size_t len);

off64_t linux_view_alloc_mem(struct linux_view *view, size_t size);

void linux_view_free_mem(struct linux_view *view, off64_t addr, size_t size);

uint64_t linux_view_do_syscall(struct linux_view *view, uint64_t nr, uint64_t arg0, uint64_t arg1,
			       uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5);
