#include "vlinux/syscall_open.h"

#include "utils.h"
#include <fcntl.h>
#include <linux/limits.h>
#include "guest_inspector.h"
#include <stdio.h>

uint64_t syscall_open(struct vm *vm, uint64_t filename, int flags, mode_t mode)
{
	char tmp_filename[PATH_MAX];
	if (read_string_host(vm, filename, tmp_filename, PATH_MAX) < 0) {
		PANIC("read_string_host");
	}

	return open(tmp_filename, flags, mode);
}
