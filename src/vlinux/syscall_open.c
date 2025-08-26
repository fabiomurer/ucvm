#include "vlinux/syscall_open.h"
#include "guest_inspector.h"
#include "vfile.h"
#include "utils.h"
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>

uint64_t syscall_open(struct vm *vm, uint64_t filename, int flags, mode_t mode)
{
	char tmp_filename[PATH_MAX];
	if (read_string_host(vm, filename, tmp_filename, PATH_MAX) < 0) {
		PANIC("read_string_host");
	}

	int vfd = handle_virtual_file(tmp_filename);
	if (vfd != -1) {
		return vfd;
	}

	return open(tmp_filename, flags, mode);
}
