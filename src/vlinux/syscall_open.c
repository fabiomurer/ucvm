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

	const char *vfile = handle_virtual_files(tmp_filename);
	if (vfile != nullptr) {
		// is a virtual file
		return open(vfile, flags, mode);
	}

	return open(tmp_filename, flags, mode);
}
