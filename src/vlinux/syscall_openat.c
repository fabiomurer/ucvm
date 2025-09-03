#include "vlinux/syscall_openat.h"
#include "guest_inspector.h"
#include "utils.h"
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <linux/limits.h>
#include <unistd.h>
#include "vfiles.h"
#include "arguments.h"

uint64_t syscall_openat(struct vm *vm, int dirfd, uint64_t filename, int flags, mode_t mode)
{
	char tmp_filename[PATH_MAX] = { 0 };
	read_string_host(vm, filename, tmp_filename, PATH_MAX);

	if (dirfd != AT_FDCWD) {
		PANIC("openat flag not supported");
	}

	if (arguments.vfiles_enabled) {
		int vfd = handle_virtual_file(tmp_filename);
		if (vfd != -1) {
			return vfd;
		}
	}

	return syscall(__NR_openat, dirfd, tmp_filename, flags, mode);
}
