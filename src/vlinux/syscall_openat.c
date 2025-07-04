#include "vlinux/syscall_openat.h"
#include "guest_inspector.h"
#include <sys/syscall.h>
#include <linux/limits.h>
#include <unistd.h>

uint64_t syscall_openat(struct vm *vm, int dirfd, uint64_t filename, int flags, mode_t mode)
{
	char tmp_filename[PATH_MAX] = { 0 };
	read_string_host(vm, filename, tmp_filename, PATH_MAX);

	return syscall(__NR_openat, dirfd, tmp_filename, flags, mode);
}
