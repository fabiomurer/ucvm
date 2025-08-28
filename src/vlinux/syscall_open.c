#include "vlinux/syscall_open.h"
#include <fcntl.h>
#include "vlinux/syscall_openat.h"


uint64_t syscall_open(struct vm *vm, uint64_t filename, int flags, mode_t mode)
{
	return syscall_openat(vm, AT_FDCWD, filename, flags, mode);
}
