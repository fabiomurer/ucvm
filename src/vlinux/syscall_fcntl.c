#include "vlinux/syscall_fcntl.h"
#include <asm/unistd_64.h>
#include <unistd.h>

uint64_t syscall_fcntl(uint64_t fd, uint64_t cmd, uint64_t arg)
{
	return syscall(__NR_fcntl, fd, cmd, arg);
}
