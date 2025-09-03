#include "vlinux/syscall_fadvise64.h"
#include <asm/unistd_64.h>
#include <unistd.h>

uint64_t syscall_fadvise64(uint64_t fd, uint64_t offset, uint64_t len, uint64_t advice)
{
	return syscall(__NR_fadvise64, fd, offset, len, advice);
}
