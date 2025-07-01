#include "vlinux/vlinux_syscall_close.h"
#include <unistd.h>

uint64_t vlinux_syscall_close(int fd)
{
	return close(fd);
}
