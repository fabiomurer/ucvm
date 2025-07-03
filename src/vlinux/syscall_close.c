#include "vlinux/syscall_close.h"
#include <unistd.h>

uint64_t syscall_close(int fd)
{
	return close(fd);
}
