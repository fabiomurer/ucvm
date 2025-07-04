#include "vlinux/syscall_exit_group.h"
#include <sys/syscall.h>
#include <unistd.h>

uint64_t syscall_exit_group(int status)
{
	return syscall(SYS_exit_group, status);
}
