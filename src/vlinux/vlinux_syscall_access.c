#include "vlinux/vlinux_syscall_access.h"
#include "guest_inspector.h"
#include <linux/limits.h>
#include <sys/syscall.h>
#include <unistd.h>


uint64_t vlinux_syscall_access(struct vm *vm, uint64_t pathname, int mode)
{
    char tmp_pathname[PATH_MAX] = { 0 };
	read_string_host(vm, pathname, tmp_pathname, PATH_MAX);

	return syscall(__NR_access, tmp_pathname, mode);
}
