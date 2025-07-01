#include "vlinux/vlinux_syscall_munmap.h"
#include "vmm.h"
#include <sys/syscall.h>

uint64_t vlinux_syscall_munmap(struct linux_view *linux_view, uint64_t addr, uint64_t len)
{
	uint64_t ret = linux_view_do_syscall(linux_view, __NR_munmap, addr, len, 0, 0, 0, 0);

	// unmap in the guest
	if (ret == 0) { // successful unmap
		unmap_range(addr, len);
	}

	return ret;
}
