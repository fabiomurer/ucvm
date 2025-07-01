#include "vlinux/vlinux_syscall_fstat.h"
#include "guest_inspector.h"
#include "utils.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>

uint64_t vlinux_syscall_fstat(struct vm *vm, int fd, uint64_t statbuf)
{
	struct stat tmp_statbuf;

	uint64_t ret = 0;

	if (fstat(fd, &tmp_statbuf) < 0) {
		ret = -errno;
	} else {
		if (write_buffer_guest(vm, statbuf, (uint8_t *)&tmp_statbuf, sizeof(tmp_statbuf)) <
		    0) {
			PANIC("write_buffer_guest");
		}
	}

	return ret;
}
