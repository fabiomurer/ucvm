#include "vlinux/syscall_pread64.h"
#include "guest_inspector.h"
#include "utils.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

uint64_t syscall_pread64(struct vm *vm, int fd, uint64_t buf, size_t count, off_t offset)
{
	uint8_t *tmp_buff = malloc(count);

	uint64_t ret = syscall(__NR_pread64, fd, tmp_buff, count, offset);

	if (write_buffer_guest(vm, buf, tmp_buff, count) < 0) {
		PANIC("write_buffer_guest");
	}
	free(tmp_buff);

	return ret;
}
