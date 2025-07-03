#include "vlinux/syscall_write.h"
#include "guest_inspector.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

uint64_t syscall_write(struct vm *vm, int fd, uint64_t buff, size_t len)
{
	uint8_t *tmp_buff = malloc(sizeof(uint8_t) * len);
	if (read_buffer_host(vm, buff, tmp_buff, len) < 0) {
		PANIC("read_buffer_host");
	}

	uint64_t ret = write(fd, tmp_buff, len);
	free(tmp_buff);

	return ret;
}
