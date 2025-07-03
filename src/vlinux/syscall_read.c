#include "vlinux/syscall_read.h"
#include "utils.h"
#include "guest_inspector.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

uint64_t syscall_read(struct vm *vm, int fd, uint64_t buff, size_t len)
{
	uint8_t *tmp_buff = malloc(sizeof(uint8_t) * len);

	uint64_t ret = read(fd, tmp_buff, len);

	if (write_buffer_guest(vm, buff, tmp_buff, len) < 0) {
		PANIC("write_buffer_guest");
	}
	free(tmp_buff);

	return ret;
}
