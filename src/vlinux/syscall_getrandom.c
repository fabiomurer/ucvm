#include "vlinux/syscall_getrandom.h"
#include "guest_inspector.h"
#include "utils.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>

uint64_t syscall_getrandom(struct vm *vm, uint64_t buf, size_t buflen, unsigned int flags)
{
	uint8_t *tbuf = malloc(buflen);
	if (tbuf == NULL) {
		PANIC_PERROR("malloc");
	}

	uint64_t ret = getrandom(tbuf, buflen, flags);

	if (write_buffer_guest(vm, buf, tbuf, buflen) < 0) {
		PANIC("write_buffer_guest");
	}
	free(tbuf);

	return ret;
}
