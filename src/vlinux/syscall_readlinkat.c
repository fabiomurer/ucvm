#include "vlinux/syscall_readlinkat.h"
#include "guest_inspector.h"
#include "utils.h"
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>

uint64_t syscall_readlinkat(struct vm* vm, int dirfd, uint64_t pathname, uint64_t buf, int bufsiz)
{
    uint64_t ret = 0;

    char tmp_pathname[PATH_MAX] = {0};
	if (read_string_host(vm, pathname, tmp_pathname, bufsiz) < 0) {
		PANIC("read_string_host");
	}
    
	if (strcmp("/proc/self/exe", tmp_pathname) == 0 && dirfd == AT_FDCWD) {
    
		char tmp_buf[PATH_MAX] = {0};
		if (realpath(vm->linux_view.argv[0], tmp_buf) == NULL) {
			PANIC_PERROR("realpath");
		}
		ret = strlen(tmp_buf);
		if (write_string_guest(vm, buf, tmp_buf, PATH_MAX) < 0) {
			PANIC("write_string_guest");
		}
    
	} else {
		PANIC("__NR_readlinkat case not supported");
		ret = -1;
	}

    return ret;
}
