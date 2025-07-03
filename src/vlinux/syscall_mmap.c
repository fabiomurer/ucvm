#include "vlinux/syscall_mmap.h"
#include "utils.h"
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <linux/limits.h>

uint64_t syscall_mmap(struct linux_view *linux_view, void *addr, size_t lenght, int prot,
			     int flags, int fd, off_t offset)
{
	uint64_t ret = 0;

	if (!(flags & MAP_PRIVATE)) {
		PANIC("syscall_mmap MAP_SHARED not supported");
	}

	// simple, no fils need to be open
	if (flags & MAP_ANONYMOUS) {
		ret = linux_view_do_syscall(linux_view, __NR_mmap, (uint64_t)addr, lenght, prot,
					    flags, fd, offset);
	} else {
		// make linux view open file, mmap, close file

		// copy file name parameter
		char *filename = get_path_from_fd(fd);
		if (filename == nullptr) {
			PANIC("get_path_from_fd");
		}

		off64_t view_addr = linux_view_alloc_mem(linux_view, (size_t)PATH_MAX);

		if (linux_view_write_mem(linux_view, view_addr, filename, PATH_MAX) != 0) {
			PANIC("linux_view_write_mem");
		}

		// open it
		uint64_t view_fd = linux_view_do_syscall(linux_view, __NR_open, view_addr, O_RDONLY,
							 0, 0, 0, 0);
		if (view_fd == (uint64_t)-1) {
			PANIC("linux_view_do_syscall(__NR_open)");
		}

		ret = linux_view_do_syscall(linux_view, __NR_mmap, (uint64_t)addr, lenght, prot,
					    flags, view_fd, offset);

		// cleanup
		free(filename);
		(void)linux_view_do_syscall(linux_view, __NR_close, view_fd, 0, 0, 0, 0, 0);
		linux_view_free_mem(linux_view, view_addr, (size_t)PATH_MAX);
	}

	return ret;
}
