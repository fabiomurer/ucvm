#define _GNU_SOURCE
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include "utils.h"

const char virtual_passwd[] = 
	"root:x:0:0:root:/root:/bin/bash\n"
	"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
	"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
	"sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
	"sync:x:4:65534:sync:/bin:/bin/sync\n"
	"games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
	"man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
	"lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
	"mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
	"news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n"
	"ucvm:x:1001:1001:User Ucvm:/home/u1:/bin/bash\n";

const char virtual_shadow[] =
	"root:$6$abcdefgh$1234567890abcdefghijklmnopqrstuvwx:19000:0:99999:7:::\n"
	"daemon:*:19000:0:99999:7:::\n"
	"bin:*:19000:0:99999:7:::\n"
	"sys:*:19000:0:99999:7:::\n"
	"sync:*:19000:0:99999:7:::\n"
	"games:*:19000:0:99999:7:::\n"
	"man:*:19000:0:99999:7:::\n"
	"lp:*:19000:0:99999:7:::\n"
	"mail:*:19000:0:99999:7:::\n"
	"news:*:19000:0:99999:7:::\n"
	"ucvm:$6$ijklmnop$0987654321ponmlkjihgfedcbazyxwvutsr:19000:0:99999:7:::\n";

struct virtual_file {
	const char *virtual_name;
	const char *content;
	size_t content_len;
};

#define VFILES_N 2

const struct virtual_file vfiles[VFILES_N] = {
	{ .virtual_name = "/etc/passwd",
	  .content = virtual_passwd,
	  .content_len = sizeof(virtual_passwd) - 1 }, // Use sizeof for compile-time length

	{ .virtual_name = "/etc/shadow",
	  .content = virtual_shadow,
	  .content_len = sizeof(virtual_shadow) - 1 }
};

int create_mem_fd(const char *name, const char *content, ssize_t len)
{
	// Create an anonymous file in memory.
	// MFD_CLOEXEC flag ensures the fd is closed on execve().
	int fd = memfd_create(name, MFD_CLOEXEC);
	if (fd == -1) {
		PANIC_PERROR("memfd_create");
	}

	// Write the content to the memory file.
	ssize_t n_written = write(fd, content, len);
	if (n_written == -1) {
		PANIC("write");
	}

    if (n_written != len) {
        PANIC("write len");
    }

	// Rewind the file descriptor to the beginning for subsequent reads.
	if (lseek(fd, 0, SEEK_SET) == -1) {
		PANIC("lseek");
	}

	return fd;
}


int handle_virtual_file(const char *filename)
{
	char filename_resolved[PATH_MAX];
	if (realpath(filename, filename_resolved) == NULL) {
		// Not a valid path or doesn't exist, can't be a virtual file.
		return -1;
	}

	for (int i = 0; i < VFILES_N; i++) {
		if (strcmp(filename_resolved, vfiles[i].virtual_name) == 0) {
			// Found a match, create a memory file descriptor.
			return create_mem_fd(filename_resolved, vfiles[i].content, vfiles[i].content_len);
		}
	}
	return -1;
}
