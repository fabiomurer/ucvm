#define _GNU_SOURCE

#include <linux/limits.h>
#include <stdio.h>
#include <unistd.h>

#include "utils.h"

// Function to get the absolute path from a file descriptor
char *get_path_from_fd(int fd)
{
	char proc_path[PATH_MAX];
	(void)snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);

	char *file_path = malloc(PATH_MAX);
	if (file_path == nullptr) {
		PANIC_PERROR("malloc");
	}

	ssize_t len = readlink(proc_path, file_path, PATH_MAX - 1);
	if (len == -1) {
		free(file_path);
		PANIC_PERROR("readlink");
	}

	file_path[len] = '\0';

	return file_path;
}
