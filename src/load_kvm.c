#define _GNU_SOURCE
#include "load_kvm.h"

#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "utils.h"
#include "vmm.h"

void copy_into_kvm(uint8_t *buffer, uint64_t len, uint64_t start,
		   uint64_t end __attribute__((unused)), char *perms __attribute__((unused)),
		   char *pathname __attribute__((unused)))
{
	// allocating memory
	struct memory_chunk mem = alloc_memory(start, len);

	// copy data into guest
	memcpy((void *)mem.host, buffer, len);
}

#define LINE_SIZE 4096

void load_kvm(pid_t pid)
{
	char pid_string[128] = { 0 };
	sprintf(pid_string, "%d", pid);

	char maps_path[PATH_MAX] = { 0 };
	snprintf(maps_path, sizeof(maps_path), "/proc/%s/maps", pid_string);

	FILE *maps_file = fopen(maps_path, "r");
	if (!maps_file) {
		PANIC_PERROR("fopen");
	}

	char mem_path[PATH_MAX] = { 0 };
	snprintf(mem_path, sizeof(mem_path), "/proc/%s/mem", pid_string);
	int mem_fd = open(mem_path, O_RDONLY);
	if (mem_fd < 0) {
		PANIC_PERROR("open");
	}

	char line[LINE_SIZE];
	while (fgets(line, sizeof(line), maps_file) != NULL) {
		u_int64_t start = 0, end = 0;
		char perms[5] = { 0 };
		u_int64_t offset = 0;
		char dev[32] = { 0 };
		u_int64_t inode = 0;
		char pathname[PATH_MAX] = { 0 };

		// Parse the line.
		// The expected format is:
		// address           perms offset  dev   inode       pathname
		// e.g., 00400000-00452000 r-xp 00000000 08:02 173521
		// /usr/bin/dbus-daemon pathname is optional, so we include it
		// as an optional field
		sscanf(line, "%lx-%lx %4s %lx %31s %lx %4095[^\n]", &start, &end, perms, &offset,
		       dev, &inode, pathname);

		// Calculate the size of the segment.
		size_t segment_size = end - start;
		if (segment_size == 0)
			continue;

		// Allocate a buffer to hold the segment's memory.
		u_int8_t *buffer = malloc(segment_size);
		if (buffer == NULL) {
			PANIC_PERROR("malloc");
		}

		// Read the segment from the process's memory.
		ssize_t read_bytes = pread(mem_fd, buffer, segment_size, start);
		if (read_bytes < 0) {
#ifdef DEBUG
			fprintf(stderr, "Failed to read memory from 0x%lx to 0x%lx: %s\n", start,
				end, strerror(errno));
// fill buffer with zeros
#endif
			memset(buffer, 0, segment_size);
		} else {
#ifdef DEBUG
			printf("Extracted segment 0x%lx-0x%lx (%ld bytes)\n", start, end,
			       (long)read_bytes);
#endif
		}

		copy_into_kvm(buffer, segment_size, start, end, perms, pathname);

		free(buffer);
	}

	close(mem_fd);
	fclose(maps_file);
}
