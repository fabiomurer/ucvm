#define _GNU_SOURCE

#include <stdio.h>
#include <sys/ioctl.h>

#include "guest_inspector.h"
#include "utils.h"
#include "vmm.h"

int vm_guest_to_host(struct vm *vm, u_int64_t guest_addr, void **host_addr, bool resolve_pf)
{
	*host_addr = host_virtual_addr_to_guest_physical_addr(guest_addr);

	// first try
	if (*host_addr == nullptr) {
		if (!resolve_pf) {
			return -1;
		}
		//  maybe the page is not mapped
		vm_page_fault_handler(vm, guest_addr);

		// second try
		*host_addr = host_virtual_addr_to_guest_physical_addr(guest_addr);

		if (*host_addr == nullptr) {
			return -1;
		}
	}
	
	return 0;
}

int read_string_host(struct vm *vm, uint64_t guest_string_addr, char *buf, size_t bufsiz)
{
	size_t byte_read = 0;
	char *host_addr = NULL;
	bool null_found = false;

	memset(buf, 0, bufsiz);

	while (byte_read < bufsiz && !null_found) {
		uint64_t current_addr = guest_string_addr + byte_read;
		uint64_t remaining = bufsiz - byte_read;
		uint64_t next_page_boundary = ROUND_PG(current_addr);
		uint64_t chunk_size;

		// If current_addr is already at a page boundary, ROUND_PG will
		// give us the next page
		if (current_addr == next_page_boundary) {
			next_page_boundary += PAGE_SIZE;
		}

		// Calculate how much we can read in this iteration
		if (current_addr + remaining <= next_page_boundary) {
			chunk_size = remaining;
		} else {
			chunk_size = next_page_boundary - current_addr;
		}

		if (vm_guest_to_host(vm, current_addr, (void **)&host_addr, true) < 0) {
			return -1;
		}

		// Look for null terminator in this chunk
		for (size_t i = 0; i < chunk_size; i++) {
			buf[byte_read + i] = host_addr[i];
			if (host_addr[i] == '\0') {
				null_found = true;
				break;
			}
		}

		if (null_found) {
			break;
		}

		byte_read += chunk_size;
	}

	return 0;
}

int write_string_guest(struct vm *vm, uint64_t guest_string_addr, char *buf, size_t bufsiz)
{
	size_t byte_written = 0;
	char *host_addr = NULL;
	bool null_found = false;

	while (byte_written < bufsiz && !null_found) {
		uint64_t current_addr = guest_string_addr + byte_written;
		uint64_t remaining = bufsiz - byte_written;
		uint64_t next_page_boundary = ROUND_PG(current_addr);
		uint64_t chunk_size;

		// If current_addr is already at a page boundary, ROUND_PG will
		// give us the next page
		if (current_addr == next_page_boundary) {
			next_page_boundary += PAGE_SIZE;
		}

		// Calculate how much we can write in this iteration
		if (current_addr + remaining <= next_page_boundary) {
			chunk_size = remaining;
		} else {
			chunk_size = next_page_boundary - current_addr;
		}

		if (vm_guest_to_host(vm, current_addr, (void **)&host_addr, true) < 0) {
			return -1;
		}

		// Copy data and check for null terminator
		for (size_t i = 0; i < chunk_size; i++) {
			host_addr[i] = buf[byte_written + i];
			if (buf[byte_written + i] == '\0') {
				null_found = true;
				byte_written += i + 1; // Include the null
						       // terminator in byte
						       // count
				break;
			}
		}

		if (null_found) {
			break;
		}

		byte_written += chunk_size;
	}

	// If we didn't find a null terminator and we have space, add one
	if (!null_found && byte_written < bufsiz) {
		uint64_t null_addr = guest_string_addr + byte_written;

		if (vm_guest_to_host(vm, null_addr, (void **)&host_addr, true) < 0) {
			return -1;
		}

		*host_addr = '\0';
	}

	return 0;
}

int read_buffer_host(struct vm *vm, uint64_t guest_buffer_addr, uint8_t *buf, size_t bufsiz)
{
	size_t byte_read = 0;
	char *host_addr = NULL;

	while (byte_read < bufsiz) {
		uint64_t current_addr = guest_buffer_addr + byte_read;
		uint64_t remaining = bufsiz - byte_read;
		uint64_t next_page_boundary;
		uint64_t chunk_size;

		// If we're exactly at a page boundary, ROUND_PG will give us
		// the next page boundary If not, it will round up to the next
		// page boundary
		next_page_boundary = ROUND_PG(current_addr);

		// If current_addr is already at a page boundary, ROUND_PG will
		// give us the next page
		if (current_addr == next_page_boundary) {
			next_page_boundary += PAGE_SIZE;
		}

		// Calculate how much we can read in this iteration
		if (current_addr + remaining <= next_page_boundary) {
			// Remaining data fits before the next page boundary
			chunk_size = remaining;
		} else {
			// Read until the next page boundary
			chunk_size = next_page_boundary - current_addr;
		}

		if (vm_guest_to_host(vm, current_addr, (void **)&host_addr, true) < 0) {
			return -1;
		}

		memcpy(buf + byte_read, host_addr, chunk_size);
		byte_read += chunk_size;
	}

	return 0;
}

int write_buffer_guest(struct vm *vm, uint64_t guest_buffer_addr, uint8_t *buf, size_t bufsiz)
{
	size_t byte_written = 0;
	char *host_addr = NULL;

	while (byte_written < bufsiz) {
		uint64_t current_addr = guest_buffer_addr + byte_written;
		uint64_t remaining = bufsiz - byte_written;
		uint64_t next_page_boundary;
		uint64_t chunk_size;

		// If we're exactly at a page boundary, ROUND_PG will give us
		// the next page boundary If not, it will round up to the next
		// page boundary
		next_page_boundary = ROUND_PG(current_addr);

		// If current_addr is already at a page boundary, ROUND_PG will
		// give us the next page
		if (current_addr == next_page_boundary) {
			next_page_boundary += PAGE_SIZE;
		}

		// Calculate how much we can write in this iteration
		if (current_addr + remaining <= next_page_boundary) {
			// Remaining data fits before the next page boundary
			chunk_size = remaining;
		} else {
			// Write until the next page boundary
			chunk_size = next_page_boundary - current_addr;
		}

		if (vm_guest_to_host(vm, current_addr, (void **)&host_addr, true) < 0) {
			return -1;
		}

		memcpy(host_addr, (char *)buf + byte_written, chunk_size);
		byte_written += chunk_size;
	}

	return 0;
}
