#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include "utils.h"
#include "vmm.h"
#include "guest_inspector.h"

/*void* vm_guest_to_host(struct vm* vm, u_int64_t guest_addr) {
	struct kvm_translation transl_addr;
	transl_addr.linear_address = guest_addr;

	if (ioctl(vm->vcpufd, KVM_TRANSLATE, &transl_addr) < 0) {
		panic("KVM_TRANSLATE");
	}

	if (transl_addr.valid == 0) {
		fprintf(stderr, "KVM_TRANSLATE address: %p not valid\n", (void*)guest_addr);
		exit(EXIT_FAILURE);
	}

	return (void*)((uint64_t)vm->memory + transl_addr.physical_address - GUEST_PHYS_ADDR);
}*/

int vm_guest_to_host(struct vm* vm, u_int64_t guest_addr, void** host_addr) {
	struct kvm_translation transl_addr;
	transl_addr.linear_address = guest_addr;

	if (ioctl(vm->vcpufd, KVM_TRANSLATE, &transl_addr) < 0) {
		panic("KVM_TRANSLATE");
	}

	if (transl_addr.valid == 0) {
		return -1;
	}

	*host_addr = (void*)((uint64_t)vm->memory + transl_addr.physical_address - GUEST_PHYS_ADDR);
	return 0;
}

int read_string_host(struct vm* vm, uint64_t guest_string_addr, char* buf, size_t bufsiz) {
	size_t byte_read = 0;
	char* host_addr = NULL;

	memset(buf, 0, bufsiz);
	do {
		if(vm_guest_to_host(vm, guest_string_addr + byte_read, (void**)&host_addr) < 0) {
			return -1;
		}
		buf[byte_read] = *host_addr;
		byte_read++;
	} while (byte_read < bufsiz && *host_addr != '\0');
	return 0;
}

int write_string_guest(struct vm* vm, uint64_t guest_string_addr, char* buf, size_t bufsiz) {
	size_t byte_written = 0;
	char* host_addr = NULL;

	do {
		if(vm_guest_to_host(vm, guest_string_addr + byte_written, (void**)&host_addr) < 0) {
			return -1;
		}
		*host_addr = buf[byte_written];
		byte_written++;
	} while (byte_written < bufsiz && buf[byte_written] != '\0');

	if (byte_written+1 < bufsiz) {
		byte_written++;
		if(vm_guest_to_host(vm, guest_string_addr + byte_written, (void**)&host_addr) < 0) {
			return -1;
		}
		*host_addr = '\0';
	}
	return 0;
}

int read_buffer_host(struct vm* vm, uint64_t guest_buffer_addr, uint8_t* buf, size_t bufsiz) {
    size_t byte_read = 0;
    char* host_addr = NULL;

    while (byte_read < bufsiz) {
        uint64_t current_addr = guest_buffer_addr + byte_read;
        uint64_t remaining = bufsiz - byte_read;
        uint64_t next_page_boundary;
        uint64_t chunk_size;
        
        // If we're exactly at a page boundary, ROUND_PG will give us the next page boundary
        // If not, it will round up to the next page boundary
        next_page_boundary = ROUND_PG(current_addr);
        
        // If current_addr is already at a page boundary, ROUND_PG will give us the next page
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
        
        if (vm_guest_to_host(vm, current_addr, (void**)&host_addr) < 0) {
            return -1;
        }
        
        memcpy(buf + byte_read, host_addr, chunk_size);
        byte_read += chunk_size;
    }
    
    return 0;
}

int write_buffer_guest(struct vm* vm, uint64_t guest_buffer_addr, uint8_t* buf, size_t bufsiz) {
    size_t byte_written = 0;
    char* host_addr = NULL;
    
    while (byte_written < bufsiz) {
        uint64_t current_addr = guest_buffer_addr + byte_written;
        uint64_t remaining = bufsiz - byte_written;
        uint64_t next_page_boundary;
        uint64_t chunk_size;
        
        // If we're exactly at a page boundary, ROUND_PG will give us the next page boundary
        // If not, it will round up to the next page boundary
        next_page_boundary = ROUND_PG(current_addr);
        
        // If current_addr is already at a page boundary, ROUND_PG will give us the next page
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
        
        if (vm_guest_to_host(vm, current_addr, (void**)&host_addr) < 0) {
            return -1;
        }
        
        memcpy(host_addr, (char*)buf + byte_written, chunk_size);
        byte_written += chunk_size;
    }
    
    return 0;
}
