#include <linux/kvm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include "utils.h"
#include "vmm.h"
#include "guest_inspector.h"

void* vm_guest_to_host(struct vm* vm, u_int64_t guest_addr) {
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
}

void read_string_host(struct vm* vm, uint64_t guest_string_addr, char* buf, size_t bufsiz) {
	size_t byte_read = 0;
	char* host_addr = NULL;

	memset(buf, 0, bufsiz);
	do {
		host_addr = vm_guest_to_host(vm, guest_string_addr + byte_read);
		buf[byte_read] = *host_addr;
		byte_read++;
	} while (byte_read < bufsiz && *host_addr != '\0');
}

void write_string_guest(struct vm* vm, uint64_t guest_string_addr, char* buf, size_t bufsiz) {
	size_t byte_written = 0;
	char* host_addr = NULL;

	do {
		host_addr = vm_guest_to_host(vm, guest_string_addr + byte_written);
		*host_addr = buf[byte_written];
		byte_written++;
	} while (byte_written < bufsiz && buf[byte_written] != '\0');

	if (byte_written+1 < bufsiz) {
		byte_written++;
		host_addr = vm_guest_to_host(vm, guest_string_addr + byte_written);
		*host_addr = '\0';
	}
}

void read_buffer_host(struct vm* vm, uint64_t guest_buffer_addr, char* buf, size_t bufsiz) {
	size_t byte_read = 0;
	char* host_addr = NULL;

    do {
        uint64_t start = guest_buffer_addr + byte_read;
        uint64_t end;
        if (ROUND_PG(start) < guest_buffer_addr + bufsiz) {
            // copy in one go at max at end of a page
            end = ROUND_PG(start);
        } else {
            // it ends before the next page
            end = guest_buffer_addr + bufsiz;
        }
        uint64_t delta = end - start;

        host_addr = vm_guest_to_host(vm, start);

        memcpy(buf + byte_read, host_addr, delta);

        byte_read += delta;
    } while (byte_read < bufsiz);
}

void write_buffer_guest(struct vm* vm, uint64_t guest_buffer_addr, void* buf, size_t bufsiz) {
	size_t byte_written = 0;
	char* host_addr = NULL;

    do {
        uint64_t start = guest_buffer_addr + byte_written;
        uint64_t end;
        if (ROUND_PG(start) < guest_buffer_addr + bufsiz) {
            // copy in one go at max at end of a page
            end = ROUND_PG(start);
        } else {
            // it ends before the next page
            end = guest_buffer_addr + bufsiz;
        }
        uint64_t delta = end - start;

        host_addr = vm_guest_to_host(vm, start);

        memcpy(host_addr, buf + byte_written, delta);

        byte_written += delta;
    } while (byte_written < bufsiz);
}