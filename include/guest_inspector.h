#pragma once

#include "vm.h"

int vm_guest_to_host(struct vm* vm, u_int64_t guest_addr, void** host_addr);

int read_string_host(struct vm* vm, uint64_t guest_string_addr, char* buf, size_t bufsiz);

int write_string_guest(struct vm* vm, uint64_t guest_string_addr, char* buf, size_t bufsiz);

int read_buffer_host(struct vm* vm, uint64_t guest_buffer_addr, uint8_t* buf, size_t bufsiz);

int write_buffer_guest(struct vm* vm, uint64_t guest_buffer_addr, uint8_t* buf, size_t bufsiz);
