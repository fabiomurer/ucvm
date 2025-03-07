#pragma once

#include "vm.h"

void* vm_guest_to_host(struct vm* vm, uint64_t guest_addr);

void read_string_host(struct vm* vm, uint64_t guest_string_addr, char* buf, size_t bufsiz);

void write_string_guest(struct vm* vm, uint64_t guest_string_addr, char* buf, size_t bufsiz);

void read_buffer_host(struct vm* vm, uint64_t guest_buffer_addr, char* buf, size_t bufsiz);

void write_buffer_guest(struct vm* vm, uint64_t guest_buffer_addr, void* buf, size_t bufsiz);