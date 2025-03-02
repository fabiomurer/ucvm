#define _GNU_SOURCE

#include "utils.h"
#include "vm.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/kvm.h>
#include <stdbool.h>
#include <error.h>

#define KVM_DEVICE "/dev/kvm"

#define PAGE_SIZE 4096
#define PAGE_NUMBER 4096
#define MEMORY_SIZE (PAGE_SIZE * PAGE_NUMBER)
#define MEMORY_SLOT 1


struct vm vm_create(void) {
    struct vm vm;

    // connect to kvm
    if ((vm.kvmfd = open(KVM_DEVICE, O_RDWR | O_CLOEXEC)) < 0) {
        panic("Failed to open " KVM_DEVICE);
    }

    // Check KVM API version
    int api_version = ioctl(vm.kvmfd, KVM_GET_API_VERSION, 0);
    if (api_version == -1) panic("KVM_GET_API_VERSION");
    if (api_version != 12) { 
        panic("KVM API version not supported");
    }

    // create a vm
    if ((vm.vmfd = ioctl(vm.kvmfd, KVM_CREATE_VM, 0)) < 0) {
        panic("KVM_CREATE_VM");
    }

    // create vcpu
    ssize_t vcpu_mmap_size;
    if ((vcpu_mmap_size = ioctl(vm.kvmfd, KVM_GET_VCPU_MMAP_SIZE, 0)) <= 0) {
        panic("KVM_GET_VCPU_MMAP_SIZE");
    }

    if ((vm.vcpufd = ioctl(vm.vmfd, KVM_CREATE_VCPU, 0)) < 0) {
        panic("KVM_CREATE_VCPU");
    }

    if ((vm.run = mmap(NULL, vcpu_mmap_size, 
            PROT_READ | PROT_WRITE, 
            MAP_SHARED, 
            vm.vcpufd, 0)) == MAP_FAILED) {
        panic("MMAP");
    }

    // create memory
    if ((vm.memory = mmap(
                NULL, MEMORY_SIZE, 
                PROT_READ | PROT_WRITE, 
                MAP_SHARED | MAP_ANONYMOUS, 
                -1, 0)
            ) == MAP_FAILED) {
        panic("MMAP");
    }

    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .flags = 0,
        .guest_phys_addr = 0,
        .memory_size = MEMORY_SIZE,
        .userspace_addr = (uint64_t)vm.memory,
    };

    if (ioctl(vm.vmfd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
        panic("KVM_SET_USER_MEMORY_REGION");
    }

    return vm;
}
