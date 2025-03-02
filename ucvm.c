
#include "vm.h"
#include <stdio.h>

int main() {
    struct vm vm = vm_create();
    printf("kvmfd: %d\n", vm.kvmfd);
    return 0;
}