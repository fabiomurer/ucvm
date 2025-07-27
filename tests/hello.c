#include "syscall.h"
#include <asm/unistd_64.h>
#include <stddef.h>

void __attribute__((noreturn)) __attribute__((section(".start"))) _start(void) {
  char *buff = "ciao a tutti\n";
  long len = 14;

  long ret = syscall_syscall(__NR_write, 1, (long)buff, len, 0, 0, 0); // write to stdout

  if (ret == len) {
    syscall_syscall(__NR_exit_group, 0, 0, 0, 0, 0, 0); // exit succes
  } else {
    syscall_syscall(__NR_exit_group, -1, 0, 0, 0, 0, 0); // exit error
  }

  for (;;) {
    __asm__("hlt");
  }
}
