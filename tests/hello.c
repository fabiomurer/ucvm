// Generic system call function for x86_64 Linux
static inline long my_syscall(long syscall_number, long arg1, long arg2,
                              long arg3, long arg4, long arg5, long arg6) {

  register long syscall_no asm("rax") = syscall_number;
  register long a1 asm("rdi") = arg1;
  register long a2 asm("rsi") = arg2;
  register long a3 asm("rdx") = arg3;
  register long a4 asm("r10") = arg4;
  register long a5 asm("r8") = arg5;
  register long a6 asm("r8") = arg6;
  asm("syscall");

  if (syscall_no < 0) {
    return -syscall_no;
  } else {
    return syscall_no;
  }
}

void __attribute__((noreturn)) __attribute__((section(".start"))) _start(void) {
  char *buff = "ciao a tutti\n";

  int ret = my_syscall(1, 1, (long)buff, 14, 0, 0, 0); // write to stdout

  if (ret == 14) {
    my_syscall(60, 0, 0, 0, 0, 0, 0); // exit succes
  } else {
    my_syscall(60, -1, 0, 0, 0, 0, 0); // exit error
  }

  for (;;)
    asm("hlt");
}