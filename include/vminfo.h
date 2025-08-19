#pragma once

#include "vm.h"

void vcpu_events_logs(struct vm *vm);

void vcpu_regs_log(struct vm *vm);

void vcpu_logs_exit(struct vm *vm, int exit_status);
