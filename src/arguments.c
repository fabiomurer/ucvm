#include "arguments.h"

struct arguments arguments = { .trace_enabled = false,
			       .vfiles_enabled = false,
			       .debug_server = nullptr,
			       .program_args = nullptr,
			       .program_args_count = 0,
			       .cpu_pin = -1 };
