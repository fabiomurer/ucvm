#pragma once

struct arguments {
    bool trace_enabled;
    char *debug_server;
    char **program_args;
    int program_args_count;
    int cpu_pin;
};

extern struct arguments arguments;
