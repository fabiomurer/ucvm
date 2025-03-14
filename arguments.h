#pragma once

struct arguments {
    bool trace_enabled;
    char *debug_server;
    char **program_args;  /* Arguments to pass to another program */
    int program_args_count;
};

extern struct arguments arguments;
