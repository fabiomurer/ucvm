
#include <argp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arguments.h"
#include "load_linux.h"
#include "mygdbstub.h"
#include "vm.h"

// Program documentation
const char *argp_program_version = "ucvm 0.1";
const char *argp_program_bug_address = "https://github.com/fabiomurer/ucvm";
static char doc[] = "Run user-mode code in a kvm vm";
static char args_doc[] = "[ARGS...]";

static struct argp_option options[] = { { "debug", 'd', "HOST:PORT", 0,
					  "Enable debug mode with specified server", 0 },
					{ "trace", 't', 0, 0, "Enable trace mode", 0 },
					{ "pin", 'p', "CORE", 0, "Pin to specified CPU core", 0 },
					{ 0 } };

// parse a single option
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;

	switch (key) {
	case 'd': /* --debug */
		arguments->debug_server = arg;
		break;
	case 't': /* --trace */
		arguments->trace_enabled = true;
		break;
	case 'p': /* --pin */
		arguments->cpu_pin = atoi(arg);
		break;
	case ARGP_KEY_END:
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = { .options = options,
			    .parser = parse_opt,
			    .args_doc = args_doc,
			    .doc = doc };

int find_dash_dash_position(int argc, char *argv[])
{
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0) {
			return i;
		}
	}
	return -1; /* Not found */
}

// global variable
struct arguments arguments;

int main(int argc, char *argv[])
{
	/* Default values */
	arguments.trace_enabled = false;
	arguments.debug_server = NULL;
	arguments.program_args = NULL;
	arguments.program_args_count = 0;
	arguments.cpu_pin = -1; /* -1 indicates no pinning */

	/* Find the position of -- if it exists */
	int separator_pos = find_dash_dash_position(argc, argv);

	/* Create modified argc/argv for parsing if -- was found */
	int parse_argc = argc;
	if (separator_pos != -1) {
		parse_argc = separator_pos;
	}

	/* Parse our arguments up to -- (if present) */
	argp_parse(&argp, parse_argc, argv, 0, 0, &arguments);

	/* Handle arguments after -- */
	if (separator_pos != -1) {
		arguments.program_args = &argv[separator_pos + 1];
		arguments.program_args_count = argc - separator_pos - 1;
	}

	struct linux_proc linux_proc;
	linux_proc.argv = arguments.program_args;

	struct vm vm = vm_create();
	vm_init(&vm);
	vm_load_program(&vm, &linux_proc);
	if (arguments.debug_server != NULL) {
		struct debug_args debug_args = { .vm = &vm, .linux_proc = &linux_proc };

		vm_set_debug(&vm, true);
		debug_start(arguments.debug_server, &debug_args);
	} else {
		while (true) {
			int exit_code = vm_run(&vm);
			vm_exit_handler(exit_code, &vm, &linux_proc);
		}
	}
}
