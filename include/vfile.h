#pragma once
#include <linux/limits.h>

struct virtual_file {
	char virtual_name[PATH_MAX];
	char real_name[PATH_MAX];

	const char *content;
};

int handle_virtual_file(const char *filename);
