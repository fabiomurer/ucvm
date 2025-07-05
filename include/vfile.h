#pragma once
#include <linux/limits.h>

struct virtual_file {
	char virtual_name[PATH_MAX];
	char real_name[PATH_MAX];

	const char *content;
};

const char *handle_virtual_files(char *filename);
