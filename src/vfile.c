#include "vfile.h"
#include "utils.h"
#include <stdio.h>

const char virtual_passwd[] = "root:x:0:0:root:/root:/bin/bash\n"
			      "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
			      "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
			      "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
			      "sync:x:4:65534:sync:/bin:/bin/sync\n"
			      "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
			      "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
			      "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
			      "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
			      "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n"
			      "ucvm:x:1001:1001:User Ucvm:/home/u1:/bin/bash\0";

const char virtual_shadow[] =
	"root:$6$abcdefgh$1234567890abcdefghijklmnopqrstuvwx:19000:0:99999:7:::\n"
	"daemon:*:19000:0:99999:7:::\n"
	"bin:*:19000:0:99999:7:::\n"
	"sys:*:19000:0:99999:7:::\n"
	"sync:*:19000:0:99999:7:::\n"
	"games:*:19000:0:99999:7:::\n"
	"man:*:19000:0:99999:7:::\n"
	"lp:*:19000:0:99999:7:::\n"
	"mail:*:19000:0:99999:7:::\n"
	"news:*:19000:0:99999:7:::\n"
	"ucvm:$6$ijklmnop$0987654321ponmlkjihgfedcbazyxwvutsr:19000:0:99999:7:::\0";

void virtual_file_create(const struct virtual_file *vfile)
{
	FILE *file = fopen(vfile->real_name, "w");
	if (!file) {
		PANIC_PERROR("fopen");
	}
	fputs(vfile->content, file);
	fclose(file);
}

#define VFILES_N 2

const struct virtual_file vfiles[VFILES_N] = { { .virtual_name = "/etc/passwd",
						 .real_name = "/tmp/ucvm_passwd",
						 .content = virtual_passwd },

					       { .virtual_name = "/etc/shadow",
						 .real_name = "/tmp/ucvm_shadow",
						 .content = virtual_shadow } };

const char *handle_virtual_files(char *filename)
{
	char filename_resolved[PATH_MAX];

	if (realpath(filename, filename_resolved) == NULL) {
		// not valid path
		return nullptr;
	}

	for (int i = 0; i < VFILES_N; i++) {
		if (strcmp(filename, vfiles[i].virtual_name) == 0) {
			virtual_file_create(&vfiles[i]);

			return vfiles[i].real_name;
		}
	}

	return nullptr;
}
