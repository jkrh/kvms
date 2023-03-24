#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <errno.h>
#include <sys/syscall.h>
typedef uint64_t u64;
typedef uint32_t u32;

#include "hyp-drv.h"

int main(int argc, char *argv[])
{
	int fd = -1, ret = 0;
	struct derived_key key;

	fd = open("/dev/kvms-if", O_RDWR);
	if (fd < 0) {
		perror("open /dev/kvms-if");
		return -1;
	}
	if (argc != 2) {
		perror("usage: getkey <salt>\n");
		return -1;
	}
	memset(&key, 0, sizeof(key));
	strncpy(key.salt, argv[1], sizeof(key.salt));
	key.saltsize = strlen(argv[1]);
	if (key.saltsize > sizeof(key.salt)) {
		key.saltsize = sizeof(key.salt);
	}
	key.keysize = 32;
	ret = ioctl(fd, HYPDRV_GET_DERIVED_KEY, &key);
	if (!ret)
		for (int i = 0; i < 32; i++)
			printf("%02x", key.key[i]);
	if (fd >= 0)
		close(fd);

	return ret;
}
