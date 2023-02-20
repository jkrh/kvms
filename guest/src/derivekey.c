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
//#include <linux/keyctl.h>
typedef uint64_t u64;
typedef uint32_t u32;

#include "hyp-drv.h"

//static char *prog_name;

//typedef int32_t key_serial_t;
/* special process keyring shortcut IDs */
#define KEY_SPEC_THREAD_KEYRING         -1      /* - key ID for thread-specific keyring */
#define KEY_SPEC_PROCESS_KEYRING        -2      /* - key ID for process-specific keyring */
#define KEY_SPEC_SESSION_KEYRING        -3      /* - key ID for session-specific keyring */
#define KEY_SPEC_USER_KEYRING           -4      /* - key ID for UID-specific keyring */
#define KEY_SPEC_USER_SESSION_KEYRING   -5      /* - key ID for UID-session keyring */
#define KEY_SPEC_GROUP_KEYRING          -6      /* - key ID for GID-specific keyring */
#define KEY_SPEC_REQKEY_AUTH_KEY        -7      /* - key ID for assumed request_key auth key */
#define KEY_SPEC_REQUESTOR_KEYRING      -8      /* - key ID for request_key() dest keyring */

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
