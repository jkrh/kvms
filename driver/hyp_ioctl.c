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

static char *prog_name;
void usage(void)
{
	printf("usage: %s <call nr> [<arg1> ...]\n\n", prog_name);
	printf("       %s 0 <maj> - specify device major for /dev/hyp-drv\n", prog_name);
	printf("       %s 1 - lock down kernel (set default protections)\n", prog_name);
	printf("       %s 2 <start> <end> <prot> - protect region (values in hex)\n", prog_name);
	printf("       %s 3 <start> <end> - [try to] write to region (values in hex)\n", prog_name);
	printf("       %s 4 <follow> - read hyp log, optionally follow (UNIMPLEMETED)\n", prog_name);
	printf("       %s 5 - generate key\n", prog_name);
	printf("       %s 6 - get key\n", prog_name);
}
typedef int32_t key_serial_t;
/* special process keyring shortcut IDs */
#define KEY_SPEC_THREAD_KEYRING         -1      /* - key ID for thread-specific keyring */
#define KEY_SPEC_PROCESS_KEYRING        -2      /* - key ID for process-specific keyring */
#define KEY_SPEC_SESSION_KEYRING        -3      /* - key ID for session-specific keyring */
#define KEY_SPEC_USER_KEYRING           -4      /* - key ID for UID-specific keyring */
#define KEY_SPEC_USER_SESSION_KEYRING   -5      /* - key ID for UID-session keyring */
#define KEY_SPEC_GROUP_KEYRING          -6      /* - key ID for GID-specific keyring */
#define KEY_SPEC_REQKEY_AUTH_KEY        -7      /* - key ID for assumed request_key auth key */
#define KEY_SPEC_REQUESTOR_KEYRING      -8      /* - key ID for request_key() dest keyring */

#define HOST_VMID 1

key_serial_t __attribute__((weak)) add_key(const char *type,
					   const char *description,
					   const void *payload,
					   size_t plen,
					   key_serial_t ringid)
{
	return syscall(__NR_add_key, type, description, payload, plen, ringid);
}

static int get_arg(char *str, u64 *dst)
{
	u64 val;

	if (sscanf(str, "%lx", &val) != 1)
		return -1;

	*dst = val;
	return 0;
}

int do_generate_key(int fd, char *arg)
{
	struct guest_key key;
	int ret;

#ifdef DEBUG
	printf("generate key %s\n", arg);
#endif
	memset(&key, 0, sizeof(key));
	strcpy(key.name, "hyp:");
	strncat(key.name, arg, 12);
	ret = ioctl(fd, HYPDRV_GENERATE_KEY, &key);
	if (ret)
		return ret;

	ret = (int) add_key("user", key.name,
		      key.key, strlen(key.key),
		      KEY_SPEC_SESSION_KEYRING);
	if (ret < 0)
		return ret;
	return 0;
}

int do_read_key(int fd, char *arg)
{
	struct guest_key key;
	int ret;

#ifdef DEBUG
	printf("read key %s\n", arg);
#endif
	strncpy(key.name, arg, 15);
	memset(&key, 0, sizeof(key));
	strcpy(key.name, "hyp:");
	strncat(key.name, arg, 12);
	ret = ioctl(fd, HYPDRV_READ_KEY, &key);
	if (ret)
		return ret;

	ret = (int) add_key("user", key.name,
			key.key, strlen(key.key),
			KEY_SPEC_SESSION_KEYRING);
	if (ret < 0)
		return ret;
	return 0;
}

int do_save_keys(int fd, char *arg)
{
	struct encrypted_keys keys;
	FILE *fp;
	int ret;

#ifdef DEBUG
	printf("save keys %s\n", arg);
#endif
	memset(&keys, 0, sizeof(keys));
	keys.vmid = HOST_VMID;
	ret = ioctl(fd, HYPDRV_SAVE_KEYS, &keys);
	if (ret)
		return ret;

	fp = fopen(arg, "w");
	if (!fp)
		return -EIO;

	fwrite(keys.buf, 1, keys.len, fp);
	fclose(fp);
	return 0;
}

int do_load_keys(int fd, char *arg)
{
	struct encrypted_keys keys;
	FILE *fp;
	int ret;
	int len = 0;
	char tst[32];

#ifdef DEBUG
	printf("load keys %s\n", arg);
#endif
	fp = fopen(arg, "r");
	if (!fp)
		return -EIO;

	keys.len = fread(keys.buf, 1, sizeof(keys.buf), fp);
	fclose(fp);
	keys.vmid = HOST_VMID;
	ret = ioctl(fd, HYPDRV_LOAD_KEYS, &keys);
	return ret;
}

int do_ioctl(int fd, int call, int argc, char *argv[])
{
	int ret = -1;
	u64 start, end, prot;
	struct hypdrv_mem_region hmr;
	unsigned int maj = 235;

	// printf("do_ioctl(%d, %d, %d, %s)\n", fd, call, argc, argc > 0 ? argv[0] : "NULL");
	errno = 0;
	switch (call) {
	case 0: /* mknod does always a local return */
		if (argc < 1 || sscanf(argv[0], "%u", &maj) != 1) {
			printf("Invalid device major: %s\n",
			       argc > 0 ? argv[0] : "NULL");
			usage();
			return -1;
		}
		/*  $ mknod  /dev/hyp-drv c 235 0 */
		if (maj == 0)
			maj = 235;
		if (mknod("/dev/hyp-drv", S_IFCHR|O_RDWR, makedev(maj, 0))) {
			perror("mknod /dev/hyp-drv");
			return -1;
		}
		return 0;
		break;
	case KERNEL_LOCK:
		// printf("ioctl(%d, HYPDRV_KERNEL_LOCK)\n", fd); ret = 0;
		ret = ioctl(fd, HYPDRV_KERNEL_LOCK);
		break;
	case KERNEL_MMAP:
		if (argc >= 3) {
			ret  = get_arg(argv[0], &start);
			ret += get_arg(argv[1], &end);
			ret += get_arg(argv[2], &prot);
			hmr = (struct hypdrv_mem_region){start, end, prot};

			if (ret == 0) {
#ifdef DEBUG
				printf("ioctl(%d, HYPDRV_KERNEL_MAP, {%lx, %lx, %lx})\n",
				       fd, start, end, prot);
#endif
				ret = ioctl(fd, HYPDRV_KERNEL_MMAP, &hmr);
			}
		}
		break;
	case KERNEL_WRITE:
		if (argc >= 2) {
			ret  = get_arg(argv[0], &start);
			ret += get_arg(argv[1], &end);
			hmr = (struct hypdrv_mem_region){start, end, 0};

			if (ret == 0) {
#ifdef DEBUG
				printf("ioctl(%d, HYPDRV_KERNEL_WRITE, {%lx, %lx, 0})\n",
				       fd, start, end);
#endif
				ret = ioctl(fd, HYPDRV_KERNEL_WRITE, &hmr);
			}
		}
		break;
	case GENERATE_KEY:
		if (argc >= 1) {
			ret = do_generate_key(fd, argv[0]);
		}
		break;
	case READ_KEY:
		if (argc >= 1) {
			ret = do_read_key(fd, argv[0]);
		}
		break;

	case SAVE_KEYS:
		if (argc >= 1)
			ret = do_save_keys(fd, argv[0]);
		break;
	case LOAD_KEYS:
		if (argc >= 1)
			ret = do_load_keys(fd, argv[0]);
		break;
	case READ_LOG:
		printf("ioctl(fd, HYPDRV_READ_LOG) not implemented.\n");
		/* fall through */
	default:
		usage();
		return -1;
	}

	if (ret < 0) {
		if (errno)
			perror("ioctl");
		else
			printf("%s %d: invalid arguments.\n", prog_name, call);
		usage();
	}

	return ret;
}

int main(int argc, char *argv[])
{
	int fd = -1, ret = 0;
	int call = -1;

	prog_name = argv[0];

	if (argc >= 2)
		call = argv[1][0] - '0';

	if (call > 0) {
		fd = open("/dev/hyp-drv", O_RDWR);
		if (fd < 0) {
			perror("open /dev/hyp-drv");
			return -1;
		}
	}

	ret = do_ioctl(fd, call, argc - 2, &argv[2]);

	if (fd >= 0)
		close(fd);

	return ret;
}
