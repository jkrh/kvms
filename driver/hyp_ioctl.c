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

typedef uint64_t u64;

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
}

static int get_arg(char *str, u64 *dst)
{
	u64 val;

	if (sscanf(str, "%lx", &val) != 1)
		return -1;

	*dst = val;
	return 0;
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
