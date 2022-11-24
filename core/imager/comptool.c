#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <byteswap.h>

#include "lz4.h"
#include "lz4hc.h"

static void help(const char *n)
{
	printf("usage: %s <file to compress> <output file>\n", n);
}

static int writebuf(int fd, const char *buf, int buflen)
{
	int r;

	r = write(fd, buf, buflen);
	if (r == -1) {
		printf("failed to write to file\n");
		return -errno;
	}
	return r;
}

int main(int argc, const char **argv)
{
	struct stat sb;
	char *inbuf, *outbin;
	int fd, os, ol, res;

	if ((argc != 3) || !argv[1] || !argv[2]) {
		help(argv[0]);
		res = -EINVAL;
		goto out_error;
	}
	if (lstat(argv[1], &sb) == -1) {
		printf("input file %s not accessible?\n", argv[1]);
		res = -ENOENT;
		goto out_error;
	}
	if (sb.st_size > LZ4_MAX_INPUT_SIZE) {
		printf("input file %s too large\n", argv[1]);
		res = -EINVAL;
		goto out_error;
	}
	fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		printf("error opening input file %s\n", argv[1]);
		res = -errno;
		goto out_error;
	}
	inbuf = malloc(sb.st_size);
	if (!inbuf) {
		printf("unable to allocate %lu bytes\n", sb.st_size);
		res = -ENOMEM;
		goto out_error;
	}
	res = read(fd, inbuf, sb.st_size);
	if (res == -1) {
		printf("unable to read file %s\n", argv[1]);
		res = -errno;
		goto out_error;
	}
	close(fd);
	os = LZ4_COMPRESSBOUND(sb.st_size);
	outbin = malloc(os);
	if (!outbin) {
		printf("unable to allocate %u bytes\n", os);
		res = -ENOMEM;
		goto out_error;
	}
	ol = LZ4_compress_HC(inbuf, outbin, (int)sb.st_size, (int)os, LZ4HC_CLEVEL_MAX);
	if (!ol) {
		printf("LZ4 compression error\n");
		res = -EFAULT;
		goto out_error;
	}
	printf("Compressed %lu bytes to %u bytes\n", sb.st_size, ol);
	unlink(argv[2]);

	fd = open(argv[2], O_CREAT|O_WRONLY, S_IRUSR|S_IRGRP);
	if (fd == -1) {
		printf("unable to open output file %s\n", argv[2]);
		res = -errno;
		goto out_error;
	}
	res = writebuf(fd, outbin, ol);
	if (res < 0) {
		res = -errno;
		goto out_error;
	}
	close(fd);

	printf("OK, output saved to %s\n", argv[2]);
	return 0;

out_error:
	printf("FAILED, error %d (%s)\n", res, strerror(errno));
	return res;
}
