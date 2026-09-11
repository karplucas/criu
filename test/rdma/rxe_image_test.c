// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE

#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "rxe_image.h"

static int image_dir = -1;

unsigned int log_get_loglevel(void)
{
	return 4;
}

void print_on_level(unsigned int level, const char *format, ...)
{
	va_list args;

	(void)level;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}

int criu_get_image_dir(void)
{
	return image_dir;
}

static int write_exact(int fd, const void *data, size_t length)
{
	return write(fd, data, length) == (ssize_t)length ? 0 : -1;
}

int main(void)
{
	const char payload[] = "RXE image\0with binary bytes\xff\x01";
	char directory[] = "/tmp/rxe-image-test.XXXXXX";
	char restored[sizeof(payload)];
	uint64_t size;
	int load_fd = -1;
	int save_fd = -1;
	int ret = EXIT_FAILURE;

	if (!mkdtemp(directory)) {
		perror("mkdtemp");
		goto out;
	}
	image_dir = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (image_dir < 0) {
		perror("open image directory");
		goto out_directory;
	}

	save_fd = memfd_create("rxe-save", MFD_CLOEXEC);
	if (save_fd < 0 || write_exact(save_fd, payload, sizeof(payload)) ||
	    lseek(save_fd, 0, SEEK_SET) < 0) {
		perror("prepare save fd");
		goto out_directory_fd;
	}
	if (rxe_image_save(save_fd, &size) || size != sizeof(payload)) {
		fprintf(stderr, "failed to save RXE image\n");
		goto out_directory_fd;
	}
	if (rxe_image_get_size(&size) || size != sizeof(payload)) {
		fprintf(stderr, "failed to query RXE image size\n");
		goto out_directory_fd;
	}

	load_fd = memfd_create("rxe-load", MFD_CLOEXEC);
	if (load_fd < 0 || rxe_image_load(load_fd, size) ||
	    lseek(load_fd, 0, SEEK_SET) < 0 ||
	    read(load_fd, restored, sizeof(restored)) != sizeof(restored) ||
	    memcmp(restored, payload, sizeof(payload))) {
		fprintf(stderr, "failed to load RXE image\n");
		goto out_directory_fd;
	}

	if (!rxe_image_load(load_fd, size + 1)) {
		fprintf(stderr, "accepted an incorrect RXE image size\n");
		goto out_directory_fd;
	}

	ret = EXIT_SUCCESS;
	printf("RXE image test: PASS\n");

out_directory_fd:
	if (load_fd >= 0)
		close(load_fd);
	if (save_fd >= 0)
		close(save_fd);
	unlinkat(image_dir, RXE_MIG_IMAGE_NAME, 0);
	close(image_dir);
out_directory:
	rmdir(directory);
out:
	return ret;
}
