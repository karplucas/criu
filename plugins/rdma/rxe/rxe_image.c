// SPDX-License-Identifier: GPL-2.0
/*
 * RXE's migration image is a single opaque byte stream produced and
 * consumed by the RXE kernel driver. CRIU stores that stream directly as
 * rxe_mig.img; it does not add an index image or interpret RXE records.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

#include "criu-log.h"

#include "rxe_image.h"

int criu_get_image_dir(void);

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "rdma_rxe_plugin: "

#define RXE_IMAGE_IO_SIZE (64 * 1024)

static int rxe_write_all(int fd, const void *buffer, size_t length)
{
	const char *data = buffer;

	while (length) {
		ssize_t ret = write(fd, data, length);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (!ret) {
			errno = EIO;
			return -1;
		}

		data += ret;
		length -= ret;
	}

	return 0;
}

int rxe_image_save(int save_fd, uint64_t *image_size)
{
	char buffer[RXE_IMAGE_IO_SIZE];
	uint64_t total = 0;
	int image_dir;
	int image_fd;

	if (save_fd < 0 || !image_size) {
		errno = EINVAL;
		return -1;
	}

	image_dir = criu_get_image_dir();
	if (image_dir < 0) {
		pr_err("No image directory for %s\n", RXE_MIG_IMAGE_NAME);
		return -1;
	}

	image_fd = openat(image_dir, RXE_MIG_IMAGE_NAME,
			  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (image_fd < 0) {
		pr_perror("Unable to create %s", RXE_MIG_IMAGE_NAME);
		return -1;
	}

	for (;;) {
		ssize_t ret = read(save_fd, buffer, sizeof(buffer));

		if (!ret)
			break;
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			pr_perror("Unable to read RXE save stream");
			goto error;
		}
		if (UINT64_MAX - total < (uint64_t)ret) {
			errno = EOVERFLOW;
			pr_perror("RXE image size overflow");
			goto error;
		}
		if (rxe_write_all(image_fd, buffer, ret)) {
			pr_perror("Unable to write %s", RXE_MIG_IMAGE_NAME);
			goto error;
		}
		total += ret;
	}

	if (!total) {
		errno = EINVAL;
		pr_perror("RXE save stream is empty");
		goto error;
	}
	if (close(image_fd)) {
		pr_perror("Unable to close %s", RXE_MIG_IMAGE_NAME);
		return -1;
	}

	*image_size = total;
	return 0;

error:
	close(image_fd);
	return -1;
}

static int rxe_open_image(uint64_t *image_size)
{
	struct stat st;
	int image_dir;
	int image_fd;

	image_dir = criu_get_image_dir();
	if (image_dir < 0) {
		pr_err("No image directory for %s\n", RXE_MIG_IMAGE_NAME);
		return -1;
	}

	image_fd = openat(image_dir, RXE_MIG_IMAGE_NAME, O_RDONLY | O_CLOEXEC);
	if (image_fd < 0) {
		pr_perror("Unable to open %s", RXE_MIG_IMAGE_NAME);
		return -1;
	}
	if (fstat(image_fd, &st)) {
		pr_perror("Unable to stat %s", RXE_MIG_IMAGE_NAME);
		goto error;
	}
	if (!S_ISREG(st.st_mode) || st.st_size <= 0) {
		errno = EINVAL;
		pr_perror("Invalid %s", RXE_MIG_IMAGE_NAME);
		goto error;
	}

	*image_size = st.st_size;
	return image_fd;

error:
	close(image_fd);
	return -1;
}

int rxe_image_get_size(uint64_t *image_size)
{
	int image_fd;

	if (!image_size) {
		errno = EINVAL;
		return -1;
	}

	image_fd = rxe_open_image(image_size);
	if (image_fd < 0)
		return -1;
	if (close(image_fd)) {
		pr_perror("Unable to close %s", RXE_MIG_IMAGE_NAME);
		return -1;
	}

	return 0;
}

int rxe_image_load(int load_fd, uint64_t expected_size)
{
	char buffer[RXE_IMAGE_IO_SIZE];
	uint64_t image_size;
	uint64_t total = 0;
	int image_fd;

	if (load_fd < 0 || !expected_size) {
		errno = EINVAL;
		return -1;
	}

	image_fd = rxe_open_image(&image_size);
	if (image_fd < 0)
		return -1;
	if (image_size != expected_size) {
		pr_err("%s size changed: expected %llu, found %llu\n",
		       RXE_MIG_IMAGE_NAME, (unsigned long long)expected_size,
		       (unsigned long long)image_size);
		errno = EINVAL;
		goto error;
	}

	while (total < image_size) {
		size_t left = image_size - total;
		ssize_t ret;

		if (left > sizeof(buffer))
			left = sizeof(buffer);
		ret = read(image_fd, buffer, left);
		if (!ret) {
			errno = EIO;
			pr_perror("Unexpected end of %s", RXE_MIG_IMAGE_NAME);
			goto error;
		}
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			pr_perror("Unable to read %s", RXE_MIG_IMAGE_NAME);
			goto error;
		}
		if (rxe_write_all(load_fd, buffer, ret)) {
			pr_perror("Unable to write RXE load stream");
			goto error;
		}
		total += ret;
	}

	if (close(image_fd)) {
		pr_perror("Unable to close %s", RXE_MIG_IMAGE_NAME);
		return -1;
	}

	return 0;

error:
	close(image_fd);
	return -1;
}
