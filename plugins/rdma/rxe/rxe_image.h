/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CRIU_RDMA_RXE_IMAGE_H__
#define __CRIU_RDMA_RXE_IMAGE_H__

#include <stdint.h>

#define RXE_MIG_IMAGE_NAME "rxe_mig.img"

int rxe_image_save(int save_fd, uint64_t *image_size);
int rxe_image_get_size(uint64_t *image_size);
int rxe_image_load(int load_fd, uint64_t expected_size);

#endif /* __CRIU_RDMA_RXE_IMAGE_H__ */
