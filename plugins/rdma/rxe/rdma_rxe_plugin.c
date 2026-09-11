/*
 * CRIU RDMA RXE plugin -- presence detection and context claim.
 *
 * The first slice of plugin coverage for RDMA: at criu startup it walks
 * /sys/class/infiniband/ and decides whether the host has any ibdev
 * backed by the soft-RoCE (rxe) driver. That presence decision then
 * gates the per-context claim hook (CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_
 * CONTEXT), through which this plugin tells criu core it owns dump and
 * restore for rxe uverbs contexts, and the restore-side cdev open hook
 * (CR_PLUGIN_HOOK__RDMA_OPEN_UVERBS_CDEV), through which it re-opens the
 * destination cdev with a restore-mode ucontext. The per-uobject
 * dump/restore hooks are wired in later commits.
 *
 * Why a separate plugin per RDMA "CRIU driver" (instead of a single
 * monolithic rdma plugin):
 *   The kernel-side "driver" for an ibdev (rxe / mlx5_core / bnxt_re / ...)
 *   does not map 1:1 to "how should CRIU dump+restore this context".
 *   mlx5_core alone has, or will have, multiple distinct CRIU strategies
 *   (host-driven SAVE/LOAD via mlx5_vfmig, future fw-assisted IB-resource
 *   replay, possibly a vfio_mlx5_pci variant for guest-mode), and each
 *   wants its own arbitration logic at dump time. Splitting per CRIU
 *   driver from day one means the future RdmaCriuDriver enum lines up
 *   directly with one .so per enumerant.
 *
 * Detection logic for rxe specifically: rxe ibdevs are software-defined
 * (no PCI parent, so no /sys/class/infiniband/<dev>/device/driver
 * symlink), but they're trivially identifiable by name prefix and by the
 * existence of /sys/class/infiniband/rxe<N>. We deliberately do not try
 * to ENABLE rxe here -- if rdma_rxe is unloaded, the plugin simply
 * declares itself inactive and lets the dump-time arbitration added in a
 * later commit fail any process that holds an rxe context (there can't be
 * one without a live rxe ibdev, so this is symmetric anyway).
 */

#include "criu-log.h"
#include "common/config.h"
#include "plugin.h"

#include "images/rdma_criu.pb-c.h"
#include "rxe_image.h"

#include <rdma/ib_user_ioctl_cmds.h>
#include <rdma/ib_user_ioctl_verbs.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/rdma_user_ioctl_cmds.h>
#include <rdma/rdma_user_rxe.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "rdma_rxe_plugin: "

#define IBDEV_SYSFS_DIR "/sys/class/infiniband"

/*
 * The uverbs cdevs are members of the infiniband_verbs class, not the
 * infiniband class: only /sys/class/infiniband_verbs/uverbsN/ exposes
 * an 'ibdev' file naming the ibdev each cdev serves. That reverse map
 * (ibdev name -> current cdev) is how the open hook finds the
 * destination cdev regardless of minor drift across boots/hosts.
 */
#define IB_UVERBS_CLASS_DIR "/sys/class/infiniband_verbs"

/*
 * Inlined kernel UAPI for the rxe ucontext-restore-mode request. The
 * installed rdma-core uapi tree can lag the in-tree kernel UAPI; use
 * the header's enum constant when available and a numeric fallback
 * otherwise. Keep in sync with include/uapi/rdma/rdma_user_rxe.h and
 * drivers/infiniband/sw/rxe/rxe_verbs.c.
 */
#ifdef CONFIG_HAS_RXE_ALLOC_UCTX_RESTORE_MODE
#define CRIU_RXE_ALLOC_UCTX_RESTORE_MODE RXE_ALLOC_UCTX_RESTORE_MODE
#else
#define CRIU_RXE_ALLOC_UCTX_RESTORE_MODE (1u << 0)
#endif

struct rxe_alloc_ucontext_req_local {
	uint32_t flags;
	uint32_t ufile_id;
	uint32_t reserved;
};

/*
 * Plugin activity is process-local state set by init() and read by the
 * per-context claim hook: an inactive plugin (no rxe ibdev on this host)
 * declines every context.
 */
static bool rxe_active = false;
static int rxe_dev_count = 0;
static char rxe_ibdev_name[64];
static int rxe_dump_control_fd = -1;

#define RXE_UVERBS_ID_NS_SHIFT_LOCAL		12
#define RXE_IB_OBJECT_MIGRATE_LOCAL		(1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL)
#define RXE_IB_OBJECT_VHCA_STREAM_LOCAL		((1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL) + 1)
#define RXE_IB_METHOD_CREATE_SAVE_FD_LOCAL	(1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL)
#define RXE_IB_METHOD_CREATE_LOAD_FD_LOCAL	((1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL) + 1)
#define RXE_IB_METHOD_LOAD_VHCA_LOCAL		((1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL) + 2)
#define RXE_IB_METHOD_REGISTER_CONTEXT_LOCAL	((1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL) + 5)
#define RXE_IB_METHOD_FREEZE_CONTEXT_LOCAL	((1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL) + 3)
#define RXE_IB_ATTR_CREATE_SAVE_FD_HANDLE_LOCAL (1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL)
#define RXE_IB_ATTR_CREATE_LOAD_FD_HANDLE_LOCAL (1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL)
#define RXE_IB_ATTR_CREATE_LOAD_FD_LENGTH_LOCAL ((1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL) + 1)
#define RXE_IB_ATTR_LOAD_VHCA_HANDLE_LOCAL	(1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL)
#define RXE_IB_ATTR_REGISTER_CONTEXT_UFILE_ID_LOCAL (1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL)
#define RXE_IB_ATTR_FREEZE_CONTEXT_FREEZE_LOCAL (1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL)

struct rxe_frozen_context {
	int fd;
	struct rxe_frozen_context *next;
};
static struct rxe_frozen_context *rxe_frozen_contexts;

enum rxe_queue_role {
	RXE_QUEUE_CQ,
	RXE_QUEUE_SQ,
	RXE_QUEUE_RQ,
};

struct rxe_queue_mapping {
	char ibdev[64];
	uint64_t pgoff;
	uint64_t length;
	uint32_t ufile_id;
	enum rxe_queue_role role;
	struct rxe_queue_mapping *next;
};
static struct rxe_queue_mapping *rxe_queue_mappings;

static int rxe_queue_mapping_add(const char *ibdev, uint64_t pgoff,
				 uint64_t length, uint32_t ufile_id,
				 enum rxe_queue_role role)
{
	struct rxe_queue_mapping *mapping;

	if (!pgoff || !length || pgoff + length < pgoff)
		return -EINVAL;
	mapping = calloc(1, sizeof(*mapping));
	if (!mapping)
		return -ENOMEM;
	snprintf(mapping->ibdev, sizeof(mapping->ibdev), "%s", ibdev);
	mapping->pgoff = pgoff;
	mapping->length = length;
	mapping->ufile_id = ufile_id;
	mapping->role = role;
	mapping->next = rxe_queue_mappings;
	rxe_queue_mappings = mapping;
	return 0;
}

static struct rxe_queue_mapping *rxe_queue_mapping_find(const char *ibdev,
							 uint64_t pgoff,
							 uint64_t length)
{
	struct rxe_queue_mapping *mapping;

	for (mapping = rxe_queue_mappings; mapping; mapping = mapping->next) {
		if (strcmp(mapping->ibdev, ibdev))
			continue;
		if (pgoff < mapping->pgoff)
			continue;
		if (pgoff - mapping->pgoff > mapping->length)
			continue;
		if (length > mapping->length - (pgoff - mapping->pgoff))
			continue;
		return mapping;
	}
	return NULL;
}

static void rxe_queue_mappings_drop_all(void)
{
	struct rxe_queue_mapping *mapping, *next;

	for (mapping = rxe_queue_mappings; mapping; mapping = next) {
		next = mapping->next;
		free(mapping);
	}
	rxe_queue_mappings = NULL;
}

static int rxe_load_image_on_restore(void);
static int rxe_create_save_fd(int control_fd);
static int rxe_save_registered_contexts(void);

/*
 * Restore-side cache of cdev fds that already carry a kernel ucontext
 * (attached by rxe_send_get_context_restore in open_uverbs_cdev). Keyed
 * by ibdev name so the UPDATE_VMA_MAP path can hand back a dup() of the
 * *same struct file* the per-uobject RESTORE_* ioctls ran on -- the only
 * file whose ufile->ucontext is non-NULL, which is exactly what
 * ib_uverbs_mmap requires (it -EINVALs via ib_uverbs_get_ucontext_file
 * otherwise). Without it, open_filemap() would re-open the cdev through
 * the generic path, mint a fresh ucontext-less ib_uverbs_file, and the
 * pie restorer's mmap of the CQ-ring VMA would die at -EINVAL.
 *
 * Lifetime: appended in open_uverbs_cdev, freed in fini(RESTORE).
 * Process-local; CRIU restore is single-threaded across these phases,
 * so no locking.
 *
 * The cached dup is parked at >= RXE_CACHED_FD_FLOOR: CRIU installs
 * workload fds with fcntl(F_DUPFD, want) and treats an occupied target
 * slot as a hard error, so a low-numbered cache fd could collide with a
 * dumpee fd. 1024 is comfortably above any plausible small workload fd.
 */
#define RXE_CACHED_FD_FLOOR 1024
struct rxe_cdev_cache_entry {
	char ibdev[64];
	uint32_t ufile_id;
	int fd; /* high-numbered dup of the GET_CONTEXT'd cdev fd */
	struct rxe_cdev_cache_entry *next;
};
static struct rxe_cdev_cache_entry *rxe_cdev_cache;

static void rxe_cdev_cache_remember(const char *ibdev, uint32_t ufile_id,
				    int fd)
{
	struct rxe_cdev_cache_entry *e;

	if (!ibdev || ibdev[0] == '\0' || fd < 0)
		return;

	e = calloc(1, sizeof(*e));
	if (!e) {
		pr_perror("rxe_cdev_cache_remember(%s)", ibdev);
		return;
	}
	snprintf(e->ibdev, sizeof(e->ibdev), "%s", ibdev);
	e->ufile_id = ufile_id;
	e->fd = fd;
	e->next = rxe_cdev_cache;
	rxe_cdev_cache = e;
	pr_debug("rxe_cdev_cache: remembered ibdev=%s fd=%d\n", ibdev, fd);
}

static int rxe_cdev_cache_lookup(const char *ibdev, uint32_t ufile_id)
{
	struct rxe_cdev_cache_entry *e;

	for (e = rxe_cdev_cache; e; e = e->next)
		if (!strcmp(e->ibdev, ibdev) && e->ufile_id == ufile_id)
			return e->fd;
	return -1;
}

static void rxe_cdev_cache_drop_all(void)
{
	struct rxe_cdev_cache_entry *e, *next;

	for (e = rxe_cdev_cache; e; e = next) {
		next = e->next;
		if (e->fd >= 0)
			close(e->fd);
		free(e);
	}
	rxe_cdev_cache = NULL;
}

/*
 * Resolve the kernel driver backing /sys/class/infiniband/<ibdev>.
 *
 * For PCI-backed ibdevs the canonical answer comes from readlink() on
 * <sysfs>/<ibdev>/device/driver -- the basename of the symlink target is
 * the kernel module name (mlx5_core, mlx4_core, bnxt_re, ...).
 *
 * Software-defined providers (rxe, siw) have no PCI parent and no
 * device/driver symlink; in that case fall back to a name-prefix
 * heuristic. We mirror the same fallback used in criu/rdma/driver.c
 * (rdma_driver_name_from_ibdev) so the two paths stay consistent --
 * if/when those helpers move to a shared header, this can collapse to
 * one call.
 *
 * Returns true and fills @out (must be at least @outsz bytes) if a
 * driver name was resolved.
 */
static bool resolve_ibdev_driver(const char *ibdev, char *out, size_t outsz)
{
	char path[PATH_MAX];
	char target[PATH_MAX];
	const char *base, *src;
	ssize_t n;

	if (outsz == 0)
		return false;

	snprintf(path, sizeof(path), "%s/%s/device/driver", IBDEV_SYSFS_DIR,
		 ibdev);
	n = readlink(path, target, sizeof(target) - 1);
	if (n > 0) {
		target[n] = '\0';
		base = strrchr(target, '/');
		src = base ? base + 1 : target;
		snprintf(out, outsz, "%.*s", (int)(outsz - 1), src);
		return true;
	}

	if (!strncmp(ibdev, "rxe", 3)) {
		snprintf(out, outsz, "%.*s", (int)(outsz - 1), "rxe");
		return true;
	}
	if (!strncmp(ibdev, "siw", 3)) {
		snprintf(out, outsz, "%.*s", (int)(outsz - 1), "siw");
		return true;
	}

	return false;
}

static int rdma_rxe_plugin_init(int stage)
{
	DIR *d;
	struct dirent *de;

	rxe_active = false;
	rxe_dev_count = 0;
	rxe_ibdev_name[0] = '\0';
	if (rxe_dump_control_fd >= 0)
		close(rxe_dump_control_fd);
	rxe_dump_control_fd = -1;

	d = opendir(IBDEV_SYSFS_DIR);
	if (!d) {
		/*
		 * No infiniband subsystem mounted at all is the common case
		 * on a host without any RDMA gear -- treat as "no rxe" rather
		 * than as an error so the plugin stays out of the way.
		 */
		pr_info("opendir(%s) failed; assuming no rxe devices, plugin inactive (stage %d)\n",
			IBDEV_SYSFS_DIR, stage);
		return 0;
	}

	while ((de = readdir(d)) != NULL) {
		char drv[64];

		if (de->d_name[0] == '.')
			continue;

		if (!resolve_ibdev_driver(de->d_name, drv, sizeof(drv))) {
			pr_debug("ibdev %s: driver unresolved, skipping\n",
				 de->d_name);
			continue;
		}

		pr_debug("ibdev %s -> driver %s\n", de->d_name, drv);

		if (!strcmp(drv, "rxe")) {
			if (!rxe_dev_count)
				snprintf(rxe_ibdev_name, sizeof(rxe_ibdev_name),
					 "%.*s", (int)sizeof(rxe_ibdev_name) - 1,
					 de->d_name);
			rxe_dev_count++;
		}
	}

	closedir(d);

	if (rxe_dev_count > 0) {
		rxe_active = true;
		pr_info("active (stage %d): %d rxe ibdev(s) found\n", stage,
			rxe_dev_count);
	} else {
		pr_info("inactive (stage %d): no rxe ibdevs on this host\n",
			stage);
	}

	if (stage == CR_PLUGIN_STAGE__RESTORE && rxe_load_image_on_restore())
		return -1;

	/*
	 * Returning zero unconditionally so the .so stays loaded even when
	 * inactive: the dump-time arbitration (rdma_arbitrate_plugin_claim)
	 * still wants the plugin queryable so it can report "no, I do not
	 * claim this context" and let the missing-coverage error name us.
	 */
	return 0;
}

static void rdma_rxe_plugin_fini(int stage, int ret)
{
	struct rxe_frozen_context *frozen, *next;

	for (frozen = rxe_frozen_contexts; frozen; frozen = next) {
		uint8_t freeze = 0;
		struct {
			struct ib_uverbs_ioctl_hdr hdr;
			struct ib_uverbs_attr attr;
		} cmd = {};

		next = frozen->next;
		cmd.hdr.object_id = RXE_IB_OBJECT_MIGRATE_LOCAL;
		cmd.hdr.method_id = RXE_IB_METHOD_FREEZE_CONTEXT_LOCAL;
		cmd.hdr.driver_id = RDMA_DRIVER_RXE;
		cmd.hdr.num_attrs = 1;
		cmd.hdr.length = sizeof(cmd);
		cmd.attr.attr_id = RXE_IB_ATTR_FREEZE_CONTEXT_FREEZE_LOCAL;
		cmd.attr.len = sizeof(freeze);
		cmd.attr.flags = UVERBS_ATTR_F_MANDATORY;
		cmd.attr.data = (uintptr_t)&freeze;
		if (ioctl(frozen->fd, RDMA_VERBS_IOCTL, &cmd) < 0)
			pr_perror("Unable to resume frozen RXE context");
		close(frozen->fd);
		free(frozen);
	}
	rxe_frozen_contexts = NULL;
	if (rxe_dump_control_fd >= 0) {
		close(rxe_dump_control_fd);
		rxe_dump_control_fd = -1;
	}

	pr_info("fini (stage %d ret %d): was %s, %d rxe ibdev(s)\n", stage,
		ret, rxe_active ? "active" : "inactive", rxe_dev_count);

	/*
	 * Close the restore-side cdev-fd cache (populated by
	 * open_uverbs_cdev, dup'd from by UPDATE_VMA_MAP). Only meaningful
	 * on the RESTORE stage; a no-op otherwise since the cache stays
	 * empty on dump.
	 */
	if (stage == CR_PLUGIN_STAGE__RESTORE)
		rxe_cdev_cache_drop_all();
	rxe_queue_mappings_drop_all();
}

static int rdma_rxe_plugin_dump_devices_late(int pid)
{
	(void)pid;

	return rxe_save_registered_contexts();
}

/*
 * Per-context claim hook (CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT).
 *
 * Invoked at dump time for every uverbs context the target process
 * holds, and again at restore time as a "does the destination's
 * plugin set still cover this image?" check. Returns the plugin's
 * RdmaCriuDriver value (RCD_RXE) iff:
 *
 *   - the plugin is active on this host (rxe_active is set, i.e.
 *     init() found at least one rxe ibdev present);
 *   - AND the context's kernel driver is RDMA_DRIVER_RXE.
 *
 * Either condition failing -> return RCD_UNKNOWN to decline the
 * context. Negative returns are reserved for "I would normally
 * claim this but a probe failed" (none of which apply to rxe; rxe
 * has no host-side gate beyond the driver being loaded). The plugin
 * set arbitration in criu/rdma/plugin_api.c (rdma_arbitrate_plugin_
 * claim) enforces exactly-one-claim across all loaded RDMA plugins.
 */
static int rdma_rxe_plugin_claim_uverbs_context(const char *ibdev, uint32_t kernel_driver_id)
{
	if (!rxe_active) {
		pr_debug("claim(%s, kdrv=%u): plugin inactive, declining\n", ibdev, kernel_driver_id);
		return RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	}
	if (kernel_driver_id != RDMA_DRIVER_RXE) {
		pr_debug("claim(%s, kdrv=%u): kernel driver is not RDMA_DRIVER_RXE (%u), declining\n", ibdev,
			 kernel_driver_id, (uint32_t)RDMA_DRIVER_RXE);
		return RDMA_CRIU_DRIVER__RCD_UNKNOWN;
	}

	pr_info("claim(%s, kdrv=%u): claiming as RCD_RXE\n", ibdev, kernel_driver_id);
	return RDMA_CRIU_DRIVER__RCD_RXE;
}

static int rdma_rxe_plugin_dump_uverbs_context(const char *ibdev,
					       uint32_t kernel_driver_id,
					       uint32_t ufile_id,
					       uint32_t ctxn, int lfd,
					       pid_t pid)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attr;
	} cmd = {};

	(void)pid;
	if (kernel_driver_id != RDMA_DRIVER_RXE)
		return -ENOTSUP;
	if (rxe_dev_count != 1 || strcmp(ibdev, rxe_ibdev_name)) {
		pr_err("RXE image capture currently requires one RXE device\n");
		return -1;
	}

	cmd.hdr.object_id = RXE_IB_OBJECT_MIGRATE_LOCAL;
	cmd.hdr.method_id = RXE_IB_METHOD_REGISTER_CONTEXT_LOCAL;
	cmd.hdr.driver_id = RDMA_DRIVER_RXE;
	cmd.hdr.num_attrs = 1;
	cmd.hdr.length = sizeof(cmd);
	cmd.attr.attr_id = RXE_IB_ATTR_REGISTER_CONTEXT_UFILE_ID_LOCAL;
	cmd.attr.len = sizeof(ufile_id);
	cmd.attr.flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attr.data = ufile_id;
	if (ioctl(lfd, RDMA_VERBS_IOCTL, &cmd) < 0) {
		pr_perror("REGISTER_CONTEXT(ufile_id=%#x ctxn=%u)",
			  ufile_id, ctxn);
		return -1;
	}

	if (rxe_dump_control_fd < 0) {
		rxe_dump_control_fd = fcntl(lfd, F_DUPFD_CLOEXEC,
					    RXE_CACHED_FD_FLOOR);
		if (rxe_dump_control_fd < 0) {
			pr_perror("Unable to retain RXE dump control fd");
			return -1;
		}
	}

	return 0;
}

static int rxe_save_registered_contexts(void)
{
	uint64_t image_size;
	int save_fd;

	if (rxe_dump_control_fd < 0)
		return 0;
	save_fd = rxe_create_save_fd(rxe_dump_control_fd);
	if (save_fd < 0) {
		pr_err("CREATE_SAVE_FD failed: %s\n", strerror(-save_fd));
		return -1;
	}
	if (rxe_image_save(save_fd, &image_size)) {
		close(save_fd);
		return -1;
	}
	close(save_fd);
	pr_info("Saved %s (%" PRIu64 " bytes) for %s\n",
		RXE_MIG_IMAGE_NAME, image_size, rxe_ibdev_name);
	return 0;
}

/*
 * Read a single-line sysfs attribute into @buf, NUL-terminated with a
 * trailing newline trimmed. Returns 0 on success, -1 on any error.
 */
static int rxe_read_sysfs(const char *path, char *buf, size_t buflen)
{
	int fd, n;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, buflen - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = '\0';
	if (n > 0 && buf[n - 1] == '\n')
		buf[n - 1] = '\0';
	return 0;
}

static int rxe_open_cdev(const char *wanted_ibdev)
{
	char path[PATH_MAX];
	char ibdev[64];
	struct dirent *de;
	DIR *directory;
	int fd = -1;

	directory = opendir(IB_UVERBS_CLASS_DIR);
	if (!directory)
		return -1;

	while ((de = readdir(directory)) != NULL) {
		if (strncmp(de->d_name, "uverbs", 6))
			continue;
		snprintf(path, sizeof(path), "%s/%s/ibdev",
			 IB_UVERBS_CLASS_DIR, de->d_name);
		if (rxe_read_sysfs(path, ibdev, sizeof(ibdev)) ||
		    strcmp(ibdev, wanted_ibdev))
			continue;
		snprintf(path, sizeof(path), "/dev/infiniband/%s", de->d_name);
		fd = open(path, O_RDWR | O_CLOEXEC);
		break;
	}

	closedir(directory);
	return fd;
}

static int rxe_create_save_fd(int control_fd)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attr;
	} cmd = {};

	cmd.hdr.object_id = RXE_IB_OBJECT_VHCA_STREAM_LOCAL;
	cmd.hdr.method_id = RXE_IB_METHOD_CREATE_SAVE_FD_LOCAL;
	cmd.hdr.driver_id = RDMA_DRIVER_RXE;
	cmd.hdr.num_attrs = 1;
	cmd.hdr.length = sizeof(cmd);
	cmd.attr.attr_id = RXE_IB_ATTR_CREATE_SAVE_FD_HANDLE_LOCAL;
	cmd.attr.flags = UVERBS_ATTR_F_MANDATORY;

	if (ioctl(control_fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;
	return (int)cmd.attr.data;
}

static int rxe_create_load_fd(int control_fd, uint64_t length)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[2];
	} cmd = {};

	cmd.hdr.object_id = RXE_IB_OBJECT_VHCA_STREAM_LOCAL;
	cmd.hdr.method_id = RXE_IB_METHOD_CREATE_LOAD_FD_LOCAL;
	cmd.hdr.driver_id = RDMA_DRIVER_RXE;
	cmd.hdr.num_attrs = 2;
	cmd.hdr.length = sizeof(cmd);
	cmd.attrs[0].attr_id = RXE_IB_ATTR_CREATE_LOAD_FD_HANDLE_LOCAL;
	cmd.attrs[0].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[1].attr_id = RXE_IB_ATTR_CREATE_LOAD_FD_LENGTH_LOCAL;
	cmd.attrs[1].len = sizeof(length);
	cmd.attrs[1].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[1].data = length;

	if (ioctl(control_fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;
	return (int)cmd.attrs[0].data;
}

static int rxe_load_vhca(int control_fd, int load_fd)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attr;
	} cmd = {};

	cmd.hdr.object_id = RXE_IB_OBJECT_VHCA_STREAM_LOCAL;
	cmd.hdr.method_id = RXE_IB_METHOD_LOAD_VHCA_LOCAL;
	cmd.hdr.driver_id = RDMA_DRIVER_RXE;
	cmd.hdr.num_attrs = 1;
	cmd.hdr.length = sizeof(cmd);
	cmd.attr.attr_id = RXE_IB_ATTR_LOAD_VHCA_HANDLE_LOCAL;
	cmd.attr.flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attr.data = load_fd;

	if (ioctl(control_fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;
	return 0;
}

static int rxe_load_image_on_restore(void)
{
	uint64_t length;
	int control_fd;
	int load_fd;
	int ret = -1;

	if (faccessat(criu_get_image_dir(), RXE_MIG_IMAGE_NAME, F_OK, 0)) {
		if (errno == ENOENT)
			return 0;
		pr_perror("Unable to inspect %s", RXE_MIG_IMAGE_NAME);
		return -1;
	}
	if (rxe_dev_count != 1) {
		pr_err("%s requires exactly one destination RXE device; found %d\n",
		       RXE_MIG_IMAGE_NAME, rxe_dev_count);
		return -1;
	}
	if (rxe_image_get_size(&length))
		return -1;

	control_fd = rxe_open_cdev(rxe_ibdev_name);
	if (control_fd < 0) {
		pr_perror("Unable to open RXE control cdev for %s",
			  rxe_ibdev_name);
		return -1;
	}
	load_fd = rxe_create_load_fd(control_fd, length);
	if (load_fd < 0) {
		pr_err("CREATE_LOAD_FD failed: %s\n", strerror(-load_fd));
		goto out_control;
	}
	if (rxe_image_load(load_fd, length))
		goto out_load;
	ret = rxe_load_vhca(control_fd, load_fd);
	if (ret) {
		pr_err("LOAD_VHCA failed: %s\n", strerror(-ret));
		ret = -1;
		goto out_load;
	}
	ret = 0;
out_load:
	close(load_fd);
out_control:
	close(control_fd);
	return ret;
}

/*
 * Issue IB_USER_VERBS_CMD_GET_CONTEXT via the legacy write() path with
 * RXE_ALLOC_UCTX_RESTORE_MODE in the trailing rxe_alloc_ucontext_req
 * driver_data.
 *
 * The RDMA_VERBS_IOCTL UVERBS_METHOD_GET_CONTEXT path doesn't currently
 * accept driver-specific data (no UHW attribute defined for it), so the
 * rxe restore-mode flag has to travel in udata via the legacy write()
 * path -- the canonical way to hand a per-driver alloc-ucontext-req to
 * the driver hook until a "UHW on UVERBS_METHOD_GET_CONTEXT" kernel
 * patch lands.
 *
 * Restore mode is unconditional here: RDMA_OPEN_UVERBS_CDEV is only
 * invoked on the restore path, and the kernel rxe_ucontext.restore_mode
 * bit is sticky-and-harmless -- it only gates the per-class
 * UVERBS_METHOD_RESTORE_<TYPE> dispatchers, which non-restoring callers
 * never issue. Closes the vestigial async_fd the kernel installs; CRIU
 * reconstructs the workload's async-event fd separately.
 *
 * Returns 0 on success, -errno on failure.
 */
static int rxe_send_get_context_restore(int fd, uint32_t ufile_id)
{
	struct {
		struct ib_uverbs_cmd_hdr hdr;
		struct ib_uverbs_get_context get_ctx;
		struct rxe_alloc_ucontext_req_local req;
	} cmd = {};
	struct ib_uverbs_get_context_resp resp = {};
	ssize_t n;

	cmd.hdr.command = IB_USER_VERBS_CMD_GET_CONTEXT;
	cmd.hdr.in_words = sizeof(cmd) / 4;
	cmd.hdr.out_words = sizeof(resp) / 4;
	cmd.get_ctx.response = (uintptr_t)&resp;
	cmd.req.flags = CRIU_RXE_ALLOC_UCTX_RESTORE_MODE;
	cmd.req.ufile_id = ufile_id;

	n = write(fd, &cmd, sizeof(cmd));
	if (n < 0)
		return -errno;
	if ((size_t)n != sizeof(cmd))
		return -EIO;
	close((int)resp.async_fd);
	return 0;
}

/*
 * Restore-side per-context cdev open
 * (CR_PLUGIN_HOOK__RDMA_OPEN_UVERBS_CDEV).
 *
 * The image's reg_file_entry carries the source's cdev path (e.g.
 * "/dev/infiniband/uverbs5"), but on the destination the same ibdev
 * name may sit at a different minor (probe order is not stable across
 * boots/hosts/rdma-link churn). Walk /sys/class/infiniband_verbs/
 * uverbsN/ibdev, match the recorded ib_dev string, and open the
 * matching /dev/infiniband/uverbsN. For rxe there is nothing else to
 * do at restore time: the destination ibdev is assumed to already
 * exist (operator ran `rdma link add rxe0 ...`).
 *
 * Per the uniform hook contract, hand back an fd that already has a
 * kernel ucontext on it -- opened in restore mode so the per-uobject
 * RESTORE_<TYPE> verbs are unblocked for uobjects this ufile holds.
 */
static int rdma_rxe_plugin_open_uverbs_cdev(const UverbsFileEntry *uvfe)
{
	char path[PATH_MAX], ibdev[64], cdevpath[PATH_MAX];
	struct dirent *de;
	DIR *d;
	int fd = -1, rc;
	bool found = false;

	if (!uvfe->ib_dev || uvfe->ib_dev[0] == '\0') {
		pr_err("open_uverbs_cdev: image record missing ib_dev (uvfe id %#x); cannot resolve cdev\n", uvfe->id);
		return -1;
	}

	d = opendir(IB_UVERBS_CLASS_DIR);
	if (!d) {
		pr_perror("open_uverbs_cdev: opendir(%s)", IB_UVERBS_CLASS_DIR);
		return -1;
	}

	while ((de = readdir(d)) != NULL) {
		if (strncmp(de->d_name, "uverbs", 6) != 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s/ibdev", IB_UVERBS_CLASS_DIR, de->d_name);
		if (rxe_read_sysfs(path, ibdev, sizeof(ibdev)) < 0)
			continue;
		if (strcmp(ibdev, uvfe->ib_dev) != 0)
			continue;

		snprintf(cdevpath, sizeof(cdevpath), "/dev/infiniband/%s", de->d_name);
		fd = open(cdevpath, O_RDWR | O_CLOEXEC);
		if (fd < 0) {
			pr_perror("open_uverbs_cdev: open(%s) for ibdev=%s", cdevpath, uvfe->ib_dev);
			closedir(d);
			return -1;
		}
		pr_info("open_uverbs_cdev: ibdev=%s -> %s (fd=%d)\n", uvfe->ib_dev, cdevpath, fd);
		found = true;
		break;
	}
	closedir(d);

	if (!found) {
		pr_err("open_uverbs_cdev: ibdev '%s' not found among %s/uverbs* -- the destination is missing the "
		       "source's ibdev. For rxe: `rdma link add %s type rxe netdev <iface>`.\n",
		       uvfe->ib_dev, IB_UVERBS_CLASS_DIR, uvfe->ib_dev);
		return -1;
	}

	rc = rxe_send_get_context_restore(fd, uvfe->id);
	if (rc) {
		pr_err("open_uverbs_cdev: GET_CONTEXT(restore mode) on fd=%d for ibdev=%s failed: %d (%s)\n", fd,
		       uvfe->ib_dev, rc, strerror(-rc));
		close(fd);
		return -1;
	}

	/*
	 * Stash a high-numbered dup of the GET_CONTEXT'd fd so the later
	 * UPDATE_VMA_MAP hook can return a sibling fd on the *same struct
	 * file* -- dup() shares it, so the ucontext just attached is visible
	 * through the dup and ib_uverbs_mmap can resolve it when the pie
	 * restorer mmaps the CQ-ring VMA. The caller-returned fd stays the
	 * original; CRIU plumbs it into the dumpee fd table and may move or
	 * close it without disturbing the cached copy. See the cache header
	 * for the FD_FLOOR parking rationale.
	 */
	{
		int hi = fcntl(fd, F_DUPFD_CLOEXEC, RXE_CACHED_FD_FLOOR);

		if (hi < 0) {
			pr_perror("open_uverbs_cdev: F_DUPFD_CLOEXEC(fd=%d, >=%d) for cache (ibdev=%s)", fd,
				  RXE_CACHED_FD_FLOOR, uvfe->ib_dev);
			close(fd);
			return -1;
		}
		rxe_cdev_cache_remember(uvfe->ib_dev, uvfe->id, hi);
	}

	return fd;
}

/*
 * Map a char-device (maj:min) to the ibdev name it serves, via
 * /sys/dev/char/<maj>:<min>/ibdev. Returns 0 and fills @out on a
 * uverbs cdev; -1 for any non-uverbs chrdev (the sysfs attr is
 * absent). Used by the HANDLE_DEVICE_VMA claim below, which only
 * has the VMA's st_rdev to work from.
 */
static int rxe_chrdev_to_ibdev(dev_t rdev, char *out, size_t outsz)
{
	char path[PATH_MAX];
	int fd;
	ssize_t n;

	snprintf(path, sizeof(path), "/sys/dev/char/%u:%u/ibdev",
		 major(rdev), minor(rdev));
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, out, outsz - 1);
	close(fd);
	if (n <= 0)
		return -1;
	while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == ' '))
		n--;
	out[n] = '\0';
	return n > 0 ? 0 : -1;
}

/*
 * Predicate behind HANDLE_DEVICE_VMA: does this VMA's @st resolve to
 * an rxe-driven uverbs cdev? On a match, writes the ibdev name (e.g.
 * "rxe0") to @ibdev_out and returns 0; on any decline returns
 * -ENOTSUP and leaves @ibdev_out untouched.
 */
static int rxe_match_cdev_vma(const struct stat *st, char *ibdev_out,
			      size_t ibdev_sz)
{
	char ibdev[64];
	char drv[64];

	if (!rxe_active)
		return -ENOTSUP;
	if (!S_ISCHR(st->st_mode))
		return -ENOTSUP;

	if (rxe_chrdev_to_ibdev(st->st_rdev, ibdev, sizeof(ibdev)))
		return -ENOTSUP;
	if (!resolve_ibdev_driver(ibdev, drv, sizeof(drv)))
		return -ENOTSUP;
	if (strcmp(drv, "rxe") != 0)
		return -ENOTSUP;

	if (ibdev_out && ibdev_sz)
		snprintf(ibdev_out, ibdev_sz, "%.*s",
			 (int)(ibdev_sz - 1), ibdev);
	return 0;
}

/*
 * Per-VMA dump-side hook (CR_PLUGIN_HOOK__HANDLE_DEVICE_VMA).
 *
 * rxe ibverbs userspace memory-maps slices of /dev/infiniband/uverbsN
 * for the per-uobject in-kernel queues it exposes: the CQ CQE ring
 * (the first such VMA, surfaced by the CQ dev gate) and, later, the
 * QP send/recv rings and the SRQ ring. CRIU's proc_parse sees the
 * S_ISCHR mapping and asks every loaded plugin "is this VMA yours?";
 * without us claiming it the dump aborts with "Can't handle
 * non-regular mapping".
 *
 * Symmetric with the restore-side rdma_rxe_plugin_open_uverbs_cdev
 * path: a chrdev is ours iff /sys/dev/char/<maj>:<min>/ibdev names an
 * ibdev whose driver resolves to "rxe". On a mixed-provider host this
 * declines mlx5 cdev VMAs so the mlx5 plugin's own hook can claim
 * them.
 *
 * Returns CR_PLUGIN_VMA_CONTENT on a successful claim because RXE uverbs
 * mappings are ordinary queue storage whose bytes CRIU must preserve.
 * Returns -ENOTSUP on any decline (so
 * run_plugins() keeps walking to other plugins, or falls through to
 * proc_parse's "Can't handle non-regular mapping" if none claim).
 * Never returns any other negative value: a non-ENOTSUP negative
 * short-circuits run_plugins() and would prevent any later plugin
 * from claiming a VMA we merely failed to inspect.
 *
 * @fd is unused: we resolve off @st->st_rdev only.
 */
static int rdma_rxe_plugin_handle_device_vma(int fd, const struct stat *st,
					     uint64_t pgoff,
					     uint64_t length)
{
	struct rxe_queue_mapping *mapping;
	char ibdev[64];
	int rc;

	(void)fd;

	rc = rxe_match_cdev_vma(st, ibdev, sizeof(ibdev));
	if (rc)
		return rc;
	mapping = rxe_queue_mapping_find(ibdev, pgoff, length);
	if (!mapping)
		return -ENOTSUP;

	pr_info("handle_vma(%s): queue role=%u offset=%#" PRIx64
		" length=%#" PRIx64 "\n", ibdev, mapping->role, pgoff,
		length);
	return CR_PLUGIN_VMA_CONTENT;
}

/*
 * Inlined kernel UAPI for RXE_IB_METHOD_QUERY_CQ, lifted from
 * include/uapi/rdma/rxe_user_ioctl_{verbs,cmds}.h + rdma_user_rxe.h.
 * The installed rdma-core UAPI lags the in-tree kernel; these _LOCAL
 * mirrors let the plugin issue QUERY_CQ before host rdma-core ships
 * rxe_user_ioctl_cmds.h.
 *
 * UVERBS_ID_NS_SHIFT is 12 across the uverbs UAPI; pinned locally so a
 * header drift can't silently shift these ids. RXE_IB_OBJECT_MIGRATE is
 * the first (and only) rxe driver object at (1<<SHIFT)+0; its methods are
 * FREEZE_DATAPATH=+0, QUERY_QP=+1, QUERY_CQ=+2, FREEZE_CONTEXT=+3, and
 * RESUME_VHCA=+4. Keep in sync with the kernel UAPI; remove once host
 * rdma-core ships them.
 */
#define RXE_IB_METHOD_QUERY_CQ_LOCAL	     ((1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL) + 2)
#define RXE_IB_ATTR_QUERY_CQ_HANDLE_LOCAL    (1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL)
#define RXE_IB_ATTR_QUERY_CQ_RESP_BLOB_LOCAL ((1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL) + 1)
/*
 * Optional CQE-ring image PTR_OUT: the kernel writes the raw in-flight
 * [consumer, producer) CQE subspan here (the CQ analogue of QUERY_QP's
 * SQ/RQ image) and reports its byte count in rxe_query_cq_resp::
 * cqe_image_bytes.
 */
#define RXE_IB_ATTR_QUERY_CQ_RESP_CQE_IMAGE_LOCAL ((1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL) + 2)

/*
 * Capacity advertised on the optional CQE image PTR_OUT. struct
 * ib_uverbs_attr::len is u16, so a single CQ ring image caps at 65535
 * bytes; the kernel emits only the actual in-flight byte count, and a
 * deep ring whose live subspan exceeds this is rejected loudly rather
 * than truncated (chunking is a kernel-side follow-up).
 */
#define RXE_CQ_IMAGE_CAP_LOCAL 65535u

/*
 * Byte-equal mirror of include/uapi/rdma/rdma_user_rxe.h::
 * rxe_query_cq_resp (32 bytes): the QUERY_CQ RESP_BLOB PTR_OUT.
 * @vm_pgoff is the CQ ring's mmap byte offset (cq->queue->ip->info.
 * offset); @cqe is the user-visible entry count (cq->ibcq.cqe);
 * @producer / @consumer are the live ring cursors (QUEUE_TYPE_TO_CLIENT);
 * @cqe_image_bytes is the in-flight [consumer, producer) subspan byte
 * length, with that subspan image carried in the optional
 * RXE_IB_ATTR_QUERY_CQ_RESP_CQE_IMAGE attr. Remove once host rdma-core
 * ships the struct.
 */
struct rxe_query_cq_resp_local {
	uint64_t vm_pgoff;
	uint32_t cqe;
	uint32_t producer;
	uint32_t consumer;
	uint32_t queue_size;
	uint32_t notify;
	uint32_t reserved;
};

/*
 * v0 rxe-private per-CQ plugin_blob schema: a fixed header followed by
 * the in-flight CQE-ring image tail (present iff @cqe_image_bytes > 0).
 * Field-for-field the kernel's rxe_restore_cq_req, but kept a distinct
 * plugin-private type (QUERY_CQ and RESTORE_CQ are separate structs, so
 * the restore hook re-shapes rather than casts). criu core treats the
 * bytes as opaque.
 *
 *   @vm_pgoff         source CQ ring mmap byte offset RESTORE_CQ replays.
 *   @producer/@consumer  source ring cursors (QUEUE_TYPE_TO_CLIENT), so
 *       the restored ring's unreaped completions are visible to
 *       ibv_poll_cq.
 *   @cqe_image_bytes  byte length of the in-flight [consumer, producer)
 *       CQE subspan appended after this header (0 => drained CQ,
 *       header-only). The destination scatters it back to source slots.
 *   @reserved         must be zero (matches the kernel req's reserved).
 */
struct rxe_cq_plugin_blob {
	uint64_t vm_pgoff;
	uint64_t queue_size;
};
_Static_assert(sizeof(struct rxe_cq_plugin_blob) == 16,
	       "rxe_cq_plugin_blob must be 16 bytes");

struct rxe_restore_cq_req_local {
	uint64_t vm_pgoff;
	uint32_t producer;
	uint32_t consumer;
	uint32_t cqe_image_bytes;
	uint32_t notify;
	uint32_t reserved;
};

/*
 * Byte-equal mirror of include/uapi/rdma/rdma_user_rxe.h::mminfo
 * (== rxe_create_cq_resp, 16 bytes): the RESTORE_CQ UHW_OUT the kernel's
 * rxe_restore_cq publishes (udata->outbuf must be at least this size).
 * @mi_offset is the destination ring's mmap byte offset, which rxe
 * replays from the UHW_IN vm_pgoff -- so the restore hook seeds it as an
 * 8-byte echo-verify template. Remove once host rdma-core ships it.
 */
struct rxe_create_cq_resp_local {
	uint64_t mi_offset;
	uint32_t mi_size;
	uint32_t mi_pad;
};
_Static_assert(sizeof(struct rxe_create_cq_resp_local) == 16, "rxe_create_cq_resp_local must be 16 bytes (kernel UAPI)");

/*
 * Issue RXE_IB_METHOD_QUERY_CQ on @fd (criu's dup of the dumpee's
 * uverbs cdev fd, holder of the CQ IDR) against @cq_handle, the
 * dump-side counterpart of UVERBS_METHOD_RESTORE_CQ. The security
 * boundary is the ufile that owns the CQ. HANDLE is an IDR-class attr
 * (len 0, handle read from attrs[].data); the kernel writes the ring
 * mmap offset + cursors into @resp_out. When @cqe_img / @img_cap are
 * provided the kernel also emits the raw in-flight [consumer, producer)
 * CQE subspan into @cqe_img, reporting its byte count in
 * @resp_out->cqe_image_bytes (a buffer smaller than that subspan fails
 * the whole QUERY_CQ with -ENOSPC, so advertise the full @img_cap).
 *
 * Returns 0 on success, -errno on failure.
 */
static int rxe_query_cq(int fd, uint32_t cq_handle, struct rxe_query_cq_resp_local *resp_out, void *cqe_img,
			uint32_t img_cap)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[3];
	} cmd = {};
	unsigned int n = 0;

	_Static_assert(sizeof(*resp_out) == 32, "rxe_query_cq_resp_local must be 32 bytes (kernel UAPI)");

	cmd.hdr.object_id = RXE_IB_OBJECT_MIGRATE_LOCAL;
	cmd.hdr.method_id = RXE_IB_METHOD_QUERY_CQ_LOCAL;
	cmd.hdr.driver_id = RDMA_DRIVER_RXE;

	cmd.attrs[n].attr_id = RXE_IB_ATTR_QUERY_CQ_HANDLE_LOCAL;
	cmd.attrs[n].len = 0;
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = cq_handle;
	n++;

	cmd.attrs[n].attr_id = RXE_IB_ATTR_QUERY_CQ_RESP_BLOB_LOCAL;
	cmd.attrs[n].len = sizeof(*resp_out);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)resp_out;
	n++;

	if (cqe_img && img_cap) {
		cmd.attrs[n].attr_id = RXE_IB_ATTR_QUERY_CQ_RESP_CQE_IMAGE_LOCAL;
		cmd.attrs[n].len = img_cap;
		cmd.attrs[n].flags = 0;
		cmd.attrs[n].data = (uintptr_t)cqe_img;
		n++;
	}

	cmd.hdr.num_attrs = n;
	cmd.hdr.length = sizeof(cmd.hdr) + n * sizeof(cmd.attrs[0]);

	if (ioctl(fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;
	return 0;
}

#define RXE_IB_METHOD_RESUME_VHCA_LOCAL		((1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL) + 4)

static int rxe_resume_vhca(int fd)
{
	struct ib_uverbs_ioctl_hdr cmd = {};

	cmd.object_id = RXE_IB_OBJECT_MIGRATE_LOCAL;
	cmd.method_id = RXE_IB_METHOD_RESUME_VHCA_LOCAL;
	cmd.driver_id = RDMA_DRIVER_RXE;
	cmd.length = sizeof(cmd);

	if (ioctl(fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;
	return 0;
}

/*
 * RDMA_DUMP_UOBJ_CQ hook (rxe). Issues QUERY_CQ on @lfd for
 * @ufile_handle and packs the CQ ring mmap offset, the ring cursors,
 * and (for an in-flight CQ) the raw unreaped-CQE image as the
 * rxe_cq_plugin_blob header + image tail into the entry-level
 * plugin_blob (malloc'd; criu/rdma/uobj_dump.c::uobj_cq_cb frees it
 * after pb_write_one). Capturing the cursors + unreaped CQEs -- not
 * just the mmap offset -- is what lets ibv_poll_cq see pre-dump
 * completions after restore, mirroring the QP SQ/RQ image round-trip.
 * Also stamps comp_vector=0 / flags=0 (rxe has a single comp vector and
 * no non-zero create-CQ flags in v0). The caller has already filled
 * cq_attrs->cqe_count from NLDEV RES_CQE.
 *
 * @kernel_driver_id is unused (the dispatcher already guaranteed an rxe
 * CQ); @pid is unused (QUERY_CQ sources everything from @lfd).
 */
static int rdma_rxe_plugin_dump_uobj_cq(const char *ibdev, uint32_t kernel_driver_id, int lfd, uint32_t ufile_handle,
					pid_t pid, RdmaCqAttrs *cq_attrs, ProtobufCBinaryData *plugin_blob)
{
	struct rxe_query_cq_resp_local resp = {};
	struct rxe_cq_plugin_blob *pb;
	int rc;

	(void)kernel_driver_id;
	(void)pid;

	rc = rxe_query_cq(lfd, ufile_handle, &resp, NULL, 0);
	if (rc) {
		pr_err("rxe: dump_uobj_cq: QUERY_CQ(handle=%u) on ibdev=%s failed: %d (%s)\n", ufile_handle, ibdev, rc,
		       strerror(-rc));
		return rc;
	}

	/*
	 * Sanity belt: NLDEV's RES_CQE (already stamped onto cqe_count)
	 * and QUERY_CQ's cqe resolve through the same kernel field
	 * (ibcq->cqe). A mismatch means the IDR walker and NLDEV are
	 * looking at different objects -- surface it, don't paper over it.
	 */
	if (cq_attrs->has_cqe_count && cq_attrs->cqe_count != resp.cqe) {
		pr_err("rxe: CQ handle=%u on ibdev=%s: NLDEV RES_CQE=%u disagrees with QUERY_CQ cqe=%u; "
		       "structural inconsistency, aborting dump\n",
		       ufile_handle, ibdev, cq_attrs->cqe_count, resp.cqe);
		rc = -EILSEQ;
		return rc;
	}
	pb = calloc(1, sizeof(*pb));
	if (!pb)
		return -ENOMEM;
	pb->vm_pgoff = resp.vm_pgoff;
	pb->queue_size = resp.queue_size;
	plugin_blob->data = (uint8_t *)pb;
	plugin_blob->len = sizeof(*pb);
	rc = rxe_queue_mapping_add(ibdev, resp.vm_pgoff, resp.queue_size, 0,
				   RXE_QUEUE_CQ);
	if (rc) {
		free(pb);
		plugin_blob->data = NULL;
		plugin_blob->len = 0;
		return rc;
	}

	cq_attrs->has_comp_vector = true;
	cq_attrs->comp_vector = 0;
	cq_attrs->has_flags = true;
	cq_attrs->flags = 0;

	pr_info("rxe: CQ handle=%u offset=%#" PRIx64 " size=%u\n",
		ufile_handle, resp.vm_pgoff, resp.queue_size);
	return 0;
}

/*
 * Inlined kernel UAPI for RXE_IB_METHOD_QUERY_QP (same
 * RXE_IB_OBJECT_MIGRATE object as QUERY_CQ). QUERY_QP is the second
 * method (FREEZE_DATAPATH=+0, QUERY_QP=+1, QUERY_CQ=+2), so its id is
 * (1<<SHIFT)+1. Attr namespace: HANDLE (IDR) at +0, RESP_BLOB (the
 * rxe_restore_qp_req PTR_OUT) at +1, RESP_USER_HANDLE (u64 PTR_OUT) at
 * +2, and the three optional in-flight image PTR_OUTs at +3/+4/+5
 * (SQ / RQ ring subspans and the responder-resources table). Keep in
 * sync with the kernel UAPI; remove once host rdma-core ships
 * rxe_user_ioctl_cmds.h.
 */
#define RXE_IB_METHOD_QUERY_QP_LOCAL		    ((1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL) + 1)
#define RXE_IB_ATTR_QUERY_QP_HANDLE_LOCAL	    (1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL)
#define RXE_IB_ATTR_QUERY_QP_RESP_BLOB_LOCAL	    ((1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL) + 1)
#define RXE_IB_ATTR_QUERY_QP_RESP_USER_HANDLE_LOCAL ((1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL) + 2)
#define RXE_IB_ATTR_QUERY_QP_RESP_SQ_IMAGE_LOCAL    ((1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL) + 3)
#define RXE_IB_ATTR_QUERY_QP_RESP_RQ_IMAGE_LOCAL    ((1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL) + 4)
#define RXE_IB_ATTR_QUERY_QP_RESP_RES_LOCAL	    ((1u << RXE_UVERBS_ID_NS_SHIFT_LOCAL) + 5)

/*
 * Per-image capture cap. Each in-flight image ships as one uverbs attr
 * whose len is u16, so a single image's [consumer, producer) subspan
 * (or the responder table) must fit in 65535 bytes; the kernel fails
 * QUERY_QP with -ENOSPC otherwise. Deep-ring chunking is a kernel-side
 * follow-up, matching the CQ image cap.
 */
#define RXE_QP_IMAGE_CAP_LOCAL 65535u

/*
 * Byte-equal mirror of include/uapi/rdma/rdma_user_rxe.h::
 * rxe_restore_qp_req (232 bytes): the QUERY_QP RESP_BLOB PTR_OUT, which
 * the kernel commit deliberately makes byte-identical to the
 * UVERBS_METHOD_RESTORE_QP UHW_IN so the dump-side blob replays verbatim
 * at restore. Unlike the CQ path (QUERY_CQ resp != RESTORE_CQ req, so
 * the blob is re-shaped), the QP blob is captured and later replayed as
 * this same struct. struct rxe_av is stable UAPI shipped by installed
 * rdma-core (rdma_user_rxe.h), so only this outer struct needs mirroring
 * until host rdma-core ships it.
 *
 * The fixed header carries identity, AV, PSN bases, the live
 * req/comp/resp cursors, ssn, transport knobs, the SQ/RQ ring mmap
 * offsets, and the in-flight datapath group: the ring producer/consumer
 * indices, the responder continuity scalars/cursors, and the
 * {sq,rq,res}_image_bytes counts. The variable-length images those
 * counts describe (SQ / RQ ring subspans, responder-resources table)
 * travel out-of-band as separate QUERY_QP PTR_OUT attrs and are appended
 * to the plugin_blob after this header (see rdma_rxe_plugin_dump_uobj_qp).
 * All the in-flight fields are zero for a drained QP.
 */
struct rxe_restore_qp_req_local {
	struct rxe_av av;
	uint64_t sq_vm_pgoff __attribute__((aligned(8)));
	uint64_t rq_vm_pgoff __attribute__((aligned(8)));
	uint32_t qpn;
	uint32_t dest_qp_num;
	uint32_t qkey;
	uint32_t sq_psn;
	uint32_t rq_psn;
	uint32_t qp_access_flags;
	uint32_t max_rd_atomic;
	uint32_t max_dest_rd_atomic;
	uint32_t req_psn;
	uint32_t comp_psn;
	uint32_t resp_psn;
	uint32_t resp_msn;
	uint32_t req_wqe_index;
	uint32_t ssn;
	uint16_t pkey_index;
	uint8_t path_mtu;
	uint8_t retry_cnt;
	uint8_t rnr_retry;
	uint8_t min_rnr_timer;
	uint8_t timeout;
	uint8_t port_num;
	uint8_t sq_sig_all;
	uint8_t resp_aeth_syndrome;
	uint16_t reserved;
	uint32_t sq_producer;
	uint32_t sq_consumer;
	uint32_t rq_producer;
	uint32_t rq_consumer;
	uint32_t resp_ack_psn;
	int32_t resp_opcode;
	uint32_t resp_status;
	uint32_t res_head;
	uint32_t res_tail;
	uint32_t sq_queue_size;
	uint32_t rq_queue_size;
	uint32_t res_image_bytes;
	uint64_t reserved2 __attribute__((aligned(8)));
};
_Static_assert(sizeof(struct rxe_restore_qp_req_local) == 232,
	       "rxe_restore_qp_req_local must be 232 bytes (field-identical to kernel rxe_restore_qp_req)");

struct rxe_qp_plugin_blob {
	uint64_t sq_vm_pgoff;
	uint64_t rq_vm_pgoff;
	uint64_t sq_queue_size;
	uint64_t rq_queue_size;
};

/*
 * Byte-equal mirror of include/uapi/rdma/rdma_user_rxe.h::
 * rxe_create_qp_resp (two mminfo, 32 bytes): the RESTORE_QP UHW_OUT the
 * kernel's rxe_restore_qp publishes (udata->outbuf must be at least this
 * size). rq_mi comes first, then sq_mi -- each carries the destination
 * ring's mmap byte offset, which rxe replays from the UHW_IN
 * rq_vm_pgoff / sq_vm_pgoff. The restore hook seeds the offsets as an
 * echo-verify template so core can confirm the kernel honoured the
 * forced ring offsets rather than falling back to its monotonic
 * counter. Remove once host rdma-core ships it.
 */
struct rxe_create_qp_resp_local {
	uint64_t rq_mi_offset;
	uint32_t rq_mi_size;
	uint32_t rq_mi_pad;
	uint64_t sq_mi_offset;
	uint32_t sq_mi_size;
	uint32_t sq_mi_pad;
};
_Static_assert(sizeof(struct rxe_create_qp_resp_local) == 32, "rxe_create_qp_resp_local must be 32 bytes (kernel UAPI)");

/*
 * Issue RXE_IB_METHOD_QUERY_QP on @fd (criu's dup of the dumpee's
 * uverbs cdev fd, holder of the QP IDR) against @qp_handle, the
 * dump-side counterpart of UVERBS_METHOD_RESTORE_QP. HANDLE is an
 * IDR-class attr (len 0, handle read from attrs[].data); the kernel
 * writes the drained wire state into @req_out and the QP's async-event
 * user_handle into @user_handle_out (both MANDATORY PTR_OUTs, so the
 * kernel writes them all or rejects the ioctl -- no partial outcome).
 *
 * When @sq_img / @rq_img / @res_img (each @img_cap bytes) are provided
 * the kernel also emits the in-flight SQ ring, RQ ring, and
 * responder-resources images into them, reporting each subspan's byte
 * count in @req_out->{sq,rq,res}_image_bytes. These are optional PTR_OUTs
 * (a drained QP writes 0 bytes); a buffer smaller than a live subspan
 * fails the whole QUERY_QP with -ENOSPC, so advertise the full @img_cap.
 *
 * Returns 0 on success, -errno on failure.
 */
static int rxe_query_qp(int fd, uint32_t qp_handle,
			struct rxe_restore_qp_req_local *req_out,
			uint64_t *user_handle_out)
{
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attrs[3];
	} cmd = {};
	unsigned int n = 0;

	cmd.hdr.object_id = RXE_IB_OBJECT_MIGRATE_LOCAL;
	cmd.hdr.method_id = RXE_IB_METHOD_QUERY_QP_LOCAL;
	cmd.hdr.driver_id = RDMA_DRIVER_RXE;

	cmd.attrs[n].attr_id = RXE_IB_ATTR_QUERY_QP_HANDLE_LOCAL;
	cmd.attrs[n].len = 0;
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = qp_handle;
	n++;

	cmd.attrs[n].attr_id = RXE_IB_ATTR_QUERY_QP_RESP_BLOB_LOCAL;
	cmd.attrs[n].len = sizeof(*req_out);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)req_out;
	n++;

	cmd.attrs[n].attr_id = RXE_IB_ATTR_QUERY_QP_RESP_USER_HANDLE_LOCAL;
	cmd.attrs[n].len = sizeof(*user_handle_out);
	cmd.attrs[n].flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attrs[n].data = (uintptr_t)user_handle_out;
	n++;

	cmd.hdr.num_attrs = n;
	cmd.hdr.length = sizeof(cmd.hdr) + n * sizeof(cmd.attrs[0]);

	if (ioctl(fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;
	return 0;
}

/*
 * RDMA_DUMP_UOBJ_QP hook (rxe). The QP twin of
 * rdma_rxe_plugin_dump_uobj_cq(): issues QUERY_QP on @lfd for
 * @ufile_handle and packs the returned rxe_restore_qp_req header plus,
 * for a non-drained QP, the in-flight SQ ring / RQ ring /
 * responder-resources images as the header + image tail into the
 * entry-level plugin_blob (malloc'd; uobj_qp_cb frees it after
 * pb_write_one). The tail layout -- header || sq || rq || res, each
 * sized by the header's {sq,rq,res}_image_bytes -- is exactly the
 * RESTORE_QP UHW_IN the kernel's tail slicer expects, so restore
 * replays the whole blob without re-shaping. Also fills the one
 * hw-agnostic field whose provenance is QUERY_QP rather than NLDEV:
 * qp_attrs->user_handle. The caller has already stamped the
 * NLDEV-derived qp_attrs (type/state/qpn/psns/port).
 *
 * @kernel_driver_id is unused (the dispatcher already guaranteed an rxe
 * QP); @pid is unused (QUERY_QP sources everything from @lfd).
 */
static int rdma_rxe_plugin_dump_uobj_qp(const char *ibdev, uint32_t kernel_driver_id, int lfd, uint32_t ufile_handle,
					pid_t pid, RdmaQpAttrs *qp_attrs, ProtobufCBinaryData *plugin_blob)
{
	struct rxe_restore_qp_req_local req = {};
	struct rxe_qp_plugin_blob *pb;
	uint64_t user_handle = 0;
	int rc;

	(void)kernel_driver_id;
	(void)pid;

	rc = rxe_query_qp(lfd, ufile_handle, &req, &user_handle);
	if (rc) {
		pr_err("rxe: dump_uobj_qp: QUERY_QP(handle=%u) on ibdev=%s failed: %d (%s)\n", ufile_handle, ibdev, rc,
		       strerror(-rc));
		return rc;
	}
	pb = calloc(1, sizeof(*pb));
	if (!pb)
		return -ENOMEM;
	pb->sq_vm_pgoff = req.sq_vm_pgoff;
	pb->rq_vm_pgoff = req.rq_vm_pgoff;
	pb->sq_queue_size = req.sq_queue_size;
	pb->rq_queue_size = req.rq_queue_size;
	plugin_blob->data = (uint8_t *)pb;
	plugin_blob->len = sizeof(*pb);
	rc = rxe_queue_mapping_add(ibdev, req.sq_vm_pgoff,
				   req.sq_queue_size, 0, RXE_QUEUE_SQ);
	if (!rc && req.rq_vm_pgoff)
		rc = rxe_queue_mapping_add(ibdev, req.rq_vm_pgoff,
					   req.rq_queue_size, 0, RXE_QUEUE_RQ);
	if (rc) {
		free(pb);
		plugin_blob->data = NULL;
		plugin_blob->len = 0;
		return rc;
	}

	qp_attrs->has_user_handle = true;
	qp_attrs->user_handle = user_handle;

	pr_info("rxe: dump_uobj_qp: ibdev=%s handle=%u qpn=%u sq_vm_pgoff=%#" PRIx64 " rq_vm_pgoff=%#" PRIx64
		" user_handle=%#" PRIx64 "\n",
		ibdev, ufile_handle, req.qpn, (uint64_t)req.sq_vm_pgoff, (uint64_t)req.rq_vm_pgoff,
		(uint64_t)user_handle);
	return 0;
}

/*
 * RDMA_RESTORE_UOBJ_CQ_UHW_PACK hook (rxe). The restore-time twin of
 * rdma_rxe_plugin_dump_uobj_cq(): reshapes the per-CQ plugin_blob it
 * emitted into the UVERBS_METHOD_RESTORE_CQ udata that core issues.
 *
 * UHW_IN is the plugin_blob verbatim -- its 24-byte header is field-
 * identical to the kernel rxe_restore_cq_req (vm_pgoff / producer /
 * consumer / cqe_image_bytes / reserved), and the tail is already the
 * in-flight [consumer, producer) CQE subspan the kernel blits back and
 * whose cursors it seeds via rxe_cq_seed_ring. UHW_OUT is a 16-byte
 * rxe_create_cq_resp receive area (the kernel's udata->outbuf minimum)
 * pre-seeded with the requested vm_pgoff so core memcmp-verifies the
 * kernel echoed the same ring offset back. Core owns and frees both
 * buffers after the ioctl.
 *
 * The blob length is validated to equal the header plus exactly its
 * declared image bytes, so a truncated/garbled image is caught here
 * rather than as a mid-restore -EINVAL from the kernel's tail slicer.
 */
static int rdma_rxe_plugin_restore_uobj_cq_uhw_pack(const RdmaUobjEntry *e, struct rdma_uhw_spec *uhw)
{
	const struct rxe_cq_plugin_blob *pb;
	struct rxe_restore_cq_req_local *in;
	struct rxe_create_cq_resp_local *out;
	uint64_t vm_pgoff;

	if (!e || !uhw)
		return -EINVAL;

	if (!e->has_plugin_blob || e->plugin_blob.len < sizeof(*pb)) {
		pr_err("rxe: RESTORE_CQ_UHW_PACK ufile_handle=%u: plugin_blob len=%zu below the %zu-byte header\n",
		       e->has_ufile_handle ? e->ufile_handle : 0, e->has_plugin_blob ? e->plugin_blob.len : (size_t)0,
		       sizeof(*pb));
		return -EINVAL;
	}
	pb = (const struct rxe_cq_plugin_blob *)e->plugin_blob.data;
	if (e->plugin_blob.len != sizeof(*pb)) {
		pr_err("rxe: CQ queue metadata has invalid length %zu\n",
		       e->plugin_blob.len);
		return -EINVAL;
	}
	vm_pgoff = pb->vm_pgoff;
	if (rxe_queue_mapping_add(rxe_ibdev_name, vm_pgoff, pb->queue_size,
				  e->ufile_id, RXE_QUEUE_CQ))
		return -EINVAL;

	out = malloc(sizeof(*out));
	if (!out) {
		pr_err("rxe: RESTORE_CQ_UHW_PACK out of memory (out_buf %zu bytes)\n", sizeof(*out));
		return -ENOMEM;
	}
	memset(out, 0, sizeof(*out));
	out->mi_offset = vm_pgoff;
	uhw->out_buf = out;
	uhw->out_len = sizeof(*out);
	uhw->verify_len = vm_pgoff ? sizeof(out->mi_offset) : 0;

	in = calloc(1, sizeof(*in));
	if (!in) {
		free(out);
		uhw->out_buf = NULL;
		uhw->out_len = 0;
		uhw->verify_len = 0;
		pr_err("rxe: RESTORE_CQ_UHW_PACK out of memory\n");
		return -ENOMEM;
	}
	in->vm_pgoff = vm_pgoff;
	uhw->in_buf = in;
	uhw->in_len = sizeof(*in);

	pr_debug("rxe: RESTORE_CQ_UHW_PACK handle=%u vm_pgoff=%#" PRIx64 "\n",
		 e->has_ufile_handle ? e->ufile_handle : 0, vm_pgoff);
	return 0;
}

/*
 * RDMA_RESTORE_UOBJ_QP_UHW_PACK hook (rxe). The restore-time twin of
 * rdma_rxe_plugin_dump_uobj_qp(): reshapes the per-QP plugin_blob it
 * emitted into the UVERBS_METHOD_RESTORE_QP udata that core issues.
 *
 * UHW_IN is the plugin_blob verbatim -- the kernel deliberately makes
 * the QUERY_QP output byte-identical to the RESTORE_QP UHW_IN (the
 * struct rxe_restore_qp_req header followed by the in-flight SQ / RQ /
 * responder-resources image tail), so unlike the CQ path there is no
 * re-shaping: the wire state (AV / PSNs / cursors / transport knobs /
 * ring vm_pgoffs) and any in-flight images replay as captured. UHW_OUT
 * is a 32-byte rxe_create_qp_resp receive area (the kernel's
 * udata->outbuf minimum) pre-seeded with the requested rq/sq ring
 * offsets so core memcmp-verifies the kernel echoed the same rq offset
 * back. Core owns and frees both buffers after the ioctl.
 *
 * The blob must be the fixed-size header plus exactly its declared
 * {sq,rq,res}_image_bytes of tail (zero for a drained QP), so a
 * truncated/garbled image is caught here rather than as a mid-restore
 * -EINVAL from the kernel's tail slicer.
 */
static int rdma_rxe_plugin_restore_uobj_qp_uhw_pack(const RdmaUobjEntry *e, struct rdma_uhw_spec *uhw)
{
	const struct rxe_qp_plugin_blob *pb;
	struct rxe_create_qp_resp_local *out;

	if (!e || !uhw)
		return -EINVAL;
	if (!e->has_plugin_blob || e->plugin_blob.len != sizeof(*pb))
		return -EINVAL;
	pb = (const struct rxe_qp_plugin_blob *)e->plugin_blob.data;
	if (rxe_queue_mapping_add(rxe_ibdev_name, pb->sq_vm_pgoff,
				  pb->sq_queue_size, e->ufile_id,
				  RXE_QUEUE_SQ))
		return -EINVAL;
	if (pb->rq_vm_pgoff &&
	    rxe_queue_mapping_add(rxe_ibdev_name, pb->rq_vm_pgoff,
				  pb->rq_queue_size, e->ufile_id,
				  RXE_QUEUE_RQ))
		return -EINVAL;

	out = calloc(1, sizeof(*out));
	if (!out) {
		pr_err("rxe: RESTORE_QP_UHW_PACK out of memory (out_buf %zu bytes)\n", sizeof(*out));
		return -ENOMEM;
	}
	uhw->out_buf = out;
	uhw->out_len = sizeof(*out);
	out->rq_mi_offset = pb->rq_vm_pgoff;
	out->sq_mi_offset = pb->sq_vm_pgoff;
	uhw->verify_len = 0;
	return 0;
}

/*
 * UPDATE_VMA_MAP hook for the /dev/infiniband/uverbs* ring VMAs the rxe
 * plugin claimed at dump time (HANDLE_DEVICE_VMA). Runs from
 * open_filemap() during open_vmas() -- after prepare_fds() (where
 * uverbsfd_open -> open_uverbs_cdev populated rxe_cdev_cache and, for a
 * CQ, RESTORE_CQ registered the ring's pending mmap slot) and before the
 * pie restorer's mmap blob.
 *
 * We must intercept here rather than let CRIU's generic open_path()
 * reopen the cdev: each fresh open() of the cdev mints an ib_uverbs_file
 * with ucontext == NULL, and ib_uverbs_mmap -EINVALs on that before ever
 * reaching rxe_mmap. Returning a dup() of the cached GET_CONTEXT'd fd
 * hands the pie a sibling on the same struct file, whose ucontext (and
 * thus the RESTORE_CQ-registered ring offset) is visible.
 *
 * The ring offset is unchanged across restore: RESTORE_CQ replays the
 * source vm_pgoff and the kernel echoes it back (verified in
 * rdma_send_restore_cq), so new_pgoff == old_pgoff and this hook only
 * substitutes the backing fd.
 *
 * Return 1 = claimed (*plugin_fd is a fresh dup for the pie, *new_pgoff
 * set); -ENOTSUP = not ours / fall through to CRIU's generic path; <0 =
 * hard error. @path is the source-side dumped cdev path; we resolve the
 * destination cdev's maj:min -> ibdev (which may differ cross-host) for
 * the cache join key, mirroring the dump-side claim.
 */
static int rdma_rxe_plugin_update_vma_map(const char *path, const uint64_t addr, const uint64_t old_pgoff,
					  uint64_t *new_pgoff, int *plugin_fd)
{
	struct stat st;
	struct rxe_queue_mapping *mapping;
	char ibdev[64];
	int cached_fd, dup_fd;

	(void)addr;

	if (!rxe_active)
		return -ENOTSUP;
	if (!path || strncmp(path, "/dev/infiniband/uverbs", 22) != 0)
		return -ENOTSUP;

	if (stat(path, &st) < 0 || !S_ISCHR(st.st_mode))
		return -ENOTSUP;
	if (rxe_chrdev_to_ibdev(st.st_rdev, ibdev, sizeof(ibdev)) < 0)
		return -ENOTSUP;

	mapping = rxe_queue_mapping_find(ibdev, old_pgoff, 1);
	if (!mapping || !mapping->ufile_id)
		return -ENOTSUP;
	cached_fd = rxe_cdev_cache_lookup(ibdev, mapping->ufile_id);
	if (cached_fd < 0) {
		pr_warn("update_vma_map: ibdev=%s not in cache (path=%s); open_uverbs_cdev did not run for this VMA's "
			"cdev. Falling through.\n",
			ibdev, path);
		return -ENOTSUP;
	}

	dup_fd = dup(cached_fd);
	if (dup_fd < 0) {
		pr_perror("update_vma_map: dup(cached_fd=%d) for ibdev=%s", cached_fd, ibdev);
		return -1;
	}

	*new_pgoff = old_pgoff;
	*plugin_fd = dup_fd;
	pr_info("update_vma_map: path=%s ibdev=%s pgoff=%#" PRIx64 " -> dest_fd=%d (dup of cached cdev w/ ucontext)\n",
		path, ibdev, old_pgoff, dup_fd);
	return 1;
}

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif

static int rxe_pidfd_open(pid_t pid)
{
	return syscall(__NR_pidfd_open, pid, 0);
}

static int rxe_pidfd_getfd(int pidfd, int targetfd)
{
	return syscall(__NR_pidfd_getfd, pidfd, targetfd, 0);
}

static int rxe_freeze_context(int fd)
{
	uint8_t freeze = 1;
	struct {
		struct ib_uverbs_ioctl_hdr hdr;
		struct ib_uverbs_attr attr;
	} cmd = {};

	cmd.hdr.object_id = RXE_IB_OBJECT_MIGRATE_LOCAL;
	cmd.hdr.method_id = RXE_IB_METHOD_FREEZE_CONTEXT_LOCAL;
	cmd.hdr.driver_id = RDMA_DRIVER_RXE;
	cmd.hdr.num_attrs = 1;
	cmd.hdr.length = sizeof(cmd);
	cmd.attr.attr_id = RXE_IB_ATTR_FREEZE_CONTEXT_FREEZE_LOCAL;
	cmd.attr.len = sizeof(freeze);
	cmd.attr.flags = UVERBS_ATTR_F_MANDATORY;
	cmd.attr.data = (uintptr_t)&freeze;
	if (ioctl(fd, RDMA_VERBS_IOCTL, &cmd) < 0)
		return -errno;
	return 0;
}

static int rdma_rxe_plugin_checkpoint_devices(int pid)
{
	char fdpath[64];
	struct dirent *de;
	int dfd, pidfd;
	DIR *directory;

	if (!rxe_active)
		return -ENOTSUP;
	snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd", pid);
	directory = opendir(fdpath);
	if (!directory)
		return -errno;
	dfd = dirfd(directory);
	pidfd = rxe_pidfd_open(pid);
	if (pidfd < 0) {
		closedir(directory);
		return -errno;
	}

	while ((de = readdir(directory)) != NULL) {
		struct rxe_frozen_context *frozen;
		struct stat st;
		int target_fd;
		int local_fd;
		int err;

		if (de->d_name[0] == '.')
			continue;
		target_fd = atoi(de->d_name);
		if (target_fd <= 0 || fstatat(dfd, de->d_name, &st, 0) < 0 ||
		    rxe_match_cdev_vma(&st, NULL, 0))
			continue;
		local_fd = rxe_pidfd_getfd(pidfd, target_fd);
		if (local_fd < 0)
			continue;
		frozen = malloc(sizeof(*frozen));
		if (!frozen) {
			close(local_fd);
			close(pidfd);
			closedir(directory);
			return -ENOMEM;
		}
		err = rxe_freeze_context(local_fd);
		if (err) {
			free(frozen);
			close(local_fd);
			close(pidfd);
			closedir(directory);
			return err;
		}
		frozen->fd = local_fd;
		frozen->next = rxe_frozen_contexts;
		rxe_frozen_contexts = frozen;
	}
	close(pidfd);
	closedir(directory);
	/* Continue the hook chain so another provider can freeze this task. */
	return -ENOTSUP;
}

/*
 * RESUME_DEVICES_LATE hook (rxe). RESTORE_QP installs every restored QP
 * datapath-frozen (the kernel rxe_qp_pause on the restore path), so no
 * traffic flows until CRIU resumes the device. RESUME_VHCA validates all
 * restored queue mappings, applies staged private state, and resumes every
 * restored context on the RXE device.
 *
 * This runs in the criu master, but the born-frozen ucontexts live in
 * the forked restored task: open_uverbs_cdev (which mints the
 * GET_CONTEXT(restore) ucontext) runs post-fork during the task's
 * prepare_fds, so the master's rxe_cdev_cache is empty here and a
 * cache-walk thaws nothing. Instead reach the task's real ucontext fds
 * the way the dump side does -- pidfd_open(@pid) + pidfd_getfd() steals a
		 * dup of the SAME struct file (ucontext intact), whereas a fresh cdev
		 * open would mint a ucontext-less ib_uverbs_file that RESUME_VHCA
 * -EINVALs. Walk /proc/<pid>/fd, filter to rxe uverbs cdevs, and thaw
 * each. RESUME_DEVICES_LATE fires after the pie placed the VMAs and
 * registered the MRs but before the tasks are released, the correct
 * post-everything / pre-resume barrier.
 *
 * Best-effort: a thaw failure is logged (the workload stalls on that
 * ucontext) but the hook still returns 0 -- the QP is otherwise fully
 * restored, and core treats the return as advisory anyway.
 */
static int rdma_rxe_plugin_resume_devices_late(int pid)
{
	char fdpath[64];
	DIR *d;
	int dfd, pidfd;
	struct dirent *de;
	int resumed = 0, failed = 0;

	if (!rxe_active)
		return -ENOTSUP;

	snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd", pid);
	d = opendir(fdpath);
	if (!d) {
		pr_perror("rxe: resume_late: opendir(%s)", fdpath);
		return -ENOTSUP;
	}
	dfd = dirfd(d);

	pidfd = rxe_pidfd_open(pid);
	if (pidfd < 0) {
		pr_perror("rxe: resume_late: pidfd_open(%d)", pid);
		closedir(d);
		return -ENOTSUP;
	}

	while ((de = readdir(d)) != NULL) {
		char ibdev[64];
		struct stat st;
		int target_fd, local_fd, rc;

		if (de->d_name[0] == '.')
			continue;
		target_fd = atoi(de->d_name);
		if (target_fd <= 0)
			continue;

		/*
		 * fstatat() follows the /proc/<pid>/fd/N symlink (no
		 * AT_SYMLINK_NOFOLLOW) so st_rdev names the device node the
		 * fd resolves to; rxe_match_cdev_vma() keeps only S_ISCHR
		 * uverbs cdevs whose ibdev resolves to rxe.
		 */
		if (fstatat(dfd, de->d_name, &st, 0) < 0)
			continue;
		if (rxe_match_cdev_vma(&st, ibdev, sizeof(ibdev)) != 0)
			continue;

		local_fd = rxe_pidfd_getfd(pidfd, target_fd);
		if (local_fd < 0) {
			pr_perror("rxe: resume_late: pidfd_getfd(pid=%d fd=%d ibdev=%s)", pid, target_fd, ibdev);
			failed++;
			continue;
		}

		rc = rxe_resume_vhca(local_fd);
		close(local_fd);
		if (rc) {
			pr_err("rxe: resume_late: RESUME_VHCA pid=%d fd=%d ibdev=%s failed: %d (%s); "
			       "restored QP datapath left frozen\n",
			       pid, target_fd, ibdev, rc, strerror(-rc));
			failed++;
			continue;
		}
		pr_info("rxe: resume_late: resumed restored device (pid=%d fd=%d ibdev=%s)\n", pid, target_fd, ibdev);
		resumed++;
	}

	close(pidfd);
	closedir(d);

	pr_debug("rxe: resume_late: pid=%d resumed=%d failed=%d\n", pid, resumed, failed);
	return 0;
}

CR_PLUGIN_REGISTER("rdma_rxe_plugin", rdma_rxe_plugin_init,
		   rdma_rxe_plugin_fini)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_CLAIM_UVERBS_CONTEXT,
			rdma_rxe_plugin_claim_uverbs_context)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_OPEN_UVERBS_CDEV,
			rdma_rxe_plugin_open_uverbs_cdev)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_DUMP_UVERBS_CONTEXT,
			rdma_rxe_plugin_dump_uverbs_context)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__HANDLE_DEVICE_VMA,
			rdma_rxe_plugin_handle_device_vma)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_CQ,
			rdma_rxe_plugin_dump_uobj_cq)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_DUMP_UOBJ_QP,
			rdma_rxe_plugin_dump_uobj_qp)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_CQ_UHW_PACK,
			rdma_rxe_plugin_restore_uobj_cq_uhw_pack)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RDMA_RESTORE_UOBJ_QP_UHW_PACK,
			rdma_rxe_plugin_restore_uobj_qp_uhw_pack)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__UPDATE_VMA_MAP,
			rdma_rxe_plugin_update_vma_map)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESUME_DEVICES_LATE,
			rdma_rxe_plugin_resume_devices_late)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__DUMP_DEVICES_LATE,
			rdma_rxe_plugin_dump_devices_late)
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__CHECKPOINT_DEVICES,
			rdma_rxe_plugin_checkpoint_devices)

/*
 * RDMA provided driver: RCD_RXE.
 *
 * The static twin of the RCD_RXE claim return value above. Tells the
 * restore-side cdev-open dispatcher (added later) that this plugin is
 * the one to call when an image's UverbsFileEntry.criu_driver names
 * RCD_RXE.
 */
CR_PLUGIN_DECLARE_RDMA_PROVIDED_DRIVER(RDMA_CRIU_DRIVER__RCD_RXE);

/*
 * RDMA sharing policy: EXCLUSIVE.
 *
 * The RXE vHCA image covers all selected contexts on one ib_device.
 * Until provider-owned coverage checks replace this temporary API,
 * reject an out-of-tree context before freezing the device.
 */
CR_PLUGIN_DECLARE_RDMA_SHARING(CR_RDMA_SHARING_EXCLUSIVE);
