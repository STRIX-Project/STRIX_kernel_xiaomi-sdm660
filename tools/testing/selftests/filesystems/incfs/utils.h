/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2019 Google LLC
 */
#include <stdbool.h>
#include <sys/stat.h>

#include "../../include/uapi/linux/incrementalfs.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

#ifdef __LP64__
#define ptr_to_u64(p) ((__u64)p)
#else
#define ptr_to_u64(p) ((__u64)(__u32)p)
#endif

int mount_fs(char *mount_dir, int backing_fd, int read_timeout_ms);

int send_md_instruction(int cmd_fd, struct incfs_instruction *inst);

int emit_node(int fd, char *filename, int *ino_out, int parent_ino,
		size_t size, mode_t mode);

int emit_dir(int fd, char *filename, int *ino_out, int parent_ino);

int emit_file(int fd, char *filename, int *ino_out, int parent_ino,
		size_t size);

int unlink_node(int fd, int parent_ino, char *filename);

loff_t get_file_size(char *name);

int open_commands_file(char *mount_dir);

int wait_for_pending_reads(int fd, int timeout_ms,
	struct incfs_pending_read_info *prs, int prs_count);

char *concat_file_name(char *dir, char *file);
