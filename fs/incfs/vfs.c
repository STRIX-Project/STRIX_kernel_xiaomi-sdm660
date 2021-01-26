// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2018 Google LLC
 */
#include <linux/blkdev.h>
#include <linux/fs.h>

#include <uapi/linux/incrementalfs.h>

static struct dentry *mount_fs(struct file_system_type *type, int flags,
			       const char *dev_name, void *data);
static void kill_sb(struct super_block *sb);

struct file_system_type incfs_fs_type = {
	.owner = THIS_MODULE,
	.name = INCFS_NAME,
	.mount = mount_fs,
	.kill_sb = kill_sb,
	.fs_flags = 0
};

static int fill_super_block(struct super_block *sb, void *data, int silent)
{
	return 0;
}

static struct dentry *mount_fs(struct file_system_type *type, int flags,
			       const char *dev_name, void *data)
{
	return mount_nodev(type, flags, data, fill_super_block);
}

static void kill_sb(struct super_block *sb)
{
	generic_shutdown_super(sb);
}

