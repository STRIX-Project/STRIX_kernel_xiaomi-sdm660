// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2018 Google LLC
 */
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>

#include <uapi/linux/incrementalfs.h>

#define INCFS_CORE_VERSION 1

extern struct file_system_type incfs_fs_type;

static struct kobject *sysfs_root;

static ssize_t version_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buff)
{
	return snprintf(buff, PAGE_SIZE, "%d\n", INCFS_CORE_VERSION);
}

static struct kobj_attribute version_attr = __ATTR_RO(version);

static struct attribute *attributes[] = {
	&version_attr.attr,
	NULL,
};

static const struct attribute_group attr_group = {
	.attrs = attributes,
};

static int __init init_sysfs(void)
{
	int res = 0;

	sysfs_root = kobject_create_and_add(INCFS_NAME, fs_kobj);
	if (!sysfs_root)
		return -ENOMEM;

	res = sysfs_create_group(sysfs_root, &attr_group);
	if (res) {
		kobject_put(sysfs_root);
		sysfs_root = NULL;
	}
	return res;
}

static void cleanup_sysfs(void)
{
	if (sysfs_root) {
		sysfs_remove_group(sysfs_root, &attr_group);
		kobject_put(sysfs_root);
		sysfs_root = NULL;
	}
}

static int __init init_incfs_module(void)
{
	int err = 0;

	err = init_sysfs();
	if (err)
		return err;

	err = register_filesystem(&incfs_fs_type);
	if (err)
		cleanup_sysfs();

	return err;
}

static void __exit cleanup_incfs_module(void)
{
	cleanup_sysfs();
	unregister_filesystem(&incfs_fs_type);
}

module_init(init_incfs_module);
module_exit(cleanup_incfs_module);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Eugene Zemtsov <ezemtsov@google.com>");
MODULE_DESCRIPTION("Incremental File System");
