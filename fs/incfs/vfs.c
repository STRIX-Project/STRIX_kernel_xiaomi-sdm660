// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2018 Google LLC
 */
#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/kernel.h>
#include <linux/pagemap.h>
#include <linux/string.h>
#include <linux/parser.h>
#include <linux/seq_file.h>
#include <linux/poll.h>

#include <uapi/linux/incrementalfs.h>
#include "data_mgmt.h"

#define READ_EXEC_FILE_MODE 0555
#define READ_WRITE_FILE_MODE 0666

static int remount_fs(struct super_block *sb, int *flags, char *data);
static struct dentry *mount_fs(struct file_system_type *type, int flags,
			       const char *dev_name, void *data);
static struct dentry *dir_lookup(struct inode *dir_inode, struct dentry *dentry,
				 unsigned int flags);
static int iterate_incfs_dir(struct file *file, struct dir_context *ctx);
static int read_one_page(struct file *f, struct page *page);
static ssize_t command_write(struct file *f, const char __user *buf,
			size_t size, loff_t *offset);
static ssize_t command_read(struct file *f, char __user *buf, size_t len,
			    loff_t *ppos);
static __poll_t command_poll(struct file *file, poll_table *wait);
static int command_open(struct inode *inode, struct file *file);
static int command_release(struct inode *, struct file *);

static void kill_sb(struct super_block *sb);
static int dentry_revalidate(struct dentry *dentry, unsigned int flags);
static int dentry_revalidate_weak(struct dentry *dentry, unsigned int flags);
static long dispatch_ioctl(struct file *f, unsigned int req, unsigned long arg);
static int show_options(struct seq_file *, struct dentry *);
static int show_devname(struct seq_file *, struct dentry *);

/* State of an open .cmd file, unique for each file descriptor. */
struct command_file_state {
	/* A serial number of the last pending read obtained from this file. */
	int last_pending_read_sn;
};

struct file_system_type incfs_fs_type = {
	.owner = THIS_MODULE,
	.name = INCFS_NAME,
	.mount = mount_fs,
	.kill_sb = kill_sb,
	.fs_flags = 0
};

static const struct super_operations incfs_super_ops = {
	.statfs = simple_statfs,
	.remount_fs = remount_fs,
	.show_options = show_options,
	.show_devname = show_devname
};

static const struct inode_operations incfs_dir_inode_ops = {
	.lookup = dir_lookup,
};

static const struct file_operations incfs_dir_fops = {
	.llseek = generic_file_llseek,
	.read = generic_read_dir,
	.iterate = iterate_incfs_dir,
};

static const struct dentry_operations incfs_dentry_ops = {
	.d_revalidate = dentry_revalidate,
	.d_weak_revalidate = dentry_revalidate_weak,
};

static const struct address_space_operations incfs_address_space_ops = {
	.readpage = read_one_page,
};

static const struct file_operations incfs_file_ops = {
	.read_iter = generic_file_read_iter,
	.mmap = generic_file_mmap,
	.splice_read = generic_file_splice_read,
	.llseek = generic_file_llseek
};

static const struct file_operations incfs_command_file_ops = {
	.read = command_read,
	.write = command_write,
	.poll = command_poll,
	.open = command_open,
	.release = command_release,
	.llseek = noop_llseek,
	.unlocked_ioctl = dispatch_ioctl,
	.compat_ioctl = dispatch_ioctl
};

static const struct inode_operations incfs_file_inode_ops = {
	.setattr = simple_setattr,
	.getattr = simple_getattr,
};

static const char command_file_name[] = ".cmd";
static struct mem_range command_file_name_range = {
	.data = (u8 *)command_file_name,
	.len = ARRAY_SIZE(command_file_name) - 1
};
static struct mem_range dot_range = {
	.data = (u8 *)".",
	.len = 1
};
static struct mem_range dotdot_range = {
	.data = (u8 *)"..",
	.len = 2
};

enum parse_parameter { Opt_backing_fd, Opt_read_timeout, Opt_err };
static const match_table_t option_tokens = {
	{ Opt_backing_fd, "backing_fd=%u" },
	{ Opt_read_timeout, "read_timeout_ms=%u" },
	{ Opt_err, NULL }
};

static struct super_block *file_superblock(struct file *f)
{
	struct inode *inode;

	inode = file_inode(f);
	return inode->i_sb;
}

static struct mount_info *get_mount_info(struct super_block *sb)
{
	struct mount_info *result = sb->s_fs_info;

	WARN_ON(!result);
	return result;
}

static int validate_name(struct mem_range name)
{
	int i = 0;

	if (name.len > INCFS_MAX_NAME_LEN)
		return -ENAMETOOLONG;

	if (incfs_equal_ranges(dot_range, name) ||
	    incfs_equal_ranges(dotdot_range, name) ||
	    incfs_equal_ranges(command_file_name_range, name))
		return -EINVAL;

	for (i = 0; i < name.len; i++)
		if (name.data[i] == 0 || name.data[i] == '/')
			return -EINVAL;

	return 0;
}

static int read_one_page(struct file *f, struct page *page)
{
	loff_t offset = 0;
	loff_t size = 0;
	ssize_t bytes_to_read = 0;
	ssize_t read_result = 0;
	struct inode *inode = page->mapping->host;
	int block_index = 0;
	int result = 0;
	struct data_file *df = NULL;
	void *page_start = kmap(page);

	offset = page_offset(page);
	block_index = offset / INCFS_DATA_FILE_BLOCK_SIZE;
	if (offset & (INCFS_DATA_FILE_BLOCK_SIZE - 1)) {
		/*
		 * Page offset must be a multiplier of
		 * INCFS_DATA_FILE_BLOCK_SIZE
		 */
		pr_warn("incfs: Not aligned read from a file %d at offset %lld",
			(int)inode->i_ino, offset);
		result = -EINVAL;
		goto out;
	}

	size = i_size_read(inode);
	df = incfs_get_file_from_node((struct inode_info *)inode->i_private);
	if (!df) {
		result = -EBADF;
		goto out;
	}

	if (offset < size) {
		bytes_to_read = min_t(loff_t, size - offset, PAGE_SIZE);
		read_result = incfs_read_data_file_block(
			range(page_start, bytes_to_read), df, block_index);
	} else {
		bytes_to_read = 0;
		read_result = 0;
	}

	if (read_result < 0)
		result = read_result;
	else if (read_result < PAGE_SIZE)
		zero_user(page, read_result, PAGE_SIZE - read_result);

out:
	if (result == 0)
		SetPageUptodate(page);
	else
		SetPageError(page);

	flush_dcache_page(page);
	kunmap(page);
	unlock_page(page);
	return result;
}

static long ioctl_process_instructions(struct mount_info *mi, void __user *arg)
{
	struct incfs_instruction inst = {};
	int error = 0;
	const ssize_t data_buf_size = 2 * INCFS_DATA_FILE_BLOCK_SIZE;
	bool copy_inst_back = false;
	struct incfs_instruction __user *inst_usr_ptr = arg;
	u8 *data_buf = NULL;

	data_buf = (u8 *)__get_free_pages(GFP_NOFS,
					  get_order(data_buf_size));
	if (!data_buf)
		return -ENOMEM;

	/*
	 * Make sure that incfs_instruction doesn't have
	 * anything beyond reserved.
	 */
	BUILD_BUG_ON(sizeof(struct incfs_instruction) >
		offsetof(struct incfs_instruction, reserved) +
		sizeof(inst.reserved));
	if (copy_from_user(&inst, inst_usr_ptr, sizeof(inst)) > 0) {
		error = -EINVAL;
		goto out;
	}

	if (inst.version != INCFS_HEADER_VER)
		return -ENOTSUPP;

	switch (inst.type) {
	case INCFS_INSTRUCTION_NEW_FILE: {
		error = incfs_process_new_file_inst(mi, &inst.file);
		copy_inst_back = true;
		break;
	}
	case INCFS_INSTRUCTION_ADD_DIR_ENTRY:
	case INCFS_INSTRUCTION_REMOVE_DIR_ENTRY: {
		if (inst.dir_entry.name_len > data_buf_size) {
			error = -E2BIG;
			break;
		}
		if (copy_from_user(data_buf,
				u64_to_user_ptr(inst.dir_entry.name),
				inst.dir_entry.name_len)) {
			error = -EFAULT;
			break;
		}
		error = validate_name(range(data_buf,
					inst.dir_entry.name_len));
		if (error)
			break;

		error = incfs_process_new_dir_entry_inst(mi, inst.type,
							&inst.dir_entry,
							(char *)data_buf);
		break;
	}
	default:
		error = -EINVAL;
		break;
	}

	if (!error && copy_inst_back) {
		/*
		 * Copy instruction back to populate _out fields.
		 */
		if (copy_to_user(inst_usr_ptr, &inst, sizeof(inst)))
			error = -EFAULT;
	}
out:
	if (data_buf)
		free_pages((unsigned long)data_buf, get_order(data_buf_size));
	return error;
}

static long dispatch_ioctl(struct file *f, unsigned int req, unsigned long arg)
{
	struct mount_info *mi = get_mount_info(file_superblock(f));

	switch (req) {
	case INCFS_IOC_PROCESS_INSTRUCTION:
		return ioctl_process_instructions(mi, (void __user *)arg);
	default:
		return -EINVAL;
	}
}

static int command_open(struct inode *inode, struct file *file)
{
	struct command_file_state *cmd_state = NULL;

	cmd_state = kzalloc(sizeof(*cmd_state), GFP_NOFS);
	if (!cmd_state)
		return -ENOMEM;

	file->private_data = cmd_state;
	return 0;
}

static int command_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}

static ssize_t command_write(struct file *f, const char __user *buf,
			size_t size, loff_t *offset)
{
	struct mount_info *mi = get_mount_info(file_superblock(f));
	const ssize_t data_buf_size = 2 * INCFS_DATA_FILE_BLOCK_SIZE;
	size_t block_count = size / sizeof(struct incfs_new_data_block);
	struct incfs_new_data_block __user *usr_blocks =
				(struct incfs_new_data_block __user *)buf;
	u8 *data_buf = NULL;
	ssize_t error = 0;
	int i = 0;

	data_buf = (u8 *)__get_free_pages(GFP_NOFS,
					  get_order(data_buf_size));
	if (!data_buf)
		return -ENOMEM;

	for (i = 0; i < block_count; i++) {
		struct incfs_new_data_block block = {};

		if (copy_from_user(&block, &usr_blocks[i], sizeof(block)) > 0) {
			error = -EFAULT;
			break;
		}

		if (block.data_len > data_buf_size) {
			error = -E2BIG;
			break;
		}
		if (copy_from_user(data_buf, u64_to_user_ptr(block.data),
					block.data_len) > 0) {
			error = -EFAULT;
			break;
		}
		block.data = 0; /* To make sure nobody uses it. */
		error = incfs_process_new_data_block(mi, &block, data_buf);
		if (error)
			break;
	}

	if (data_buf)
		free_pages((unsigned long)data_buf, get_order(data_buf_size));
	*offset = 0;

	/*
	 * Only report the error if no records were processed, otherwise
	 * just return how many were processed successfully.
	 */
	if (i == 0)
		return error;

	return i * sizeof(struct incfs_new_data_block);
}

static ssize_t command_read(struct file *f, char __user *buf, size_t len,
			    loff_t *ppos)
{
	struct command_file_state *cmd_state = f->private_data;
	struct mount_info *mi = get_mount_info(file_superblock(f));
	struct incfs_pending_read_info *reads_buf = NULL;
	size_t reads_to_collect = len / sizeof(*reads_buf);
	int last_known_read_sn = READ_ONCE(cmd_state->last_pending_read_sn);
	int new_max_sn = last_known_read_sn;
	int reads_collected = 0;
	ssize_t result = 0;
	int i = 0;

	if (!incfs_fresh_pending_reads_exist(mi, last_known_read_sn))
		return 0;

	reads_buf = (struct incfs_pending_read_info *)get_zeroed_page(
		GFP_NOFS);
	if (!reads_buf)
		return -ENOMEM;

	reads_to_collect = min_t(size_t, PAGE_SIZE / sizeof(*reads_buf),
				reads_to_collect);

	reads_collected = incfs_collect_pending_reads(
		mi, last_known_read_sn, reads_buf, reads_to_collect);
	if (reads_collected < 0) {
		result = reads_collected;
		goto out;
	}

	for (i = 0; i < reads_collected; i++)
		if (reads_buf[i].serial_number > new_max_sn)
			new_max_sn = reads_buf[i].serial_number;

	/*
	 * Just to make sure that we don't accidentally copy more data
	 * to reads buffer than userspace can handle.
	 */
	reads_collected = min_t(size_t, reads_collected, reads_to_collect);
	result = reads_collected * sizeof(*reads_buf);

	/* Copy reads info to the userspace buffer */
	if (copy_to_user(buf, reads_buf, result)) {
		result = -EFAULT;
		goto out;
	}

	 WRITE_ONCE(cmd_state->last_pending_read_sn, new_max_sn);
	 *ppos = 0;
out:
	if (reads_buf)
		free_page((unsigned long)reads_buf);
	return result;
}

static __poll_t command_poll(struct file *file, poll_table *wait)
{
	struct command_file_state *cmd_state = file->private_data;
	struct mount_info *mi = get_mount_info(file_superblock(file));
	__poll_t ret = 0;

	poll_wait(file, &mi->mi_pending_reads_notif_wq, wait);
	if (incfs_fresh_pending_reads_exist(mi,
		cmd_state->last_pending_read_sn))
		ret = EPOLLIN | EPOLLRDNORM;

	return ret;
}

static struct timespec64 backing_file_time(struct super_block *sb)
{
	struct timespec64 zero_time = { .tv_sec = 0, .tv_nsec = 0 };
	struct mount_info *mi = get_mount_info(sb);
	struct inode *backing_inode = NULL;

	backing_inode = file_inode(mi->mi_bf_context->bc_file);
	if (!backing_inode)
		return zero_time;
	return backing_inode->i_ctime;
}

static struct inode *get_inode_for_incfs_node(struct super_block *sb,
					      struct inode_info *n_info)
{
	unsigned long ino = n_info->n_ino;
	struct inode *inode = iget_locked(sb, ino);

	if (!inode)
		return NULL;

	if (inode->i_state & I_NEW) {
		inode->i_ctime = backing_file_time(sb);
		inode->i_mtime = inode->i_ctime;
		inode->i_atime = inode->i_ctime;
		inode->i_ino = ino;
		inode->i_private = n_info;
		inode_init_owner(inode, NULL, n_info->n_mode);

		switch (n_info->n_type) {
		case INCFS_NODE_FILE: {
			struct data_file *df = incfs_get_file_from_node(n_info);

			inode->i_size = df->df_size;
			inode->i_blocks = df->df_block_count;
			inode->i_mapping->a_ops = &incfs_address_space_ops;
			inode->i_op = &incfs_file_inode_ops;
			inode->i_fop = &incfs_file_ops;
			break;
		}
		case INCFS_NODE_DIR:
			inode->i_size = 0;
			inode->i_blocks = 1;
			inode->i_mapping->a_ops = &incfs_address_space_ops;
			inode->i_op = &incfs_dir_inode_ops;
			inode->i_fop = &incfs_dir_fops;
			break;

			break;
		default:
			pr_warn("incfs: Unknown inode type");
			break;
		}

		unlock_new_inode(inode);
	}

	return inode;
}

static struct inode *get_inode_for_commands(struct super_block *sb)
{
	struct inode *inode = iget_locked(sb, INCFS_COMMAND_INODE);

	if (!inode)
		return NULL;

	if (inode->i_state & I_NEW) {
		inode->i_ctime = backing_file_time(sb);
		inode->i_mtime = inode->i_ctime;
		inode->i_atime = inode->i_ctime;
		inode->i_size = 0;
		inode->i_ino = INCFS_COMMAND_INODE;
		inode->i_private = NULL;

		inode_init_owner(inode, NULL, S_IFREG | READ_WRITE_FILE_MODE);

		inode->i_op = &incfs_file_inode_ops;
		inode->i_fop = &incfs_command_file_ops;

		unlock_new_inode(inode);
	}

	return inode;
}

static int iterate_incfs_dir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct directory *dir = NULL;
	struct mount_info *mi = NULL;
	struct dir_entry_info *entry;
	loff_t entries_found = 0;
	loff_t aux_entries_count = 2; // 2 for "." and ".."

	dir = incfs_get_dir_from_node((struct inode_info *)inode->i_private);
	if (!dir)
		return -EFAULT;

	if (!dir_emit_dots(file, ctx))
		return 0;

	mi = dir->d_node.n_mount_info;
	if (ctx->pos == 2 && dir->d_node.n_ino == INCFS_ROOT_INODE) {
		if (!dir_emit(ctx, command_file_name,
			      ARRAY_SIZE(command_file_name) - 1,
			      INCFS_COMMAND_INODE, DT_REG))
			return 0;
		ctx->pos++;
		aux_entries_count++; //Aux entry for the .cmd file
	}

	mutex_lock(&mi->mi_dir_ops_mutex);
	list_for_each_entry(entry, &dir->d_entries_head, de_entries_list) {
		unsigned int type = (entry->de_child->n_type == INCFS_NODE_DIR)
					? DT_DIR : DT_REG;

		entries_found++;
		if (entries_found > ctx->pos - aux_entries_count) {
			if (!dir_emit(ctx, entry->de_name.data,
					entry->de_name.len,
					entry->de_child->n_ino, type))
				break;
			ctx->pos++;
		}
	}
	mutex_unlock(&mi->mi_dir_ops_mutex);
	return 0;
}

static struct dentry *dir_lookup(struct inode *dir_inode, struct dentry *dentry,
				 unsigned int flags)
{
	struct inode *result = NULL;
	struct super_block *sb = dir_inode->i_sb;
	struct mount_info *mi = get_mount_info(sb);
	int dir_ver = 0;
	struct mem_range name_rng = range((u8 *)dentry->d_name.name,
						dentry->d_name.len);

	if (incfs_equal_ranges(dot_range, name_rng))
		result = dir_inode;
	else if (incfs_equal_ranges(dotdot_range, name_rng)) {
		struct directory *parent_dir = NULL;

		mutex_lock(&mi->mi_nodes_mutex);
		parent_dir = incfs_get_dir_by_ino(mi, parent_ino(dentry));
		if (parent_dir)
			result = get_inode_for_incfs_node(sb,
							&parent_dir->d_node);
		mutex_unlock(&mi->mi_nodes_mutex);
	} else if (incfs_equal_ranges(command_file_name_range, name_rng)) {
		result = get_inode_for_commands(sb);
	} else {
		struct directory *dir = NULL;
		struct inode_info *n_info = NULL;

		mutex_lock(&mi->mi_nodes_mutex);
		dir = incfs_get_dir_from_node(
			(struct inode_info *)dir_inode->i_private);
		n_info = incfs_get_node_by_name(dir, dentry->d_name.name,
						&dir_ver);
		if (n_info)
			result = get_inode_for_incfs_node(sb, n_info);

		mutex_unlock(&mi->mi_nodes_mutex);
	}
	dentry->d_fsdata = (void *)(long)dir_ver;
	d_add(dentry, result);
	return NULL;
}

static int parse_options(struct mount_options *opts, char *str)
{
	substring_t args[MAX_OPT_ARGS];
	int value;
	char *position;

	if (opts == NULL)
		return -EFAULT;

	opts->backing_fd = 0;
	opts->read_timeout_ms = 1000; /* Default: 1s */
	if (str == NULL || *str == 0)
		return 0;

	while ((position = strsep(&str, ",")) != NULL) {
		int token;

		if (!*position)
			continue;

		token = match_token(position, option_tokens, args);

		switch (token) {
		case Opt_backing_fd:
			if (match_int(&args[0], &value))
				return -EINVAL;
			opts->backing_fd = value;
			break;
		case Opt_read_timeout:
			if (match_int(&args[0], &value))
				return -EINVAL;
			opts->read_timeout_ms = value;
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

static int remount_fs(struct super_block *sb, int *flags, char *data)
{
	struct mount_info *mi = get_mount_info(sb);
	struct mount_options options;
	int err = 0;

	sync_filesystem(sb);
	err = parse_options(&options, (char *)data);
	if (err)
		return err;

	if (mi->mi_options.read_timeout_ms != options.read_timeout_ms) {
		mi->mi_options.read_timeout_ms = options.read_timeout_ms;
		pr_info("New Incremental-fs timeout_ms=%d",
			options.read_timeout_ms);
	}

	return 0;
}

static int dentry_revalidate(struct dentry *dentry, unsigned int flags)
{
	int dentry_ver = (int)(long)dentry->d_fsdata;
	struct inode *inode = NULL;
	struct dentry *parent = NULL;
	struct directory *parent_dir = NULL;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	parent = dget_parent(dentry);
	parent_dir = incfs_get_dir_from_node((struct inode_info *)
						d_inode(parent)->i_private);
	dput(parent);

	if (!parent_dir)
		return 0;

	/*
	 * Reload globally visible parent dir version. If it hasn't changed
	 * since the dentry had been created, it must be still valid.
	 */
	smp_mb__before_atomic();
	if (dentry_ver == atomic_read(&parent_dir->d_version))
		return 1;

	/* Root dentry is always valid. */
	inode = d_inode(dentry);
	if (inode && inode->i_ino == INCFS_ROOT_INODE)
		return 1;

	return 0;
}

static int dentry_revalidate_weak(struct dentry *dentry, unsigned int flags)
{
	/*
	 * Weak version of revalidate only needs to make sure that inode
	 * is still okay. Incremental-fs never deletes inodes, so no need
	 * for extra steps here.
	 */
	struct inode *inode = d_inode(dentry);

	if (!inode || !inode->i_private)
		return 0;
	return 1;
}

static int fill_super_block(struct super_block *sb, void *data, int silent)
{
	struct mount_options options;
	struct inode *inode = NULL;
	struct mount_info *mi = NULL;
	struct file *backing_file = NULL;
	const char *file_name = NULL;
	int result = 0;

	sb->s_op = &incfs_super_ops;
	sb->s_d_op = &incfs_dentry_ops;
	sb->s_flags |= S_NOATIME;
	sb->s_magic = INCFS_MAGIC_NUMBER;
	sb->s_time_gran = 1;
	sb->s_blocksize = INCFS_DATA_FILE_BLOCK_SIZE;
	sb->s_blocksize_bits = blksize_bits(sb->s_blocksize);
	sb->s_maxbytes = MAX_LFS_FILESIZE;

	BUILD_BUG_ON(PAGE_SIZE != INCFS_DATA_FILE_BLOCK_SIZE);

	result = parse_options(&options, (char *)data);
	if (result != 0)
		goto err;

	if (options.backing_fd == 0) {
		pr_err("Backing FD not set, filesystem can't be mounted.");
		result = -EBADFD;
		goto err;
	}

	backing_file = fget(options.backing_fd);
	if (!backing_file) {
		pr_err("Invalid backing FD: %d", options.backing_fd);
		result = -EBADFD;
		goto err;
	}

	mi = incfs_alloc_mount_info(sb, backing_file);
	if (IS_ERR_OR_NULL(mi)) {
		result = PTR_ERR(mi);
		mi = NULL;
		goto err;
	}

	mi->mi_options = options;
	sb->s_fs_info = mi;
	file_name = mi->mi_bf_context->bc_file->f_path.dentry->d_name.name;

	inode = new_inode(sb);
	if (inode) {
		inode->i_ino = INCFS_ROOT_INODE;
		inode->i_ctime = backing_file_time(sb);
		inode->i_mtime = inode->i_ctime;
		inode->i_atime = inode->i_ctime;
		inode->i_private = &mi->mi_root.d_node;

		inode->i_op = &incfs_dir_inode_ops;
		inode->i_fop = &incfs_dir_fops;

		inode_init_owner(inode, NULL, S_IFDIR | READ_EXEC_FILE_MODE);
	}

	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		result = -ENOMEM;
		goto err;
	}

	if (incfs_get_end_offset(mi->mi_bf_context->bc_file) > 0) {
		int found_mds = 0;

		/*
		 * Backing file has data,
		 * let's try to interpret it as inc-fs image.
		 */
		found_mds = incfs_scan_backing_file(mi);
		if (found_mds < 0) {
			result = found_mds;
			pr_err("Backing file '%s' scan error: %d",
				file_name, -result);
			goto err;
		}
	} else {
		/*
		 * No data in the backing file,
		 * let's initialize a new image.
		 */
		result = incfs_make_empty_backing_file(mi->mi_bf_context);
		if (result < 0) {
			pr_err("Backing file '%s' initialization error: %d",
				file_name, -result);
			goto err;
		}
	}
	return 0;
err:
	sb->s_fs_info = NULL;
	incfs_free_mount_info(mi);
	if (!mi && backing_file) {
		/*
		 * Close backing_file only if mount_info was never created.
		 * Otherwise it's closed in incfs_free_mount_info.
		 */
		fput(backing_file);
	}
	return result;
}

static struct dentry *mount_fs(struct file_system_type *type, int flags,
			       const char *dev_name, void *data)
{
	return mount_nodev(type, flags, data, fill_super_block);
}

static void kill_sb(struct super_block *sb)
{
	struct mount_info *mi = sb->s_fs_info;

	incfs_free_mount_info(mi);
	generic_shutdown_super(sb);
}

static int show_devname(struct seq_file *m, struct dentry *root)
{
	struct mount_info *mi = get_mount_info(root->d_sb);
	const char *backing_file =
			mi->mi_bf_context->bc_file->f_path.dentry->d_name.name;

	seq_puts(m, backing_file);
	return 0;
}

static int show_options(struct seq_file *m, struct dentry *root)
{
	struct mount_info *mi = get_mount_info(root->d_sb);

	seq_printf(m, ",read_timeout_ms=%u", mi->mi_options.read_timeout_ms);
	return 0;
}
