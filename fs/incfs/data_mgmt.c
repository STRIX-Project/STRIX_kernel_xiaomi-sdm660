// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 Google LLC
 */
#include <linux/gfp.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/lz4.h>
#include <linux/rhashtable.h>
#include <linux/crc32.h>

#include "data_mgmt.h"

#define INCFS_MIN_FILE_INODE INCFS_ROOT_INODE
#define INCFS_MAX_FILE_INODE (INCFS_MIN_FILE_INODE + (1 << 30))

static u32 ino_hash(const void *data, u32 len, u32 seed);

static struct rhashtable_params node_map_params = {
	.nelem_hint		= 20,
	.key_len		= FIELD_SIZEOF(struct inode_info, n_ino),
	.key_offset		= offsetof(struct inode_info, n_ino),
	.head_offset		= offsetof(struct inode_info, n_hash_list),
	.automatic_shrinking	= false,
	.hashfn = ino_hash
};

struct mount_info *incfs_alloc_mount_info(struct super_block *sb,
					struct file *backing_file)
{
	struct mount_info *mi = NULL;
	int error = 0;

	mi = kzalloc(sizeof(*mi), GFP_NOFS);
	if (!mi) {
		error = -ENOMEM;
		goto err;
	}

	error = rhashtable_init(&mi->mi_nodes, &node_map_params);
	if (error)
		goto err;

	mi->mi_bf_context = incfs_alloc_bfc(backing_file);
	if (IS_ERR(mi->mi_bf_context)) {
		error = PTR_ERR(mi->mi_bf_context);
		mi->mi_bf_context = NULL;
		goto err;
	}

	mi->mi_sb = sb;

	/* Initialize root dir */
	mi->mi_root.d_node.n_ino = INCFS_ROOT_INODE;
	mi->mi_root.d_node.n_mount_info = mi;
	mi->mi_root.d_node.n_type = INCFS_NODE_DIR;
	mi->mi_root.d_node.n_mode = S_IFDIR | 0555;
	INIT_LIST_HEAD(&mi->mi_root.d_entries_head);
	INIT_LIST_HEAD(&mi->mi_root.d_node.n_parent_links_head);
	mi->mi_next_ino = INCFS_ROOT_INODE + 1;

	error = rhashtable_insert_fast(&mi->mi_nodes,
					&mi->mi_root.d_node.n_hash_list,
					node_map_params);
	if (error)
		goto err;

	spin_lock_init(&mi->pending_reads_counters_lock);
	mutex_init(&mi->mi_nodes_mutex);
	mutex_init(&mi->mi_dir_ops_mutex);
	init_waitqueue_head(&mi->mi_pending_reads_notif_wq);
	return mi;
err:

	if (mi) {
		rhashtable_destroy(&mi->mi_nodes);

		if (mi->mi_bf_context)
			incfs_free_bfc(mi->mi_bf_context);

		kfree(mi);
	}
	return ERR_PTR(error);
}

static bool is_valid_inode(int ino)
{
	return ino >= INCFS_MIN_FILE_INODE && ino <= INCFS_MAX_FILE_INODE;
}

static u32 ino_hash(const void *data, u32 len, u32 seed)
{
	const int *ino = data;

	return (u32)(*ino) ^ seed;
}

static void data_file_segment_init(struct data_file_segment *segment)
{
	INIT_LIST_HEAD(&segment->reads_list_head);
	init_waitqueue_head(&segment->new_data_arrival_wq);
	mutex_init(&segment->reads_mutex);
	mutex_init(&segment->blockmap_mutex);
}

static void data_file_segment_destroy(struct data_file_segment *segment)
{
	list_del(&segment->reads_list_head);
	mutex_destroy(&segment->reads_mutex);
	mutex_destroy(&segment->blockmap_mutex);
}

static void free_data_file(struct data_file *df)
{
	int i;

	if (!df)
		return;

	for (i = 0; i < ARRAY_SIZE(df->df_segments); i++)
		data_file_segment_destroy(&df->df_segments[i]);
	kfree(df);
}

/*
 * Adds a new file to the mount_info and
 * returns an error code (!NULL) in case of an error.
 */
static struct data_file *add_data_file(struct mount_info *mi, int ino,
					loff_t size, umode_t mode)
{
	struct data_file *df = NULL;
	int error = 0;
	int i;

	if (!mi)
		return ERR_PTR(-EFAULT);

	if (!is_valid_inode(ino))
		return ERR_PTR(-EINVAL);

	LOCK_REQUIRED(mi->mi_nodes_mutex);

	if (rhashtable_lookup_fast(&mi->mi_nodes, &ino, node_map_params))
		return ERR_PTR(-EEXIST);

	df = kzalloc(sizeof(*df), GFP_NOFS);
	if (!df)
		return ERR_PTR(-ENOMEM);

	df->df_node.n_ino = ino;
	df->df_node.n_type = INCFS_NODE_FILE;
	df->df_node.n_mode = (mode & 0555) | S_IFREG;
	df->df_node.n_mount_info = mi;
	INIT_LIST_HEAD(&df->df_node.n_parent_links_head);

	df->df_size = size;
	if (size > 0)
		df->df_block_count =
			1 + (size - 1) / INCFS_DATA_FILE_BLOCK_SIZE;

	for (i = 0; i < ARRAY_SIZE(df->df_segments); i++)
		data_file_segment_init(&df->df_segments[i]);

	error = rhashtable_insert_fast(&mi->mi_nodes,
					&df->df_node.n_hash_list,
					node_map_params);
	if (error) {
		free_data_file(df);
		return ERR_PTR(error);
	}
	return df;
}

static void free_dir_entry(struct dir_entry_info *entry)
{
	if (!entry)
		return;

	kfree(entry->de_name.data);
	kfree(entry);
}

static void free_dir(struct directory *dir)
{
	struct dir_entry_info *entry = NULL;
	struct dir_entry_info *tmp = NULL;

	if (!dir)
		return;

	list_for_each_entry_safe(entry, tmp, &dir->d_entries_head,
				  de_entries_list) {
		free_dir_entry(entry);
	}

	kfree(dir);
}

static void hashtable_free_node(void *ptr, void *arg)
{
	struct mount_info *mi = arg;
	struct inode_info *node = ptr;
	struct data_file *df = incfs_get_file_from_node(node);
	struct directory *dir = NULL;

	if (df) {
		free_data_file(df);
		return;
	}

	dir = incfs_get_dir_from_node(node);
	if (dir && dir != &mi->mi_root)
		free_dir(dir);
}

void incfs_free_mount_info(struct mount_info *mi)
{
	if (!mi)
		return;

	if (mi->mi_bf_context)
		incfs_free_bfc(mi->mi_bf_context);

	rhashtable_free_and_destroy(&mi->mi_nodes, hashtable_free_node, mi);
	mutex_destroy(&mi->mi_nodes_mutex);
	mutex_destroy(&mi->mi_dir_ops_mutex);
	kfree(mi);
}

static struct directory *add_dir(struct mount_info *mi, int ino, umode_t mode)
{
	struct directory *result = NULL;
	int error = 0;

	if (!mi)
		return ERR_PTR(-EFAULT);

	if (!is_valid_inode(ino))
		return ERR_PTR(-EINVAL);

	LOCK_REQUIRED(mi->mi_nodes_mutex);

	if (rhashtable_lookup_fast(&mi->mi_nodes, &ino, node_map_params))
		return ERR_PTR(-EEXIST);

	result = kzalloc(sizeof(*result), GFP_NOFS);
	if (!result)
		return ERR_PTR(-ENOMEM);

	result->d_node.n_ino = ino;
	result->d_node.n_type = INCFS_NODE_DIR;
	result->d_node.n_mode = (mode & 0555) | S_IFDIR;
	result->d_node.n_mount_info = mi;
	INIT_LIST_HEAD(&result->d_entries_head);
	INIT_LIST_HEAD(&result->d_node.n_parent_links_head);

	error = rhashtable_insert_fast(&mi->mi_nodes,
					&result->d_node.n_hash_list,
					node_map_params);
	if (error) {
		free_dir(result);
		return ERR_PTR(error);
	}
	return result;
}

static struct dir_entry_info *add_dir_entry(struct directory *dir,
				     const char *name, size_t name_len,
				     struct inode_info *child)
{
	struct dir_entry_info *result = NULL;
	struct dir_entry_info *entry = NULL;
	struct mount_info *mi = NULL;
	int error = 0;

	if (!dir || !child || !name)
		return ERR_PTR(-EFAULT);

	if ((child->n_ino == INCFS_ROOT_INODE) ||
		(child->n_ino == dir->d_node.n_ino))
		return ERR_PTR(-EINVAL);

	mi = dir->d_node.n_mount_info;

	result = kzalloc(sizeof(*result), GFP_NOFS);
	if (!result) {
		error = -ENOMEM;
		goto err;
	}

	result->de_parent = dir;
	result->de_child = child;
	result->de_name.len = name_len;
	result->de_name.data = kstrndup(name, name_len, GFP_NOFS);
	if (!result->de_name.data) {
		error = -ENOMEM;
		goto err;
	}

	mutex_lock(&mi->mi_dir_ops_mutex);
	list_for_each_entry(entry, &dir->d_entries_head, de_entries_list) {
		if (incfs_equal_ranges(range((u8 *)name, name_len),
				       entry->de_name)) {
			error = -EEXIST;
			goto err;
		}
	}

	if (child->n_type == INCFS_NODE_DIR) {
		/*
		 * Directories are not allowed to be referenced from more
		 * than one parent directory. If parent link list is not
		 * empty we can't create another name for this directory.
		 */
		if (!list_empty(&child->n_parent_links_head)) {
			error = -EMLINK;
			goto err;
		}
	}
	/* Adding to the child's list of all links pointing to it. */
	list_add_tail(&result->de_backlink_list,
		&child->n_parent_links_head);

	/* Adding to the dentry list's end to preserve insertion order. */
	list_add_tail(&result->de_entries_list, &dir->d_entries_head);
	atomic_inc(&dir->d_version);

	mutex_unlock(&mi->mi_dir_ops_mutex);
	return result;

err:
	mutex_unlock(&mi->mi_dir_ops_mutex);
	if (result) {
		kfree(result->de_name.data);
		kfree(result);
	}

	return ERR_PTR(error);
}

static int remove_dir_entry(struct directory *dir,
			const char *name, size_t name_len)
{
	struct dir_entry_info *entry = NULL;
	struct dir_entry_info *iter = NULL;
	struct directory *subdir = NULL;
	struct mount_info *mi = NULL;
	int result = 0;

	if (!dir || !name)
		return -EFAULT;

	mi = dir->d_node.n_mount_info;
	mutex_lock(&mi->mi_dir_ops_mutex);
	list_for_each_entry(iter, &dir->d_entries_head, de_entries_list) {
		if (incfs_equal_ranges(range((u8 *)name, name_len),
					iter->de_name)) {
			entry = iter;
			break;
		}
	}

	if (!entry) {
		result = -ENOENT;
		goto out;
	}

	subdir = incfs_get_dir_from_node(entry->de_child);
	if (subdir && !list_empty(&subdir->d_entries_head)) {
		/* Can't remove a dir entry for not empty directory. */
		result = -ENOTEMPTY;
		goto out;
	}

	list_del(&entry->de_backlink_list);
	list_del(&entry->de_entries_list);

	free_dir_entry(entry);
	atomic_inc(&dir->d_version);

out:
	mutex_unlock(&mi->mi_dir_ops_mutex);
	return result;
}

static struct data_file_segment *get_file_segment(struct data_file *df,
					   int block_index)
{
	int seg_idx = block_index % ARRAY_SIZE(df->df_segments);

	return &df->df_segments[seg_idx];
}

static struct pending_read *alloc_pending_read(void)
{
	struct pending_read *result = NULL;

	result = kzalloc(sizeof(*result), GFP_NOFS);
	if (!result)
		return NULL;

	INIT_LIST_HEAD(&result->reads_list);
	return result;
}

static bool is_read_done(struct pending_read *read)
{
	/*
	 * A barrier to make sure that updated value of read->done
	 * is properly reloaded each time we try to wake up or just before
	 * sleeping on new_data_arrival_wq.
	 */
	smp_mb__before_atomic();
	return atomic_read(&read->done) != 0;
}

static void set_read_done(struct pending_read *read)
{
	atomic_inc(&read->done);
	/*
	 * A barrier to make sure that a new value of read->done
	 * is globally visible.
	 */
	smp_mb__after_atomic();
}

struct inode_info *incfs_get_node_by_name(struct directory *dir,
					  const char *name, int *dir_ver_out)
{
	struct mount_info *mi = NULL;
	struct dir_entry_info *entry = NULL;
	struct inode_info *result = NULL;
	size_t len = 0;

	if (!dir || !name)
		return NULL;

	mi = dir->d_node.n_mount_info;
	len = strlen(name);

	mutex_lock(&mi->mi_dir_ops_mutex);
	list_for_each_entry(entry, &dir->d_entries_head, de_entries_list) {
		if (incfs_equal_ranges(entry->de_name,
					range((u8 *)name, len))) {
			result = entry->de_child;
			break;
		}
	}
	if (dir_ver_out)
		*dir_ver_out = atomic_read(&dir->d_version);
	mutex_unlock(&mi->mi_dir_ops_mutex);
	return result;
}

struct data_file *incfs_get_file_from_node(struct inode_info *node)
{
	if (!node || node->n_type != INCFS_NODE_FILE)
		return NULL;
	return container_of(node, struct data_file, df_node);
}

struct directory *incfs_get_dir_from_node(struct inode_info *node)
{
	if (!node || node->n_type != INCFS_NODE_DIR)
		return NULL;
	return container_of(node, struct directory, d_node);
}

struct inode_info *incfs_get_node_by_ino(struct mount_info *mi, int ino)
{
	if (!mi)
		return NULL;

	LOCK_REQUIRED(mi->mi_nodes_mutex);
	return rhashtable_lookup_fast(&mi->mi_nodes, &ino, node_map_params);
}

struct data_file *incfs_get_file_by_ino(struct mount_info *mi, int ino)
{
	return incfs_get_file_from_node(incfs_get_node_by_ino(mi, ino));
}

struct directory *incfs_get_dir_by_ino(struct mount_info *mi, int ino)
{
	return incfs_get_dir_from_node(incfs_get_node_by_ino(mi, ino));
}

static int get_data_file_block(struct data_file *df, int index,
			struct data_file_block *res_block)
{
	struct incfs_blockmap_entry bme = {};
	struct backing_file_context *bfc = NULL;
	loff_t blockmap_off = 0;
	u16 flags = 0;
	int error = 0;

	if (!df || !res_block)
		return -EFAULT;

	blockmap_off = atomic64_read(&df->df_blockmap_off);
	bfc = df->df_node.n_mount_info->mi_bf_context;

	if (index < 0 || index >= df->df_block_count || blockmap_off == 0)
		return -EINVAL;

	error = incfs_read_blockmap_entry(bfc, index, blockmap_off, &bme);
	if (error)
		return error;

	flags = le16_to_cpu(bme.me_flags);
	res_block->db_backing_file_data_offset =
		le16_to_cpu(bme.me_data_offset_hi);
	res_block->db_backing_file_data_offset <<= 32;
	res_block->db_backing_file_data_offset |=
		le32_to_cpu(bme.me_data_offset_lo);
	res_block->db_stored_size = le16_to_cpu(bme.me_data_size);
	res_block->db_crc = le32_to_cpu(bme.me_data_crc);
	res_block->db_comp_alg = (flags & INCFS_BLOCK_COMPRESSED_LZ4) ?
					 COMPRESSION_LZ4 :
					 COMPRESSION_NONE;
	return 0;
}

static int notify_pending_reads(struct data_file_segment *segment, int index)
{
	struct pending_read *entry = NULL;

	if (!segment || index < 0)
		return -EINVAL;

	/* Notify pending reads waiting for this block. */
	mutex_lock(&segment->reads_mutex);
	list_for_each_entry(entry, &segment->reads_list_head, reads_list) {
		if (entry->block_index == index)
			set_read_done(entry);
	}
	mutex_unlock(&segment->reads_mutex);
	wake_up_all(&segment->new_data_arrival_wq);
	return 0;
}

/*
 * Quickly checks if there are pending reads with a serial number larger
 * than a given one.
 */
bool incfs_fresh_pending_reads_exist(struct mount_info *mi, int last_number)
{
	bool result = false;

	spin_lock(&mi->pending_reads_counters_lock);
	result = (mi->mi_last_pending_read_number > last_number) &&
		 (mi->mi_pending_reads_count > 0);
	spin_unlock(&mi->pending_reads_counters_lock);
	return result;
}

static bool is_data_block_present(struct data_file_block *block)
{
	return (block->db_backing_file_data_offset != 0) &&
	       (block->db_stored_size != 0);
}

/*
 * Notifies a given data file about pending read from a given block.
 * Returns a new pending read entry.
 */
static struct pending_read *add_pending_read(struct data_file *df,
						int block_index)
{
	struct pending_read *result = NULL;
	struct data_file_segment *segment = NULL;
	struct mount_info *mi = NULL;

	WARN_ON(!df);
	segment = get_file_segment(df, block_index);
	mi = df->df_node.n_mount_info;

	WARN_ON(!segment);
	WARN_ON(!mi);

	result = alloc_pending_read();
	if (!result)
		return NULL;

	result->block_index = block_index;

	mutex_lock(&segment->reads_mutex);

	spin_lock(&mi->pending_reads_counters_lock);
	result->serial_number = ++mi->mi_last_pending_read_number;
	mi->mi_pending_reads_count++;
	spin_unlock(&mi->pending_reads_counters_lock);

	list_add(&result->reads_list, &segment->reads_list_head);
	mutex_unlock(&segment->reads_mutex);

	wake_up_all(&mi->mi_pending_reads_notif_wq);
	return result;
}

/* Notifies a given data file that pending read is completed. */
static void remove_pending_read(struct data_file *df, struct pending_read *read)
{
	struct data_file_segment *segment = NULL;
	struct mount_info *mi = NULL;

	if (!df || !read) {
		WARN_ON(!df);
		WARN_ON(!read);
		return;
	}

	segment = get_file_segment(df, read->block_index);
	mi = df->df_node.n_mount_info;

	WARN_ON(!segment);
	WARN_ON(!mi);

	mutex_lock(&segment->reads_mutex);
	list_del(&read->reads_list);

	spin_lock(&mi->pending_reads_counters_lock);
	mi->mi_pending_reads_count--;
	spin_unlock(&mi->pending_reads_counters_lock);
	mutex_unlock(&segment->reads_mutex);

	kfree(read);
}

static int wait_for_data_block(struct data_file *df, int block_index,
			int timeout_ms, struct data_file_block *res_block)
{
	struct data_file_block block = {};
	struct data_file_segment *segment = NULL;
	struct pending_read *read = NULL;
	int error = 0;
	int wait_res = 0;

	if (!df || !res_block)
		return -EFAULT;

	if (block_index < 0 || block_index >= df->df_block_count)
		return -EINVAL;

	if (atomic64_read(&df->df_blockmap_off) <= 0)
		return -ENODATA;

	segment = get_file_segment(df, block_index);
	WARN_ON(!segment);

	error = mutex_lock_interruptible(&segment->blockmap_mutex);
	if (error)
		return error;

	/* Look up the given block */
	error = get_data_file_block(df, block_index, &block);

	/* If it's not found, create a pending read */
	if (!error && !is_data_block_present(&block))
		read = add_pending_read(df, block_index);

	mutex_unlock(&segment->blockmap_mutex);
	if (error)
		return error;

	/* If the block was found, just return it. No need to wait. */
	if (is_data_block_present(&block)) {
		*res_block = block;
		return 0;
	}

	if (!read)
		return -ENOMEM;

	/* Wait for notifications about block's arrival */
	wait_res =
		wait_event_interruptible_timeout(segment->new_data_arrival_wq,
						 (is_read_done(read)),
						 msecs_to_jiffies(timeout_ms));

	/* Woke up, the pending read is nor longer needed. */
	remove_pending_read(df, read);
	read = NULL;

	if (wait_res == 0) {
		/* Wait has timed out */
		return -ETIME;
	}
	if (wait_res < 0) {
		/*
		 * Only ERESTARTSYS is really expected here when a signal
		 * comes while we wait.
		 */
		return wait_res;
	}

	error = mutex_lock_interruptible(&segment->blockmap_mutex);
	if (error)
		return error;

	/*
	 * Re-read block's info now, it has just arrived and
	 * should be available.
	 */
	error = get_data_file_block(df, block_index, &block);
	if (!error) {
		if (is_data_block_present(&block))
			*res_block = block;
		else {
			/*
			 * Somehow wait finished successfully bug block still
			 * can't be found. It's not normal.
			 */
			pr_warn("Wait succeeded, but block %d:%d not found.",
				df->df_node.n_ino, block_index);
			error = -ENODATA;
		}
	}

	mutex_unlock(&segment->blockmap_mutex);
	return error;
}

int incfs_collect_pending_reads(struct mount_info *mi, int sn_lowerbound,
			  struct incfs_pending_read_info *reads, int reads_size)
{
	int i = 0;
	int reported_reads = 0;
	bool stop = true;
	int start_sn = 0;
	int start_count = 0;
	struct rhashtable_iter iter;
	struct inode_info *node;
	int error = 0;

	if (!mi)
		return -EFAULT;

	mutex_lock(&mi->mi_nodes_mutex);

	spin_lock(&mi->pending_reads_counters_lock);
	start_sn = mi->mi_last_pending_read_number;
	start_count = mi->mi_pending_reads_count;
	spin_unlock(&mi->pending_reads_counters_lock);

	stop = (reads_size == 0 || start_count == 0);

	rhashtable_walk_enter(&mi->mi_nodes, &iter);
	rhashtable_walk_start(&iter);

	while (!stop && (node = rhashtable_walk_next(&iter))) {
		struct data_file *df = NULL;

		if (IS_ERR(node)) {
			error = PTR_ERR(node);
			break;
		}
		df = incfs_get_file_from_node(node);
		if (!df)
			continue;

		rhashtable_walk_stop(&iter);
		for (i = 0; i < SEGMENTS_PER_FILE && !stop; i++) {
			struct data_file_segment *segment = &df->df_segments[i];
			struct pending_read *entry = NULL;

			mutex_lock(&segment->reads_mutex);
			list_for_each_entry(entry, &segment->reads_list_head,
					     reads_list) {
				if (entry->serial_number <= sn_lowerbound)
					continue;
				/*
				 * Skip over pending reads that were not here at
				 * the beggining of the collection process.
				 * They will be addressed during a next call.
				 *
				 * If this is not done, and all pending reads
				 * are reported, then there might be a race
				 * between this code and pending reads being
				 * added to other segmeents/files.
				 *
				 * Skipping everything newer than read number
				 * known at the beggining guaranties consistent
				 * snapshot of pending reads across all files
				 * and segments. Is saves us from having to
				 * instoduce a big contended lock for
				 * everything.
				 */
				if (entry->serial_number > start_sn)
					continue;

				reads[reported_reads].file_ino =
					df->df_node.n_ino;
				reads[reported_reads].block_index =
					entry->block_index;
				reads[reported_reads].serial_number =
					entry->serial_number;

				reported_reads++;
				stop = (reported_reads >= reads_size) ||
					(reported_reads >= start_count);
				if (stop)
					break;
			}
			mutex_unlock(&segment->reads_mutex);
		}
		rhashtable_walk_start(&iter);
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
	mutex_unlock(&mi->mi_nodes_mutex);
	return error ? error : reported_reads;
}

static ssize_t decompress(struct mem_range src, struct mem_range dst)
{
	int result = LZ4_decompress_safe(src.data, dst.data, src.len, dst.len);

	if (result < 0)
		return -EBADMSG;

	return result;
}

static ssize_t read_with_crc(struct file *f, void *buf, size_t len,
				loff_t pos, u32 expected_crc)
{
	ssize_t result = 0;
	u32 buf_crc = 0;

	result = kernel_read(f, buf, len, &pos);
	if (result == len) {
		buf_crc = crc32(0, buf, len);
		if (buf_crc != expected_crc) {
			const char *name = f->f_path.dentry->d_name.name;

			pr_warn_once("incfs: Data CRC mismatch in %s. %u %u",
				name, buf_crc, expected_crc);
			return -EBADMSG;
		}
	}
	return result;
}

ssize_t incfs_read_data_file_block(struct mem_range dst, struct data_file *df,
			     int index)
{
	loff_t pos;
	ssize_t result;
	size_t bytes_to_read;
	u8 *decomp_buffer;
	struct mount_info *mi = NULL;
	struct file *bf = NULL;
	const size_t decomp_buf_size = 2 * INCFS_DATA_FILE_BLOCK_SIZE;
	struct data_file_block block = {};
	int timeout_ms = 0;

	if (!dst.data || !df)
		return -EFAULT;

	mi = df->df_node.n_mount_info;
	bf = mi->mi_bf_context->bc_file;
	timeout_ms = mi->mi_options.read_timeout_ms;

	result = wait_for_data_block(df, index, timeout_ms, &block);
	if (result < 0)
		return result;

	pos = block.db_backing_file_data_offset;
	if (block.db_comp_alg == COMPRESSION_NONE) {
		bytes_to_read = min(dst.len, block.db_stored_size);
		result = read_with_crc(bf, dst.data, bytes_to_read,
					pos, block.db_crc);

		/* Some data was read, but not enough */
		if (result >= 0 && result != bytes_to_read)
			result = -EIO;
	} else {
		decomp_buffer = (u8 *)__get_free_pages(
			GFP_NOFS, get_order(decomp_buf_size));
		if (!decomp_buffer)
			return -ENOMEM;

		bytes_to_read = min(decomp_buf_size, block.db_stored_size);
		result = read_with_crc(bf, decomp_buffer, bytes_to_read,
					pos, block.db_crc);
		if (result == bytes_to_read) {
			result = decompress(range(decomp_buffer, bytes_to_read),
					    dst);
			if (result < 0) {
				const char *name =
						bf->f_path.dentry->d_name.name;

				pr_warn_once("incfs: Decompression error. %s",
					name);
			}
		} else if (result >= 0) {
			/* Some data was read, but not enough */
			result = -EIO;
		}

		free_pages((unsigned long)decomp_buffer,
			   get_order(decomp_buf_size));
	}

	return result;
}

int incfs_process_new_data_block(struct mount_info *mi,
			   struct incfs_new_data_block *block,
			   u8 *data)
{
	struct backing_file_context *bfc = NULL;
	struct data_file *df = NULL;
	struct data_file_segment *segment = NULL;
	struct data_file_block existing_block = {};
	u16 flags = 0;
	u32 crc = 0;
	int error = 0;

	if (!mi || !block)
		return -EFAULT;
	bfc = mi->mi_bf_context;

	mutex_lock(&mi->mi_nodes_mutex);
	df = incfs_get_file_by_ino(mi, block->file_ino);
	mutex_unlock(&mi->mi_nodes_mutex);

	if (!df)
		return -ENOENT;
	if (block->block_index >= df->df_block_count)
		return -ERANGE;
	segment = get_file_segment(df, block->block_index);
	if (!segment)
		return -EFAULT;
	if (block->compression == COMPRESSION_LZ4)
		flags |= INCFS_BLOCK_COMPRESSED_LZ4;


	crc = crc32(0, data, block->data_len);
	error = mutex_lock_interruptible(&segment->blockmap_mutex);
	if (error)
		return error;

	error = get_data_file_block(df, block->block_index, &existing_block);
	if (error)
		goto unlock;
	if (is_data_block_present(&existing_block)) {
		/* Block is already present, nothing to do here */
		goto unlock;
	}

	error = mutex_lock_interruptible(&bfc->bc_mutex);
	if (!error) {
		error = incfs_write_data_block_to_backing_file(
			bfc, range(data, block->data_len),
			block->block_index, atomic64_read(&df->df_blockmap_off),
			flags, crc);
		mutex_unlock(&bfc->bc_mutex);
	}
	if (!error)
		error = notify_pending_reads(segment, block->block_index);

unlock:
	mutex_unlock(&segment->blockmap_mutex);
	return error;
}

int incfs_process_new_file_inst(struct mount_info *mi,
			  struct incfs_new_file_instruction *inst)
{
	struct directory *new_dir = NULL;
	struct data_file *new_file = NULL;
	struct backing_file_context *bfc = NULL;
	u16 mode = 0;
	int error = 0;

	if (!mi || !inst)
		return -EFAULT;

	bfc = mi->mi_bf_context;
	error = mutex_lock_interruptible(&bfc->bc_mutex);
	if (error)
		return error;

	/* Create and register in-memory dir or data_file objects */
	mutex_lock(&mi->mi_nodes_mutex);
	if (atomic_read(&mi->mi_nodes.nelems) >= INCFS_MAX_FILES) {
		/* File system already has too many files. */
		error = -ENFILE;
	} else if (S_ISREG(inst->mode)) {
		/* Create a regular file. */
		inst->ino_out = mi->mi_next_ino;
		new_file = add_data_file(mi, inst->ino_out, inst->size,
			inst->mode);

		if (IS_ERR_OR_NULL(new_file))
			error = PTR_ERR(new_file);
		else {
			mi->mi_next_ino++;
			mode = new_file->df_node.n_mode;
		}
	} else if (S_ISDIR(inst->mode)) {
		/* Create a directory. */
		inst->ino_out = mi->mi_next_ino;
		new_dir = add_dir(mi, inst->ino_out, inst->mode);

		if (IS_ERR_OR_NULL(new_dir))
			error = PTR_ERR(new_dir);
		else {
			mi->mi_next_ino++;
			mode = new_dir->d_node.n_mode;
		}
	} else
		error = -EINVAL;
	mutex_unlock(&mi->mi_nodes_mutex);
	if (error)
		goto out;

	/* Write inode to the backing file */
	error = incfs_write_inode_to_backing_file(bfc, inst->ino_out,
					inst->size, mode);
	if (error)
		goto out;

	/* If it's a data file, also reserve space for the block map. */
	if (new_file && new_file->df_block_count > 0) {
		loff_t bm_base_off = 0;

		error = incfs_write_blockmap_to_backing_file(bfc,
						       new_file->df_node.n_ino,
						       new_file->df_block_count,
						       &bm_base_off);
		if (error)
			goto out;
		atomic64_set(&new_file->df_blockmap_off, bm_base_off);
	}
out:
	mutex_unlock(&bfc->bc_mutex);
	return error;
}

int incfs_process_new_dir_entry_inst(struct mount_info *mi,
			       enum incfs_instruction_type type,
			       struct incfs_dir_entry_instruction *inst,
			       char *name)
{
	struct backing_file_context *bfc = NULL;
	int error = 0;

	if (!mi || !inst)
		return -EFAULT;

	bfc = mi->mi_bf_context;
	error = mutex_lock_interruptible(&bfc->bc_mutex);
	if (error)
		return error;

	switch (type) {
	case INCFS_INSTRUCTION_ADD_DIR_ENTRY: {
		struct dir_entry_info *dentry = NULL;
		struct inode_info *child = NULL;
		struct directory *parent = NULL;

		/* Find nodes that we want to connect */
		mutex_lock(&mi->mi_nodes_mutex);
		parent = incfs_get_dir_by_ino(mi, inst->dir_ino);
		child = incfs_get_node_by_ino(mi, inst->child_ino);
		mutex_unlock(&mi->mi_nodes_mutex);
		if (!child || !parent) {
			error = -ENOENT;
			goto out;
		}

		/* Put a dir/file into a parent dir object in memory */
		dentry = add_dir_entry(parent, name, inst->name_len, child);
		if (IS_ERR_OR_NULL(dentry)) {
			error = PTR_ERR(dentry);
			goto out;
		}

		/* Save record about the dir entry to the backing file */
		error = incfs_write_dir_action(bfc, inst->dir_ino,
				inst->child_ino, INCFS_DIRA_ADD_ENTRY,
				dentry->de_name);
		break;
	}
	case INCFS_INSTRUCTION_REMOVE_DIR_ENTRY: {
		struct directory *dir = NULL;

		/* Find nodes that we want to connect */
		mutex_lock(&mi->mi_nodes_mutex);
		dir = incfs_get_dir_by_ino(mi, inst->dir_ino);
		mutex_unlock(&mi->mi_nodes_mutex);

		if (!dir) {
			error = -ENOENT;
			goto out;
		}

		/* Remove dir entry from the dir object in memory */
		error = remove_dir_entry(dir, name, inst->name_len);
		if (error)
			goto out;

		/* Save record about the dir entry to the backing file */
		error = incfs_write_dir_action(
			bfc, dir->d_node.n_ino, inst->child_ino,
			INCFS_DIRA_REMOVE_ENTRY,
			range((u8 *)name, inst->name_len));
		break;
	}
	default:
		error = -ENOTSUPP;
		break;
	}

out:
	mutex_unlock(&bfc->bc_mutex);
	return error;
}

static int process_inode_md(struct incfs_inode *inode,
			    struct metadata_handler *handler)
{
	struct mount_info *mi = handler->context;
	int error = 0;
	u64 ino = le64_to_cpu(inode->i_no);
	u64 size = le64_to_cpu(inode->i_size);
	u16 mode = le16_to_cpu(inode->i_mode);

	if (!mi)
		return -EFAULT;

	mutex_lock(&mi->mi_nodes_mutex);
	if (S_ISREG(mode)) {
		struct data_file *df = add_data_file(mi, ino, size, mode);

		if (!df)
			error = -EFAULT;
		else if (IS_ERR(df))
			error = PTR_ERR(df);
	} else if (S_ISDIR(mode)) {
		struct directory *dir = add_dir(mi, ino, mode);

		if (!dir)
			error = -EFAULT;
		else if (IS_ERR(dir))
			error = PTR_ERR(dir);
	} else
		error = -EINVAL;

	if (!error && ino >= mi->mi_next_ino)
		mi->mi_next_ino = ino + 1;
	mutex_unlock(&mi->mi_nodes_mutex);
	return error;
}

static int process_blockmap_md(struct incfs_blockmap *bm,
			       struct metadata_handler *handler)
{
	struct mount_info *mi = handler->context;
	struct data_file *df = NULL;
	int error = 0;
	u64 ino = le64_to_cpu(bm->m_inode);
	loff_t base_off = le64_to_cpu(bm->m_base_offset);
	u32 block_count = le32_to_cpu(bm->m_block_count);

	if (!mi)
		return -EFAULT;

	mutex_lock(&mi->mi_nodes_mutex);
	df = incfs_get_file_by_ino(mi, ino);
	mutex_unlock(&mi->mi_nodes_mutex);

	if (!df)
		return -ENOENT;

	if (df->df_block_count != block_count)
		return -EBADFD;

	if (atomic64_cmpxchg(&df->df_blockmap_off, 0, base_off) != 0)
		error = -EBADFD;

	return error;
}

static int process_dir_action_md(struct incfs_dir_action *da,
				 struct metadata_handler *handler)
{
	struct mount_info *mi = handler->context;
	struct directory *dir = NULL;
	u64 dir_ino = le64_to_cpu(da->da_dir_inode);
	u64 entry_ino = le64_to_cpu(da->da_entry_inode);
	u8 type = da->da_type;
	u8 name_len = da->da_name_len;
	char *name = da->da_name;
	int result = 0;

	if (!mi)
		return -EFAULT;

	switch (type) {
	case INCFS_DIRA_NONE:
		result = 0;
		break;
	case INCFS_DIRA_ADD_ENTRY: {
		struct inode_info *node = NULL;
		struct dir_entry_info *dentry = NULL;

		mutex_lock(&mi->mi_nodes_mutex);
		dir = incfs_get_dir_by_ino(mi, dir_ino);
		node = incfs_get_node_by_ino(mi, entry_ino);
		mutex_unlock(&mi->mi_nodes_mutex);

		if (!dir || !node)
			return -ENOENT;

		dentry = add_dir_entry(dir, name, name_len, node);
		if (IS_ERR_OR_NULL(dentry))
			return PTR_ERR(dentry);
		break;
	}

	case INCFS_DIRA_REMOVE_ENTRY: {
		mutex_lock(&mi->mi_nodes_mutex);
		dir = incfs_get_dir_by_ino(mi, dir_ino);
		mutex_unlock(&mi->mi_nodes_mutex);

		if (!dir)
			return -ENOENT;

		result = remove_dir_entry(dir, name, name_len);
		break;
	}
	default:
		result = -ENOTSUPP;
	}
	return result;
}

int incfs_scan_backing_file(struct mount_info *mi)
{
	struct metadata_handler *handler = NULL;
	int result = 0;
	int records_count = 0;
	int error = 0;
	struct backing_file_context *bfc = NULL;

	if (!mi || !mi->mi_bf_context)
		return -EFAULT;

	bfc = mi->mi_bf_context;

	handler = kzalloc(sizeof(*handler), GFP_NOFS);
	if (!handler)
		return -ENOMEM;

	/* No writing to the backing file while it's being scanned. */
	error = mutex_lock_interruptible(&bfc->bc_mutex);
	if (error)
		goto out;

	/* Reading superblock */
	error = incfs_read_superblock(bfc, &handler->md_record_offset);
	if (error)
		goto unlock;

	handler->context = mi;
	handler->handle_inode = process_inode_md;
	handler->handle_blockmap = process_blockmap_md;
	handler->handle_dir_action = process_dir_action_md;

	pr_debug("Starting reading incfs-metadata records at offset %lld",
		 handler->md_record_offset);
	while (handler->md_record_offset > 0) {
		error = incfs_read_next_metadata_record(bfc, handler);
		if (error) {
			pr_warn("incfs: Error during reading incfs-metadata record. Offset: %lld Record #%d Error code:%d",
				handler->md_record_offset, records_count + 1,
				-error);
			break;
		}
		records_count++;
	}
	if (error) {
		pr_debug("Error %d after reading %d incfs-metadata records.",
			 -error, records_count);
		result = error;
	} else {
		pr_debug("Finished reading %d incfs-metadata records.",
			 records_count);
		result = records_count;
	}
unlock:
	mutex_unlock(&bfc->bc_mutex);
out:
	kfree(handler);
	return result;
}

bool incfs_equal_ranges(struct mem_range lhs, struct mem_range rhs)
{
	if (lhs.len != rhs.len)
		return false;
	return memcmp(lhs.data, rhs.data, lhs.len) == 0;
}
