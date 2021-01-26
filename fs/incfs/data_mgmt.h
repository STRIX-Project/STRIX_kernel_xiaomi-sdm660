/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2019 Google LLC
 */
#ifndef _INCFS_DATA_MGMT_H
#define _INCFS_DATA_MGMT_H

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/wait.h>
#include <linux/rhashtable-types.h>

#include "internal.h"
#include "format.h"

#define SEGMENTS_PER_FILE 5

struct data_file_block {
	loff_t db_backing_file_data_offset;

	size_t db_stored_size;

	u32 db_crc;

	enum incfs_compression_alg db_comp_alg;
};

struct pending_read {
	struct list_head reads_list;

	int block_index;

	int serial_number;

	atomic_t done;
};

struct data_file_segment {
	wait_queue_head_t new_data_arrival_wq;

	/* Protects reads and writes from the blockmap */
	/* Good candidate for read/write mutex */
	struct mutex blockmap_mutex;

	/* Protects reads_list_head */
	struct mutex reads_mutex;

	/* List of active pending_read objects */
	struct list_head reads_list_head;
};

struct mount_info;

enum incfs_node_type { INCFS_NODE_FILE = 0, INCFS_NODE_DIR = 1 };

/* Common parts between data files and dirs. */
struct inode_info {
	struct mount_info *n_mount_info; /* Mount this file belongs to */

	/* Hash bucket list for mount_info.mi_nodes */
	struct rhash_head n_hash_list;

	/* List of dir_entry_info pointing to this node */
	struct list_head n_parent_links_head;

	int n_ino;

	umode_t n_mode;

	u8 n_type; /* Node type values from enum incfs_node_type */
};

struct data_file {
	struct inode_info df_node;

	/*
	 * Array of segments used to reduce lock contention for the file.
	 * Segment is chosen for a block depends on the block's index.
	 */
	struct data_file_segment df_segments[SEGMENTS_PER_FILE];

	/* Base offset of the block map. */
	atomic64_t df_blockmap_off;

	/* File size in bytes */
	loff_t df_size;

	int df_block_count; /* File size in DATA_FILE_BLOCK_SIZE blocks */
};

struct directory {
	struct inode_info d_node;

	/* List of struct dir_entry_info belonging to this directory */
	struct list_head d_entries_head;

	atomic_t d_version;
};

struct dir_entry_info {
	struct list_head de_entries_list;

	struct list_head de_backlink_list;

	struct mem_range de_name;

	struct inode_info *de_child;

	struct directory *de_parent;
};

struct mount_options {
	unsigned int backing_fd;
	unsigned int read_timeout_ms;
};

struct mount_info {
	struct super_block *mi_sb;
	struct mount_options mi_options;

	/*
	 * Protects operations with directory entries, basically it
	 * protects all instances of lists:
	 *   - directory.d_entries_head
	 *   - inode_info.n_parent_links_head
	 */
	struct mutex mi_dir_ops_mutex;

	/* Protects mi_nodes, mi_next_ino, and mi_root */
	struct mutex mi_nodes_mutex;

	/* State of the backing file */
	struct backing_file_context *mi_bf_context;

	/*
	 * Hashtable (int ino) -> (struct inode_info)
	 */
	struct rhashtable mi_nodes;

	/* Directory entry for the filesystem root */
	struct directory mi_root;

	/* Node number to allocate next */
	int mi_next_ino;

	/* Protects mi_last_pending_read_number and mi_pending_reads_count */
	spinlock_t pending_reads_counters_lock;

	/*
	 * A queue of waiters who want to be notified about new pending reads.
	 */
	wait_queue_head_t mi_pending_reads_notif_wq;

	/*
	 * Last serial number that was assigned to a pending read.
	 * 0 means no pending reads have been seen yet.
	 */
	int mi_last_pending_read_number;

	/* Total number of reads waiting on data from all files */
	int mi_pending_reads_count;
};

/* mount_info functions */
struct mount_info *incfs_alloc_mount_info(struct super_block *sb,
					struct file *backing_file);
void incfs_free_mount_info(struct mount_info *mi);

bool incfs_fresh_pending_reads_exist(struct mount_info *mi, int last_number);

struct inode_info *incfs_get_node_by_name(struct directory *dir,
					const char *name, int *dir_ver_out);
struct data_file *incfs_get_file_from_node(struct inode_info *node);
struct directory *incfs_get_dir_from_node(struct inode_info *node);
struct inode_info *incfs_get_node_by_ino(struct mount_info *mi, int ino);
struct data_file *incfs_get_file_by_ino(struct mount_info *mi, int ino);
struct directory *incfs_get_dir_by_ino(struct mount_info *mi, int ino);

ssize_t incfs_read_data_file_block(struct mem_range dst, struct data_file *df,
			     int index);

/*
 * Collects pending reads and saves them into the array (reads/reads_size).
 * Only reads with serial_number > sn_lowerbound are reported.
 * Returns how many reads were saved into the array.
 */
int incfs_collect_pending_reads(struct mount_info *mi, int sn_lowerbound,
			  struct incfs_pending_read_info *reads,
			  int reads_size);

/* Instructions processing */
int incfs_process_new_file_inst(struct mount_info *mi,
			  struct incfs_new_file_instruction *inst);
int incfs_process_new_dir_entry_inst(struct mount_info *mi,
			       enum incfs_instruction_type type,
			       struct incfs_dir_entry_instruction *inst,
			       char *name);

int incfs_process_new_data_block(struct mount_info *mi,
			   struct incfs_new_data_block *block,
			   u8 *data);

/*
 * Scans whole backing file for metadata records.
 * Returns an error or a number of processed metadata records.
 */
int incfs_scan_backing_file(struct mount_info *mi);

bool incfs_equal_ranges(struct mem_range lhs, struct mem_range rhs);

#endif /* _INCFS_DATA_MGMT_H */
