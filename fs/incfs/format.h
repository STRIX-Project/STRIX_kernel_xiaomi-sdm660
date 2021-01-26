/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2018 Google LLC
 */

/*
 * Overview
 * --------
 * The backbone of the incremental-fs ondisk format is an append only linked
 * list of metadata blocks. Each metadata block contains an offset of the next
 * one. These blocks describe files and directories on the
 * file system. They also represent actions of adding and removing file names
 * (hard links).
 *
 * Every time incremental-fs instance is mounted, it reads through this list
 * to recreate filesystem's state in memory. An offset of the first record in
 * the metadata list is stored in the superblock at the beginning of the backing
 * file.
 *
 * Most of the backing file is taken by data areas and blockmaps.
 * Since data blocks can be compressed and have different sizes,
 * single per-file data area can't be pre-allocated. That's why blockmaps are
 * needed in order to find a location and size of each data block in
 * the backing file. Each time a file is created, a corresponding block map is
 * allocated to store future offsets of data blocks.
 *
 * Whenever a data block is given by data loader to incremental-fs:
 *   - A data area with the given block is appended to the end of
 *     the backing file.
 *   - A record in the blockmap for the given block index is updated to reflect
 *     its location, size, and compression algorithm.

 * Metadata records
 * ----------------
 * incfs_inode - metadata record to declare a file or a directory.
 *                    incfs_inode.i_mode determents if it is a file
 *                    or a directory.
 * incfs_blockmap_entry - metadata record that specifies size and location
 *                           of a blockmap area for a given file. This area
 *                           contains an array of incfs_blockmap_entry-s.
 * incfs_dir_action - metadata record that specifies changes made to a
 *                   to a directory structure, e.g. add or remove a hardlink.
 *
 * Metadata header
 * ---------------
 * incfs_md_header - header of a metadata record. It's always a part
 *                   of other structures and served purpose of metadata
 *                   bookkeeping.
 *
 *              +-----------------------------------------------+       ^
 *              |            incfs_md_header                    |       |
 *              | 1. type of body(INODE, BLOCKMAP, DIR ACTION..)|       |
 *              | 2. size of the whole record header + body     |       |
 *              | 3. CRC the whole record header + body         |       |
 *              | 4. offset of the previous md record           |]------+
 *              | 5. offset of the next md record (md link)     |]---+
 *              +-----------------------------------------------+    |
 *              |  Metadata record body with useful data        |    |
 *              +-----------------------------------------------+    |
 *                                                                   +--->
 *
 * Other ondisk structures
 * -----------------------
 * incfs_super_block - backing file header
 * incfs_blockmap_entry - a record in a blockmap area that describes size
 *                       and location of a data block.
 * Data blocks dont have any particular structure, they are written to the
 * backing file in a raw form as they come from a data loader.
 *
 * Backing file layout
 * -------------------
 *
 *
 *              +-------------------------------------------+
 *              |            incfs_super_block              |]---+
 *              +-------------------------------------------+    |
 *              |                 metadata                  |<---+
 *              |                incfs_inode                |]---+
 *              +-------------------------------------------+    |
 *                        .........................              |
 *              +-------------------------------------------+    |   metadata
 *     +------->|               blockmap area               |    |  list links
 *     |        |          [incfs_blockmap_entry]           |    |
 *     |        |          [incfs_blockmap_entry]           |    |
 *     |        |          [incfs_blockmap_entry]           |    |
 *     |    +--[|          [incfs_blockmap_entry]           |    |
 *     |    |   |          [incfs_blockmap_entry]           |    |
 *     |    |   |          [incfs_blockmap_entry]           |    |
 *     |    |   +-------------------------------------------+    |
 *     |    |             .........................              |
 *     |    |   +-------------------------------------------+    |
 *     |    |   |                 metadata                  |<---+
 *     +----|--[|               incfs_blockmap              |]---+
 *          |   +-------------------------------------------+    |
 *          |             .........................              |
 *          |   +-------------------------------------------+    |
 *          +-->|                 data block                |    |
 *              +-------------------------------------------+    |
 *                        .........................              |
 *              +-------------------------------------------+    |
 *              |                 metadata                  |<---+
 *              |             incfs_dir_action              |
 *              +-------------------------------------------+
 */
#ifndef _INCFS_FORMAT_H
#define _INCFS_FORMAT_H
#include <linux/types.h>
#include <linux/kernel.h>
#include <uapi/linux/incrementalfs.h>

#include "internal.h"

#define INCFS_MAX_NAME_LEN 255
#define INCFS_FORMAT_V1 1
#define INCFS_FORMAT_CURRENT_VER INCFS_FORMAT_V1

enum incfs_metadata_type {
	INCFS_MD_NONE = 0,
	INCFS_MD_INODE = 1,
	INCFS_MD_BLOCK_MAP = 2,
	INCFS_MD_DIR_ACTION = 3
};

/* Header included at the beginning of all metadata records on the disk. */
struct incfs_md_header {
	__u8 h_md_entry_type;

	/*
	 * Size of the metadata record.
	 * (e.g. inode, dir entry etc) not just this struct.
	 */
	__le16 h_record_size;

	/*
	 * CRC32 of the metadata record.
	 * (e.g. inode, dir entry etc) not just this struct.
	 */
	__le32 h_record_crc;

	/* Offset of the next metadata entry if any */
	__le64 h_next_md_offset;

	/* Offset of the previous metadata entry if any */
	__le64 h_prev_md_offset;

} __packed;

/* Backing file header */
struct incfs_super_block {
	__le64 s_magic; /* Magic signature: INCFS_MAGIC_NUMBER */
	__le64 s_version; /* Format version: INCFS_FORMAT_CURRENT_VER */
	__le16 s_super_block_size; /* sizeof(incfs_super_block) */
	__le32 s_flags; /* Reserved for future use. */
	__le64 s_first_md_offset; /* Offset of the first metadata record */
	__le16 s_data_block_size; /* INCFS_DATA_FILE_BLOCK_SIZE */
} __packed;

/* Metadata record for files and directories. Type = INCFS_MD_INODE */
struct incfs_inode {
	struct incfs_md_header i_header;
	__le64 i_no; /* inode number */
	__le64 i_size; /* Full size of the file's content */
	__le16 i_mode; /* File mode */
	__le32 i_flags; /* Reserved for future use. */
} __packed;

enum incfs_block_map_entry_flags {
	INCFS_BLOCK_COMPRESSED_LZ4 = (1 << 0),
};

/* Block map entry pointing to an actual location of the data block. */
struct incfs_blockmap_entry {
	/* Offset of the actual data block. Lower 32 bits */
	__le32 me_data_offset_lo;

	/* Offset of the actual data block. Higher 16 bits */
	__le16 me_data_offset_hi;

	/* How many bytes the data actually occupies in the backing file */
	__le16 me_data_size;

	/* Block flags from incfs_block_map_entry_flags */
	__u16 me_flags;

	/* CRC32 of the block's data */
	__le32 me_data_crc;
} __packed;

/* Metadata record for locations of file blocks. Type = INCFS_MD_BLOCK_MAP */
struct incfs_blockmap {
	struct incfs_md_header m_header;
	/* inode of a file this map belongs to */
	__le64 m_inode;

	/* Base offset of the array of incfs_blockmap_entry */
	__le64 m_base_offset;

	/* Size of the map entry array in blocks */
	__le32 m_block_count;
} __packed;

enum incfs_dir_action_type {
	INCFS_DIRA_NONE = 0,
	INCFS_DIRA_ADD_ENTRY = 1,
	INCFS_DIRA_REMOVE_ENTRY = 2,
};

/* Metadata record of directory content change. Type = INCFS_MD_DIR_ACTION */
struct incfs_dir_action {
	struct incfs_md_header da_header;
	__le64 da_dir_inode; /* Parent directory inode number */
	__le64 da_entry_inode; /* File/subdirectory inode number */
	__u8 da_type; /* One of enums incfs_dir_action_type */
	__u8 da_name_len; /* Name length */
	char da_name[INCFS_MAX_NAME_LEN]; /* File name */
} __packed;

/* State of the backing file. */
struct backing_file_context {
	/* Protects writes to bc_file */
	struct mutex bc_mutex;

	/* File object to read data from */
	struct file *bc_file;

	/*
	 * Offset of the last known metadata record in the backing file.
	 * 0 means there are no metadata records.
	 */
	loff_t bc_last_md_record_offset;
};

struct metadata_handler {
	loff_t md_record_offset;
	loff_t md_prev_record_offset;
	void *context;

	union {
		struct incfs_md_header md_header;
		struct incfs_inode inode;
		struct incfs_blockmap blockmap;
		struct incfs_dir_action dir_action;
	} md_buffer;

	int (*handle_inode)(struct incfs_inode *inode,
			    struct metadata_handler *handler);
	int (*handle_blockmap)(struct incfs_blockmap *bm,
			       struct metadata_handler *handler);
	int (*handle_dir_action)(struct incfs_dir_action *da,
				 struct metadata_handler *handler);
};
#define INCFS_MAX_METADATA_RECORD_SIZE \
	FIELD_SIZEOF(struct metadata_handler, md_buffer)

loff_t incfs_get_end_offset(struct file *f);

/* Backing file context management */
struct backing_file_context *incfs_alloc_bfc(struct file *backing_file);

void incfs_free_bfc(struct backing_file_context *bfc);

/* Writing stuff */
int incfs_write_inode_to_backing_file(struct backing_file_context *bfc, u64 ino,
				      u64 size, u16 mode);

int incfs_write_dir_action(struct backing_file_context *bfc, u64 dir_ino,
			   u64 dentry_ino, enum incfs_dir_action_type type,
			   struct mem_range name);

int incfs_write_blockmap_to_backing_file(struct backing_file_context *bfc,
					 u64 ino, u32 block_count,
					 loff_t *map_base_off);

int incfs_write_sb_to_backing_file(struct backing_file_context *bfc);

int incfs_write_data_block_to_backing_file(struct backing_file_context *bfc,
					   struct mem_range block,
					   int block_index, loff_t bm_base_off,
					   u16 flags, u32 crc);

int incfs_make_empty_backing_file(struct backing_file_context *bfc);

/* Reading stuff */
int incfs_read_superblock(struct backing_file_context *bfc,
			  loff_t *first_md_off);

int incfs_read_blockmap_entry(struct backing_file_context *bfc, int block_index,
			      loff_t bm_base_off,
			      struct incfs_blockmap_entry *bm_entry);

int incfs_read_next_metadata_record(struct backing_file_context *bfc,
				    struct metadata_handler *handler);

#endif /* _INCFS_FORMAT_H */
