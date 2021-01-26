/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Userspace interface for Incremental FS.
 *
 * Incremental FS is special-purpose Linux virtual file system that allows
 * execution of a program while its binary and resource files are still being
 * lazily downloaded over the network, USB etc.
 *
 * Copyright 2019 Google LLC
 */
#ifndef _UAPI_LINUX_INCREMENTALFS_H
#define _UAPI_LINUX_INCREMENTALFS_H

#include <linux/limits.h>
#include <linux/ioctl.h>
#include <linux/types.h>

/* ===== constants ===== */
#define INCFS_NAME "incremental-fs"
#define INCFS_MAGIC_NUMBER (0x5346434e49ul)
#define INCFS_DATA_FILE_BLOCK_SIZE 4096
#define INCFS_HEADER_VER 1

#define INCFS_MAX_FILES 1000
#define INCFS_COMMAND_INODE 1
#define INCFS_ROOT_INODE 2

#define INCFS_IOCTL_BASE_CODE 'g'

/* ===== ioctl requests on command file ===== */

/* Make changes to the file system via incfs instructions. */
#define INCFS_IOC_PROCESS_INSTRUCTION \
	_IOWR(INCFS_IOCTL_BASE_CODE, 30, struct incfs_instruction)

enum incfs_compression_alg { COMPRESSION_NONE = 0, COMPRESSION_LZ4 = 1 };

/*
 * Description of a pending read. A pending read - a read call by
 * a userspace program for which the filesystem currently doesn't have data.
 *
 * This structs can be read from .cmd file to obtain a set of reads which
 * are currently pending.
 */
struct incfs_pending_read_info {
	/* Inode number of a file that is being read from. */
	__aligned_u64 file_ino;

	/* Index of a file block that is being read. */
	__u32 block_index;

	/* A serial number of this pending read. */
	__u32 serial_number;
};

/*
 * A struct to be written into a .cmd file to provide a data block for a file.
 */
struct incfs_new_data_block {
	/* Inode number of a file this block belongs to. */
	__aligned_u64 file_ino;

	/* Index of a data block. */
	__u32 block_index;

	/* Length of data */
	__u32 data_len;

	/*
	 * A pointer ot an actual data for the block.
	 *
	 * Equivalent to: __u8 *data;
	 */
	__aligned_u64 data;

	/*
	 * Compression algorithm used to compress the data block.
	 * Values from enum incfs_compression_alg.
	 */
	__u32 compression;

	__u32 reserved1;

	__aligned_u64 reserved2;
};

enum incfs_instruction_type {
	INCFS_INSTRUCTION_NOOP = 0,
	INCFS_INSTRUCTION_NEW_FILE = 1,
	INCFS_INSTRUCTION_ADD_DIR_ENTRY = 3,
	INCFS_INSTRUCTION_REMOVE_DIR_ENTRY = 4,
};

/*
 * Create a new file or directory.
 * Corresponds to INCFS_INSTRUCTION_NEW_FILE
 */
struct incfs_new_file_instruction {
	/*
	 * [Out param. Populated by the kernel after ioctl.]
	 * Inode number of a newly created file.
	 */
	__aligned_u64 ino_out;

	/*
	 * Total size of the new file. Ignored if S_ISDIR(mode).
	 */
	__aligned_u64 size;

	/*
	 * File mode. Permissions and dir flag.
	 */
	__u16 mode;

	__u16 reserved1;

	__u32 reserved2;

	__aligned_u64 reserved3;

	__aligned_u64 reserved4;

	__aligned_u64 reserved5;

	__aligned_u64 reserved6;

	__aligned_u64 reserved7;
};

/*
 * Create or remove a name (aka hardlink) for a file in a directory.
 * Corresponds to
 * INCFS_INSTRUCTION_ADD_DIR_ENTRY,
 * INCFS_INSTRUCTION_REMOVE_DIR_ENTRY
 */
struct incfs_dir_entry_instruction {
	/* Inode number of a directory to add/remove a file to/from. */
	__aligned_u64 dir_ino;

	/* File to add/remove. */
	__aligned_u64 child_ino;

	/* Length of name field */
	__u32 name_len;

	__u32 reserved1;

	/*
	 * A pointer to the name characters of a file to add/remove
	 *
	 * Equivalent to: char *name;
	 */
	__aligned_u64 name;

	__aligned_u64 reserved2;

	__aligned_u64 reserved3;

	__aligned_u64 reserved4;

	__aligned_u64 reserved5;
};

/*
 * An Incremental FS instruction is the way for userspace
 * to
 *   - create files and directories
 *   - show and hide files in the directory structure
 */
struct incfs_instruction {
	/* Populate with INCFS_HEADER_VER */
	__u32 version;

	/*
	 * Type - what this instruction actually does.
	 * Values from enum incfs_instruction_type.
	 */
	__u32 type;

	union {
		struct incfs_new_file_instruction file;
		struct incfs_dir_entry_instruction dir_entry;

		/* Hard limit on the instruction body size in the future. */
		__u8 reserved[64];
	};
};

#endif /* _UAPI_LINUX_INCREMENTALFS_H */
