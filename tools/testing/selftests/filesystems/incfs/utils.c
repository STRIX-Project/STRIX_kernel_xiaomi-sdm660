// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2018 Google LLC
 */
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <errno.h>
#include <string.h>
#include <poll.h>

#include "utils.h"

int mount_fs(char *mount_dir, int backing_fd, int read_timeout_ms)
{
	static const char fs_name[] = INCFS_NAME;
	char mount_options[512];
	int result;

	snprintf(mount_options, ARRAY_SIZE(mount_options),
		 "backing_fd=%u,read_timeout_ms=%u",
		 backing_fd, read_timeout_ms);

	result = mount(fs_name, mount_dir, fs_name, 0, mount_options);
	if (result != 0)
		perror("Error mounting fs.");
	return result;
}

int unlink_node(int fd, int parent_ino, char *filename)
{
	struct incfs_instruction inst = {
			.type = INCFS_INSTRUCTION_REMOVE_DIR_ENTRY,
			.dir_entry = {
				.dir_ino = parent_ino,
				.name = ptr_to_u64(filename),
				.name_len = strlen(filename)
			}
	};

	return send_md_instruction(fd, &inst);
}

int emit_node(int fd, char *filename, int *ino_out, int parent_ino,
		size_t size, mode_t mode)
{
	int ret = 0;
	__u64 ino = 0;
	struct incfs_instruction inst = {
			.type = INCFS_INSTRUCTION_NEW_FILE,
			.file = {
				.size = size,
				.mode = mode,
			}
	};

	ret = send_md_instruction(fd, &inst);
	if (ret)
		return ret;

	ino = inst.file.ino_out;
	inst = (struct incfs_instruction){
			.type = INCFS_INSTRUCTION_ADD_DIR_ENTRY,
			.dir_entry = {
				.dir_ino = parent_ino,
				.child_ino = ino,
				.name = ptr_to_u64(filename),
				.name_len = strlen(filename)
			}
		};
	ret = send_md_instruction(fd, &inst);
	if (ret)
		return ret;
	*ino_out = ino;
	return 0;
}


int emit_dir(int fd, char *filename, int *ino_out, int parent_ino)
{
	return emit_node(fd, filename, ino_out, parent_ino, 0, S_IFDIR | 0555);
}

int emit_file(int fd, char *filename, int *ino_out, int parent_ino, size_t size)
{
	return emit_node(fd, filename, ino_out, parent_ino, size,
				S_IFREG | 0555);
}

int send_md_instruction(int cmd_fd, struct incfs_instruction *inst)
{
	inst->version = INCFS_HEADER_VER;
	if (ioctl(cmd_fd, INCFS_IOC_PROCESS_INSTRUCTION, inst) == 0)
		return 0;
	return -errno;
}

loff_t get_file_size(char *name)
{
	struct stat st;

	if (stat(name, &st) == 0)
		return st.st_size;
	return -ENOENT;
}

int open_commands_file(char *mount_dir)
{
	char cmd_file[255];
	int cmd_fd;

	snprintf(cmd_file, ARRAY_SIZE(cmd_file), "%s/.cmd", mount_dir);
	cmd_fd = open(cmd_file, O_RDWR);
	if (cmd_fd < 0)
		perror("Can't open commands file");
	return cmd_fd;
}

int wait_for_pending_reads(int fd, int timeout_ms,
	struct incfs_pending_read_info *prs, int prs_count)
{
	ssize_t read_res = 0;

	if (timeout_ms > 0) {
		int poll_res = 0;
		struct pollfd pollfd = {
			.fd = fd,
			.events = POLLIN
		};

		poll_res = poll(&pollfd, 1, timeout_ms);
		if (poll_res < 0)
			return -errno;
		if (poll_res == 0)
			return 0;
		if (!(pollfd.revents | POLLIN))
			return 0;
	}

	read_res = read(fd, prs, prs_count * sizeof(*prs));
	if (read_res < 0)
		return -errno;

	return read_res / sizeof(*prs);
}

char *concat_file_name(char *dir, char *file)
{
	char full_name[FILENAME_MAX] = "";

	if (snprintf(full_name, ARRAY_SIZE(full_name), "%s/%s", dir, file) < 0)
		return NULL;
	return strdup(full_name);
}
