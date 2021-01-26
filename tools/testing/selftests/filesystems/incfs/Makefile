# SPDX-License-Identifier: GPL-2.0
CFLAGS += -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Wall
CFLAGS += -I../../../../../usr/include/
CFLAGS += -I../../../../include/uapi/
CFLAGS += -I../../../../lib

EXTRA_SOURCES := utils.c ../../../../lib/lz4.c
TEST_GEN_PROGS := incfs_test

include ../../lib.mk

$(OUTPUT)/incfs_test: incfs_test.c $(EXTRA_SOURCES)
