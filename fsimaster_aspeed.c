/*
 * Copyright 2020 IBM Corporation
 *
 * Eddie James <eajames@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <endian.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define FSI_MASTER_ASPEED_ADDR	0x80000000

#define OPB_TRIGGER		0x04
#define OPB0_RW			0x14
#define OPB0_XFER_SIZE		0x18
#define OPB0_FSI_ADDR		0x1c
#define OPB0_FSI_DATA_W		0x20
#define OPB_IRQ_CLEAR		0x40
#define OPB_IRQ_STATUS		0x48
#define  OPB0_XFER_ACK_EN 	 0x00010000
#define OPB0_STATUS		0x80
#define  OPB_STATUS_ERR_ACK	 0x00000004
#define OPB0_FSI_DATA_R		0x84

#define CMD_READ		0x00000001
#define CMD_WRITE		0

#define XFER_FULLWORD		0x00000003

void diff_timespec(const struct timespec *start, const struct timespec *end,
		   struct timespec *diff)
{
	if (end->tv_nsec - start->tv_nsec < 0) {
		diff->tv_sec = end->tv_sec - start->tv_sec - 1;
		diff->tv_nsec = end->tv_nsec - start->tv_nsec + 1000000000ULL;
	} else {
		diff->tv_sec = end->tv_sec - start->tv_sec;
		diff->tv_nsec = end->tv_nsec - start->tv_nsec;
	}
}

unsigned long read32(void *mem, unsigned long offs)
{
	return ((uint32_t *)mem)[offs / 4];
}

void write32(void *mem, unsigned long offs, unsigned long val)
{
	((uint32_t *)mem)[offs / 4] = val;
}

int fsi_master_aspeed_xfer_ackd(void *mem)
{
	uint32_t status;
	struct timespec df;
	struct timespec end;
	struct timespec start;

	clock_gettime(CLOCK_MONOTONIC, &start);

	do {
		status = read32(mem, OPB_IRQ_STATUS);

		clock_gettime(CLOCK_MONOTONIC, &end);
		diff_timespec(&start, &end, &df);
		if (df.tv_sec > 0)
			return -ETIMEDOUT;
	} while (!(status & OPB0_XFER_ACK_EN));

	return 0;
}

int fsi_master_aspeed_read(void *mem, unsigned long reg, unsigned long *val)
{
	int rc;
	uint32_t status;

	write32(mem, OPB0_RW, CMD_READ);
	write32(mem, OPB0_XFER_SIZE, XFER_FULLWORD);
	write32(mem, OPB0_FSI_ADDR, reg + FSI_MASTER_ASPEED_ADDR);
	write32(mem, OPB_IRQ_CLEAR, 1);
	write32(mem, OPB_TRIGGER, 1);

	rc = fsi_master_aspeed_xfer_ackd(mem);
	if (rc)
		return rc;

	status = read32(mem, OPB0_STATUS);
	if (status & OPB_STATUS_ERR_ACK)
		return -EIO;

	*val = be32toh(read32(mem, OPB0_FSI_DATA_R));

	return 0;
}

int fsi_master_aspeed_write(void *mem, unsigned long reg, unsigned long val)
{
	int rc;
	uint32_t status;

	write32(mem, OPB0_RW, CMD_WRITE);
	write32(mem, OPB0_XFER_SIZE, XFER_FULLWORD);
	write32(mem, OPB0_FSI_ADDR, reg + FSI_MASTER_ASPEED_ADDR);
	write32(mem, OPB0_FSI_DATA_W, htobe32(val));
	write32(mem, OPB_IRQ_CLEAR, 1);
	write32(mem, OPB_TRIGGER, 1);

	rc = fsi_master_aspeed_xfer_ackd(mem);
	if (rc)
		return rc;

	status = read32(mem, OPB0_STATUS);
	if (status & OPB_STATUS_ERR_ACK)
		return -EIO;

	return 0;
}

void help()
{
	printf("Usage: fsimaster-aspeed <register> (optional <value>)\n");
}

int main(int argc, char **argv)
{
	int fd;
	void *mem;
	unsigned long reg;
	unsigned long val;

	if (argc < 2) {
		help();
		return -EINVAL;
	}

	errno = 0;
	reg = strtoul(argv[1], NULL, 0);
	if (errno) {
		printf("Failed to parse register %s\n", argv[1]);
		return -EINVAL;
	}

	fd = open("/dev/mem", O_RDWR);
	if (fd < 0) {
		printf("Failed to open /dev/mem\n");
		return -ENODEV;
	}

	mem = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, fd,
		   0x1e79b000);
	if (mem == MAP_FAILED) {
		printf("Failed to mmap FSI: %d - %s\n", errno,
		       strerror(errno));
		return -ENODEV;
	}

	if (argc > 2) {
		errno = 0;
		val = strtoul(argv[2], NULL, 0);

		if (errno) {
			printf("Failed to parse value %s\n", argv[2]);
			return -EINVAL;
		}

		fsi_master_aspeed_write(mem, reg, val);
	}
	else {
		fsi_master_aspeed_read(mem, reg, &val);

		printf("0x%08x\n", val);
	}

	return 0;
}
