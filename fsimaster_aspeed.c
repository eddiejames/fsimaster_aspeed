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

#define _DEFAULT_SOURCE 1

#include <endian.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
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

#define FSI_MASTER_ASPEED_ADDR		0xa0000000
#define FSI_MASTER_ASPEED_CTRL_ADDR	0x80000000

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

#define REG(x)			((x) / sizeof(uint32_t))

#define CMD_READ		0x00000001
#define CMD_WRITE		0

#define XFER_FULLWORD		0x00000003

static int verbose = 0;

#define vprintf(...)			\
({					\
	if (verbose)			\
		printf(__VA_ARGS__);	\
})

int arg_to_u32(char *arg, uint32_t *val)
{
	uint32_t tval;

	errno = 0;
	tval = strtoul(arg, NULL, 0);
	if (errno) {
		printf("couldn't parse arg %s\n", arg);
		return -EINVAL;
	}

	*val = tval;
	return 0;
}

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

uint32_t read32(volatile uint32_t *mem, uint32_t offs)
{
	uint32_t val = atomic_load(&mem[REG(offs)]);

	vprintf("read32[%02x]:%08x\n", offs, val);
	return val;
}

void write32(volatile uint32_t *mem, uint32_t offs, uint32_t val)
{
	vprintf("write32[%02x]:%08x\n", offs, val);
	atomic_store(&mem[REG(offs)], val);
}

int fsi_master_aspeed_xfer_ackd(volatile uint32_t *mem)
{
	struct timespec df;
	struct timespec end;
	struct timespec rem;
	struct timespec slp;
	struct timespec start;
	uint32_t status;
	int i = 0;

	slp.tv_sec = 0;
	slp.tv_nsec = 500000;
	timespec_get(&start, TIME_UTC);

	do {
		if (i)
			nanosleep(&slp, &rem);

		status = read32(mem, OPB_IRQ_STATUS);

		timespec_get(&end, TIME_UTC);
		diff_timespec(&start, &end, &df);
		if (df.tv_sec > 0) {
			printf("Timed out status:%08x [%d]\n", status, i);
			return -ETIMEDOUT;
		}

		++i;
	} while (!(status & OPB0_XFER_ACK_EN));

	return 0;
}

int fsi_master_aspeed_read(volatile uint32_t *mem, uint32_t reg, uint32_t *val)
{
	int rc;
	uint32_t status;

	write32(mem, OPB0_RW, CMD_READ);
	write32(mem, OPB0_XFER_SIZE, XFER_FULLWORD);
	write32(mem, OPB0_FSI_ADDR, reg);
	write32(mem, OPB_IRQ_CLEAR, 1);
	write32(mem, OPB_TRIGGER, 1);

	rc = fsi_master_aspeed_xfer_ackd(mem);
	if (rc)
		return rc;

	status = read32(mem, OPB0_STATUS);
	if (status & OPB_STATUS_ERR_ACK) {
		printf("OPB read error status:%08x\n", status);
		return -EIO;
	}

	*val = be32toh(read32(mem, OPB0_FSI_DATA_R));

	return 0;
}

int fsi_master_aspeed_write(volatile uint32_t *mem, uint32_t reg, uint32_t val)
{
	int rc;
	uint32_t status;

	write32(mem, OPB0_RW, CMD_WRITE);
	write32(mem, OPB0_XFER_SIZE, XFER_FULLWORD);
	write32(mem, OPB0_FSI_ADDR, reg);
	write32(mem, OPB0_FSI_DATA_W, htobe32(val));
	write32(mem, OPB_IRQ_CLEAR, 1);
	write32(mem, OPB_TRIGGER, 1);

	rc = fsi_master_aspeed_xfer_ackd(mem);
	if (rc)
		return rc;

	status = read32(mem, OPB0_STATUS);
	if (status & OPB_STATUS_ERR_ACK) {
		printf("OPB write error status:%08x\n", status);
		return -EIO;
	}

	return 0;
}

void help()
{
	printf("Usage: fsimaster-aspeed (options) <mode> <register> (optional <values>)\n");
	printf("\tModes:\n");
	printf("\t\taspeed\tread/write Aspeed FSI register space\n");
	printf("\t\tcfam\tread/write cfam address space\n");
	printf("\t\tmaster\tread/write FSI master space\n");
	printf("\tOptions:\n");
	printf("\t\t-n --num_words <count>\tnumber of words to read/write\n");
	printf("\t\t-v --verbose\n");
}

int main(int argc, char **argv)
{
	volatile uint32_t *mem;
	uint32_t _data = 0;
	uint32_t *data = &_data;
	uint32_t words = 1;
	uint32_t base = 0;
	uint32_t reg = 0;
	uint32_t i = 1;
	int write = 0;
	int fd;
	int rc;

	if (argc < 2) {
		help();
		return -EINVAL;
	}

	if (!strncmp(argv[i], "-h", 2) || !strncmp(argv[i], "--help", 6)) {
		help();
		return 0;
	}

	if (!strncmp(argv[i], "-v", 2) || !strncmp(argv[i], "--verbose", 9)) {
		++i;
		if (i >= argc) {
			help();
			return -EINVAL;
		}

		verbose = 1;
	}

	if (!strncmp(argv[i], "-n", 2) || !strncmp(argv[i], "--num_words", 11)) {
		++i;
		if (i >= argc) {
			help();
			return -EINVAL;
		}

		rc = arg_to_u32(argv[i], &words);
		if (rc)
			return rc;

		if (!words) {
			printf("No words specified.\n");
			return -EINVAL;
		}

		++i;
		if (i >= argc) {
			help();
			return -EINVAL;
		}
	}

	if (!strncmp(argv[i], "cfam", 4)) {
		base = FSI_MASTER_ASPEED_ADDR;
	} else if (!strncmp(argv[i], "master", 6)) {
		base = FSI_MASTER_ASPEED_CTRL_ADDR;
	} else if (strncmp(argv[i], "aspeed", 6)) {
		help();
		return -EINVAL;
	}

	++i;
	if (i >= argc) {
		printf("No register specified.\n");
		return -EINVAL;
	}
	rc = arg_to_u32(argv[i], &reg);
	if (rc)
		return rc;

	++i;
	if (i < argc) {
		uint32_t j;

		if (words > 1) {
			data = malloc(words * sizeof(uint32_t));
			if (!data)
				return -ENOMEM;

			memset(data, 0, words * sizeof(uint32_t));
		}

		for (j = 0; j < words && i < argc; ++j) {
			rc = arg_to_u32(argv[i++], &data[j]);
			if (rc)
				goto done;

			vprintf("data[%u]:%08x\n", j, data[j]);
		}

		write = 1;
	}

	fd = open("/dev/mem", O_RDWR);
	if (fd < 0) {
		printf("Failed to open /dev/mem\n");
		rc = -ENODEV;
		goto done;
	}

	mem = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0x1e79b000);
	if (mem == MAP_FAILED) {
		printf("Failed to mmap: %d - %s\n", errno, strerror(errno));
		rc = -ENODEV;
		goto done;
	}

	if (base == 0)
		reg /= 4;

	for (i = 0; i < words; ++i) {
		if (write) {
			if (base == 0) {
				atomic_store(&mem[reg + i], data[i]);
			} else {
				rc = fsi_master_aspeed_write(mem, base + reg + (i * 4), data[i]);
				if (rc)
					goto done;
			}
		} else {
			if (base == 0) {
				data[0] = atomic_load(&mem[reg + i]);
				printf("FSIM%02x: %08x\n", reg + i, data[0]);
			} else {
				rc = fsi_master_aspeed_read(mem, base + reg + (i * 4), &data[0]);
				if (rc)
					goto done;

				printf("%s%02x: %08x\n", base == FSI_MASTER_ASPEED_ADDR ? "CFAM" : "MFSI", reg + (i * 4), data[0]);
			}
		}
	}

done:
	if (data != &_data)
		free(data);

	return rc;
}
