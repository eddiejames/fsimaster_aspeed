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

#ifdef __aarch64__
#define FSI_MASTER_BASE			0x21800000
#define FSI_CONTROL_BASE		0x21000000
#define FSI_BASE			0x20000000
#else
#define FSI_MASTER_BASE			0x1e79b000
#endif

#define FSI_MASTER_ASPEED_ADDR		0xa0000000
#define FSI_MASTER_ASPEED_CTRL_ADDR	0x80000000

#define OPB_TRIGGER		0x04
#define OPB_CTRL_BASE		0x08
#define OPB_FSI_BASE		0x0c
#define OPB0_SELECT		0x10
#define OPB0_RW			0x14
#define OPB0_XFER_SIZE		0x18
#define OPB0_FSI_ADDR		0x1c
#define OPB0_FSI_DATA_W		0x20
#define OPB1_DMA_ENABLE		0x24
#define OPB1_SELECT		0x28
#define OPB1_RW			0x2c
#define OPB1_XFER_SIZE		0x30
#define OPB1_FSI_ADDR		0x34
#define OPB1_FSI_DATA_W		0x38
#define OPB_IRQ_CLEAR		0x40
#define OPB_IRQ_MASK		0x44
#define OPB_IRQ_STATUS		0x48
#define  OPB0_XFER_ACK_EN 	 0x00010000
#define  OPB1_XFER_ACK_EN	 0x00020000
#define  OPB_DMA_IRQ_EN		 0xffff
#define OPB1_WRITE_ORDER1	0x54
#define OPB1_WRITE_ORDER2	0x58
#define OPB1_READ_ORDER		0x60
#define OPB_RETRY_COUNTER	0x64
#define OPB0_STATUS		0x80
#define  OPB_STATUS_ERR_ACK	 0x00000004
#define OPB0_FSI_DATA_R		0x84
#define OPB1_STATUS		0x8c
#define OPB1_FSI_DATA_R		0x90
#define DMA_CHAN0_ADDR		0xc4
#define DMA_CHAN0_CTRL		0xc8
#define DMA_FUNC_EN		0xe4

#define REG(x)			((x) / sizeof(uint32_t))

#define CMD_READ		0x00000001
#define CMD_WRITE		0

#define XFER_FULLWORD		0x00000003

struct reg {
	const char *name;
	uint32_t reg;
};

static const struct reg aspeed_regs[] = {
	{ "version", 0x00 },
	{ "control address", 0x08 },
	{ "fsi address", 0x0c },
	{ "opb0 bus select", 0x10 },
	{ "opb0 read/write", 0x14 },
	{ "opb0 xfer size", 0x18 },
	{ "opb0 addr", 0x1c },
	{ "opb0 write data", 0x20 },
	{ "opb1 dma enable", 0x24 },
	{ "opb1 bus select", 0x28 },
	{ "opb1 read/write", 0x2c },
	{ "opb1 xfer size", 0x30 },
	{ "opb1 addr", 0x34 },
	{ "opb1 write data", 0x38 },
	{ "clock source gate", 0x3c },
	{ "irq mask", 0x44 },
	{ "irq status", 0x48 },
	{ "opb0 write byte order1", 0x4c },
	{ "opb0 write byte order2", 0x50 },
	{ "opb1 write byte order1", 0x54 },
	{ "opb1 write byte order2", 0x58 },
	{ "opb0 read byte order", 0x5c },
	{ "opb1 read byte order", 0x60 },
	{ "opb retry counter", 0x64 },
#ifdef __aarch64__
	{ "cmdq and fsi error irq mask", 0x68 },
	{ "cmdq and fsi error irq status", 0x6c },
	{ "stop cmdq content", 0x70 },
#endif
	{ "opb0 status", 0x80 },
	{ "opb0 read data", 0x84 },
	{ "opb1 dma status", 0x88 },
	{ "opb1 status", 0x8c },
	{ "opb1 read data", 0x90 },
#ifdef __aarch64__
	{ "dma0 fsi addr", 0xb0 },
	{ "dma1 fsi addr", 0xb4 },
	{ "dma2 fsi addr", 0xb8 },
	{ "dma3 fsi addr", 0xbc },
#endif
	{ "opb1 dma debug", 0xc0 },
	{ "dma0 addr", 0xc4 },
	{ "dma0 ctrl", 0xc8 },
	{ "dma1 addr", 0xcc },
	{ "dma1 ctrl", 0xd0 },
	{ "dma2 addr", 0xd4 },
	{ "dma2 ctrl", 0xd8 },
	{ "dma3 addr", 0xdc },
	{ "dma3 ctrl", 0xe0 },
	{ "dma enable", 0xe4 },
	{ "fsi ctrl", 0xe8 }
};

static const struct reg mfsi_regs[] = {
	{ "MMODE", 0x000 },
	{ "MDLYR", 0x004 },
	{ "MCRSP0", 0x008 },
	{ "MENP0", 0x010 },
	{ "MLEVP0", 0x018 },
	{ "MREFP0", 0x020 },
	{ "MHPMP0", 0x028 },
	{ "MSIEP0", 0x030 },
	{ "MAESP0", 0x050 },
	{ "MAEB", 0x070 },
	{ "MVER", 0x074 },
	{ "MBSYP0", 0x078 },
	{ "MSTAP0", 0x0d0 },
	{ "MSTAP1", 0x0d4 },
	{ "MSTAP2", 0x0d8 },
	{ "MSTAP3", 0x0dc },
	{ "MSTAP4", 0x0e0 },
	{ "MSTAP5", 0x0e4 },
	{ "MSTAP6", 0x0e8 },
	{ "MSTAP7", 0x0ec },
	{ "MESRB0", 0x1d0 },
	{ "MSCSB0", 0x1d4 },
	{ "MATRB0", 0x1d8 },
	{ "MDTRB0", 0x1dc },
	{ "MECTRL", 0x2e0 }
};

#ifdef __aarch64__
static int dma = 0;
#endif
static int opb1 = 0;
static int verbose = 0;
static int page_size = 0;

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
	const uint32_t bit = opb1 ? OPB1_XFER_ACK_EN : OPB0_XFER_ACK_EN;
	int i = 0;

	slp.tv_sec = 0;
	slp.tv_nsec = 500000;
	timespec_get(&start, TIME_UTC);

	do {
		if (i)
			nanosleep(&slp, &rem);

		status = atomic_load(&mem[REG(OPB_IRQ_STATUS)]);

		timespec_get(&end, TIME_UTC);
		diff_timespec(&start, &end, &df);
		if (df.tv_sec > 0) {
			uint32_t opb_status = read32(mem, opb1 ? OPB1_STATUS : OPB0_STATUS);

			printf("Timed out irq status:%08x opb status:%08x [%d]\n", status, opb_status, i);
			return -ETIMEDOUT;
		}

		++i;
	} while (!(status & bit));

	vprintf("read32[%02x]:%08x\n", OPB_IRQ_STATUS, status);
	return 0;
}

int fsi_master_aspeed_read(volatile uint32_t *mem, uint32_t reg, uint32_t *val)
{
	int rc;
	uint32_t status;

	write32(mem, opb1 ? OPB1_RW : OPB0_RW, CMD_READ);
	write32(mem, opb1 ? OPB1_XFER_SIZE : OPB0_XFER_SIZE, XFER_FULLWORD);
	write32(mem, opb1 ? OPB1_FSI_ADDR : OPB0_FSI_ADDR, reg);
	write32(mem, OPB_IRQ_CLEAR, 1);

	if (opb1)
		write32(mem, DMA_FUNC_EN, 0x1);

	write32(mem, OPB_TRIGGER, 1);

	rc = fsi_master_aspeed_xfer_ackd(mem);
	if (rc)
		return rc;

	status = read32(mem, opb1 ? OPB1_STATUS : OPB0_STATUS);
	if (status & OPB_STATUS_ERR_ACK) {
		printf("OPB read error status:%08x\n", status);
		return -EIO;
	}

	*val = be32toh(read32(mem, opb1 ? OPB1_FSI_DATA_R : OPB0_FSI_DATA_R));

	return 0;
}

int fsi_master_aspeed_write(volatile uint32_t *mem, uint32_t reg, uint32_t val)
{
	int rc;
	uint32_t status;

	write32(mem, opb1 ? OPB1_RW : OPB0_RW, CMD_WRITE);
	write32(mem, opb1 ? OPB1_XFER_SIZE : OPB0_XFER_SIZE, XFER_FULLWORD);
	write32(mem, opb1 ? OPB1_FSI_ADDR : OPB0_FSI_ADDR, reg);
	write32(mem, opb1 ? OPB1_FSI_DATA_W : OPB0_FSI_DATA_W, htobe32(val));
	write32(mem, OPB_IRQ_CLEAR, 1);

	if (opb1)
		write32(mem, DMA_FUNC_EN, 0x1);

	write32(mem, OPB_TRIGGER, 1);

	rc = fsi_master_aspeed_xfer_ackd(mem);
	if (rc)
		return rc;

	status = read32(mem, opb1 ? OPB1_STATUS : OPB0_STATUS);
	if (status & OPB_STATUS_ERR_ACK) {
		printf("OPB write error status:%08x\n", status);
		return -EIO;
	}

	return 0;
}

#ifdef __aarch64__
int check_errors(volatile uint32_t *ctrl)
{
	uint32_t mesrb = read32(ctrl, 0x1d0);

	if (mesrb & 0xf0000000) {
		uint32_t mmode = read32(ctrl, 0x0);
		uint32_t mstap = read32(ctrl, 0xd0);

		printf("MESRB0[1d0]: %08x MSTAP0[0d0]: %08x\n", mesrb, mstap);

		write32(ctrl, 0, mmode & 0x5fffffff);
		write32(ctrl, 0xd0, 0x20000000);
		write32(ctrl, 0, mmode);

		return -EIO;
	}

	return 0;
}

void dma_link_enable(volatile uint32_t *ctrl, uint32_t link)
{
	uint32_t menp = read32(ctrl, 0x10);
	uint32_t bit = 0x80000000 >> link;

	if (!(menp & bit)) {
		write32(ctrl, 0x10, menp | bit);
		usleep(10000);
	}
}
#endif

int link_enable(volatile uint32_t *mem, uint32_t link)
{
	uint32_t bit = 0x80000000 >> link;
	uint32_t menp;
	int rc;

	rc = fsi_master_aspeed_read(mem, FSI_MASTER_ASPEED_CTRL_ADDR + 0x10, &menp);
	if (rc)
		return rc;

	if (!(menp & bit)) {
		rc = fsi_master_aspeed_write(mem, FSI_MASTER_ASPEED_CTRL_ADDR + 0x10, menp | bit);
		if (rc)
			return rc;

		usleep(10000);
	}

	return 0;
}

void help()
{
	printf("Usage: fsimaster-aspeed (options) <mode> <register> (optional <values>)\n");
	printf("\tModes:\n");
	printf("\t\taspeed\tread/write Aspeed FSI register space\n");
	printf("\t\tcfam\tread/write cfam address space\n");
	printf("\t\tdump\tread all registers of address space\n");
	printf("\t\tmaster\tread/write FSI master space\n");
	printf("\tOptions:\n");
#ifdef __aarch64__
	printf("\t\t-d --dma\n");
#endif
	printf("\t\t-l --link <link>\tFSI link to access\n");
	printf("\t\t-o --opb1\n");
	printf("\t\t-n --num_words <count>\tnumber of words to read/write\n");
	printf("\t\t-v --verbose\n");
}

int get_physical_address(void *addr, uint32_t *phys)
{
	uint64_t pfn;
	FILE *pm = fopen("/proc/self/pagemap", "rb");
	uint32_t offset;

	if (!pm) {
		printf("failed to open pagemap\n");
		return -1;
	}

	offset = (uint32_t)addr / page_size * 8;
	if (fseek(pm, offset, SEEK_SET)) {
		printf("failed to seek pagemap\n");
		return -1;
	}

	if (fread(&pfn, 7, 1, pm) != 1) {
		printf("failed to read pfn\n");
		return -1;
	}

	printf("PFN:%016llx vaddr:%08x\n", pfn, (uint32_t)addr);

	fclose(pm);
	pfn &= 0x7FFFFFFFFFFFFF;
	*phys = (uint32_t)((pfn << 12)) + ((uint32_t)addr % page_size);

	return 0;
}

int main(int argc, char **argv)
{
	const struct reg *regs = NULL;
	void *dma_addr = NULL;
	volatile uint32_t *mem;
#ifdef __aarch64__
	volatile uint32_t *ctrl = NULL;
	volatile uint32_t *fsi = NULL;
#endif
	uint32_t _data = 0;
	uint32_t *data = &_data;
	uint32_t imask = 0;
	uint32_t words = 1;
	uint32_t link = 0;
	uint32_t base = 0;
	uint32_t reg = 0;
	uint32_t i = 1;
	int write = 0;
	int dump = 0;
	int use_opb1 = 0;
	int fd;
	int rc;

	page_size = getpagesize();

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

	if (!strncmp(argv[i], "-o", 2) || !strncmp(argv[i], "--opb1", 6)) {
		++i;
		if (i >= argc) {
			help();
			return -EINVAL;
		}

		use_opb1 = 1;
	}

#ifdef __aarch64__
	if (!strncmp(argv[i], "-d", 2) || !strncmp(argv[i], "--dma", 5)) {
		++i;
		if (i >= argc) {
			help();
			return -EINVAL;
		}

		dma = 1;
	}
#endif

	if (!strncmp(argv[i], "-l", 2) || !strncmp(argv[i], "--link", 6)) {
		++i;
		if (i >= argc) {
			help();
			return -EINVAL;
		}

		rc = arg_to_u32(argv[i], &link);
		if (rc)
			return rc;

		++i;
		if (i >= argc) {
			help();
			return -EINVAL;
		}
	}

	if (!strncmp(argv[i], "cfam", 4)) {
		base = FSI_MASTER_ASPEED_ADDR;
	} else if (!strncmp(argv[i], "dump", 4)) {
		dump = 1;
	} else if (!strncmp(argv[i], "master", 6)) {
		base = FSI_MASTER_ASPEED_CTRL_ADDR;
	} else if (strncmp(argv[i], "aspeed", 6)) {
		help();
		return -EINVAL;
	}

	++i;
	if (i >= argc) {
		printf("No register%s specified.\n", dump ? " space" : "");
		return -EINVAL;
	}

	if (dump) {
		if (!strncmp(argv[i], "master", 6)) {
			base = FSI_MASTER_ASPEED_CTRL_ADDR;
			words = sizeof(mfsi_regs) / sizeof(mfsi_regs[0]);
			regs = mfsi_regs;
		} else if (!strncmp(argv[i], "aspeed", 5)) {
			words = sizeof(aspeed_regs) / sizeof(aspeed_regs[0]);
			regs = aspeed_regs;
		} else {
			printf("Unknown register space: %s\n", argv[i]);
			return -EINVAL;
		}
	} else {
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
	}

	fd = open("/dev/mem", O_RDWR);
	if (fd < 0) {
		printf("Failed to open /dev/mem\n");
		rc = -ENODEV;
		goto done;
	}

	mem = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, FSI_MASTER_BASE);
	if (mem == MAP_FAILED) {
		printf("Failed to mmap: %d - %s\n", errno, strerror(errno));
		rc = -ENODEV;
		goto done;
	}

#ifdef __aarch64__
	if (dma) {
		if (base) {
			ctrl = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, FSI_CONTROL_BASE);
			if (!ctrl) {
				printf("Failed to mmap FSI master: %d - %s\n", errno, strerror(errno));
				rc = -ENODEV;
				goto done;
			}

			if (base == FSI_MASTER_ASPEED_ADDR) {
				fsi = mmap(NULL, 14336, PROT_READ | PROT_WRITE, MAP_SHARED, fd, FSI_BASE + (link * 0x80000));
				if (!fsi) {
					printf("Failed to mmap FSI: %d - %s\n", errno, strerror(errno));
					rc = -ENODEV;
					goto done;
				}
			}
		}

		write32(mem, OPB_RETRY_COUNTER, 0x00100010);
		write32(mem, OPB_CTRL_BASE, FSI_CONTROL_BASE);
		write32(mem, OPB_FSI_BASE, FSI_BASE);
	}
#endif

	if (dump) {
		for (i = 0; i < words; ++i) {
			if (base == 0) {
				data[0] = atomic_load(&mem[REG(regs[i].reg)]);
			} else {
#ifdef __aarch64__
				if (dma)
					data[0] = atomic_load(&ctrl[REG(regs[i].reg)]);
				else {
#endif
				rc = fsi_master_aspeed_read(mem, base + regs[i].reg, data);
				if (rc)
					goto undo;
#ifdef __aarch64__
				}
#endif
			}

			printf("%s[%03x]: %08x\n", regs[i].name, regs[i].reg, data[0]);
		}
	} else {
		if (base == FSI_MASTER_ASPEED_ADDR) {
#ifdef __aarch64__
			if (dma)
				dma_link_enable(ctrl, link);
			else {
#endif
			rc = link_enable(mem, link);
			if (rc)
				goto undo;
#ifdef __aarch64__
			}
#endif

			if (use_opb1) {
				uint32_t phys;

				dma_addr = malloc(page_size);
				if (!dma_addr) {
					rc = -ENOMEM;
					printf("Failed to allocate a page for DMA\n");
					goto proceed;
				}

				if (mlock(dma_addr, page_size)) {
					rc = -ENOMEM;
					printf("Failed to lock DMA page\n");
					goto proceed;
				}

				if (get_physical_address(dma_addr, &phys)) {
					rc = -ENOMEM;
					goto proceed;
				}

				memset(dma_addr, 0, 4);

				opb1 = 1;

				imask = read32(mem, OPB_IRQ_MASK);

				write32(mem, OPB_IRQ_MASK, imask | OPB_DMA_IRQ_EN);
				write32(mem, OPB1_DMA_ENABLE, 0xf);
				write32(mem, DMA_CHAN0_ADDR, phys);
				write32(mem, DMA_CHAN0_CTRL, write ? 0x1 : 0x10001);

				write32(mem, OPB1_READ_ORDER, 0x00030b1b);
				write32(mem, OPB1_WRITE_ORDER1, 0x0011101b);
				write32(mem, OPB1_WRITE_ORDER2, 0x0c330f3f);
				write32(mem, OPB0_SELECT, 0);
				write32(mem, OPB1_SELECT, 1);
			}
		}

proceed:
		for (i = 0; i < words; ++i) {
			if (write) {
				if (base == 0) {
					atomic_store(&mem[REG(reg) + i], data[i]);
				} else {
#ifdef __aarch64__
					if (dma) {
						if (base == FSI_MASTER_ASPEED_ADDR) {
							atomic_store(&fsi[REG(reg) + i], data[i]);
							rc = check_errors(ctrl);
						}
						else {
							atomic_store(&ctrl[REG(reg) + i], data[i]);
							rc = 0;
						}
					}
					else
#endif
					rc = fsi_master_aspeed_write(mem, base + reg + (i * 4), data[i]);
					if (rc)
						goto undo;
				}
			} else {
				if (base == 0) {
					data[0] = atomic_load(&mem[REG(reg) + i]);
					printf("FSIM%03x: %08x\n", reg + (i * 4), data[0]);
				} else {
#ifdef __aarch64__
					if (dma) {
						if (base == FSI_MASTER_ASPEED_ADDR) {
							data[0] = atomic_load(&fsi[REG(reg) + i]);
							rc = check_errors(ctrl);
						}
						else {
							data[0] = atomic_load(&ctrl[REG(reg) + i]);
							rc = 0;
						}
					}
					else
#endif
					rc = fsi_master_aspeed_read(mem, base + reg + (i * 4), data);
					if (rc)
						goto undo;

					printf("%s%03x: %08x\n", base == FSI_MASTER_ASPEED_ADDR ? "CFAM" : "MFSI", reg + (i * 4), data[0]);
				}
			}
		}
	}

undo:
#ifdef __aarch64__
	if (dma) {
		write32(mem, OPB_RETRY_COUNTER, 0x000c0010);
		write32(mem, OPB_CTRL_BASE, FSI_MASTER_ASPEED_CTRL_ADDR);
		write32(mem, OPB_FSI_BASE, FSI_MASTER_ASPEED_ADDR);
	}
#endif
	if (opb1) {
		printf("result dma %08x\n", *(uint32_t *)dma_addr);

		write32(mem, OPB_IRQ_MASK, imask);
		write32(mem, OPB1_SELECT, 0);
		write32(mem, OPB0_SELECT, 1);
	}

done:
	if (dma_addr)
		free(dma_addr);

	if (data != &_data)
		free(data);

	return rc;
}
