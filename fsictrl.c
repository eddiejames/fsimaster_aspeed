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

#include "fsi.h"

static int _verbose = 0;

#define REG(x)			((x) / sizeof(uint32_t))

#define vprintf( ...)		\
({					\
	if (_verbose)		\
		printf(__VA_ARGS__);	\
})

enum spaces {
	SPACE_AHB2OPB,
	SPACE_CTRL,
	SPACE_CFAM,
	SPACE_COUNT,
};

static const char *space_names[SPACE_COUNT] = {
	"AHB2OPB",
	"CTRL",
	"CFAM",
};

struct space {
	int (*read32)(struct space *, uint32_t, uint32_t *);
	int (*write32)(struct space *, uint32_t, uint32_t);
	volatile uint32_t *map;
	enum spaces s;
};

#define space_to_fsictrl(s) container_of(s, struct fsictrl, spaces[s->s])

struct reg {
	const char *name;
	uint32_t reg;
};

static const struct reg ahb2opb_regs[] = {
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

static const struct reg cfam_regs[] = {
	{ "SMODE", 0x000 },
	{ "SDMA", 0x004 },
	{ "SISC", 0x008 },
	{ "SISM", 0x00c },
	{ "SISS", 0x010 },
	{ "SSTAT", 0x014 },
	{ "SI1M", 0x018 },
	{ "SI1S", 0x01c },
	{ "SIC", 0x020 },
	{ "SI2M", 0x024 },
	{ "SI2S", 0x028 },
	{ "SCMDT", 0x02c },
	{ "SDATA", 0x030 },
	{ "SLASTD", 0x034 },
	{ "SMBL" 0x038 },
	{ "SOML", 0x03c },
	{ "SNML", 0x040 },
	{ "SMBR", 0x044 },
	{ "SOMR", 0x048 },
	{ "SNMR", 0x04c },
};

static const struct reg ctrl_regs[] = {
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

struct fsictrl {
	struct reg *regs;
	struct space spaces[SPACE_COUNT];
	uint32_t num_words;
	enum spaces target;
	unsigned int link : 8;
	unsigned int dump : 1;
	unsigned int irq : 1;
	unsigned int write : 1;
};

static int read32_map(struct space *spc, uint32_t addr, uint32_t *val)
{
	*val = atomic_load(&spc->map[REG(addr)]);
	vprintf("%s[%03x]:%08x\n", space_names[spc->s], addr, *val);
	return 0;
}

static int write32_map(struct space *spc, uint32_t addr, uint32_t val)
{
	vprintf("%s[%03x]:%08x\n", space_names[spc->s], addr, val);
	atomic_store(&spc->map[REG(addr)], val);
	return 0;
}

static int opb_xfer_ackd(struct fsictrl *fsi)
{
	struct space *ahb2opb = &fsi->spaces[SPACE_AHB2OPB];
	volatile uint32_t *map = ahb2opb->map;
	struct timespec df;
	struct timespec end;
	struct timespec rem;
	struct timespec slp;
	struct timespec start;
	uint32_t status;
	int rc = 0;
	int i = 0;

	slp.tv_sec = 0;
	slp.tv_nsec = 500000;
	timespec_get(&start, TIME_UTC);

	do {
		if (i)
			nanosleep(&slp, &rem);

		status = atomic_load(&map[REG(OPB_IRQ_STATUS)]);

		timespec_get(&end, TIME_UTC);
		diff_timespec(&start, &end, &df);
		if (df.tv_sec > 0) {
			uint32_t opb_status = atomic_load(&map[REG(OPB0_STATUS)]);

			printf("OPB timed out irq_status:%08x opb_status:%08x [%d]\n", status,
			       opb_status, i);
			rc = -ETIMEDOUT;
			goto done;
		}

		++i;
	} while (!(status & OPB0_XFER_ACK_EN));

	vprintf("%s[%03x]:%08x\n", spaces[SPACE_AHB2OPB], OPB_IRQ_STATUS, status);
done:
	if (fsi->irq)
		ahb2opb->write32(ahb2opb, OPB_IRQ_STATUS, OPB0_XFER_ACK_EN);
	return rc;
}

static int read32_opb(struct space *spc, uint32_t addr, uint32_t *val)
{
	struct fsictrl *fsi = space_to_fsictrl(spc);
	struct space *ahb2opb = &fsi->spaces[SPACE_AHB2OPB];
	uint32_t status;
	uint32_t data;
	int rc;

	if (fsi->target == SPACE_CTRL)
		addr += OPB_CTRL_BASE_DEFAULT;
	else if (fsi->target == SPACE_CFAM)
		addr += OPB_FSI_BASE_DEFAULT;
	else
		return -EINVAL;

	ahb2opb->write32(ahb2opb, OPB0_RW, CMD_READ);
	ahb2opb->write32(ahb2opb, OPB0_XFER_SIZE, XFER_FULLWORD);
	ahb2opb->write32(ahb2opb, OPB0_FSI_ADDR, addr);
	if (fsi->irq)
		ahb2opb->write32(ahb2opb, OPB_IRQ_STATUS, 0);
	else
		ahb2opb->write32(ahb2opb, OPB_IRQ_CLEAR, 1);
	ahb2opb->write32(ahb2opb, OPB_TRIGGER, 1);

	rc = opb_xfer_ackd(fsi);
	if (rc)
		return rc;

	status = atomic_load(&ahb2opb->map[REG(OPB0_STATUS)]);
	if (status & OPB_STATUS_ERR_ACK) {
		printf("OPB read error status:%08x\n", status);
		return -EIO;
	}

	vprintf("%s[%03x]:%08x\n", space_names[SPACE_AHB2OPB], OPB0_STATUS, status);

	ahb2opb->read32(ahb2opb, OPB0_FSI_DATA_R, &data);
	*val = be32toh(data);
	return 0;
}

static int write32_opb(struct space *spc, uint32_t addr, uint32_t val)
{
	struct fsictrl *fsi = space_to_fsictrl(spc);
	struct space *ahb2opb = &fsi->spaces[SPACE_AHB2OPB];
	uint32_t status;
	int rc;

	if (fsi->target == SPACE_CTRL)
		addr += OPB_CTRL_BASE_DEFAULT;
	else if (fsi->target == SPACE_CFAM)
		addr += OPB_FSI_BASE_DEFAULT;
	else
		return -EINVAL;

	ahb2opb->write32(ahb2opb, OPB0_RW, CMD_WRITE);
	ahb2opb->write32(ahb2opb, OPB0_XFER_SIZE, XFER_FULLWORD);
	ahb2opb->write32(ahb2opb, OPB0_FSI_ADDR, addr);
	ahb2opb->write32(ahb2opb, OPB0_FSI_DATA_W, htobe32(val));
	if (irq_enabled)
		ahb2opb->write32(ahb2opb, OPB_IRQ_STATUS, 0);
	else
		ahb2opb->write32(ahb2opb, OPB_IRQ_CLEAR, 1);
	ahb2opb->write32(ahb2opb, OPB_TRIGGER, 1);

	rc = opb_xfer_ackd(fsi);
	if (rc)
		return rc;

	status = atomic_load(&ahb2opb->map[REG(OPB0_STATUS)]);
	if (status & OPB_STATUS_ERR_ACK) {
		printf("OPB write error status:%08x\n", status);
		return -EIO;
	}

	vprintf("%s[%03x]:%08x\n", space_names[SPACE_AHB2OPB], OPB0_STATUS, status);
	return 0;
}

static int arg_to_u32(char *arg, uint32_t *val)
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

static int help()
{

	return -EINVAL;
}

static int parse_arguments(int argc, char **argv, struct fsictrl *fsi)
{
	int i = 1;

	if (argc < 2)
		return help();

	if (!strncmp(argv[i], "-h", 2) || !strncmp(argv[i], "--help", 6)) {
		help();
		return 0;
	}

	if (!strncmp(argv[i], "-v", 2) || !strncmp(argv[i], "--verbose", 9)) {
		++i;
		if (i >= argc)
			return help();

		_verbose = 1;
	}

	if (!strncmp(argv[i], "-n", 2) || !strncmp(argv[i], "--num_words", 11)) {
		++i;
		if (i >= argc)
			return help();

		rc = arg_to_u32(argv[i], &fsi->num_words);
		if (rc)
			return rc;

		if (!fsi->num_words) {
			printf("Zero words specified.\n");
			return -EINVAL;
		}

		++i;
		if (i >= argc)
			return help();
	}

	if (!strncmp(argv[i], "-l", 2) || !strncmp(argv[i], "--link", 6)) {
		uint32_t link = 0;

		++i;
		if (i >= argc)
			return help();

		rc = arg_to_u32(argv[i], &link);
		if (rc)
			return rc;

		if (link >= 64) {
			printf("Bad link %u specified.\n", link);
			return -EINVAL;
		}

		fsi->link = link;

		++i;
		if (i >= argc)
			return help();
	}

	if (!strncmp(argv[i], "cfam", 4))
		fsi->target = SPACE_CFAM;
	else if (!strncmp(argv[i], "dump", 4))
		fsi->dump = 1;
	else if (!strncmp(argv[i], "ctrl", 4))
		fsi->target = SPACE_CTRL;
	else if (strncmp(argv[i], "ahb2opb", 7))
		return help();

	++i;
	if (i >= argc) {
		printf("No register space specified.\n");
		return -EINVAL;
	}

	if (fsi->dump) {
		if (!strncmp(argv[i], "cfam", 4)) {
			fsi->target = SPACE_CFAM;
			fsi->num_words = sizeof(cfam_regs) / sizeof(cfam_regs[0]);
			fsi->regs = cfam_regs;
		} else if (!strncmp(argv[i], "ctrl", 4)) {
			fsi->target = SPACE_CTRL;
			fsi->num_words = sizeof(ctrl_regs) / sizeof(ctrl_regs[0]);
			fsi->regs = ctrl_regs;
		} else if (!strncmp(argv[i], "ahb2opb", 7)) {
			fsi->target = SPACE_AHB2OPB;
			fsi->num_words = sizeof(ahb2opb_regs) / sizeof(ahb2opb_regs[0]);
			fsi->regs = ahb2opb_regs;
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

			fsi->write = 1;
		}
	}
}

int main(int argc, char **argv)
{
	struct fsictrl fsi;
	int fd;

	memset(&fsi, 0, sizeof(fsi));
	fsi->num_words = 1;
	fsi->target = SPACE_AHB2OPB;
	fsi->link = 0;

	fd = open("/dev/mem", O_RDWR);
	if (fd < 0) {
		printf("Failed to open /dev/mem\n");
		return -ENODEV;
	}

	fsi.spaces[SPACE_AHB2OPB].read32 = read32_map;
	fsi.spaces[SPACE_AHB2OPB].write32 = write32_map;
	fsi.spaces[SPACE_AHB2OPB].map = mmap(NULL, 0x100, PROT_READ | PROT_WRITE, MAP_SHARED, fd, FSI_MASTER_BASE);
	if (fsi.spaces[SPACE_AHB2OPB].map == MAP_FAILED) {
		printf("Failed to mmap: %d - %s\n", errno, strerror(errno));
		return -ENODEV;
	}
}
