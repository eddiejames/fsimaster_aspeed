#ifndef _FSI_H_
#define _FSI_H_

#define OPB_TRIGGER		0x04
#define OPB_CTRL_BASE		0x08
#define  OPB_CTRL_BASE_DEFAULT	 0x80000000
#define OPB_FSI_BASE		0x0c
#define  OPB_FSI_BASE_DEFAULT	 0xa0000000
#define OPB0_SELECT		0x10
#define OPB0_RW			0x14
#define  CMD_READ		 1
#define  CMD_WRITE		 0
#define OPB0_XFER_SIZE		0x18
#define  XFER_FULLWORD		 3
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

#endif /* _FSI_H_ */
