/*
 * QEMU S390 IPL Block
 *
 * Copyright 2015 IBM Corp.
 * Author(s): Alexander Yarygin <yarygin@linux.vnet.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at
 * your option) any later version. See the COPYING file in the top-level
 * directory.
 */

#ifndef IPLB_H
#define IPLB_H

struct IplBlockCcw {
    uint8_t  reserved0[85];
    uint8_t  ssid;
    uint16_t devno;
    uint8_t  vm_flags;
    uint8_t  reserved3[3];
    uint32_t vm_parm_len;
    uint8_t  nss_name[8];
    uint8_t  vm_parm[64];
    uint8_t  reserved4[8];
} __attribute__ ((packed));
typedef struct IplBlockCcw IplBlockCcw;

struct IplBlockFcp {
    uint8_t  reserved1[305 - 1];
    uint8_t  opt;
    uint8_t  reserved2[3];
    uint16_t reserved3;
    uint16_t devno;
    uint8_t  reserved4[4];
    uint64_t wwpn;
    uint64_t lun;
    uint32_t bootprog;
    uint8_t  reserved5[12];
    uint64_t br_lba;
    uint32_t scp_data_len;
    uint8_t  reserved6[260];
    uint8_t  scp_data[];
} __attribute__ ((packed));
typedef struct IplBlockFcp IplBlockFcp;

struct IplBlockQemuScsi {
    uint32_t lun;
    uint16_t target;
    uint16_t channel;
    uint8_t  reserved0[77];
    uint8_t  ssid;
    uint16_t devno;
} __attribute__ ((packed));
typedef struct IplBlockQemuScsi IplBlockQemuScsi;

struct IplParameterBlock {
    uint32_t len;
    uint8_t  reserved0[3];
    uint8_t  version;
    uint32_t blk0_len;
    uint8_t  pbt;
    uint8_t  flags;
    uint16_t reserved01;
    uint8_t  loadparm[8];
    union {
        IplBlockCcw ccw;
        IplBlockFcp fcp;
        IplBlockQemuScsi scsi;
    };
} __attribute__ ((packed));
typedef struct IplParameterBlock IplParameterBlock;

extern IplParameterBlock iplb __attribute__((__aligned__(PAGE_SIZE)));

#define S390_IPL_TYPE_FCP 0x00
#define S390_IPL_TYPE_CCW 0x02
#define S390_IPL_TYPE_QEMU_SCSI 0xff

static inline bool store_iplb(IplParameterBlock *iplb)
{
    register unsigned long addr asm("0") = (unsigned long) iplb;
    register unsigned long rc asm("1") = 0;

    asm volatile ("diag %0,%2,0x308\n"
                  : "+d" (addr), "+d" (rc)
                  : "d" (6)
                  : "memory", "cc");
    return rc == 0x01;
}

#endif /* IPLB_H */
