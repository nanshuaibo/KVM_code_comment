/*
 * s390 PCI BUS definitions
 *
 * Copyright 2014 IBM Corp.
 * Author(s): Frank Blaschka <frank.blaschka@de.ibm.com>
 *            Hong Bo Li <lihbbj@cn.ibm.com>
 *            Yi Min Zhao <zyimin@cn.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at
 * your option) any later version. See the COPYING file in the top-level
 * directory.
 */

#ifndef HW_S390_PCI_BUS_H
#define HW_S390_PCI_BUS_H

#include "hw/pci/pci.h"
#include "hw/pci/pci_host.h"
#include "hw/s390x/sclp.h"
#include "hw/s390x/s390_flic.h"
#include "hw/s390x/css.h"

#define TYPE_S390_PCI_HOST_BRIDGE "s390-pcihost"
#define TYPE_S390_PCI_BUS "s390-pcibus"
#define TYPE_S390_PCI_DEVICE "zpci"
#define FH_MASK_ENABLE   0x80000000
#define FH_MASK_INSTANCE 0x7f000000
#define FH_MASK_SHM      0x00ff0000
#define FH_MASK_INDEX    0x0000001f
#define FH_SHM_VFIO      0x00010000
#define FH_SHM_EMUL      0x00020000
#define S390_PCIPT_ADAPTER 2
#define ZPCI_MAX_FID 0xffffffff
#define ZPCI_MAX_UID 0xffff
#define UID_UNDEFINED 0
#define UID_CHECKING_ENABLED 0x01
#define HOT_UNPLUG_TIMEOUT (NANOSECONDS_PER_SECOND * 60 * 5)

#define S390_PCI_HOST_BRIDGE(obj) \
    OBJECT_CHECK(S390pciState, (obj), TYPE_S390_PCI_HOST_BRIDGE)
#define S390_PCI_BUS(obj) \
    OBJECT_CHECK(S390PCIBus, (obj), TYPE_S390_PCI_BUS)
#define S390_PCI_DEVICE(obj) \
    OBJECT_CHECK(S390PCIBusDevice, (obj), TYPE_S390_PCI_DEVICE)

#define HP_EVENT_TO_CONFIGURED        0x0301
#define HP_EVENT_RESERVED_TO_STANDBY  0x0302
#define HP_EVENT_DECONFIGURE_REQUEST  0x0303
#define HP_EVENT_CONFIGURED_TO_STBRES 0x0304
#define HP_EVENT_STANDBY_TO_RESERVED  0x0308

#define ERR_EVENT_INVALAS 0x1
#define ERR_EVENT_OORANGE 0x2
#define ERR_EVENT_INVALTF 0x3
#define ERR_EVENT_TPROTE  0x4
#define ERR_EVENT_APROTE  0x5
#define ERR_EVENT_KEYE    0x6
#define ERR_EVENT_INVALTE 0x7
#define ERR_EVENT_INVALTL 0x8
#define ERR_EVENT_TT      0x9
#define ERR_EVENT_INVALMS 0xa
#define ERR_EVENT_SERR    0xb
#define ERR_EVENT_NOMSI   0x10
#define ERR_EVENT_INVALBV 0x11
#define ERR_EVENT_AIBV    0x12
#define ERR_EVENT_AIRERR  0x13
#define ERR_EVENT_FMBA    0x2a
#define ERR_EVENT_FMBUP   0x2b
#define ERR_EVENT_FMBPRO  0x2c
#define ERR_EVENT_CCONF   0x30
#define ERR_EVENT_SERVAC  0x3a
#define ERR_EVENT_PERMERR 0x3b

#define ERR_EVENT_Q_BIT 0x2
#define ERR_EVENT_MVN_OFFSET 16

#define ZPCI_MSI_VEC_BITS 11
#define ZPCI_MSI_VEC_MASK 0x7ff

#define ZPCI_MSI_ADDR  0xfe00000000000000ULL
#define ZPCI_SDMA_ADDR 0x100000000ULL
#define ZPCI_EDMA_ADDR 0x1ffffffffffffffULL

#define PAGE_SHIFT      12
#define PAGE_SIZE       (1 << PAGE_SHIFT)
#define PAGE_MASK       (~(PAGE_SIZE-1))
#define PAGE_DEFAULT_ACC        0
#define PAGE_DEFAULT_KEY        (PAGE_DEFAULT_ACC << 4)

/* I/O Translation Anchor (IOTA) */
enum ZpciIoatDtype {
    ZPCI_IOTA_STO = 0,
    ZPCI_IOTA_RTTO = 1,
    ZPCI_IOTA_RSTO = 2,
    ZPCI_IOTA_RFTO = 3,
    ZPCI_IOTA_PFAA = 4,
    ZPCI_IOTA_IOPFAA = 5,
    ZPCI_IOTA_IOPTO = 7
};

#define ZPCI_IOTA_IOT_ENABLED           0x800ULL
#define ZPCI_IOTA_DT_ST                 (ZPCI_IOTA_STO  << 2)
#define ZPCI_IOTA_DT_RT                 (ZPCI_IOTA_RTTO << 2)
#define ZPCI_IOTA_DT_RS                 (ZPCI_IOTA_RSTO << 2)
#define ZPCI_IOTA_DT_RF                 (ZPCI_IOTA_RFTO << 2)
#define ZPCI_IOTA_DT_PF                 (ZPCI_IOTA_PFAA << 2)
#define ZPCI_IOTA_FS_4K                 0
#define ZPCI_IOTA_FS_1M                 1
#define ZPCI_IOTA_FS_2G                 2
#define ZPCI_KEY                        (PAGE_DEFAULT_KEY << 5)

#define ZPCI_IOTA_STO_FLAG  (ZPCI_IOTA_IOT_ENABLED | ZPCI_KEY | ZPCI_IOTA_DT_ST)
#define ZPCI_IOTA_RTTO_FLAG (ZPCI_IOTA_IOT_ENABLED | ZPCI_KEY | ZPCI_IOTA_DT_RT)
#define ZPCI_IOTA_RSTO_FLAG (ZPCI_IOTA_IOT_ENABLED | ZPCI_KEY | ZPCI_IOTA_DT_RS)
#define ZPCI_IOTA_RFTO_FLAG (ZPCI_IOTA_IOT_ENABLED | ZPCI_KEY | ZPCI_IOTA_DT_RF)
#define ZPCI_IOTA_RFAA_FLAG (ZPCI_IOTA_IOT_ENABLED | ZPCI_KEY |\
                             ZPCI_IOTA_DT_PF | ZPCI_IOTA_FS_2G)

/* I/O Region and segment tables */
#define ZPCI_INDEX_MASK         0x7ffULL

#define ZPCI_TABLE_TYPE_MASK    0xc
#define ZPCI_TABLE_TYPE_RFX     0xc
#define ZPCI_TABLE_TYPE_RSX     0x8
#define ZPCI_TABLE_TYPE_RTX     0x4
#define ZPCI_TABLE_TYPE_SX      0x0

#define ZPCI_TABLE_LEN_RFX      0x3
#define ZPCI_TABLE_LEN_RSX      0x3
#define ZPCI_TABLE_LEN_RTX      0x3

#define ZPCI_TABLE_OFFSET_MASK  0xc0
#define ZPCI_TABLE_SIZE         0x4000
#define ZPCI_TABLE_ALIGN        ZPCI_TABLE_SIZE
#define ZPCI_TABLE_ENTRY_SIZE   (sizeof(unsigned long))
#define ZPCI_TABLE_ENTRIES      (ZPCI_TABLE_SIZE / ZPCI_TABLE_ENTRY_SIZE)

#define ZPCI_TABLE_BITS         11
#define ZPCI_PT_BITS            8
#define ZPCI_ST_SHIFT           (ZPCI_PT_BITS + PAGE_SHIFT)
#define ZPCI_RT_SHIFT           (ZPCI_ST_SHIFT + ZPCI_TABLE_BITS)

#define ZPCI_RTE_FLAG_MASK      0x3fffULL
#define ZPCI_RTE_ADDR_MASK      (~ZPCI_RTE_FLAG_MASK)
#define ZPCI_STE_FLAG_MASK      0x7ffULL
#define ZPCI_STE_ADDR_MASK      (~ZPCI_STE_FLAG_MASK)

/* I/O Page tables */
#define ZPCI_PTE_VALID_MASK             0x400
#define ZPCI_PTE_INVALID                0x400
#define ZPCI_PTE_VALID                  0x000
#define ZPCI_PT_SIZE                    0x800
#define ZPCI_PT_ALIGN                   ZPCI_PT_SIZE
#define ZPCI_PT_ENTRIES                 (ZPCI_PT_SIZE / ZPCI_TABLE_ENTRY_SIZE)
#define ZPCI_PT_MASK                    (ZPCI_PT_ENTRIES - 1)

#define ZPCI_PTE_FLAG_MASK              0xfffULL
#define ZPCI_PTE_ADDR_MASK              (~ZPCI_PTE_FLAG_MASK)

/* Shared bits */
#define ZPCI_TABLE_VALID                0x00
#define ZPCI_TABLE_INVALID              0x20
#define ZPCI_TABLE_PROTECTED            0x200
#define ZPCI_TABLE_UNPROTECTED          0x000

#define ZPCI_TABLE_VALID_MASK           0x20
#define ZPCI_TABLE_PROT_MASK            0x200

/* PCI Function States
 *
 * reserved: default; device has just been plugged or is in progress of being
 *           unplugged
 * standby: device is present but not configured; transition from any
 *          configured state/to this state via sclp configure/deconfigure
 *
 * The following states make up the "configured" meta-state:
 * disabled: device is configured but not enabled; transition between this
 *           state and enabled via clp enable/disable
 * enbaled: device is ready for use; transition to disabled via clp disable;
 *          may enter an error state
 * blocked: ignore all DMA and interrupts; transition back to enabled or from
 *          error state via mpcifc
 * error: an error occured; transition back to enabled via mpcifc
 * permanent error: an unrecoverable error occured; transition to standby via
 *                  sclp deconfigure
 */
typedef enum {
    ZPCI_FS_RESERVED,
    ZPCI_FS_STANDBY,
    ZPCI_FS_DISABLED,
    ZPCI_FS_ENABLED,
    ZPCI_FS_BLOCKED,
    ZPCI_FS_ERROR,
    ZPCI_FS_PERMANENT_ERROR,
} ZpciState;

typedef struct SeiContainer {
    QTAILQ_ENTRY(SeiContainer) link;
    uint32_t fid;
    uint32_t fh;
    uint8_t cc;
    uint16_t pec;
    uint64_t faddr;
    uint32_t e;
} SeiContainer;

typedef struct PciCcdfErr {
    uint32_t reserved1;
    uint32_t fh;
    uint32_t fid;
    uint32_t e;
    uint64_t faddr;
    uint32_t reserved3;
    uint16_t reserved4;
    uint16_t pec;
} QEMU_PACKED PciCcdfErr;

typedef struct PciCcdfAvail {
    uint32_t reserved1;
    uint32_t fh;
    uint32_t fid;
    uint32_t reserved2;
    uint32_t reserved3;
    uint32_t reserved4;
    uint32_t reserved5;
    uint16_t reserved6;
    uint16_t pec;
} QEMU_PACKED PciCcdfAvail;

typedef struct ChscSeiNt2Res {
    uint16_t length;
    uint16_t code;
    uint16_t reserved1;
    uint8_t reserved2;
    uint8_t nt;
    uint8_t flags;
    uint8_t reserved3;
    uint8_t reserved4;
    uint8_t cc;
    uint32_t reserved5[13];
    uint8_t ccdf[4016];
} QEMU_PACKED ChscSeiNt2Res;

typedef struct PciCfgSccb {
    SCCBHeader header;
    uint8_t atype;
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t aid;
} QEMU_PACKED PciCfgSccb;

typedef struct S390MsixInfo {
    bool available;
    uint8_t table_bar;
    uint8_t pba_bar;
    uint16_t entries;
    uint32_t table_offset;
    uint32_t pba_offset;
} S390MsixInfo;

typedef struct S390PCIIOMMU {
    AddressSpace as;
    MemoryRegion mr;
} S390PCIIOMMU;

typedef struct S390PCIBusDevice {
    DeviceState qdev;
    PCIDevice *pdev;
    ZpciState state;
    bool iommu_enabled;
    char *target;
    uint16_t uid;
    uint32_t fh;
    uint32_t fid;
    bool fid_defined;
    uint64_t g_iota;
    uint64_t pba;
    uint64_t pal;
    uint64_t fmb_addr;
    uint8_t isc;
    uint16_t noi;
    uint8_t sum;
    S390MsixInfo msix;
    AdapterRoutes routes;
    S390PCIIOMMU *iommu;
    MemoryRegion iommu_mr;
    MemoryRegion msix_notify_mr;
    IndAddr *summary_ind;
    IndAddr *indicator;
    QEMUTimer *release_timer;
} S390PCIBusDevice;

typedef struct S390PCIBus {
    BusState qbus;
} S390PCIBus;

typedef struct S390pciState {
    PCIHostState parent_obj;
    S390PCIBus *bus;
    S390PCIBusDevice *pbdev[PCI_SLOT_MAX];
    S390PCIIOMMU *iommu[PCI_SLOT_MAX];
    QTAILQ_HEAD(, SeiContainer) pending_sei;
} S390pciState;

int chsc_sei_nt2_get_event(void *res);
int chsc_sei_nt2_have_event(void);
void s390_pci_sclp_configure(SCCB *sccb);
void s390_pci_sclp_deconfigure(SCCB *sccb);
void s390_pci_iommu_enable(S390PCIBusDevice *pbdev);
void s390_pci_iommu_disable(S390PCIBusDevice *pbdev);
void s390_pci_generate_error_event(uint16_t pec, uint32_t fh, uint32_t fid,
                                   uint64_t faddr, uint32_t e);
S390PCIBusDevice *s390_pci_find_dev_by_idx(uint32_t idx);
S390PCIBusDevice *s390_pci_find_dev_by_fh(uint32_t fh);
S390PCIBusDevice *s390_pci_find_dev_by_fid(uint32_t fid);
S390PCIBusDevice *s390_pci_find_next_avail_dev(S390PCIBusDevice *pbdev);

#endif
