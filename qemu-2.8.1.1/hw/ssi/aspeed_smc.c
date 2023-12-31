/*
 * ASPEED AST2400 SMC Controller (SPI Flash Only)
 *
 * Copyright (C) 2016 IBM Corp.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "sysemu/sysemu.h"
#include "qemu/log.h"
#include "include/qemu/error-report.h"
#include "exec/address-spaces.h"

#include "hw/ssi/aspeed_smc.h"

/* CE Type Setting Register */
#define R_CONF            (0x00 / 4)
#define   CONF_LEGACY_DISABLE  (1 << 31)
#define   CONF_ENABLE_W4       20
#define   CONF_ENABLE_W3       19
#define   CONF_ENABLE_W2       18
#define   CONF_ENABLE_W1       17
#define   CONF_ENABLE_W0       16
#define   CONF_FLASH_TYPE4     9
#define   CONF_FLASH_TYPE3     7
#define   CONF_FLASH_TYPE2     5
#define   CONF_FLASH_TYPE1     3
#define   CONF_FLASH_TYPE0     1

/* CE Control Register */
#define R_CE_CTRL            (0x04 / 4)
#define   CTRL_EXTENDED4       4  /* 32 bit addressing for SPI */
#define   CTRL_EXTENDED3       3  /* 32 bit addressing for SPI */
#define   CTRL_EXTENDED2       2  /* 32 bit addressing for SPI */
#define   CTRL_EXTENDED1       1  /* 32 bit addressing for SPI */
#define   CTRL_EXTENDED0       0  /* 32 bit addressing for SPI */

/* Interrupt Control and Status Register */
#define R_INTR_CTRL       (0x08 / 4)
#define   INTR_CTRL_DMA_STATUS            (1 << 11)
#define   INTR_CTRL_CMD_ABORT_STATUS      (1 << 10)
#define   INTR_CTRL_WRITE_PROTECT_STATUS  (1 << 9)
#define   INTR_CTRL_DMA_EN                (1 << 3)
#define   INTR_CTRL_CMD_ABORT_EN          (1 << 2)
#define   INTR_CTRL_WRITE_PROTECT_EN      (1 << 1)

/* CEx Control Register */
#define R_CTRL0           (0x10 / 4)
#define   CTRL_CMD_SHIFT           16
#define   CTRL_CMD_MASK            0xff
#define   CTRL_CE_STOP_ACTIVE      (1 << 2)
#define   CTRL_CMD_MODE_MASK       0x3
#define     CTRL_READMODE          0x0
#define     CTRL_FREADMODE         0x1
#define     CTRL_WRITEMODE         0x2
#define     CTRL_USERMODE          0x3
#define R_CTRL1           (0x14 / 4)
#define R_CTRL2           (0x18 / 4)
#define R_CTRL3           (0x1C / 4)
#define R_CTRL4           (0x20 / 4)

/* CEx Segment Address Register */
#define R_SEG_ADDR0       (0x30 / 4)
#define   SEG_END_SHIFT        24   /* 8MB units */
#define   SEG_END_MASK         0xff
#define   SEG_START_SHIFT      16   /* address bit [A29-A23] */
#define   SEG_START_MASK       0xff
#define R_SEG_ADDR1       (0x34 / 4)
#define R_SEG_ADDR2       (0x38 / 4)
#define R_SEG_ADDR3       (0x3C / 4)
#define R_SEG_ADDR4       (0x40 / 4)

/* Misc Control Register #1 */
#define R_MISC_CTRL1      (0x50 / 4)

/* Misc Control Register #2 */
#define R_MISC_CTRL2      (0x54 / 4)

/* DMA Control/Status Register */
#define R_DMA_CTRL        (0x80 / 4)
#define   DMA_CTRL_DELAY_MASK   0xf
#define   DMA_CTRL_DELAY_SHIFT  8
#define   DMA_CTRL_FREQ_MASK    0xf
#define   DMA_CTRL_FREQ_SHIFT   4
#define   DMA_CTRL_MODE         (1 << 3)
#define   DMA_CTRL_CKSUM        (1 << 2)
#define   DMA_CTRL_DIR          (1 << 1)
#define   DMA_CTRL_EN           (1 << 0)

/* DMA Flash Side Address */
#define R_DMA_FLASH_ADDR  (0x84 / 4)

/* DMA DRAM Side Address */
#define R_DMA_DRAM_ADDR   (0x88 / 4)

/* DMA Length Register */
#define R_DMA_LEN         (0x8C / 4)

/* Checksum Calculation Result */
#define R_DMA_CHECKSUM    (0x90 / 4)

/* Misc Control Register #2 */
#define R_TIMINGS         (0x94 / 4)

/* SPI controller registers and bits */
#define R_SPI_CONF        (0x00 / 4)
#define   SPI_CONF_ENABLE_W0   0
#define R_SPI_CTRL0       (0x4 / 4)
#define R_SPI_MISC_CTRL   (0x10 / 4)
#define R_SPI_TIMINGS     (0x14 / 4)

#define ASPEED_SOC_SMC_FLASH_BASE   0x10000000
#define ASPEED_SOC_FMC_FLASH_BASE   0x20000000
#define ASPEED_SOC_SPI_FLASH_BASE   0x30000000
#define ASPEED_SOC_SPI2_FLASH_BASE  0x38000000

/*
 * Default segments mapping addresses and size for each slave per
 * controller. These can be changed when board is initialized with the
 * Segment Address Registers.
 */
static const AspeedSegments aspeed_segments_legacy[] = {
    { 0x10000000, 32 * 1024 * 1024 },
};

static const AspeedSegments aspeed_segments_fmc[] = {
    { 0x20000000, 64 * 1024 * 1024 }, /* start address is readonly */
    { 0x24000000, 32 * 1024 * 1024 },
    { 0x26000000, 32 * 1024 * 1024 },
    { 0x28000000, 32 * 1024 * 1024 },
    { 0x2A000000, 32 * 1024 * 1024 }
};

static const AspeedSegments aspeed_segments_spi[] = {
    { 0x30000000, 64 * 1024 * 1024 },
};

static const AspeedSegments aspeed_segments_ast2500_fmc[] = {
    { 0x20000000, 128 * 1024 * 1024 }, /* start address is readonly */
    { 0x28000000,  32 * 1024 * 1024 },
    { 0x2A000000,  32 * 1024 * 1024 },
};

static const AspeedSegments aspeed_segments_ast2500_spi1[] = {
    { 0x30000000, 32 * 1024 * 1024 }, /* start address is readonly */
    { 0x32000000, 96 * 1024 * 1024 }, /* end address is readonly */
};

static const AspeedSegments aspeed_segments_ast2500_spi2[] = {
    { 0x38000000, 32 * 1024 * 1024 }, /* start address is readonly */
    { 0x3A000000, 96 * 1024 * 1024 }, /* end address is readonly */
};

static const AspeedSMCController controllers[] = {
    { "aspeed.smc.smc", R_CONF, R_CE_CTRL, R_CTRL0, R_TIMINGS,
      CONF_ENABLE_W0, 5, aspeed_segments_legacy,
      ASPEED_SOC_SMC_FLASH_BASE, 0x6000000 },
    { "aspeed.smc.fmc", R_CONF, R_CE_CTRL, R_CTRL0, R_TIMINGS,
      CONF_ENABLE_W0, 5, aspeed_segments_fmc,
      ASPEED_SOC_FMC_FLASH_BASE, 0x10000000 },
    { "aspeed.smc.spi", R_SPI_CONF, 0xff, R_SPI_CTRL0, R_SPI_TIMINGS,
      SPI_CONF_ENABLE_W0, 1, aspeed_segments_spi,
      ASPEED_SOC_SPI_FLASH_BASE, 0x10000000 },
    { "aspeed.smc.ast2500-fmc", R_CONF, R_CE_CTRL, R_CTRL0, R_TIMINGS,
      CONF_ENABLE_W0, 3, aspeed_segments_ast2500_fmc,
      ASPEED_SOC_FMC_FLASH_BASE, 0x10000000 },
    { "aspeed.smc.ast2500-spi1", R_CONF, R_CE_CTRL, R_CTRL0, R_TIMINGS,
      CONF_ENABLE_W0, 2, aspeed_segments_ast2500_spi1,
      ASPEED_SOC_SPI_FLASH_BASE, 0x8000000 },
    { "aspeed.smc.ast2500-spi2", R_CONF, R_CE_CTRL, R_CTRL0, R_TIMINGS,
      CONF_ENABLE_W0, 2, aspeed_segments_ast2500_spi2,
      ASPEED_SOC_SPI2_FLASH_BASE, 0x8000000 },
};

/*
 * The Segment Register uses a 8MB unit to encode the start address
 * and the end address of the mapping window of a flash SPI slave :
 *
 *        | byte 1 | byte 2 | byte 3 | byte 4 |
 *        +--------+--------+--------+--------+
 *        |  end   |  start |   0    |   0    |
 *
 */
static inline uint32_t aspeed_smc_segment_to_reg(const AspeedSegments *seg)
{
    uint32_t reg = 0;
    reg |= ((seg->addr >> 23) & SEG_START_MASK) << SEG_START_SHIFT;
    reg |= (((seg->addr + seg->size) >> 23) & SEG_END_MASK) << SEG_END_SHIFT;
    return reg;
}

static inline void aspeed_smc_reg_to_segment(uint32_t reg, AspeedSegments *seg)
{
    seg->addr = ((reg >> SEG_START_SHIFT) & SEG_START_MASK) << 23;
    seg->size = (((reg >> SEG_END_SHIFT) & SEG_END_MASK) << 23) - seg->addr;
}

static bool aspeed_smc_flash_overlap(const AspeedSMCState *s,
                                     const AspeedSegments *new,
                                     int cs)
{
    AspeedSegments seg;
    int i;

    for (i = 0; i < s->ctrl->max_slaves; i++) {
        if (i == cs) {
            continue;
        }

        aspeed_smc_reg_to_segment(s->regs[R_SEG_ADDR0 + i], &seg);

        if (new->addr + new->size > seg.addr &&
            new->addr < seg.addr + seg.size) {
            qemu_log_mask(LOG_GUEST_ERROR, "%s: new segment CS%d [ 0x%"
                          HWADDR_PRIx" - 0x%"HWADDR_PRIx" ] overlaps with "
                          "CS%d [ 0x%"HWADDR_PRIx" - 0x%"HWADDR_PRIx" ]\n",
                          s->ctrl->name, cs, new->addr, new->addr + new->size,
                          i, seg.addr, seg.addr + seg.size);
            return true;
        }
    }
    return false;
}

static void aspeed_smc_flash_set_segment(AspeedSMCState *s, int cs,
                                         uint64_t new)
{
    AspeedSMCFlash *fl = &s->flashes[cs];
    AspeedSegments seg;

    aspeed_smc_reg_to_segment(new, &seg);

    /* The start address of CS0 is read-only */
    if (cs == 0 && seg.addr != s->ctrl->flash_window_base) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: Tried to change CS0 start address to 0x%"
                      HWADDR_PRIx "\n", s->ctrl->name, seg.addr);
        return;
    }

    /*
     * The end address of the AST2500 spi controllers is also
     * read-only.
     */
    if ((s->ctrl->segments == aspeed_segments_ast2500_spi1 ||
         s->ctrl->segments == aspeed_segments_ast2500_spi2) &&
        cs == s->ctrl->max_slaves &&
        seg.addr + seg.size != s->ctrl->segments[cs].addr +
        s->ctrl->segments[cs].size) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: Tried to change CS%d end address to 0x%"
                      HWADDR_PRIx "\n", s->ctrl->name, cs, seg.addr);
        return;
    }

    /* Keep the segment in the overall flash window */
    if (seg.addr + seg.size <= s->ctrl->flash_window_base ||
        seg.addr > s->ctrl->flash_window_base + s->ctrl->flash_window_size) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: new segment for CS%d is invalid : "
                      "[ 0x%"HWADDR_PRIx" - 0x%"HWADDR_PRIx" ]\n",
                      s->ctrl->name, cs, seg.addr, seg.addr + seg.size);
        return;
    }

    /* Check start address vs. alignment */
    if (seg.addr % seg.size) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: new segment for CS%d is not "
                      "aligned : [ 0x%"HWADDR_PRIx" - 0x%"HWADDR_PRIx" ]\n",
                      s->ctrl->name, cs, seg.addr, seg.addr + seg.size);
    }

    /* And segments should not overlap */
    if (aspeed_smc_flash_overlap(s, &seg, cs)) {
        return;
    }

    /* All should be fine now to move the region */
    memory_region_transaction_begin();
    memory_region_set_size(&fl->mmio, seg.size);
    memory_region_set_address(&fl->mmio, seg.addr - s->ctrl->flash_window_base);
    memory_region_set_enabled(&fl->mmio, true);
    memory_region_transaction_commit();

    s->regs[R_SEG_ADDR0 + cs] = new;
}

static uint64_t aspeed_smc_flash_default_read(void *opaque, hwaddr addr,
                                              unsigned size)
{
    qemu_log_mask(LOG_GUEST_ERROR, "%s: To 0x%" HWADDR_PRIx " of size %u"
                  PRIx64 "\n", __func__, addr, size);
    return 0;
}

static void aspeed_smc_flash_default_write(void *opaque, hwaddr addr,
                                           uint64_t data, unsigned size)
{
   qemu_log_mask(LOG_GUEST_ERROR, "%s: To 0x%" HWADDR_PRIx " of size %u: 0x%"
                 PRIx64 "\n", __func__, addr, size, data);
}

static const MemoryRegionOps aspeed_smc_flash_default_ops = {
    .read = aspeed_smc_flash_default_read,
    .write = aspeed_smc_flash_default_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

static inline int aspeed_smc_flash_mode(const AspeedSMCState *s, int cs)
{
    return s->regs[s->r_ctrl0 + cs] & CTRL_CMD_MODE_MASK;
}

static inline bool aspeed_smc_is_usermode(const AspeedSMCState *s, int cs)
{
    return aspeed_smc_flash_mode(s, cs) == CTRL_USERMODE;
}

static inline bool aspeed_smc_is_writable(const AspeedSMCState *s, int cs)
{
    return s->regs[s->r_conf] & (1 << (s->conf_enable_w0 + cs));
}

static uint64_t aspeed_smc_flash_read(void *opaque, hwaddr addr, unsigned size)
{
    AspeedSMCFlash *fl = opaque;
    const AspeedSMCState *s = fl->controller;
    uint64_t ret = 0;
    int i;

    if (aspeed_smc_is_usermode(s, fl->id)) {
        for (i = 0; i < size; i++) {
            ret |= ssi_transfer(s->spi, 0x0) << (8 * i);
        }
    } else {
        qemu_log_mask(LOG_UNIMP, "%s: usermode not implemented\n",
                      __func__);
        ret = -1;
    }

    return ret;
}

static void aspeed_smc_flash_write(void *opaque, hwaddr addr, uint64_t data,
                           unsigned size)
{
    AspeedSMCFlash *fl = opaque;
    const AspeedSMCState *s = fl->controller;
    int i;

    if (!aspeed_smc_is_writable(s, fl->id)) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: flash is not writable at 0x%"
                      HWADDR_PRIx "\n", __func__, addr);
        return;
    }

    if (!aspeed_smc_is_usermode(s, fl->id)) {
        qemu_log_mask(LOG_UNIMP, "%s: usermode not implemented\n",
                      __func__);
        return;
    }

    for (i = 0; i < size; i++) {
        ssi_transfer(s->spi, (data >> (8 * i)) & 0xff);
    }
}

static const MemoryRegionOps aspeed_smc_flash_ops = {
    .read = aspeed_smc_flash_read,
    .write = aspeed_smc_flash_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

static bool aspeed_smc_is_ce_stop_active(const AspeedSMCState *s, int cs)
{
    return s->regs[s->r_ctrl0 + cs] & CTRL_CE_STOP_ACTIVE;
}

static void aspeed_smc_update_cs(const AspeedSMCState *s)
{
    int i;

    for (i = 0; i < s->num_cs; ++i) {
        qemu_set_irq(s->cs_lines[i], aspeed_smc_is_ce_stop_active(s, i));
    }
}

static void aspeed_smc_reset(DeviceState *d)
{
    AspeedSMCState *s = ASPEED_SMC(d);
    int i;

    memset(s->regs, 0, sizeof s->regs);

    /* Pretend DMA is done (u-boot initialization) */
    s->regs[R_INTR_CTRL] = INTR_CTRL_DMA_STATUS;

    /* Unselect all slaves */
    for (i = 0; i < s->num_cs; ++i) {
        s->regs[s->r_ctrl0 + i] |= CTRL_CE_STOP_ACTIVE;
    }

    /* setup default segment register values for all */
    for (i = 0; i < s->ctrl->max_slaves; ++i) {
        s->regs[R_SEG_ADDR0 + i] =
            aspeed_smc_segment_to_reg(&s->ctrl->segments[i]);
    }

    aspeed_smc_update_cs(s);
}

static uint64_t aspeed_smc_read(void *opaque, hwaddr addr, unsigned int size)
{
    AspeedSMCState *s = ASPEED_SMC(opaque);

    addr >>= 2;

    if (addr >= ARRAY_SIZE(s->regs)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: Out-of-bounds read at 0x%" HWADDR_PRIx "\n",
                      __func__, addr);
        return 0;
    }

    if (addr == s->r_conf ||
        addr == s->r_timings ||
        addr == s->r_ce_ctrl ||
        addr == R_INTR_CTRL ||
        (addr >= R_SEG_ADDR0 && addr < R_SEG_ADDR0 + s->ctrl->max_slaves) ||
        (addr >= s->r_ctrl0 && addr < s->r_ctrl0 + s->num_cs)) {
        return s->regs[addr];
    } else {
        qemu_log_mask(LOG_UNIMP, "%s: not implemented: 0x%" HWADDR_PRIx "\n",
                      __func__, addr);
        return 0;
    }
}

static void aspeed_smc_write(void *opaque, hwaddr addr, uint64_t data,
                             unsigned int size)
{
    AspeedSMCState *s = ASPEED_SMC(opaque);
    uint32_t value = data;

    addr >>= 2;

    if (addr >= ARRAY_SIZE(s->regs)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: Out-of-bounds write at 0x%" HWADDR_PRIx "\n",
                      __func__, addr);
        return;
    }

    if (addr == s->r_conf ||
        addr == s->r_timings ||
        addr == s->r_ce_ctrl) {
        s->regs[addr] = value;
    } else if (addr >= s->r_ctrl0 && addr < s->r_ctrl0 + s->num_cs) {
        s->regs[addr] = value;
        aspeed_smc_update_cs(s);
    } else if (addr >= R_SEG_ADDR0 &&
               addr < R_SEG_ADDR0 + s->ctrl->max_slaves) {
        int cs = addr - R_SEG_ADDR0;

        if (value != s->regs[R_SEG_ADDR0 + cs]) {
            aspeed_smc_flash_set_segment(s, cs, value);
        }
    } else {
        qemu_log_mask(LOG_UNIMP, "%s: not implemented: 0x%" HWADDR_PRIx "\n",
                      __func__, addr);
        return;
    }
}

static const MemoryRegionOps aspeed_smc_ops = {
    .read = aspeed_smc_read,
    .write = aspeed_smc_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.unaligned = true,
};

static void aspeed_smc_realize(DeviceState *dev, Error **errp)
{
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    AspeedSMCState *s = ASPEED_SMC(dev);
    AspeedSMCClass *mc = ASPEED_SMC_GET_CLASS(s);
    int i;
    char name[32];
    hwaddr offset = 0;

    s->ctrl = mc->ctrl;

    /* keep a copy under AspeedSMCState to speed up accesses */
    s->r_conf = s->ctrl->r_conf;
    s->r_ce_ctrl = s->ctrl->r_ce_ctrl;
    s->r_ctrl0 = s->ctrl->r_ctrl0;
    s->r_timings = s->ctrl->r_timings;
    s->conf_enable_w0 = s->ctrl->conf_enable_w0;

    /* Enforce some real HW limits */
    if (s->num_cs > s->ctrl->max_slaves) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: num_cs cannot exceed: %d\n",
                      __func__, s->ctrl->max_slaves);
        s->num_cs = s->ctrl->max_slaves;
    }

    s->spi = ssi_create_bus(dev, "spi");

    /* Setup cs_lines for slaves */
    sysbus_init_irq(sbd, &s->irq);
    s->cs_lines = g_new0(qemu_irq, s->num_cs);
    ssi_auto_connect_slaves(dev, s->cs_lines, s->spi);

    for (i = 0; i < s->num_cs; ++i) {
        sysbus_init_irq(sbd, &s->cs_lines[i]);
    }

    aspeed_smc_reset(dev);

    /* The memory region for the controller registers */
    memory_region_init_io(&s->mmio, OBJECT(s), &aspeed_smc_ops, s,
                          s->ctrl->name, ASPEED_SMC_R_MAX * 4);
    sysbus_init_mmio(sbd, &s->mmio);

    /*
     * The container memory region representing the address space
     * window in which the flash modules are mapped. The size and
     * address depends on the SoC model and controller type.
     */
    snprintf(name, sizeof(name), "%s.flash", s->ctrl->name);

    memory_region_init_io(&s->mmio_flash, OBJECT(s),
                          &aspeed_smc_flash_default_ops, s, name,
                          s->ctrl->flash_window_size);
    sysbus_init_mmio(sbd, &s->mmio_flash);

    s->flashes = g_new0(AspeedSMCFlash, s->ctrl->max_slaves);

    /*
     * Let's create a sub memory region for each possible slave. All
     * have a configurable memory segment in the overall flash mapping
     * window of the controller but, there is not necessarily a flash
     * module behind to handle the memory accesses. This depends on
     * the board configuration.
     */
    for (i = 0; i < s->ctrl->max_slaves; ++i) {
        AspeedSMCFlash *fl = &s->flashes[i];

        snprintf(name, sizeof(name), "%s.%d", s->ctrl->name, i);

        fl->id = i;
        fl->controller = s;
        fl->size = s->ctrl->segments[i].size;
        memory_region_init_io(&fl->mmio, OBJECT(s), &aspeed_smc_flash_ops,
                              fl, name, fl->size);
        memory_region_add_subregion(&s->mmio_flash, offset, &fl->mmio);
        offset += fl->size;
    }
}

static const VMStateDescription vmstate_aspeed_smc = {
    .name = "aspeed.smc",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32_ARRAY(regs, AspeedSMCState, ASPEED_SMC_R_MAX),
        VMSTATE_END_OF_LIST()
    }
};

static Property aspeed_smc_properties[] = {
    DEFINE_PROP_UINT32("num-cs", AspeedSMCState, num_cs, 1),
    DEFINE_PROP_END_OF_LIST(),
};

static void aspeed_smc_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    AspeedSMCClass *mc = ASPEED_SMC_CLASS(klass);

    dc->realize = aspeed_smc_realize;
    dc->reset = aspeed_smc_reset;
    dc->props = aspeed_smc_properties;
    dc->vmsd = &vmstate_aspeed_smc;
    mc->ctrl = data;
}

static const TypeInfo aspeed_smc_info = {
    .name           = TYPE_ASPEED_SMC,
    .parent         = TYPE_SYS_BUS_DEVICE,
    .instance_size  = sizeof(AspeedSMCState),
    .class_size     = sizeof(AspeedSMCClass),
    .abstract       = true,
};

static void aspeed_smc_register_types(void)
{
    int i;

    type_register_static(&aspeed_smc_info);
    for (i = 0; i < ARRAY_SIZE(controllers); ++i) {
        TypeInfo ti = {
            .name       = controllers[i].name,
            .parent     = TYPE_ASPEED_SMC,
            .class_init = aspeed_smc_class_init,
            .class_data = (void *)&controllers[i],
        };
        type_register(&ti);
    }
}

type_init(aspeed_smc_register_types)
