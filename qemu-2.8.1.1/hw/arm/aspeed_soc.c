/*
 * ASPEED SoC family
 *
 * Andrew Jeffery <andrew@aj.id.au>
 * Jeremy Kerr <jk@ozlabs.org>
 *
 * Copyright 2016 IBM Corp.
 *
 * This code is licensed under the GPL version 2 or later.  See
 * the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "cpu.h"
#include "exec/address-spaces.h"
#include "hw/arm/aspeed_soc.h"
#include "hw/char/serial.h"
#include "qemu/log.h"
#include "hw/i2c/aspeed_i2c.h"

#define ASPEED_SOC_UART_5_BASE      0x00184000
#define ASPEED_SOC_IOMEM_SIZE       0x00200000
#define ASPEED_SOC_IOMEM_BASE       0x1E600000
#define ASPEED_SOC_FMC_BASE         0x1E620000
#define ASPEED_SOC_SPI_BASE         0x1E630000
#define ASPEED_SOC_SPI2_BASE        0x1E631000
#define ASPEED_SOC_VIC_BASE         0x1E6C0000
#define ASPEED_SOC_SDMC_BASE        0x1E6E0000
#define ASPEED_SOC_SCU_BASE         0x1E6E2000
#define ASPEED_SOC_TIMER_BASE       0x1E782000
#define ASPEED_SOC_I2C_BASE         0x1E78A000

static const int uart_irqs[] = { 9, 32, 33, 34, 10 };
static const int timer_irqs[] = { 16, 17, 18, 35, 36, 37, 38, 39, };

#define AST2400_SDRAM_BASE       0x40000000
#define AST2500_SDRAM_BASE       0x80000000

static const hwaddr aspeed_soc_ast2400_spi_bases[] = { ASPEED_SOC_SPI_BASE };
static const char *aspeed_soc_ast2400_typenames[] = { "aspeed.smc.spi" };

static const hwaddr aspeed_soc_ast2500_spi_bases[] = { ASPEED_SOC_SPI_BASE,
                                                       ASPEED_SOC_SPI2_BASE};
static const char *aspeed_soc_ast2500_typenames[] = {
    "aspeed.smc.ast2500-spi1", "aspeed.smc.ast2500-spi2" };

static const AspeedSoCInfo aspeed_socs[] = {
    { "ast2400-a0", "arm926", AST2400_A0_SILICON_REV, AST2400_SDRAM_BASE,
      1, aspeed_soc_ast2400_spi_bases,
      "aspeed.smc.fmc", aspeed_soc_ast2400_typenames },
    { "ast2400",    "arm926", AST2400_A0_SILICON_REV, AST2400_SDRAM_BASE,
      1, aspeed_soc_ast2400_spi_bases,
     "aspeed.smc.fmc", aspeed_soc_ast2400_typenames },
    { "ast2500-a1", "arm1176", AST2500_A1_SILICON_REV, AST2500_SDRAM_BASE,
      2, aspeed_soc_ast2500_spi_bases,
      "aspeed.smc.ast2500-fmc", aspeed_soc_ast2500_typenames },
};

/*
 * IO handlers: simply catch any reads/writes to IO addresses that aren't
 * handled by a device mapping.
 */

static uint64_t aspeed_soc_io_read(void *p, hwaddr offset, unsigned size)
{
    qemu_log_mask(LOG_UNIMP, "%s: 0x%" HWADDR_PRIx " [%u]\n",
                  __func__, offset, size);
    return 0;
}

static void aspeed_soc_io_write(void *opaque, hwaddr offset, uint64_t value,
                unsigned size)
{
    qemu_log_mask(LOG_UNIMP, "%s: 0x%" HWADDR_PRIx " <- 0x%" PRIx64 " [%u]\n",
                  __func__, offset, value, size);
}

static const MemoryRegionOps aspeed_soc_io_ops = {
    .read = aspeed_soc_io_read,
    .write = aspeed_soc_io_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void aspeed_soc_init(Object *obj)
{
    AspeedSoCState *s = ASPEED_SOC(obj);
    AspeedSoCClass *sc = ASPEED_SOC_GET_CLASS(s);
    int i;

    s->cpu = cpu_arm_init(sc->info->cpu_model);

    object_initialize(&s->vic, sizeof(s->vic), TYPE_ASPEED_VIC);
    object_property_add_child(obj, "vic", OBJECT(&s->vic), NULL);
    qdev_set_parent_bus(DEVICE(&s->vic), sysbus_get_default());

    object_initialize(&s->timerctrl, sizeof(s->timerctrl), TYPE_ASPEED_TIMER);
    object_property_add_child(obj, "timerctrl", OBJECT(&s->timerctrl), NULL);
    qdev_set_parent_bus(DEVICE(&s->timerctrl), sysbus_get_default());

    object_initialize(&s->i2c, sizeof(s->i2c), TYPE_ASPEED_I2C);
    object_property_add_child(obj, "i2c", OBJECT(&s->i2c), NULL);
    qdev_set_parent_bus(DEVICE(&s->i2c), sysbus_get_default());

    object_initialize(&s->scu, sizeof(s->scu), TYPE_ASPEED_SCU);
    object_property_add_child(obj, "scu", OBJECT(&s->scu), NULL);
    qdev_set_parent_bus(DEVICE(&s->scu), sysbus_get_default());
    qdev_prop_set_uint32(DEVICE(&s->scu), "silicon-rev",
                         sc->info->silicon_rev);
    object_property_add_alias(obj, "hw-strap1", OBJECT(&s->scu),
                              "hw-strap1", &error_abort);
    object_property_add_alias(obj, "hw-strap2", OBJECT(&s->scu),
                              "hw-strap2", &error_abort);

    object_initialize(&s->fmc, sizeof(s->fmc), sc->info->fmc_typename);
    object_property_add_child(obj, "fmc", OBJECT(&s->fmc), NULL);
    qdev_set_parent_bus(DEVICE(&s->fmc), sysbus_get_default());

    for (i = 0; i < sc->info->spis_num; i++) {
        object_initialize(&s->spi[i], sizeof(s->spi[i]),
                          sc->info->spi_typename[i]);
        object_property_add_child(obj, "spi", OBJECT(&s->spi[i]), NULL);
        qdev_set_parent_bus(DEVICE(&s->spi[i]), sysbus_get_default());
    }

    object_initialize(&s->sdmc, sizeof(s->sdmc), TYPE_ASPEED_SDMC);
    object_property_add_child(obj, "sdmc", OBJECT(&s->sdmc), NULL);
    qdev_set_parent_bus(DEVICE(&s->sdmc), sysbus_get_default());
    qdev_prop_set_uint32(DEVICE(&s->sdmc), "silicon-rev",
                         sc->info->silicon_rev);
    object_property_add_alias(obj, "ram-size", OBJECT(&s->sdmc),
                              "ram-size", &error_abort);
}

static void aspeed_soc_realize(DeviceState *dev, Error **errp)
{
    int i;
    AspeedSoCState *s = ASPEED_SOC(dev);
    AspeedSoCClass *sc = ASPEED_SOC_GET_CLASS(s);
    Error *err = NULL, *local_err = NULL;

    /* IO space */
    memory_region_init_io(&s->iomem, NULL, &aspeed_soc_io_ops, NULL,
            "aspeed_soc.io", ASPEED_SOC_IOMEM_SIZE);
    memory_region_add_subregion_overlap(get_system_memory(),
                                        ASPEED_SOC_IOMEM_BASE, &s->iomem, -1);

    /* VIC */
    object_property_set_bool(OBJECT(&s->vic), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    sysbus_mmio_map(SYS_BUS_DEVICE(&s->vic), 0, ASPEED_SOC_VIC_BASE);
    sysbus_connect_irq(SYS_BUS_DEVICE(&s->vic), 0,
                       qdev_get_gpio_in(DEVICE(s->cpu), ARM_CPU_IRQ));
    sysbus_connect_irq(SYS_BUS_DEVICE(&s->vic), 1,
                       qdev_get_gpio_in(DEVICE(s->cpu), ARM_CPU_FIQ));

    /* Timer */
    object_property_set_bool(OBJECT(&s->timerctrl), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    sysbus_mmio_map(SYS_BUS_DEVICE(&s->timerctrl), 0, ASPEED_SOC_TIMER_BASE);
    for (i = 0; i < ARRAY_SIZE(timer_irqs); i++) {
        qemu_irq irq = qdev_get_gpio_in(DEVICE(&s->vic), timer_irqs[i]);
        sysbus_connect_irq(SYS_BUS_DEVICE(&s->timerctrl), i, irq);
    }

    /* SCU */
    object_property_set_bool(OBJECT(&s->scu), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    sysbus_mmio_map(SYS_BUS_DEVICE(&s->scu), 0, ASPEED_SOC_SCU_BASE);

    /* UART - attach an 8250 to the IO space as our UART5 */
    if (serial_hds[0]) {
        qemu_irq uart5 = qdev_get_gpio_in(DEVICE(&s->vic), uart_irqs[4]);
        serial_mm_init(&s->iomem, ASPEED_SOC_UART_5_BASE, 2,
                       uart5, 38400, serial_hds[0], DEVICE_LITTLE_ENDIAN);
    }

    /* I2C */
    object_property_set_bool(OBJECT(&s->i2c), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    sysbus_mmio_map(SYS_BUS_DEVICE(&s->i2c), 0, ASPEED_SOC_I2C_BASE);
    sysbus_connect_irq(SYS_BUS_DEVICE(&s->i2c), 0,
                       qdev_get_gpio_in(DEVICE(&s->vic), 12));

    /* FMC */
    object_property_set_int(OBJECT(&s->fmc), 1, "num-cs", &err);
    object_property_set_bool(OBJECT(&s->fmc), true, "realized", &local_err);
    error_propagate(&err, local_err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    sysbus_mmio_map(SYS_BUS_DEVICE(&s->fmc), 0, ASPEED_SOC_FMC_BASE);
    sysbus_mmio_map(SYS_BUS_DEVICE(&s->fmc), 1,
                    s->fmc.ctrl->flash_window_base);
    sysbus_connect_irq(SYS_BUS_DEVICE(&s->fmc), 0,
                       qdev_get_gpio_in(DEVICE(&s->vic), 19));

    /* SPI */
    for (i = 0; i < sc->info->spis_num; i++) {
        object_property_set_int(OBJECT(&s->spi[i]), 1, "num-cs", &err);
        object_property_set_bool(OBJECT(&s->spi[i]), true, "realized",
                                 &local_err);
        error_propagate(&err, local_err);
        if (err) {
            error_propagate(errp, err);
            return;
        }
        sysbus_mmio_map(SYS_BUS_DEVICE(&s->spi[i]), 0, sc->info->spi_bases[i]);
        sysbus_mmio_map(SYS_BUS_DEVICE(&s->spi[i]), 1,
                        s->spi[i].ctrl->flash_window_base);
    }

    /* SDMC - SDRAM Memory Controller */
    object_property_set_bool(OBJECT(&s->sdmc), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    sysbus_mmio_map(SYS_BUS_DEVICE(&s->sdmc), 0, ASPEED_SOC_SDMC_BASE);
}

static void aspeed_soc_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    AspeedSoCClass *sc = ASPEED_SOC_CLASS(oc);

    sc->info = (AspeedSoCInfo *) data;
    dc->realize = aspeed_soc_realize;

    /*
     * Reason: creates an ARM CPU, thus use after free(), see
     * arm_cpu_class_init()
     */
    dc->cannot_destroy_with_object_finalize_yet = true;
}

static const TypeInfo aspeed_soc_type_info = {
    .name           = TYPE_ASPEED_SOC,
    .parent         = TYPE_DEVICE,
    .instance_init  = aspeed_soc_init,
    .instance_size  = sizeof(AspeedSoCState),
    .class_size     = sizeof(AspeedSoCClass),
    .abstract       = true,
};

static void aspeed_soc_register_types(void)
{
    int i;

    type_register_static(&aspeed_soc_type_info);
    for (i = 0; i < ARRAY_SIZE(aspeed_socs); ++i) {
        TypeInfo ti = {
            .name       = aspeed_socs[i].name,
            .parent     = TYPE_ASPEED_SOC,
            .class_init = aspeed_soc_class_init,
            .class_data = (void *) &aspeed_socs[i],
        };
        type_register(&ti);
    }
}

type_init(aspeed_soc_register_types)
