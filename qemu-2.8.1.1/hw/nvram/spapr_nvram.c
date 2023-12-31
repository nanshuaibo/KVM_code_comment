/*
 * QEMU sPAPR NVRAM emulation
 *
 * Copyright (C) 2012 David Gibson, IBM Corporation.
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
#include "qapi/error.h"
#include "qemu-common.h"
#include "cpu.h"
#include <libfdt.h>

#include "sysemu/block-backend.h"
#include "sysemu/device_tree.h"
#include "hw/sysbus.h"
#include "hw/nvram/chrp_nvram.h"
#include "hw/ppc/spapr.h"
#include "hw/ppc/spapr_vio.h"

typedef struct sPAPRNVRAM {
    VIOsPAPRDevice sdev;
    uint32_t size;
    uint8_t *buf;
    BlockBackend *blk;
    VMChangeStateEntry *vmstate;
} sPAPRNVRAM;

#define TYPE_VIO_SPAPR_NVRAM "spapr-nvram"
#define VIO_SPAPR_NVRAM(obj) \
     OBJECT_CHECK(sPAPRNVRAM, (obj), TYPE_VIO_SPAPR_NVRAM)

#define MIN_NVRAM_SIZE 8192
#define DEFAULT_NVRAM_SIZE 65536
#define MAX_NVRAM_SIZE 1048576

static void rtas_nvram_fetch(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                             uint32_t token, uint32_t nargs,
                             target_ulong args,
                             uint32_t nret, target_ulong rets)
{
    sPAPRNVRAM *nvram = spapr->nvram;
    hwaddr offset, buffer, len;
    void *membuf;

    if ((nargs != 3) || (nret != 2)) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    if (!nvram) {
        rtas_st(rets, 0, RTAS_OUT_HW_ERROR);
        rtas_st(rets, 1, 0);
        return;
    }

    offset = rtas_ld(args, 0);
    buffer = rtas_ld(args, 1);
    len = rtas_ld(args, 2);

    if (((offset + len) < offset)
        || ((offset + len) > nvram->size)) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        rtas_st(rets, 1, 0);
        return;
    }

    assert(nvram->buf);

    membuf = cpu_physical_memory_map(buffer, &len, 1);
    memcpy(membuf, nvram->buf + offset, len);
    cpu_physical_memory_unmap(membuf, len, 1, len);

    rtas_st(rets, 0, RTAS_OUT_SUCCESS);
    rtas_st(rets, 1, len);
}

static void rtas_nvram_store(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                             uint32_t token, uint32_t nargs,
                             target_ulong args,
                             uint32_t nret, target_ulong rets)
{
    sPAPRNVRAM *nvram = spapr->nvram;
    hwaddr offset, buffer, len;
    int alen;
    void *membuf;

    if ((nargs != 3) || (nret != 2)) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    if (!nvram) {
        rtas_st(rets, 0, RTAS_OUT_HW_ERROR);
        return;
    }

    offset = rtas_ld(args, 0);
    buffer = rtas_ld(args, 1);
    len = rtas_ld(args, 2);

    if (((offset + len) < offset)
        || ((offset + len) > nvram->size)) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    membuf = cpu_physical_memory_map(buffer, &len, 0);

    alen = len;
    if (nvram->blk) {
        alen = blk_pwrite(nvram->blk, offset, membuf, len, 0);
    }

    assert(nvram->buf);
    memcpy(nvram->buf + offset, membuf, len);

    cpu_physical_memory_unmap(membuf, len, 0, len);

    rtas_st(rets, 0, (alen < len) ? RTAS_OUT_HW_ERROR : RTAS_OUT_SUCCESS);
    rtas_st(rets, 1, (alen < 0) ? 0 : alen);
}

static void spapr_nvram_realize(VIOsPAPRDevice *dev, Error **errp)
{
    sPAPRNVRAM *nvram = VIO_SPAPR_NVRAM(dev);

    if (nvram->blk) {
        nvram->size = blk_getlength(nvram->blk);
    } else {
        nvram->size = DEFAULT_NVRAM_SIZE;
    }

    nvram->buf = g_malloc0(nvram->size);

    if ((nvram->size < MIN_NVRAM_SIZE) || (nvram->size > MAX_NVRAM_SIZE)) {
        error_setg(errp, "spapr-nvram must be between %d and %d bytes in size",
                   MIN_NVRAM_SIZE, MAX_NVRAM_SIZE);
        return;
    }

    if (nvram->blk) {
        int alen = blk_pread(nvram->blk, 0, nvram->buf, nvram->size);

        if (alen != nvram->size) {
            error_setg(errp, "can't read spapr-nvram contents");
            return;
        }
    } else if (nb_prom_envs > 0) {
        /* Create a system partition to pass the -prom-env variables */
        chrp_nvram_create_system_partition(nvram->buf, MIN_NVRAM_SIZE / 4);
        chrp_nvram_create_free_partition(&nvram->buf[MIN_NVRAM_SIZE / 4],
                                         nvram->size - MIN_NVRAM_SIZE / 4);
    }

    spapr_rtas_register(RTAS_NVRAM_FETCH, "nvram-fetch", rtas_nvram_fetch);
    spapr_rtas_register(RTAS_NVRAM_STORE, "nvram-store", rtas_nvram_store);
}

static int spapr_nvram_devnode(VIOsPAPRDevice *dev, void *fdt, int node_off)
{
    sPAPRNVRAM *nvram = VIO_SPAPR_NVRAM(dev);

    return fdt_setprop_cell(fdt, node_off, "#bytes", nvram->size);
}

static int spapr_nvram_pre_load(void *opaque)
{
    sPAPRNVRAM *nvram = VIO_SPAPR_NVRAM(opaque);

    g_free(nvram->buf);
    nvram->buf = NULL;
    nvram->size = 0;

    return 0;
}

static void postload_update_cb(void *opaque, int running, RunState state)
{
    sPAPRNVRAM *nvram = opaque;

    /* This is called after bdrv_invalidate_cache_all.  */

    qemu_del_vm_change_state_handler(nvram->vmstate);
    nvram->vmstate = NULL;

    blk_pwrite(nvram->blk, 0, nvram->buf, nvram->size, 0);
}

static int spapr_nvram_post_load(void *opaque, int version_id)
{
    sPAPRNVRAM *nvram = VIO_SPAPR_NVRAM(opaque);

    if (nvram->blk) {
        nvram->vmstate = qemu_add_vm_change_state_handler(postload_update_cb,
                                                          nvram);
    }

    return 0;
}

static const VMStateDescription vmstate_spapr_nvram = {
    .name = "spapr_nvram",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_load = spapr_nvram_pre_load,
    .post_load = spapr_nvram_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(size, sPAPRNVRAM),
        VMSTATE_VBUFFER_ALLOC_UINT32(buf, sPAPRNVRAM, 1, NULL, 0, size),
        VMSTATE_END_OF_LIST()
    },
};

static Property spapr_nvram_properties[] = {
    DEFINE_SPAPR_PROPERTIES(sPAPRNVRAM, sdev),
    DEFINE_PROP_DRIVE("drive", sPAPRNVRAM, blk),
    DEFINE_PROP_END_OF_LIST(),
};

static void spapr_nvram_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VIOsPAPRDeviceClass *k = VIO_SPAPR_DEVICE_CLASS(klass);

    k->realize = spapr_nvram_realize;
    k->devnode = spapr_nvram_devnode;
    k->dt_name = "nvram";
    k->dt_type = "nvram";
    k->dt_compatible = "qemu,spapr-nvram";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    dc->props = spapr_nvram_properties;
    dc->vmsd = &vmstate_spapr_nvram;
}

static const TypeInfo spapr_nvram_type_info = {
    .name          = TYPE_VIO_SPAPR_NVRAM,
    .parent        = TYPE_VIO_SPAPR_DEVICE,
    .instance_size = sizeof(sPAPRNVRAM),
    .class_init    = spapr_nvram_class_init,
};

static void spapr_nvram_register_types(void)
{
    type_register_static(&spapr_nvram_type_info);
}

type_init(spapr_nvram_register_types)
