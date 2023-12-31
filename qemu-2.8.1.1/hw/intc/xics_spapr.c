/*
 * QEMU PowerPC pSeries Logical Partition (aka sPAPR) hardware System Emulator
 *
 * PAPR Virtualized Interrupt System, aka ICS/ICP aka xics
 *
 * Copyright (c) 2010,2011 David Gibson, IBM Corporation.
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
 *
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "hw/hw.h"
#include "trace.h"
#include "qemu/timer.h"
#include "hw/ppc/spapr.h"
#include "hw/ppc/xics.h"
#include "hw/ppc/fdt.h"
#include "qapi/visitor.h"
#include "qapi/error.h"

/*
 * Guest interfaces
 */

static target_ulong h_cppr(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                           target_ulong opcode, target_ulong *args)
{
    CPUState *cs = CPU(cpu);
    ICPState *icp = &spapr->xics->ss[cs->cpu_index];
    target_ulong cppr = args[0];

    icp_set_cppr(icp, cppr);
    return H_SUCCESS;
}

static target_ulong h_ipi(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                          target_ulong opcode, target_ulong *args)
{
    target_ulong server = xics_get_cpu_index_by_dt_id(args[0]);
    target_ulong mfrr = args[1];

    if (server >= spapr->xics->nr_servers) {
        return H_PARAMETER;
    }

    icp_set_mfrr(spapr->xics->ss + server, mfrr);
    return H_SUCCESS;
}

static target_ulong h_xirr(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                           target_ulong opcode, target_ulong *args)
{
    CPUState *cs = CPU(cpu);
    ICPState *icp = &spapr->xics->ss[cs->cpu_index];
    uint32_t xirr = icp_accept(icp);

    args[0] = xirr;
    return H_SUCCESS;
}

static target_ulong h_xirr_x(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                             target_ulong opcode, target_ulong *args)
{
    CPUState *cs = CPU(cpu);
    ICPState *icp = &spapr->xics->ss[cs->cpu_index];
    uint32_t xirr = icp_accept(icp);

    args[0] = xirr;
    args[1] = cpu_get_host_ticks();
    return H_SUCCESS;
}

static target_ulong h_eoi(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                          target_ulong opcode, target_ulong *args)
{
    CPUState *cs = CPU(cpu);
    ICPState *icp = &spapr->xics->ss[cs->cpu_index];
    target_ulong xirr = args[0];

    icp_eoi(icp, xirr);
    return H_SUCCESS;
}

static target_ulong h_ipoll(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                            target_ulong opcode, target_ulong *args)
{
    CPUState *cs = CPU(cpu);
    ICPState *icp = &spapr->xics->ss[cs->cpu_index];
    uint32_t mfrr;
    uint32_t xirr = icp_ipoll(icp, &mfrr);

    args[0] = xirr;
    args[1] = mfrr;

    return H_SUCCESS;
}

static void rtas_set_xive(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                          uint32_t token,
                          uint32_t nargs, target_ulong args,
                          uint32_t nret, target_ulong rets)
{
    ICSState *ics = QLIST_FIRST(&spapr->xics->ics);
    uint32_t nr, srcno, server, priority;

    if ((nargs != 3) || (nret != 1)) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }
    if (!ics) {
        rtas_st(rets, 0, RTAS_OUT_HW_ERROR);
        return;
    }

    nr = rtas_ld(args, 0);
    server = xics_get_cpu_index_by_dt_id(rtas_ld(args, 1));
    priority = rtas_ld(args, 2);

    if (!ics_valid_irq(ics, nr) || (server >= ics->xics->nr_servers)
        || (priority > 0xff)) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    srcno = nr - ics->offset;
    ics_simple_write_xive(ics, srcno, server, priority, priority);

    rtas_st(rets, 0, RTAS_OUT_SUCCESS);
}

static void rtas_get_xive(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                          uint32_t token,
                          uint32_t nargs, target_ulong args,
                          uint32_t nret, target_ulong rets)
{
    ICSState *ics = QLIST_FIRST(&spapr->xics->ics);
    uint32_t nr, srcno;

    if ((nargs != 1) || (nret != 3)) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }
    if (!ics) {
        rtas_st(rets, 0, RTAS_OUT_HW_ERROR);
        return;
    }

    nr = rtas_ld(args, 0);

    if (!ics_valid_irq(ics, nr)) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    rtas_st(rets, 0, RTAS_OUT_SUCCESS);
    srcno = nr - ics->offset;
    rtas_st(rets, 1, ics->irqs[srcno].server);
    rtas_st(rets, 2, ics->irqs[srcno].priority);
}

static void rtas_int_off(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                         uint32_t token,
                         uint32_t nargs, target_ulong args,
                         uint32_t nret, target_ulong rets)
{
    ICSState *ics = QLIST_FIRST(&spapr->xics->ics);
    uint32_t nr, srcno;

    if ((nargs != 1) || (nret != 1)) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }
    if (!ics) {
        rtas_st(rets, 0, RTAS_OUT_HW_ERROR);
        return;
    }

    nr = rtas_ld(args, 0);

    if (!ics_valid_irq(ics, nr)) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    srcno = nr - ics->offset;
    ics_simple_write_xive(ics, srcno, ics->irqs[srcno].server, 0xff,
                          ics->irqs[srcno].priority);

    rtas_st(rets, 0, RTAS_OUT_SUCCESS);
}

static void rtas_int_on(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                        uint32_t token,
                        uint32_t nargs, target_ulong args,
                        uint32_t nret, target_ulong rets)
{
    ICSState *ics = QLIST_FIRST(&spapr->xics->ics);
    uint32_t nr, srcno;

    if ((nargs != 1) || (nret != 1)) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }
    if (!ics) {
        rtas_st(rets, 0, RTAS_OUT_HW_ERROR);
        return;
    }

    nr = rtas_ld(args, 0);

    if (!ics_valid_irq(ics, nr)) {
        rtas_st(rets, 0, RTAS_OUT_PARAM_ERROR);
        return;
    }

    srcno = nr - ics->offset;
    ics_simple_write_xive(ics, srcno, ics->irqs[srcno].server,
                          ics->irqs[srcno].saved_priority,
                          ics->irqs[srcno].saved_priority);

    rtas_st(rets, 0, RTAS_OUT_SUCCESS);
}

static void xics_spapr_set_nr_irqs(XICSState *xics, uint32_t nr_irqs,
                                   Error **errp)
{
    ICSState *ics = QLIST_FIRST(&xics->ics);

    /* This needs to be deprecated ... */
    xics->nr_irqs = nr_irqs;
    if (ics) {
        ics->nr_irqs = nr_irqs;
    }
}

static void xics_spapr_set_nr_servers(XICSState *xics, uint32_t nr_servers,
                                      Error **errp)
{
    xics_set_nr_servers(xics, nr_servers, TYPE_ICP, errp);
}

static void xics_spapr_realize(DeviceState *dev, Error **errp)
{
    XICSState *xics = XICS_SPAPR(dev);
    ICSState *ics;
    Error *error = NULL;
    int i;

    if (!xics->nr_servers) {
        error_setg(errp, "Number of servers needs to be greater 0");
        return;
    }

    /* Registration of global state belongs into realize */
    spapr_rtas_register(RTAS_IBM_SET_XIVE, "ibm,set-xive", rtas_set_xive);
    spapr_rtas_register(RTAS_IBM_GET_XIVE, "ibm,get-xive", rtas_get_xive);
    spapr_rtas_register(RTAS_IBM_INT_OFF, "ibm,int-off", rtas_int_off);
    spapr_rtas_register(RTAS_IBM_INT_ON, "ibm,int-on", rtas_int_on);

    spapr_register_hypercall(H_CPPR, h_cppr);
    spapr_register_hypercall(H_IPI, h_ipi);
    spapr_register_hypercall(H_XIRR, h_xirr);
    spapr_register_hypercall(H_XIRR_X, h_xirr_x);
    spapr_register_hypercall(H_EOI, h_eoi);
    spapr_register_hypercall(H_IPOLL, h_ipoll);

    QLIST_FOREACH(ics, &xics->ics, list) {
        object_property_set_bool(OBJECT(ics), true, "realized", &error);
        if (error) {
            error_propagate(errp, error);
            return;
        }
    }

    for (i = 0; i < xics->nr_servers; i++) {
        object_property_set_bool(OBJECT(&xics->ss[i]), true, "realized",
                                 &error);
        if (error) {
            error_propagate(errp, error);
            return;
        }
    }
}

static void xics_spapr_initfn(Object *obj)
{
    XICSState *xics = XICS_SPAPR(obj);
    ICSState *ics;

    ics = ICS_SIMPLE(object_new(TYPE_ICS_SIMPLE));
    object_property_add_child(obj, "ics", OBJECT(ics), NULL);
    ics->xics = xics;
    QLIST_INSERT_HEAD(&xics->ics, ics, list);
}

static void xics_spapr_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    XICSStateClass *xsc = XICS_SPAPR_CLASS(oc);

    dc->realize = xics_spapr_realize;
    xsc->set_nr_irqs = xics_spapr_set_nr_irqs;
    xsc->set_nr_servers = xics_spapr_set_nr_servers;
}

static const TypeInfo xics_spapr_info = {
    .name          = TYPE_XICS_SPAPR,
    .parent        = TYPE_XICS_COMMON,
    .instance_size = sizeof(XICSState),
    .class_size = sizeof(XICSStateClass),
    .class_init    = xics_spapr_class_init,
    .instance_init = xics_spapr_initfn,
};

#define ICS_IRQ_FREE(ics, srcno)   \
    (!((ics)->irqs[(srcno)].flags & (XICS_FLAGS_IRQ_MASK)))

static int ics_find_free_block(ICSState *ics, int num, int alignnum)
{
    int first, i;

    for (first = 0; first < ics->nr_irqs; first += alignnum) {
        if (num > (ics->nr_irqs - first)) {
            return -1;
        }
        for (i = first; i < first + num; ++i) {
            if (!ICS_IRQ_FREE(ics, i)) {
                break;
            }
        }
        if (i == (first + num)) {
            return first;
        }
    }

    return -1;
}

int xics_spapr_alloc(XICSState *xics, int irq_hint, bool lsi, Error **errp)
{
    ICSState *ics = QLIST_FIRST(&xics->ics);
    int irq;

    if (!ics) {
        return -1;
    }
    if (irq_hint) {
        if (!ICS_IRQ_FREE(ics, irq_hint - ics->offset)) {
            error_setg(errp, "can't allocate IRQ %d: already in use", irq_hint);
            return -1;
        }
        irq = irq_hint;
    } else {
        irq = ics_find_free_block(ics, 1, 1);
        if (irq < 0) {
            error_setg(errp, "can't allocate IRQ: no IRQ left");
            return -1;
        }
        irq += ics->offset;
    }

    ics_set_irq_type(ics, irq - ics->offset, lsi);
    trace_xics_alloc(irq);

    return irq;
}

/*
 * Allocate block of consecutive IRQs, and return the number of the first IRQ in
 * the block. If align==true, aligns the first IRQ number to num.
 */
int xics_spapr_alloc_block(XICSState *xics, int num, bool lsi, bool align,
                           Error **errp)
{
    ICSState *ics = QLIST_FIRST(&xics->ics);
    int i, first = -1;

    if (!ics) {
        return -1;
    }

    /*
     * MSIMesage::data is used for storing VIRQ so
     * it has to be aligned to num to support multiple
     * MSI vectors. MSI-X is not affected by this.
     * The hint is used for the first IRQ, the rest should
     * be allocated continuously.
     */
    if (align) {
        assert((num == 1) || (num == 2) || (num == 4) ||
               (num == 8) || (num == 16) || (num == 32));
        first = ics_find_free_block(ics, num, num);
    } else {
        first = ics_find_free_block(ics, num, 1);
    }
    if (first < 0) {
        error_setg(errp, "can't find a free %d-IRQ block", num);
        return -1;
    }

    if (first >= 0) {
        for (i = first; i < first + num; ++i) {
            ics_set_irq_type(ics, i, lsi);
        }
    }
    first += ics->offset;

    trace_xics_alloc_block(first, num, lsi, align);

    return first;
}

static void ics_free(ICSState *ics, int srcno, int num)
{
    int i;

    for (i = srcno; i < srcno + num; ++i) {
        if (ICS_IRQ_FREE(ics, i)) {
            trace_xics_ics_free_warn(0, i + ics->offset);
        }
        memset(&ics->irqs[i], 0, sizeof(ICSIRQState));
    }
}

void xics_spapr_free(XICSState *xics, int irq, int num)
{
    ICSState *ics = xics_find_source(xics, irq);

    if (ics) {
        trace_xics_ics_free(0, irq, num);
        ics_free(ics, irq - ics->offset, num);
    }
}

void spapr_dt_xics(XICSState *xics, void *fdt, uint32_t phandle)
{
    uint32_t interrupt_server_ranges_prop[] = {
        0, cpu_to_be32(xics->nr_servers),
    };
    int node;

    _FDT(node = fdt_add_subnode(fdt, 0, "interrupt-controller"));

    _FDT(fdt_setprop_string(fdt, node, "device_type",
                            "PowerPC-External-Interrupt-Presentation"));
    _FDT(fdt_setprop_string(fdt, node, "compatible", "IBM,ppc-xicp"));
    _FDT(fdt_setprop(fdt, node, "interrupt-controller", NULL, 0));
    _FDT(fdt_setprop(fdt, node, "ibm,interrupt-server-ranges",
                     interrupt_server_ranges_prop,
                     sizeof(interrupt_server_ranges_prop)));
    _FDT(fdt_setprop_cell(fdt, node, "#interrupt-cells", 2));
    _FDT(fdt_setprop_cell(fdt, node, "linux,phandle", phandle));
    _FDT(fdt_setprop_cell(fdt, node, "phandle", phandle));
}

static void xics_spapr_register_types(void)
{
    type_register_static(&xics_spapr_info);
}

type_init(xics_spapr_register_types)
