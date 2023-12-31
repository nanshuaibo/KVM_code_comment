/*
 * ARM Generic Interrupt Controller v3
 *
 * Copyright (c) 2016 Linaro Limited
 * Written by Peter Maydell
 *
 * This code is licensed under the GPL, version 2 or (at your option)
 * any later version.
 */

/* This file contains the code for the system register interface
 * portions of the GICv3.
 */

#include "qemu/osdep.h"
#include "trace.h"
#include "gicv3_internal.h"
#include "cpu.h"

static GICv3CPUState *icc_cs_from_env(CPUARMState *env)
{
    /* Given the CPU, find the right GICv3CPUState struct.
     * Since we registered the CPU interface with the EL change hook as
     * the opaque pointer, we can just directly get from the CPU to it.
     */
    return arm_get_el_change_hook_opaque(arm_env_get_cpu(env));
}

static bool gicv3_use_ns_bank(CPUARMState *env)
{
    /* Return true if we should use the NonSecure bank for a banked GIC
     * CPU interface register. Note that this differs from the
     * access_secure_reg() function because GICv3 banked registers are
     * banked even for AArch64, unlike the other CPU system registers.
     */
    return !arm_is_secure_below_el3(env);
}

static int icc_highest_active_prio(GICv3CPUState *cs)
{
    /* Calculate the current running priority based on the set bits
     * in the Active Priority Registers.
     */
    int i;

    for (i = 0; i < ARRAY_SIZE(cs->icc_apr[0]); i++) {
        uint32_t apr = cs->icc_apr[GICV3_G0][i] |
            cs->icc_apr[GICV3_G1][i] | cs->icc_apr[GICV3_G1NS][i];

        if (!apr) {
            continue;
        }
        return (i * 32 + ctz32(apr)) << (GIC_MIN_BPR + 1);
    }
    /* No current active interrupts: return idle priority */
    return 0xff;
}

static uint32_t icc_gprio_mask(GICv3CPUState *cs, int group)
{
    /* Return a mask word which clears the subpriority bits from
     * a priority value for an interrupt in the specified group.
     * This depends on the BPR value:
     *  a BPR of 0 means the group priority bits are [7:1];
     *  a BPR of 1 means they are [7:2], and so on down to
     *  a BPR of 7 meaning no group priority bits at all.
     * Which BPR to use depends on the group of the interrupt and
     * the current ICC_CTLR.CBPR settings.
     */
    if ((group == GICV3_G1 && cs->icc_ctlr_el1[GICV3_S] & ICC_CTLR_EL1_CBPR) ||
        (group == GICV3_G1NS &&
         cs->icc_ctlr_el1[GICV3_NS] & ICC_CTLR_EL1_CBPR)) {
        group = GICV3_G0;
    }

    return ~0U << ((cs->icc_bpr[group] & 7) + 1);
}

static bool icc_no_enabled_hppi(GICv3CPUState *cs)
{
    /* Return true if there is no pending interrupt, or the
     * highest priority pending interrupt is in a group which has been
     * disabled at the CPU interface by the ICC_IGRPEN* register enable bits.
     */
    return cs->hppi.prio == 0xff || (cs->icc_igrpen[cs->hppi.grp] == 0);
}

static bool icc_hppi_can_preempt(GICv3CPUState *cs)
{
    /* Return true if we have a pending interrupt of sufficient
     * priority to preempt.
     */
    int rprio;
    uint32_t mask;

    if (icc_no_enabled_hppi(cs)) {
        return false;
    }

    if (cs->hppi.prio >= cs->icc_pmr_el1) {
        /* Priority mask masks this interrupt */
        return false;
    }

    rprio = icc_highest_active_prio(cs);
    if (rprio == 0xff) {
        /* No currently running interrupt so we can preempt */
        return true;
    }

    mask = icc_gprio_mask(cs, cs->hppi.grp);

    /* We only preempt a running interrupt if the pending interrupt's
     * group priority is sufficient (the subpriorities are not considered).
     */
    if ((cs->hppi.prio & mask) < (rprio & mask)) {
        return true;
    }

    return false;
}

void gicv3_cpuif_update(GICv3CPUState *cs)
{
    /* Tell the CPU about its highest priority pending interrupt */
    int irqlevel = 0;
    int fiqlevel = 0;
    ARMCPU *cpu = ARM_CPU(cs->cpu);
    CPUARMState *env = &cpu->env;

    trace_gicv3_cpuif_update(gicv3_redist_affid(cs), cs->hppi.irq,
                             cs->hppi.grp, cs->hppi.prio);

    if (cs->hppi.grp == GICV3_G1 && !arm_feature(env, ARM_FEATURE_EL3)) {
        /* If a Security-enabled GIC sends a G1S interrupt to a
         * Security-disabled CPU, we must treat it as if it were G0.
         */
        cs->hppi.grp = GICV3_G0;
    }

    if (icc_hppi_can_preempt(cs)) {
        /* We have an interrupt: should we signal it as IRQ or FIQ?
         * This is described in the GICv3 spec section 4.6.2.
         */
        bool isfiq;

        switch (cs->hppi.grp) {
        case GICV3_G0:
            isfiq = true;
            break;
        case GICV3_G1:
            isfiq = (!arm_is_secure(env) ||
                     (arm_current_el(env) == 3 && arm_el_is_aa64(env, 3)));
            break;
        case GICV3_G1NS:
            isfiq = arm_is_secure(env);
            break;
        default:
            g_assert_not_reached();
        }

        if (isfiq) {
            fiqlevel = 1;
        } else {
            irqlevel = 1;
        }
    }

    trace_gicv3_cpuif_set_irqs(gicv3_redist_affid(cs), fiqlevel, irqlevel);

    qemu_set_irq(cs->parent_fiq, fiqlevel);
    qemu_set_irq(cs->parent_irq, irqlevel);
}

static uint64_t icc_pmr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    uint32_t value = cs->icc_pmr_el1;

    if (arm_feature(env, ARM_FEATURE_EL3) && !arm_is_secure(env) &&
        (env->cp15.scr_el3 & SCR_FIQ)) {
        /* NS access and Group 0 is inaccessible to NS: return the
         * NS view of the current priority
         */
        if (value & 0x80) {
            /* Secure priorities not visible to NS */
            value = 0;
        } else if (value != 0xff) {
            value = (value << 1) & 0xff;
        }
    }

    trace_gicv3_icc_pmr_read(gicv3_redist_affid(cs), value);

    return value;
}

static void icc_pmr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                          uint64_t value)
{
    GICv3CPUState *cs = icc_cs_from_env(env);

    trace_gicv3_icc_pmr_write(gicv3_redist_affid(cs), value);

    value &= 0xff;

    if (arm_feature(env, ARM_FEATURE_EL3) && !arm_is_secure(env) &&
        (env->cp15.scr_el3 & SCR_FIQ)) {
        /* NS access and Group 0 is inaccessible to NS: return the
         * NS view of the current priority
         */
        if (!(cs->icc_pmr_el1 & 0x80)) {
            /* Current PMR in the secure range, don't allow NS to change it */
            return;
        }
        value = (value >> 1) & 0x80;
    }
    cs->icc_pmr_el1 = value;
    gicv3_cpuif_update(cs);
}

static void icc_activate_irq(GICv3CPUState *cs, int irq)
{
    /* Move the interrupt from the Pending state to Active, and update
     * the Active Priority Registers
     */
    uint32_t mask = icc_gprio_mask(cs, cs->hppi.grp);
    int prio = cs->hppi.prio & mask;
    int aprbit = prio >> 1;
    int regno = aprbit / 32;
    int regbit = aprbit % 32;

    cs->icc_apr[cs->hppi.grp][regno] |= (1 << regbit);

    if (irq < GIC_INTERNAL) {
        cs->gicr_iactiver0 = deposit32(cs->gicr_iactiver0, irq, 1, 1);
        cs->gicr_ipendr0 = deposit32(cs->gicr_ipendr0, irq, 1, 0);
        gicv3_redist_update(cs);
    } else {
        gicv3_gicd_active_set(cs->gic, irq);
        gicv3_gicd_pending_clear(cs->gic, irq);
        gicv3_update(cs->gic, irq, 1);
    }
}

static uint64_t icc_hppir0_value(GICv3CPUState *cs, CPUARMState *env)
{
    /* Return the highest priority pending interrupt register value
     * for group 0.
     */
    bool irq_is_secure;

    if (cs->hppi.prio == 0xff) {
        return INTID_SPURIOUS;
    }

    /* Check whether we can return the interrupt or if we should return
     * a special identifier, as per the CheckGroup0ForSpecialIdentifiers
     * pseudocode. (We can simplify a little because for us ICC_SRE_EL1.RM
     * is always zero.)
     */
    irq_is_secure = (!(cs->gic->gicd_ctlr & GICD_CTLR_DS) &&
                     (cs->hppi.grp != GICV3_G1NS));

    if (cs->hppi.grp != GICV3_G0 && !arm_is_el3_or_mon(env)) {
        return INTID_SPURIOUS;
    }
    if (irq_is_secure && !arm_is_secure(env)) {
        /* Secure interrupts not visible to Nonsecure */
        return INTID_SPURIOUS;
    }

    if (cs->hppi.grp != GICV3_G0) {
        /* Indicate to EL3 that there's a Group 1 interrupt for the other
         * state pending.
         */
        return irq_is_secure ? INTID_SECURE : INTID_NONSECURE;
    }

    return cs->hppi.irq;
}

static uint64_t icc_hppir1_value(GICv3CPUState *cs, CPUARMState *env)
{
    /* Return the highest priority pending interrupt register value
     * for group 1.
     */
    bool irq_is_secure;

    if (cs->hppi.prio == 0xff) {
        return INTID_SPURIOUS;
    }

    /* Check whether we can return the interrupt or if we should return
     * a special identifier, as per the CheckGroup1ForSpecialIdentifiers
     * pseudocode. (We can simplify a little because for us ICC_SRE_EL1.RM
     * is always zero.)
     */
    irq_is_secure = (!(cs->gic->gicd_ctlr & GICD_CTLR_DS) &&
                     (cs->hppi.grp != GICV3_G1NS));

    if (cs->hppi.grp == GICV3_G0) {
        /* Group 0 interrupts not visible via HPPIR1 */
        return INTID_SPURIOUS;
    }
    if (irq_is_secure) {
        if (!arm_is_secure(env)) {
            /* Secure interrupts not visible in Non-secure */
            return INTID_SPURIOUS;
        }
    } else if (!arm_is_el3_or_mon(env) && arm_is_secure(env)) {
        /* Group 1 non-secure interrupts not visible in Secure EL1 */
        return INTID_SPURIOUS;
    }

    return cs->hppi.irq;
}

static uint64_t icc_iar0_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    uint64_t intid;

    if (!icc_hppi_can_preempt(cs)) {
        intid = INTID_SPURIOUS;
    } else {
        intid = icc_hppir0_value(cs, env);
    }

    if (!(intid >= INTID_SECURE && intid <= INTID_SPURIOUS)) {
        icc_activate_irq(cs, intid);
    }

    trace_gicv3_icc_iar0_read(gicv3_redist_affid(cs), intid);
    return intid;
}

static uint64_t icc_iar1_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    uint64_t intid;

    if (!icc_hppi_can_preempt(cs)) {
        intid = INTID_SPURIOUS;
    } else {
        intid = icc_hppir1_value(cs, env);
    }

    if (!(intid >= INTID_SECURE && intid <= INTID_SPURIOUS)) {
        icc_activate_irq(cs, intid);
    }

    trace_gicv3_icc_iar1_read(gicv3_redist_affid(cs), intid);
    return intid;
}

static void icc_drop_prio(GICv3CPUState *cs, int grp)
{
    /* Drop the priority of the currently active interrupt in
     * the specified group.
     *
     * Note that we can guarantee (because of the requirement to nest
     * ICC_IAR reads [which activate an interrupt and raise priority]
     * with ICC_EOIR writes [which drop the priority for the interrupt])
     * that the interrupt we're being called for is the highest priority
     * active interrupt, meaning that it has the lowest set bit in the
     * APR registers.
     *
     * If the guest does not honour the ordering constraints then the
     * behaviour of the GIC is UNPREDICTABLE, which for us means that
     * the values of the APR registers might become incorrect and the
     * running priority will be wrong, so interrupts that should preempt
     * might not do so, and interrupts that should not preempt might do so.
     */
    int i;

    for (i = 0; i < ARRAY_SIZE(cs->icc_apr[grp]); i++) {
        uint64_t *papr = &cs->icc_apr[grp][i];

        if (!*papr) {
            continue;
        }
        /* Clear the lowest set bit */
        *papr &= *papr - 1;
        break;
    }

    /* running priority change means we need an update for this cpu i/f */
    gicv3_cpuif_update(cs);
}

static bool icc_eoi_split(CPUARMState *env, GICv3CPUState *cs)
{
    /* Return true if we should split priority drop and interrupt
     * deactivation, ie whether the relevant EOIMode bit is set.
     */
    if (arm_is_el3_or_mon(env)) {
        return cs->icc_ctlr_el3 & ICC_CTLR_EL3_EOIMODE_EL3;
    }
    if (arm_is_secure_below_el3(env)) {
        return cs->icc_ctlr_el1[GICV3_S] & ICC_CTLR_EL1_EOIMODE;
    } else {
        return cs->icc_ctlr_el1[GICV3_NS] & ICC_CTLR_EL1_EOIMODE;
    }
}

static int icc_highest_active_group(GICv3CPUState *cs)
{
    /* Return the group with the highest priority active interrupt.
     * We can do this by just comparing the APRs to see which one
     * has the lowest set bit.
     * (If more than one group is active at the same priority then
     * we're in UNPREDICTABLE territory.)
     */
    int i;

    for (i = 0; i < ARRAY_SIZE(cs->icc_apr[0]); i++) {
        int g0ctz = ctz32(cs->icc_apr[GICV3_G0][i]);
        int g1ctz = ctz32(cs->icc_apr[GICV3_G1][i]);
        int g1nsctz = ctz32(cs->icc_apr[GICV3_G1NS][i]);

        if (g1nsctz < g0ctz && g1nsctz < g1ctz) {
            return GICV3_G1NS;
        }
        if (g1ctz < g0ctz) {
            return GICV3_G1;
        }
        if (g0ctz < 32) {
            return GICV3_G0;
        }
    }
    /* No set active bits? UNPREDICTABLE; return -1 so the caller
     * ignores the spurious EOI attempt.
     */
    return -1;
}

static void icc_deactivate_irq(GICv3CPUState *cs, int irq)
{
    if (irq < GIC_INTERNAL) {
        cs->gicr_iactiver0 = deposit32(cs->gicr_iactiver0, irq, 1, 0);
        gicv3_redist_update(cs);
    } else {
        gicv3_gicd_active_clear(cs->gic, irq);
        gicv3_update(cs->gic, irq, 1);
    }
}

static void icc_eoir_write(CPUARMState *env, const ARMCPRegInfo *ri,
                           uint64_t value)
{
    /* End of Interrupt */
    GICv3CPUState *cs = icc_cs_from_env(env);
    int irq = value & 0xffffff;
    int grp;

    trace_gicv3_icc_eoir_write(ri->crm == 8 ? 0 : 1,
                               gicv3_redist_affid(cs), value);

    if (ri->crm == 8) {
        /* EOIR0 */
        grp = GICV3_G0;
    } else {
        /* EOIR1 */
        if (arm_is_secure(env)) {
            grp = GICV3_G1;
        } else {
            grp = GICV3_G1NS;
        }
    }

    if (irq >= cs->gic->num_irq) {
        /* This handles two cases:
         * 1. If software writes the ID of a spurious interrupt [ie 1020-1023]
         * to the GICC_EOIR, the GIC ignores that write.
         * 2. If software writes the number of a non-existent interrupt
         * this must be a subcase of "value written does not match the last
         * valid interrupt value read from the Interrupt Acknowledge
         * register" and so this is UNPREDICTABLE. We choose to ignore it.
         */
        return;
    }

    if (icc_highest_active_group(cs) != grp) {
        return;
    }

    icc_drop_prio(cs, grp);

    if (!icc_eoi_split(env, cs)) {
        /* Priority drop and deactivate not split: deactivate irq now */
        icc_deactivate_irq(cs, irq);
    }
}

static uint64_t icc_hppir0_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    uint64_t value = icc_hppir0_value(cs, env);

    trace_gicv3_icc_hppir0_read(gicv3_redist_affid(cs), value);
    return value;
}

static uint64_t icc_hppir1_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    uint64_t value = icc_hppir1_value(cs, env);

    trace_gicv3_icc_hppir1_read(gicv3_redist_affid(cs), value);
    return value;
}

static uint64_t icc_bpr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    int grp = (ri->crm == 8) ? GICV3_G0 : GICV3_G1;
    bool satinc = false;
    uint64_t bpr;

    if (grp == GICV3_G1 && gicv3_use_ns_bank(env)) {
        grp = GICV3_G1NS;
    }

    if (grp == GICV3_G1 && !arm_is_el3_or_mon(env) &&
        (cs->icc_ctlr_el1[GICV3_S] & ICC_CTLR_EL1_CBPR)) {
        /* CBPR_EL1S means secure EL1 or AArch32 EL3 !Mon BPR1 accesses
         * modify BPR0
         */
        grp = GICV3_G0;
    }

    if (grp == GICV3_G1NS && arm_current_el(env) < 3 &&
        (cs->icc_ctlr_el1[GICV3_NS] & ICC_CTLR_EL1_CBPR)) {
        /* reads return bpr0 + 1 sat to 7, writes ignored */
        grp = GICV3_G0;
        satinc = true;
    }

    bpr = cs->icc_bpr[grp];
    if (satinc) {
        bpr++;
        bpr = MIN(bpr, 7);
    }

    trace_gicv3_icc_bpr_read(ri->crm == 8 ? 0 : 1, gicv3_redist_affid(cs), bpr);

    return bpr;
}

static void icc_bpr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                          uint64_t value)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    int grp = (ri->crm == 8) ? GICV3_G0 : GICV3_G1;

    trace_gicv3_icc_bpr_write(ri->crm == 8 ? 0 : 1,
                              gicv3_redist_affid(cs), value);

    if (grp == GICV3_G1 && gicv3_use_ns_bank(env)) {
        grp = GICV3_G1NS;
    }

    if (grp == GICV3_G1 && !arm_is_el3_or_mon(env) &&
        (cs->icc_ctlr_el1[GICV3_S] & ICC_CTLR_EL1_CBPR)) {
        /* CBPR_EL1S means secure EL1 or AArch32 EL3 !Mon BPR1 accesses
         * modify BPR0
         */
        grp = GICV3_G0;
    }

    if (grp == GICV3_G1NS && arm_current_el(env) < 3 &&
        (cs->icc_ctlr_el1[GICV3_NS] & ICC_CTLR_EL1_CBPR)) {
        /* reads return bpr0 + 1 sat to 7, writes ignored */
        return;
    }

    cs->icc_bpr[grp] = value & 7;
    gicv3_cpuif_update(cs);
}

static uint64_t icc_ap_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    uint64_t value;

    int regno = ri->opc2 & 3;
    int grp = ri->crm & 1 ? GICV3_G0 : GICV3_G1;

    if (grp == GICV3_G1 && gicv3_use_ns_bank(env)) {
        grp = GICV3_G1NS;
    }

    value = cs->icc_apr[grp][regno];

    trace_gicv3_icc_ap_read(ri->crm & 1, regno, gicv3_redist_affid(cs), value);
    return value;
}

static void icc_ap_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    GICv3CPUState *cs = icc_cs_from_env(env);

    int regno = ri->opc2 & 3;
    int grp = ri->crm & 1 ? GICV3_G0 : GICV3_G1;

    trace_gicv3_icc_ap_write(ri->crm & 1, regno, gicv3_redist_affid(cs), value);

    if (grp == GICV3_G1 && gicv3_use_ns_bank(env)) {
        grp = GICV3_G1NS;
    }

    /* It's not possible to claim that a Non-secure interrupt is active
     * at a priority outside the Non-secure range (128..255), since this
     * would otherwise allow malicious NS code to block delivery of S interrupts
     * by writing a bad value to these registers.
     */
    if (grp == GICV3_G1NS && regno < 2 && arm_feature(env, ARM_FEATURE_EL3)) {
        return;
    }

    cs->icc_apr[grp][regno] = value & 0xFFFFFFFFU;
    gicv3_cpuif_update(cs);
}

static void icc_dir_write(CPUARMState *env, const ARMCPRegInfo *ri,
                          uint64_t value)
{
    /* Deactivate interrupt */
    GICv3CPUState *cs = icc_cs_from_env(env);
    int irq = value & 0xffffff;
    bool irq_is_secure, single_sec_state, irq_is_grp0;
    bool route_fiq_to_el3, route_irq_to_el3, route_fiq_to_el2, route_irq_to_el2;

    trace_gicv3_icc_dir_write(gicv3_redist_affid(cs), value);

    if (irq >= cs->gic->num_irq) {
        /* Also catches special interrupt numbers and LPIs */
        return;
    }

    if (!icc_eoi_split(env, cs)) {
        return;
    }

    int grp = gicv3_irq_group(cs->gic, cs, irq);

    single_sec_state = cs->gic->gicd_ctlr & GICD_CTLR_DS;
    irq_is_secure = !single_sec_state && (grp != GICV3_G1NS);
    irq_is_grp0 = grp == GICV3_G0;

    /* Check whether we're allowed to deactivate this interrupt based
     * on its group and the current CPU state.
     * These checks are laid out to correspond to the spec's pseudocode.
     */
    route_fiq_to_el3 = env->cp15.scr_el3 & SCR_FIQ;
    route_irq_to_el3 = env->cp15.scr_el3 & SCR_IRQ;
    /* No need to include !IsSecure in route_*_to_el2 as it's only
     * tested in cases where we know !IsSecure is true.
     */
    route_fiq_to_el2 = env->cp15.hcr_el2 & HCR_FMO;
    route_irq_to_el2 = env->cp15.hcr_el2 & HCR_FMO;

    switch (arm_current_el(env)) {
    case 3:
        break;
    case 2:
        if (single_sec_state && irq_is_grp0 && !route_fiq_to_el3) {
            break;
        }
        if (!irq_is_secure && !irq_is_grp0 && !route_irq_to_el3) {
            break;
        }
        return;
    case 1:
        if (!arm_is_secure_below_el3(env)) {
            if (single_sec_state && irq_is_grp0 &&
                !route_fiq_to_el3 && !route_fiq_to_el2) {
                break;
            }
            if (!irq_is_secure && !irq_is_grp0 &&
                !route_irq_to_el3 && !route_irq_to_el2) {
                break;
            }
        } else {
            if (irq_is_grp0 && !route_fiq_to_el3) {
                break;
            }
            if (!irq_is_grp0 &&
                (!irq_is_secure || !single_sec_state) &&
                !route_irq_to_el3) {
                break;
            }
        }
        return;
    default:
        g_assert_not_reached();
    }

    icc_deactivate_irq(cs, irq);
}

static uint64_t icc_rpr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    int prio = icc_highest_active_prio(cs);

    if (arm_feature(env, ARM_FEATURE_EL3) &&
        !arm_is_secure(env) && (env->cp15.scr_el3 & SCR_FIQ)) {
        /* NS GIC access and Group 0 is inaccessible to NS */
        if (prio & 0x80) {
            /* NS mustn't see priorities in the Secure half of the range */
            prio = 0;
        } else if (prio != 0xff) {
            /* Non-idle priority: show the Non-secure view of it */
            prio = (prio << 1) & 0xff;
        }
    }

    trace_gicv3_icc_rpr_read(gicv3_redist_affid(cs), prio);
    return prio;
}

static void icc_generate_sgi(CPUARMState *env, GICv3CPUState *cs,
                             uint64_t value, int grp, bool ns)
{
    GICv3State *s = cs->gic;

    /* Extract Aff3/Aff2/Aff1 and shift into the bottom 24 bits */
    uint64_t aff = extract64(value, 48, 8) << 16 |
        extract64(value, 32, 8) << 8 |
        extract64(value, 16, 8);
    uint32_t targetlist = extract64(value, 0, 16);
    uint32_t irq = extract64(value, 24, 4);
    bool irm = extract64(value, 40, 1);
    int i;

    if (grp == GICV3_G1 && s->gicd_ctlr & GICD_CTLR_DS) {
        /* If GICD_CTLR.DS == 1, the Distributor treats Secure Group 1
         * interrupts as Group 0 interrupts and must send Secure Group 0
         * interrupts to the target CPUs.
         */
        grp = GICV3_G0;
    }

    trace_gicv3_icc_generate_sgi(gicv3_redist_affid(cs), irq, irm,
                                 aff, targetlist);

    for (i = 0; i < s->num_cpu; i++) {
        GICv3CPUState *ocs = &s->cpu[i];

        if (irm) {
            /* IRM == 1 : route to all CPUs except self */
            if (cs == ocs) {
                continue;
            }
        } else {
            /* IRM == 0 : route to Aff3.Aff2.Aff1.n for all n in [0..15]
             * where the corresponding bit is set in targetlist
             */
            int aff0;

            if (ocs->gicr_typer >> 40 != aff) {
                continue;
            }
            aff0 = extract64(ocs->gicr_typer, 32, 8);
            if (aff0 > 15 || extract32(targetlist, aff0, 1) == 0) {
                continue;
            }
        }

        /* The redistributor will check against its own GICR_NSACR as needed */
        gicv3_redist_send_sgi(ocs, grp, irq, ns);
    }
}

static void icc_sgi0r_write(CPUARMState *env, const ARMCPRegInfo *ri,
                           uint64_t value)
{
    /* Generate Secure Group 0 SGI. */
    GICv3CPUState *cs = icc_cs_from_env(env);
    bool ns = !arm_is_secure(env);

    icc_generate_sgi(env, cs, value, GICV3_G0, ns);
}

static void icc_sgi1r_write(CPUARMState *env, const ARMCPRegInfo *ri,
                           uint64_t value)
{
    /* Generate Group 1 SGI for the current Security state */
    GICv3CPUState *cs = icc_cs_from_env(env);
    int grp;
    bool ns = !arm_is_secure(env);

    grp = ns ? GICV3_G1NS : GICV3_G1;
    icc_generate_sgi(env, cs, value, grp, ns);
}

static void icc_asgi1r_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    /* Generate Group 1 SGI for the Security state that is not
     * the current state
     */
    GICv3CPUState *cs = icc_cs_from_env(env);
    int grp;
    bool ns = !arm_is_secure(env);

    grp = ns ? GICV3_G1 : GICV3_G1NS;
    icc_generate_sgi(env, cs, value, grp, ns);
}

static uint64_t icc_igrpen_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    int grp = ri->opc2 & 1 ? GICV3_G1 : GICV3_G0;
    uint64_t value;

    if (grp == GICV3_G1 && gicv3_use_ns_bank(env)) {
        grp = GICV3_G1NS;
    }

    value = cs->icc_igrpen[grp];
    trace_gicv3_icc_igrpen_read(ri->opc2 & 1 ? 1 : 0,
                                gicv3_redist_affid(cs), value);
    return value;
}

static void icc_igrpen_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    int grp = ri->opc2 & 1 ? GICV3_G1 : GICV3_G0;

    trace_gicv3_icc_igrpen_write(ri->opc2 & 1 ? 1 : 0,
                                 gicv3_redist_affid(cs), value);

    if (grp == GICV3_G1 && gicv3_use_ns_bank(env)) {
        grp = GICV3_G1NS;
    }

    cs->icc_igrpen[grp] = value & ICC_IGRPEN_ENABLE;
    gicv3_cpuif_update(cs);
}

static uint64_t icc_igrpen1_el3_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    uint64_t value;

    /* IGRPEN1_EL3 bits 0 and 1 are r/w aliases into IGRPEN1_EL1 NS and S */
    value = cs->icc_igrpen[GICV3_G1NS] | (cs->icc_igrpen[GICV3_G1] << 1);
    trace_gicv3_icc_igrpen1_el3_read(gicv3_redist_affid(cs), value);
    return value;
}

static void icc_igrpen1_el3_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                  uint64_t value)
{
    GICv3CPUState *cs = icc_cs_from_env(env);

    trace_gicv3_icc_igrpen1_el3_write(gicv3_redist_affid(cs), value);

    /* IGRPEN1_EL3 bits 0 and 1 are r/w aliases into IGRPEN1_EL1 NS and S */
    cs->icc_igrpen[GICV3_G1NS] = extract32(value, 0, 1);
    cs->icc_igrpen[GICV3_G1] = extract32(value, 1, 1);
    gicv3_cpuif_update(cs);
}

static uint64_t icc_ctlr_el1_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    int bank = gicv3_use_ns_bank(env) ? GICV3_NS : GICV3_S;
    uint64_t value;

    value = cs->icc_ctlr_el1[bank];
    trace_gicv3_icc_ctlr_read(gicv3_redist_affid(cs), value);
    return value;
}

static void icc_ctlr_el1_write(CPUARMState *env, const ARMCPRegInfo *ri,
                               uint64_t value)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    int bank = gicv3_use_ns_bank(env) ? GICV3_NS : GICV3_S;
    uint64_t mask;

    trace_gicv3_icc_ctlr_write(gicv3_redist_affid(cs), value);

    /* Only CBPR and EOIMODE can be RW;
     * for us PMHE is RAZ/WI (we don't implement 1-of-N interrupts or
     * the asseciated priority-based routing of them);
     * if EL3 is implemented and GICD_CTLR.DS == 0, then PMHE and CBPR are RO.
     */
    if (arm_feature(env, ARM_FEATURE_EL3) &&
        ((cs->gic->gicd_ctlr & GICD_CTLR_DS) == 0)) {
        mask = ICC_CTLR_EL1_EOIMODE;
    } else {
        mask = ICC_CTLR_EL1_CBPR | ICC_CTLR_EL1_EOIMODE;
    }

    cs->icc_ctlr_el1[bank] &= ~mask;
    cs->icc_ctlr_el1[bank] |= (value & mask);
    gicv3_cpuif_update(cs);
}


static uint64_t icc_ctlr_el3_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    uint64_t value;

    value = cs->icc_ctlr_el3;
    if (cs->icc_ctlr_el1[GICV3_NS] & ICC_CTLR_EL1_EOIMODE) {
        value |= ICC_CTLR_EL3_EOIMODE_EL1NS;
    }
    if (cs->icc_ctlr_el1[GICV3_NS] & ICC_CTLR_EL1_CBPR) {
        value |= ICC_CTLR_EL3_CBPR_EL1NS;
    }
    if (cs->icc_ctlr_el1[GICV3_NS] & ICC_CTLR_EL1_EOIMODE) {
        value |= ICC_CTLR_EL3_EOIMODE_EL1S;
    }
    if (cs->icc_ctlr_el1[GICV3_NS] & ICC_CTLR_EL1_CBPR) {
        value |= ICC_CTLR_EL3_CBPR_EL1S;
    }

    trace_gicv3_icc_ctlr_el3_read(gicv3_redist_affid(cs), value);
    return value;
}

static void icc_ctlr_el3_write(CPUARMState *env, const ARMCPRegInfo *ri,
                               uint64_t value)
{
    GICv3CPUState *cs = icc_cs_from_env(env);
    uint64_t mask;

    trace_gicv3_icc_ctlr_el3_write(gicv3_redist_affid(cs), value);

    /* *_EL1NS and *_EL1S bits are aliases into the ICC_CTLR_EL1 bits. */
    cs->icc_ctlr_el1[GICV3_NS] &= (ICC_CTLR_EL1_CBPR | ICC_CTLR_EL1_EOIMODE);
    if (value & ICC_CTLR_EL3_EOIMODE_EL1NS) {
        cs->icc_ctlr_el1[GICV3_NS] |= ICC_CTLR_EL1_EOIMODE;
    }
    if (value & ICC_CTLR_EL3_CBPR_EL1NS) {
        cs->icc_ctlr_el1[GICV3_NS] |= ICC_CTLR_EL1_CBPR;
    }

    cs->icc_ctlr_el1[GICV3_S] &= (ICC_CTLR_EL1_CBPR | ICC_CTLR_EL1_EOIMODE);
    if (value & ICC_CTLR_EL3_EOIMODE_EL1S) {
        cs->icc_ctlr_el1[GICV3_S] |= ICC_CTLR_EL1_EOIMODE;
    }
    if (value & ICC_CTLR_EL3_CBPR_EL1S) {
        cs->icc_ctlr_el1[GICV3_S] |= ICC_CTLR_EL1_CBPR;
    }

    /* The only bit stored in icc_ctlr_el3 which is writeable is EOIMODE_EL3: */
    mask = ICC_CTLR_EL3_EOIMODE_EL3;

    cs->icc_ctlr_el3 &= ~mask;
    cs->icc_ctlr_el3 |= (value & mask);
    gicv3_cpuif_update(cs);
}

static CPAccessResult gicv3_irqfiq_access(CPUARMState *env,
                                          const ARMCPRegInfo *ri, bool isread)
{
    CPAccessResult r = CP_ACCESS_OK;

    if ((env->cp15.scr_el3 & (SCR_FIQ | SCR_IRQ)) == (SCR_FIQ | SCR_IRQ)) {
        switch (arm_current_el(env)) {
        case 1:
            if (arm_is_secure_below_el3(env) ||
                ((env->cp15.hcr_el2 & (HCR_IMO | HCR_FMO)) == 0)) {
                r = CP_ACCESS_TRAP_EL3;
            }
            break;
        case 2:
            r = CP_ACCESS_TRAP_EL3;
            break;
        case 3:
            if (!is_a64(env) && !arm_is_el3_or_mon(env)) {
                r = CP_ACCESS_TRAP_EL3;
            }
            break;
        default:
            g_assert_not_reached();
        }
    }

    if (r == CP_ACCESS_TRAP_EL3 && !arm_el_is_aa64(env, 3)) {
        r = CP_ACCESS_TRAP;
    }
    return r;
}

static CPAccessResult gicv3_fiq_access(CPUARMState *env,
                                       const ARMCPRegInfo *ri, bool isread)
{
    CPAccessResult r = CP_ACCESS_OK;

    if (env->cp15.scr_el3 & SCR_FIQ) {
        switch (arm_current_el(env)) {
        case 1:
            if (arm_is_secure_below_el3(env) ||
                ((env->cp15.hcr_el2 & HCR_FMO) == 0)) {
                r = CP_ACCESS_TRAP_EL3;
            }
            break;
        case 2:
            r = CP_ACCESS_TRAP_EL3;
            break;
        case 3:
            if (!is_a64(env) && !arm_is_el3_or_mon(env)) {
                r = CP_ACCESS_TRAP_EL3;
            }
            break;
        default:
            g_assert_not_reached();
        }
    }

    if (r == CP_ACCESS_TRAP_EL3 && !arm_el_is_aa64(env, 3)) {
        r = CP_ACCESS_TRAP;
    }
    return r;
}

static CPAccessResult gicv3_irq_access(CPUARMState *env,
                                       const ARMCPRegInfo *ri, bool isread)
{
    CPAccessResult r = CP_ACCESS_OK;

    if (env->cp15.scr_el3 & SCR_IRQ) {
        switch (arm_current_el(env)) {
        case 1:
            if (arm_is_secure_below_el3(env) ||
                ((env->cp15.hcr_el2 & HCR_IMO) == 0)) {
                r = CP_ACCESS_TRAP_EL3;
            }
            break;
        case 2:
            r = CP_ACCESS_TRAP_EL3;
            break;
        case 3:
            if (!is_a64(env) && !arm_is_el3_or_mon(env)) {
                r = CP_ACCESS_TRAP_EL3;
            }
            break;
        default:
            g_assert_not_reached();
        }
    }

    if (r == CP_ACCESS_TRAP_EL3 && !arm_el_is_aa64(env, 3)) {
        r = CP_ACCESS_TRAP;
    }
    return r;
}

static void icc_reset(CPUARMState *env, const ARMCPRegInfo *ri)
{
    GICv3CPUState *cs = icc_cs_from_env(env);

    cs->icc_ctlr_el1[GICV3_S] = ICC_CTLR_EL1_A3V |
        (1 << ICC_CTLR_EL1_IDBITS_SHIFT) |
        (7 << ICC_CTLR_EL1_PRIBITS_SHIFT);
    cs->icc_ctlr_el1[GICV3_NS] = ICC_CTLR_EL1_A3V |
        (1 << ICC_CTLR_EL1_IDBITS_SHIFT) |
        (7 << ICC_CTLR_EL1_PRIBITS_SHIFT);
    cs->icc_pmr_el1 = 0;
    cs->icc_bpr[GICV3_G0] = GIC_MIN_BPR;
    cs->icc_bpr[GICV3_G1] = GIC_MIN_BPR;
    if (arm_feature(env, ARM_FEATURE_EL3)) {
        cs->icc_bpr[GICV3_G1NS] = GIC_MIN_BPR_NS;
    } else {
        cs->icc_bpr[GICV3_G1NS] = GIC_MIN_BPR;
    }
    memset(cs->icc_apr, 0, sizeof(cs->icc_apr));
    memset(cs->icc_igrpen, 0, sizeof(cs->icc_igrpen));
    cs->icc_ctlr_el3 = ICC_CTLR_EL3_NDS | ICC_CTLR_EL3_A3V |
        (1 << ICC_CTLR_EL3_IDBITS_SHIFT) |
        (7 << ICC_CTLR_EL3_PRIBITS_SHIFT);
}

static const ARMCPRegInfo gicv3_cpuif_reginfo[] = {
    { .name = "ICC_PMR_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 4, .crm = 6, .opc2 = 0,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_irqfiq_access,
      .readfn = icc_pmr_read,
      .writefn = icc_pmr_write,
      /* We hang the whole cpu interface reset routine off here
       * rather than parcelling it out into one little function
       * per register
       */
      .resetfn = icc_reset,
    },
    { .name = "ICC_IAR0_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 0,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_R, .accessfn = gicv3_fiq_access,
      .readfn = icc_iar0_read,
    },
    { .name = "ICC_EOIR0_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 1,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_W, .accessfn = gicv3_fiq_access,
      .writefn = icc_eoir_write,
    },
    { .name = "ICC_HPPIR0_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 2,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_R, .accessfn = gicv3_fiq_access,
      .readfn = icc_hppir0_read,
    },
    { .name = "ICC_BPR0_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 3,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_fiq_access,
      .fieldoffset = offsetof(GICv3CPUState, icc_bpr[GICV3_G0]),
      .writefn = icc_bpr_write,
    },
    { .name = "ICC_AP0R0_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 4,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_fiq_access,
      .fieldoffset = offsetof(GICv3CPUState, icc_apr[GICV3_G0][0]),
      .writefn = icc_ap_write,
    },
    { .name = "ICC_AP0R1_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 5,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_fiq_access,
      .fieldoffset = offsetof(GICv3CPUState, icc_apr[GICV3_G0][1]),
      .writefn = icc_ap_write,
    },
    { .name = "ICC_AP0R2_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 6,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_fiq_access,
      .fieldoffset = offsetof(GICv3CPUState, icc_apr[GICV3_G0][2]),
      .writefn = icc_ap_write,
    },
    { .name = "ICC_AP0R3_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 7,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_fiq_access,
      .fieldoffset = offsetof(GICv3CPUState, icc_apr[GICV3_G0][3]),
      .writefn = icc_ap_write,
    },
    /* All the ICC_AP1R*_EL1 registers are banked */
    { .name = "ICC_AP1R0_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 9, .opc2 = 0,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_irq_access,
      .readfn = icc_ap_read,
      .writefn = icc_ap_write,
    },
    { .name = "ICC_AP1R1_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 9, .opc2 = 1,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_irq_access,
      .readfn = icc_ap_read,
      .writefn = icc_ap_write,
    },
    { .name = "ICC_AP1R2_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 9, .opc2 = 2,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_irq_access,
      .readfn = icc_ap_read,
      .writefn = icc_ap_write,
    },
    { .name = "ICC_AP1R3_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 9, .opc2 = 3,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_irq_access,
      .readfn = icc_ap_read,
      .writefn = icc_ap_write,
    },
    { .name = "ICC_DIR_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 11, .opc2 = 1,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_W, .accessfn = gicv3_irqfiq_access,
      .writefn = icc_dir_write,
    },
    { .name = "ICC_RPR_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 11, .opc2 = 3,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_R, .accessfn = gicv3_irqfiq_access,
      .readfn = icc_rpr_read,
    },
    { .name = "ICC_SGI1R_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 11, .opc2 = 5,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_W, .accessfn = gicv3_irqfiq_access,
      .writefn = icc_sgi1r_write,
    },
    { .name = "ICC_SGI1R",
      .cp = 15, .opc1 = 0, .crm = 12,
      .type = ARM_CP_64BIT | ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_W, .accessfn = gicv3_irqfiq_access,
      .writefn = icc_sgi1r_write,
    },
    { .name = "ICC_ASGI1R_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 11, .opc2 = 6,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_W, .accessfn = gicv3_irqfiq_access,
      .writefn = icc_asgi1r_write,
    },
    { .name = "ICC_ASGI1R",
      .cp = 15, .opc1 = 1, .crm = 12,
      .type = ARM_CP_64BIT | ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_W, .accessfn = gicv3_irqfiq_access,
      .writefn = icc_asgi1r_write,
    },
    { .name = "ICC_SGI0R_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 11, .opc2 = 7,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_W, .accessfn = gicv3_irqfiq_access,
      .writefn = icc_sgi0r_write,
    },
    { .name = "ICC_SGI0R",
      .cp = 15, .opc1 = 2, .crm = 12,
      .type = ARM_CP_64BIT | ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_W, .accessfn = gicv3_irqfiq_access,
      .writefn = icc_sgi0r_write,
    },
    { .name = "ICC_IAR1_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 0,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_R, .accessfn = gicv3_irq_access,
      .readfn = icc_iar1_read,
    },
    { .name = "ICC_EOIR1_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 1,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_W, .accessfn = gicv3_irq_access,
      .writefn = icc_eoir_write,
    },
    { .name = "ICC_HPPIR1_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 2,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_R, .accessfn = gicv3_irq_access,
      .readfn = icc_hppir1_read,
    },
    /* This register is banked */
    { .name = "ICC_BPR1_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 3,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_irq_access,
      .readfn = icc_bpr_read,
      .writefn = icc_bpr_write,
    },
    /* This register is banked */
    { .name = "ICC_CTLR_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 4,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_irqfiq_access,
      .readfn = icc_ctlr_el1_read,
      .writefn = icc_ctlr_el1_write,
    },
    { .name = "ICC_SRE_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 5,
      .type = ARM_CP_NO_RAW | ARM_CP_CONST,
      .access = PL1_RW,
      /* We don't support IRQ/FIQ bypass and system registers are
       * always enabled, so all our bits are RAZ/WI or RAO/WI.
       * This register is banked but since it's constant we don't
       * need to do anything special.
       */
      .resetvalue = 0x7,
    },
    { .name = "ICC_IGRPEN0_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 6,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_fiq_access,
      .fieldoffset = offsetof(GICv3CPUState, icc_igrpen[GICV3_G0]),
      .writefn = icc_igrpen_write,
    },
    /* This register is banked */
    { .name = "ICC_IGRPEN1_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 7,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL1_RW, .accessfn = gicv3_irq_access,
      .readfn = icc_igrpen_read,
      .writefn = icc_igrpen_write,
    },
    { .name = "ICC_SRE_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 12, .crm = 9, .opc2 = 5,
      .type = ARM_CP_NO_RAW | ARM_CP_CONST,
      .access = PL2_RW,
      /* We don't support IRQ/FIQ bypass and system registers are
       * always enabled, so all our bits are RAZ/WI or RAO/WI.
       */
      .resetvalue = 0xf,
    },
    { .name = "ICC_CTLR_EL3", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 6, .crn = 12, .crm = 12, .opc2 = 4,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL3_RW,
      .fieldoffset = offsetof(GICv3CPUState, icc_ctlr_el3),
      .readfn = icc_ctlr_el3_read,
      .writefn = icc_ctlr_el3_write,
    },
    { .name = "ICC_SRE_EL3", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 6, .crn = 12, .crm = 12, .opc2 = 5,
      .type = ARM_CP_NO_RAW | ARM_CP_CONST,
      .access = PL3_RW,
      /* We don't support IRQ/FIQ bypass and system registers are
       * always enabled, so all our bits are RAZ/WI or RAO/WI.
       */
      .resetvalue = 0xf,
    },
    { .name = "ICC_IGRPEN1_EL3", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 6, .crn = 12, .crm = 12, .opc2 = 7,
      .type = ARM_CP_IO | ARM_CP_NO_RAW,
      .access = PL3_RW,
      .readfn = icc_igrpen1_el3_read,
      .writefn = icc_igrpen1_el3_write,
    },
    REGINFO_SENTINEL
};

static void gicv3_cpuif_el_change_hook(ARMCPU *cpu, void *opaque)
{
    GICv3CPUState *cs = opaque;

    gicv3_cpuif_update(cs);
}

void gicv3_init_cpuif(GICv3State *s)
{
    /* Called from the GICv3 realize function; register our system
     * registers with the CPU
     */
    int i;

    for (i = 0; i < s->num_cpu; i++) {
        ARMCPU *cpu = ARM_CPU(qemu_get_cpu(i));
        GICv3CPUState *cs = &s->cpu[i];

        /* Note that we can't just use the GICv3CPUState as an opaque pointer
         * in define_arm_cp_regs_with_opaque(), because when we're called back
         * it might be with code translated by CPU 0 but run by CPU 1, in
         * which case we'd get the wrong value.
         * So instead we define the regs with no ri->opaque info, and
         * get back to the GICv3CPUState from the ARMCPU by reading back
         * the opaque pointer from the el_change_hook, which we're going
         * to need to register anyway.
         */
        define_arm_cp_regs(cpu, gicv3_cpuif_reginfo);
        arm_register_el_change_hook(cpu, gicv3_cpuif_el_change_hook, cs);
    }
}
