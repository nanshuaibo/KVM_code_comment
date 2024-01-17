/*
 * irq.c: API for in kernel interrupt controller
 * Copyright (c) 2007, Intel Corporation.
 * Copyright 2009 Red Hat, Inc. and/or its affiliates.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 * Authors:
 *   Yaozu (Eddie) Dong <Eddie.dong@intel.com>
 *
 */

#include <linux/module.h>
#include <linux/kvm_host.h>

#include "irq.h"
#include "i8254.h"
#include "x86.h"

/*
 * 检查是否有待处理的定时器事件。
 */

int kvm_cpu_has_pending_timer(struct kvm_vcpu *vcpu)
{
	return apic_has_pending_timer(vcpu);
}
EXPORT_SYMBOL(kvm_cpu_has_pending_timer);

/*
 * 检查是否有待处理的用户空间外部中断。
 */
static int pending_userspace_extint(struct kvm_vcpu *v)
{
	return v->arch.pending_external_vector != -1;
}

/*
 * 检查是否存在来自非APIC源的未经中断确认的挂起中断。
 */

static int kvm_cpu_has_extint(struct kvm_vcpu *v)
{
	u8 accept = kvm_apic_accept_pic_intr(v);

	if (accept) {
		if (irqchip_split(v->kvm))
			return pending_userspace_extint(v);
		else
			return pic_irqchip(v->kvm)->output;
	} else
		return 0;
}

/*
 * 检查是否存在可注入的中断：
 * 当启用虚拟中断传递时，
 * 来自APIC的中断将由硬件处理，
 * 我们不需要在这里进行检查。
 */

int kvm_cpu_has_injectable_intr(struct kvm_vcpu *v)
{
	if (!lapic_in_kernel(v))
		return v->arch.interrupt.pending;

	if (kvm_cpu_has_extint(v))
		return 1;

	if (kvm_vcpu_apic_vid_enabled(v)) //判断是否支持apicv
		return 0;

	return kvm_apic_has_interrupt(v) != -1; /* LAPIC */
}

/*
 * 检查是否存在未经中断确认的挂起中断。
 */

int kvm_cpu_has_interrupt(struct kvm_vcpu *v)
{
	if (!lapic_in_kernel(v))
		return v->arch.interrupt.pending;

	if (kvm_cpu_has_extint(v))
		return 1;

	return kvm_apic_has_interrupt(v) != -1;	/* LAPIC */
}
EXPORT_SYMBOL_GPL(kvm_cpu_has_interrupt);

/*
 * 读取挂起中断（来自非APIC源）的向量并进行中断确认。
 */

static int kvm_cpu_get_extint(struct kvm_vcpu *v)
{
	if (kvm_cpu_has_extint(v)) {
		if (irqchip_split(v->kvm)) {
			int vector = v->arch.pending_external_vector;

			v->arch.pending_external_vector = -1;
			return vector;
		} else
			return kvm_pic_read_irq(v->kvm); /* PIC */
	} else
		return -1;
}

/*
 * 读取挂起中断的向量并进行中断确认。
 */

int kvm_cpu_get_interrupt(struct kvm_vcpu *v)
{
	int vector;

	if (!lapic_in_kernel(v))
		return v->arch.interrupt.nr;

	vector = kvm_cpu_get_extint(v);

	if (vector != -1)
		return vector;			/* PIC */

	return kvm_get_apic_interrupt(v);	/* APIC */
}
EXPORT_SYMBOL_GPL(kvm_cpu_get_interrupt);

void kvm_inject_pending_timer_irqs(struct kvm_vcpu *vcpu)
{
	kvm_inject_apic_timer_irqs(vcpu);
	/* TODO: PIT, RTC etc. */
}
EXPORT_SYMBOL_GPL(kvm_inject_pending_timer_irqs);

void __kvm_migrate_timers(struct kvm_vcpu *vcpu)
{
	__kvm_migrate_apic_timer(vcpu);
	__kvm_migrate_pit_timer(vcpu);
}
