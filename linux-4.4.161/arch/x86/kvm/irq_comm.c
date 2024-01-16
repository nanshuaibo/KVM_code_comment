/*
 * irq_comm.c: Common API for in kernel interrupt controller
 * Copyright (c) 2007, Intel Corporation.
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
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 */

#include <linux/kvm_host.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <trace/events/kvm.h>

#include <asm/msidef.h>

#include "irq.h"

#include "ioapic.h"

#include "lapic.h"

static int kvm_set_pic_irq(struct kvm_kernel_irq_routing_entry *e,
			   struct kvm *kvm, int irq_source_id, int level,
			   bool line_status)
{
	struct kvm_pic *pic = pic_irqchip(kvm);

	/*
	 * XXX: rejecting pic routes when pic isn't in use would be better,
	 * but the default routing table is installed while kvm->arch.vpic is
	 * NULL and KVM_CREATE_IRQCHIP can race with KVM_IRQ_LINE.
	 */
	if (!pic)
		return -1;

	return kvm_pic_set_irq(pic, e->irqchip.pin, irq_source_id, level);
}

static int kvm_set_ioapic_irq(struct kvm_kernel_irq_routing_entry *e,
			      struct kvm *kvm, int irq_source_id, int level,
			      bool line_status)
{
	struct kvm_ioapic *ioapic = kvm->arch.vioapic; //从虚拟机内部获取kvm_ioapic

	if (!ioapic)
		return -1;

	return kvm_ioapic_set_irq(ioapic, e->irqchip.pin, irq_source_id, level,
				line_status);
}

int kvm_irq_delivery_to_apic(struct kvm *kvm, struct kvm_lapic *src,
		struct kvm_lapic_irq *irq, unsigned long *dest_map)
{
	int i, r = -1;
	struct kvm_vcpu *vcpu, *lowest = NULL;

	if (irq->dest_mode == 0 && irq->dest_id == 0xff &&
			kvm_lowest_prio_delivery(irq)) {
		printk(KERN_INFO "kvm: apic: phys broadcast and lowest prio\n");
		irq->delivery_mode = APIC_DM_FIXED;
	}

	//使用预先存在kvm中的kvm_apic_map来查找lapic
	if (kvm_irq_delivery_to_apic_fast(kvm, src, irq, &r, dest_map))
		return r;
	
	/*目的是在虚拟机中选择一个或多个目标 vcpu，
	 将中断传递给它们。如果是选择最低优先级的 vcpu，则在循环结束后，
	 lowest 变量将指向具有最低优先级的 vcpu。
	*/
	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (!kvm_apic_present(vcpu))  //当前vcpu没有启用lapic
			continue;

		if (!kvm_apic_match_dest(vcpu, src, irq->shorthand,
					irq->dest_id, irq->dest_mode)) //如果vcpu的lapic匹配了指定的目标
			continue;

		if (!kvm_lowest_prio_delivery(irq)) { //如果不是要求将中断传递给具有最低优先级的处理器
			if (r < 0)
				r = 0;
			r += kvm_apic_set_irq(vcpu, irq, dest_map);
		} else if (kvm_lapic_enabled(vcpu)) { //如果是要求将中断传递给具有最低优先级的处理器，
		//并且当前 vcpu 的 LAPIC 已启用
			if (!lowest)
				lowest = vcpu;
			else if (kvm_apic_compare_prio(vcpu, lowest) < 0) //如果当前 vcpu 的 LAPIC 优先级比
			// lowest 的 LAPIC 优先级更低
				lowest = vcpu;
		}
	}

	if (lowest)
		r = kvm_apic_set_irq(lowest, irq, dest_map);

	return r;
}

void kvm_set_msi_irq(struct kvm_kernel_irq_routing_entry *e,
		     struct kvm_lapic_irq *irq)
{
	//tracepoint kvm_msi_set_irq
	trace_kvm_msi_set_irq(e->msi.address_lo, e->msi.data);

	// 解析 MSI 中断信息并填充到 kvm_lapic_irq 结构体中
	irq->dest_id = (e->msi.address_lo &
			MSI_ADDR_DEST_ID_MASK) >> MSI_ADDR_DEST_ID_SHIFT;
	irq->vector = (e->msi.data &
			MSI_DATA_VECTOR_MASK) >> MSI_DATA_VECTOR_SHIFT;
	irq->dest_mode = (1 << MSI_ADDR_DEST_MODE_SHIFT) & e->msi.address_lo;
	irq->trig_mode = (1 << MSI_DATA_TRIGGER_SHIFT) & e->msi.data;
	irq->delivery_mode = e->msi.data & 0x700;
	irq->msi_redir_hint = ((e->msi.address_lo
		& MSI_ADDR_REDIRECTION_LOWPRI) > 0);
	irq->level = 1;
	irq->shorthand = 0;
}
EXPORT_SYMBOL_GPL(kvm_set_msi_irq);

int kvm_set_msi(struct kvm_kernel_irq_routing_entry *e,
		struct kvm *kvm, int irq_source_id, int level, bool line_status)
{
	struct kvm_lapic_irq irq;

	if (!level)
		return -1;

	kvm_set_msi_irq(e, &irq);

	return kvm_irq_delivery_to_apic(kvm, NULL, &irq, NULL); //分发中断
}


int kvm_arch_set_irq_inatomic(struct kvm_kernel_irq_routing_entry *e,
			      struct kvm *kvm, int irq_source_id, int level,
			      bool line_status)
{
	struct kvm_lapic_irq irq;
	int r;

	if (unlikely(e->type != KVM_IRQ_ROUTING_MSI))
		return -EWOULDBLOCK;

	kvm_set_msi_irq(e, &irq);

	if (kvm_irq_delivery_to_apic_fast(kvm, NULL, &irq, &r, NULL))
		return r;
	else
		return -EWOULDBLOCK;
}

int kvm_request_irq_source_id(struct kvm *kvm)
{
	unsigned long *bitmap = &kvm->arch.irq_sources_bitmap;
	int irq_source_id;

	mutex_lock(&kvm->irq_lock);
	irq_source_id = find_first_zero_bit(bitmap, BITS_PER_LONG);

	if (irq_source_id >= BITS_PER_LONG) {
		printk(KERN_WARNING "kvm: exhaust allocatable IRQ sources!\n");
		irq_source_id = -EFAULT;
		goto unlock;
	}

	ASSERT(irq_source_id != KVM_USERSPACE_IRQ_SOURCE_ID);
	ASSERT(irq_source_id != KVM_IRQFD_RESAMPLE_IRQ_SOURCE_ID);
	set_bit(irq_source_id, bitmap);
unlock:
	mutex_unlock(&kvm->irq_lock);

	return irq_source_id;
}

void kvm_free_irq_source_id(struct kvm *kvm, int irq_source_id)
{
	ASSERT(irq_source_id != KVM_USERSPACE_IRQ_SOURCE_ID);
	ASSERT(irq_source_id != KVM_IRQFD_RESAMPLE_IRQ_SOURCE_ID);

	mutex_lock(&kvm->irq_lock);
	if (irq_source_id < 0 ||
	    irq_source_id >= BITS_PER_LONG) {
		printk(KERN_ERR "kvm: IRQ source ID out of range!\n");
		goto unlock;
	}
	clear_bit(irq_source_id, &kvm->arch.irq_sources_bitmap);
	if (!ioapic_in_kernel(kvm))
		goto unlock;

	kvm_ioapic_clear_all(kvm->arch.vioapic, irq_source_id);
	kvm_pic_clear_all(pic_irqchip(kvm), irq_source_id);
unlock:
	mutex_unlock(&kvm->irq_lock);
}

void kvm_register_irq_mask_notifier(struct kvm *kvm, int irq,
				    struct kvm_irq_mask_notifier *kimn)
{
	mutex_lock(&kvm->irq_lock);
	kimn->irq = irq;
	hlist_add_head_rcu(&kimn->link, &kvm->arch.mask_notifier_list);
	mutex_unlock(&kvm->irq_lock);
}

void kvm_unregister_irq_mask_notifier(struct kvm *kvm, int irq,
				      struct kvm_irq_mask_notifier *kimn)
{
	mutex_lock(&kvm->irq_lock);
	hlist_del_rcu(&kimn->link);
	mutex_unlock(&kvm->irq_lock);
	synchronize_srcu(&kvm->irq_srcu);
}

void kvm_fire_mask_notifiers(struct kvm *kvm, unsigned irqchip, unsigned pin,
			     bool mask)
{
	struct kvm_irq_mask_notifier *kimn;
	int idx, gsi;

	idx = srcu_read_lock(&kvm->irq_srcu);
	gsi = kvm_irq_map_chip_pin(kvm, irqchip, pin);
	if (gsi != -1)
		hlist_for_each_entry_rcu(kimn, &kvm->arch.mask_notifier_list, link)
			if (kimn->irq == gsi)
				kimn->func(kimn, mask);
	srcu_read_unlock(&kvm->irq_srcu, idx);
}

/*
 * kvm_set_routing_entry - 设置虚拟中断路由表条目
 * @e: 虚拟中断路由表的内核数据结构
 * @ue: 用户空间传递的虚拟中断路由表条目
 *
 * 此函数根据用户空间传递的虚拟中断路由表条目（ue），填充内核中的虚拟中断路由表数据结构（e）。
 * 返回 0 表示成功，否则返回相应的错误码（例如 EINVAL）。
 */
int kvm_set_routing_entry(struct kvm_kernel_irq_routing_entry *e,
			  const struct kvm_irq_routing_entry *ue)
{
	int r = -EINVAL;  // 默认返回值为错误（EINVAL）

	int delta;
	unsigned max_pin;

	switch (ue->type) {
	case KVM_IRQ_ROUTING_IRQCHIP:
		delta = 0;
		switch (ue->u.irqchip.irqchip) {
		case KVM_IRQCHIP_PIC_MASTER:
			e->set = kvm_set_pic_irq;  // 设置处理 PIC 中断的回调函数
			max_pin = PIC_NUM_PINS;    // PIC 的最大引脚数
			break;
		case KVM_IRQCHIP_PIC_SLAVE:
			e->set = kvm_set_pic_irq;  // 设置处理 PIC 中断的回调函数
			max_pin = PIC_NUM_PINS;    // PIC 的最大引脚数
			delta = 8;                 // 增加偏移以处理从 PIC
			break;
		case KVM_IRQCHIP_IOAPIC:
			max_pin = KVM_IOAPIC_NUM_PINS;  // IOAPIC 的最大引脚数
			e->set = kvm_set_ioapic_irq;    // 设置处理 IOAPIC 中断的回调函数
			break;
		default:
			goto out;  // 未知的 irqchip 类型，跳到错误处理部分
		}
		e->irqchip.irqchip = ue->u.irqchip.irqchip;
		e->irqchip.pin = ue->u.irqchip.pin + delta;  // 设置 IRQCHIP 中断引脚
		if (e->irqchip.pin >= max_pin)
			goto out;  // 超出引脚范围，跳到错误处理部分
		break;
	case KVM_IRQ_ROUTING_MSI:
		e->set = kvm_set_msi;              // 设置处理 MSI 中断的回调函数
		e->msi.address_lo = ue->u.msi.address_lo; //msi地址的第32位
		e->msi.address_hi = ue->u.msi.address_hi;//msi地址的高32位
		e->msi.data = ue->u.msi.data;  //  msi数据的低16位 
		break;
	default:
		goto out;  // 未知的中断类型，跳到错误处理部分
	}

	r = 0;  // 操作成功，将返回值设置为 0
out:
	return r;  // 返回操作结果
}


bool kvm_intr_is_single_vcpu(struct kvm *kvm, struct kvm_lapic_irq *irq,
			     struct kvm_vcpu **dest_vcpu)
{
	int i, r = 0;
	struct kvm_vcpu *vcpu;

	if (kvm_intr_is_single_vcpu_fast(kvm, irq, dest_vcpu))
		return true;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (!kvm_apic_present(vcpu))
			continue;

		if (!kvm_apic_match_dest(vcpu, NULL, irq->shorthand,
					irq->dest_id, irq->dest_mode))
			continue;

		if (++r == 2)
			return false;

		*dest_vcpu = vcpu;
	}

	return r == 1;
}
EXPORT_SYMBOL_GPL(kvm_intr_is_single_vcpu);

// 宏：生成 IOAPIC 类型的中断路由表条目
#define IOAPIC_ROUTING_ENTRY(irq) \
    { .gsi = irq, .type = KVM_IRQ_ROUTING_IRQCHIP, \
      .u.irqchip = { .irqchip = KVM_IRQCHIP_IOAPIC, .pin = (irq) } }

// 宏：生成只包含 IOAPIC 类型的中断路由表条目
#define ROUTING_ENTRY1(irq) IOAPIC_ROUTING_ENTRY(irq)

// 宏：生成 PIC 类型的中断路由表条目
#define PIC_ROUTING_ENTRY(irq) \
    { .gsi = irq, .type = KVM_IRQ_ROUTING_IRQCHIP, \
      .u.irqchip = { .irqchip = SELECT_PIC(irq), .pin = (irq) % 8 } }

// 宏：生成同时包含 IOAPIC 和 PIC 类型的两个中断路由表条目
#define ROUTING_ENTRY2(irq) \
    IOAPIC_ROUTING_ENTRY(irq), PIC_ROUTING_ENTRY(irq)

static const struct kvm_irq_routing_entry default_routing[] = {
	ROUTING_ENTRY2(0), ROUTING_ENTRY2(1),
	ROUTING_ENTRY2(2), ROUTING_ENTRY2(3),
	ROUTING_ENTRY2(4), ROUTING_ENTRY2(5),
	ROUTING_ENTRY2(6), ROUTING_ENTRY2(7),
	ROUTING_ENTRY2(8), ROUTING_ENTRY2(9),
	ROUTING_ENTRY2(10), ROUTING_ENTRY2(11),
	ROUTING_ENTRY2(12), ROUTING_ENTRY2(13),
	ROUTING_ENTRY2(14), ROUTING_ENTRY2(15),
	ROUTING_ENTRY1(16), ROUTING_ENTRY1(17),
	ROUTING_ENTRY1(18), ROUTING_ENTRY1(19),
	ROUTING_ENTRY1(20), ROUTING_ENTRY1(21),
	ROUTING_ENTRY1(22), ROUTING_ENTRY1(23),
};

int kvm_setup_default_irq_routing(struct kvm *kvm)
{
	return kvm_set_irq_routing(kvm, default_routing,
				   ARRAY_SIZE(default_routing), 0);
}

static const struct kvm_irq_routing_entry empty_routing[] = {};

int kvm_setup_empty_irq_routing(struct kvm *kvm)
{
	return kvm_set_irq_routing(kvm, empty_routing, 0, 0);
}

void kvm_arch_irq_routing_update(struct kvm *kvm)
{
	if (ioapic_in_kernel(kvm) || !irqchip_in_kernel(kvm))
		return;
	kvm_make_scan_ioapic_request(kvm);
}

void kvm_scan_ioapic_routes(struct kvm_vcpu *vcpu, u64 *eoi_exit_bitmap)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_kernel_irq_routing_entry *entry;
	struct kvm_irq_routing_table *table;
	u32 i, nr_ioapic_pins;
	int idx;

	/* kvm->irq_routing must be read after clearing
	 * KVM_SCAN_IOAPIC. */
	smp_mb();
	idx = srcu_read_lock(&kvm->irq_srcu);
	table = srcu_dereference(kvm->irq_routing, &kvm->irq_srcu);
	nr_ioapic_pins = min_t(u32, table->nr_rt_entries,
			       kvm->arch.nr_reserved_ioapic_pins);
	for (i = 0; i < nr_ioapic_pins; ++i) {
		hlist_for_each_entry(entry, &table->map[i], link) {
			u32 dest_id, dest_mode;
			bool level;

			if (entry->type != KVM_IRQ_ROUTING_MSI)
				continue;
			dest_id = (entry->msi.address_lo >> 12) & 0xff;
			dest_mode = (entry->msi.address_lo >> 2) & 0x1;
			level = entry->msi.data & MSI_DATA_TRIGGER_LEVEL;
			if (level && kvm_apic_match_dest(vcpu, NULL, 0,
						dest_id, dest_mode)) {
				u32 vector = entry->msi.data & 0xff;

				__set_bit(vector,
					  (unsigned long *) eoi_exit_bitmap);
			}
		}
	}
	srcu_read_unlock(&kvm->irq_srcu, idx);
}
