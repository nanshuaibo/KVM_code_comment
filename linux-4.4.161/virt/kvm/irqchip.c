/*
 * irqchip.c: Common API for in kernel interrupt controllers
 * Copyright (c) 2007, Intel Corporation.
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 * Copyright (c) 2013, Alexander Graf <agraf@suse.de>
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
 *
 * This file is derived from virt/kvm/irq_comm.c.
 *
 * Authors:
 *   Yaozu (Eddie) Dong <Eddie.dong@intel.com>
 *   Alexander Graf <agraf@suse.de>
 */

#include <linux/kvm_host.h>
#include <linux/slab.h>
#include <linux/srcu.h>
#include <linux/export.h>
#include <trace/events/kvm.h>
#include "irq.h"

int kvm_irq_map_gsi(struct kvm *kvm,
		    struct kvm_kernel_irq_routing_entry *entries, int gsi)
{
	struct kvm_irq_routing_table *irq_rt;
	struct kvm_kernel_irq_routing_entry *e;
	int n = 0;

	irq_rt = srcu_dereference_check(kvm->irq_routing, &kvm->irq_srcu,
					lockdep_is_held(&kvm->irq_lock));
	if (irq_rt && gsi < irq_rt->nr_rt_entries) {
		hlist_for_each_entry(e, &irq_rt->map[gsi], link) {
			entries[n] = *e;
			++n;
		}
	}

	return n;
}

int kvm_irq_map_chip_pin(struct kvm *kvm, unsigned irqchip, unsigned pin)
{
	struct kvm_irq_routing_table *irq_rt;

	irq_rt = srcu_dereference(kvm->irq_routing, &kvm->irq_srcu);
	return irq_rt->chip[irqchip][pin];
}

int kvm_send_userspace_msi(struct kvm *kvm, struct kvm_msi *msi)
{
	struct kvm_kernel_irq_routing_entry route;

	if (!irqchip_in_kernel(kvm) || msi->flags != 0)
		return -EINVAL;

	route.msi.address_lo = msi->address_lo;
	route.msi.address_hi = msi->address_hi;
	route.msi.data = msi->data;

	return kvm_set_msi(&route, kvm, KVM_USERSPACE_IRQ_SOURCE_ID, 1, false);
}

/*
 * 返回值：
 *  < 0   中断被忽略（被屏蔽或由于其他原因未传递）
 *  = 0   中断被合并（先前的中断仍然挂起）
 *  > 0   中断传递给的 CPU 数量
 */

int kvm_set_irq(struct kvm *kvm, int irq_source_id, u32 irq, int level,
		bool line_status)
{
	struct kvm_kernel_irq_routing_entry irq_set[KVM_NR_IRQCHIPS];
	int ret = -1, i, idx;

	trace_kvm_set_irq(irq, level, irq_source_id);

	/* Not possible to detect if the guest uses the PIC or the
	 * IOAPIC.  So set the bit in both. The guest will ignore
	 * writes to the unused one.
     * 无法检测客户端使用的是 PIC 还是 IOAPIC。因此在两者中都设置该位。
     * 客户端将忽略对未使用的那一方的写入。
     */

	idx = srcu_read_lock(&kvm->irq_srcu);
	i = kvm_irq_map_gsi(kvm, irq_set, irq); //获取虚拟机的中断路由表
	srcu_read_unlock(&kvm->irq_srcu, idx);

	while (i--) {
		int r;
		r = irq_set[i].set(&irq_set[i], kvm, irq_source_id, level,
				   line_status);
		if (r < 0)
			continue;

		ret = r + ((ret < 0) ? 0 : ret);
	}

	return ret;
}

static void free_irq_routing_table(struct kvm_irq_routing_table *rt)
{
	int i;

	if (!rt)
		return;

	for (i = 0; i < rt->nr_rt_entries; ++i) {
		struct kvm_kernel_irq_routing_entry *e;
		struct hlist_node *n;

		hlist_for_each_entry_safe(e, n, &rt->map[i], link) {
			hlist_del(&e->link);
			kfree(e);
		}
	}

	kfree(rt);
}

void kvm_free_irq_routing(struct kvm *kvm)
{
	/* Called only during vm destruction. Nobody can use the pointer
	   at this stage */
	struct kvm_irq_routing_table *rt = rcu_access_pointer(kvm->irq_routing);
	free_irq_routing_table(rt);
}

/**
 * setup_routing_entry - 设置 IRQ 路由表中的一条目
 * @rt: 指向 kvm_irq_routing_table 结构的指针
 * @e: 指向 kvm_kernel_irq_routing_entry 结构的指针，用于存储新的路由表条目
 * @ue: 指向 kvm_irq_routing_entry 结构的指针，包含新条目的信息
 *
 * 此函数用于向 IRQ 路由表中添加新的中断条目。该函数会检查是否已经存在相同的 GSI 映射到相同的 IRQChip，
 * 并且只允许 GSI 与 IRQChip 的一对一映射，以及不允许重复映射同一个 IRQChip。
 *
 * 成功返回0，失败返回负错误代码。
 */
static int setup_routing_entry(struct kvm_irq_routing_table *rt,
                               struct kvm_kernel_irq_routing_entry *e,
                               const struct kvm_irq_routing_entry *ue)
{
    int r = -EINVAL;
    struct kvm_kernel_irq_routing_entry *ei;

    /*
     * 不允许将 GSI 多次映射到同一个 IRQChip。
     * 仅允许 GSI 与非 IRQChip 路由之间的一对一映射。
     */
    hlist_for_each_entry(ei, &rt->map[ue->gsi], link)
        if (ei->type != KVM_IRQ_ROUTING_IRQCHIP ||
            ue->type != KVM_IRQ_ROUTING_IRQCHIP ||
            ue->u.irqchip.irqchip == ei->irqchip.irqchip)
            return r;

    e->gsi = ue->gsi;
    e->type = ue->type;

    // 根据中断类型设置回调函数
    r = kvm_set_routing_entry(e, ue);
    if (r)
        goto out;

    // 如果新的条目类型为 IRQChip，则在芯片数组中保存 GSI 映射关系
    if (e->type == KVM_IRQ_ROUTING_IRQCHIP)
        rt->chip[e->irqchip.irqchip][e->irqchip.pin] = e->gsi;

    // 将新的条目添加到 GSI 映射的散列表中
    hlist_add_head(&e->link, &rt->map[e->gsi]);

    r = 0;
out:
    return r;
}


/**
 * kvm_set_irq_routing - 设置 KVM 实例的 IRQ 路由表
 * @kvm: 指向 KVM 实例的指针
 * @ue: 指向 kvm_irq_routing_entry 结构数组的指针
 * @nr: 数组中的条目数量
 * @flags: 附加标志（目前未使用）
 *
 * 该函数基于提供的 kvm_irq_routing_entry 结构数组设置 KVM 实例的 IRQ 路由表。
 * 每个条目指定 GSI（全局系统中断）及其路由信息。
 *
 * 成功返回0，失败返回负错误代码。
 */
int kvm_set_irq_routing(struct kvm *kvm,
                        const struct kvm_irq_routing_entry *ue,
                        unsigned nr,
                        unsigned flags)
{
    struct kvm_irq_routing_table *new, *old;
    u32 i, j, nr_rt_entries = 0;
    int r;

    // 在输入数组中验证 GSI 值
    for (i = 0; i < nr; ++i) {
        if (ue[i].gsi >= KVM_MAX_IRQ_ROUTES)
            return -EINVAL;
        nr_rt_entries = max(nr_rt_entries, ue[i].gsi);
    }

    nr_rt_entries += 1;

    // 为新的路由表分配内存
    new = kzalloc(sizeof(*new) + (nr_rt_entries * sizeof(struct hlist_head)),
                  GFP_KERNEL);

    if (!new)
        return -ENOMEM;

    new->nr_rt_entries = nr_rt_entries;

    // 在新的路由表中初始化芯片数组
    for (i = 0; i < KVM_NR_IRQCHIPS; i++)
        for (j = 0; j < KVM_IRQCHIP_NUM_PINS; j++)
            new->chip[i][j] = -1;
    }

    // 遍历输入数组，为每个条目创建新的内核 IRQ 路由表条目
    for (i = 0; i < nr; ++i) {
        struct kvm_kernel_irq_routing_entry *e;

        // 分配新的内核 IRQ 路由表条目
        r = -ENOMEM;
        e = kzalloc(sizeof(*e), GFP_KERNEL);
        if (!e)
            goto out;

        r = -EINVAL;
        // 确保输入条目没有附加标志
        if (ue->flags) {
            kfree(e);
            goto out;
        }

        // 设置新的路由表条目
        r = setup_routing_entry(new, e, ue);
        if (r) {
            kfree(e);
            goto out;
        }
        ++ue;
    }

    // 使用互斥锁锁住 IRQ
    mutex_lock(&kvm->irq_lock);

    // 将旧的路由表指针保存在 'old' 变量中
    old = kvm->irq_routing;

    // 将新的路由表指针指向 KVM 实例
    rcu_assign_pointer(kvm->irq_routing, new);

    // 更新 KVM 实例的 IRQ
    kvm_irq_routing_update(kvm);

    // 解锁 IRQ 互斥锁
    mutex_unlock(&kvm->irq_lock);

    // 更新架构相关的 IRQ 路由
    kvm_arch_irq_routing_update(kvm);

    // 等待所有的 SRCU 读者完成
    synchronize_srcu_expedited(&kvm->irq_srcu);

    // 释放旧的路由表
    new = old;
    r = 0;

out:
    // 释放新的路由表（如果有错误）
    free_irq_routing_table(new);

    return r;
}
