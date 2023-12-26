/*
 * irq.h: in kernel interrupt controller related definitions
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
 */

#ifndef __IRQ_H
#define __IRQ_H

#include <linux/mm_types.h>
#include <linux/hrtimer.h>
#include <linux/kvm_host.h>
#include <linux/spinlock.h>

#include <kvm/iodev.h>
#include "ioapic.h"
#include "lapic.h"

#define PIC_NUM_PINS 16
#define SELECT_PIC(irq) \
	((irq) < 8 ? KVM_IRQCHIP_PIC_MASTER : KVM_IRQCHIP_PIC_SLAVE)

struct kvm;
struct kvm_vcpu;

struct kvm_kpic_state {
    u8 last_irr;                    /* 边沿检测（edge detection） */
    u8 irr;                         /* 中断请求寄存器（interrupt request register） */
    u8 imr;                         /* 中断屏蔽寄存器（interrupt mask register） */
    u8 isr;                         /* 中断服务寄存器（interrupt service register） */
    u8 priority_add;                /* 最高中断请求优先级（highest irq priority） */
    u8 irq_base;                    /* 中断请求基地址（IRQ base address） */
    u8 read_reg_select;             /* 读寄存器选择（read register select） */
    u8 poll;                        /* 轮询标志（poll flag） */
    u8 special_mask;                /* 特殊屏蔽标志（special mask flag） */
    u8 init_state;                  /* 初始化状态（init state） */
    u8 auto_eoi;                    /* 自动 EOI（End Of Interrupt）标志 */
    u8 rotate_on_auto_eoi;          /* 自动 EOI 时是否轮转（rotate on auto EOI） */
    u8 special_fully_nested_mode;   /* 特殊完全嵌套模式标志 */
    u8 init4;                       /* 如果是 4 字节的初始化，则为真 */
    u8 elcr;                        /* PIIX（Intel 8259A兼容芯片）边沿/触发选择 */
    u8 elcr_mask;
    u8 isr_ack;                     /* 中断应答检测（interrupt acknowledge detection） */
    struct kvm_pic *pics_state;     /* 指向 kvm_pic 结构的指针，表示 PIC 的状态 */
};


struct kvm_pic {
    spinlock_t lock;               // 用于同步的自旋锁
    bool wakeup_needed;             // 表示是否需要唤醒
    unsigned pending_acks;          // 未决待确认的中断计数
    struct kvm *kvm;                // 指向 KVM 实例的指针
    struct kvm_kpic_state pics[2];  // 表示主 PIC 和从 PIC 状态的数组
    int output;                     // 来自主 PIC 的中断
    struct kvm_io_device dev_master; // 主 PIC 的 I/O 设备
    struct kvm_io_device dev_slave;  // 从 PIC 的 I/O 设备
    struct kvm_io_device dev_eclr;   // "eclr"（假设这是某个特定设备）PIC 的 I/O 设备
    void (*ack_notifier)(void *opaque, int irq); // 确认通知函数指针
    unsigned long irq_states[PIC_NUM_PINS]; // 每个 PIC 引脚状态的数组
};


struct kvm_pic *kvm_create_pic(struct kvm *kvm);
void kvm_destroy_pic(struct kvm_pic *vpic);
int kvm_pic_read_irq(struct kvm *kvm);
void kvm_pic_update_irq(struct kvm_pic *s);

static inline struct kvm_pic *pic_irqchip(struct kvm *kvm)
{
	return kvm->arch.vpic;
}

static inline int pic_in_kernel(struct kvm *kvm)
{
	int ret;

	ret = (pic_irqchip(kvm) != NULL);
	return ret;
}

static inline int irqchip_split(struct kvm *kvm)
{
	return kvm->arch.irqchip_split;
}

static inline int irqchip_in_kernel(struct kvm *kvm)
{
	struct kvm_pic *vpic = pic_irqchip(kvm);
	bool ret;

	ret = (vpic != NULL);
	ret |= irqchip_split(kvm);

	/* Read vpic before kvm->irq_routing.  */
	smp_rmb();
	return ret;
}

static inline int lapic_in_kernel(struct kvm_vcpu *vcpu)
{
	/* Same as irqchip_in_kernel(vcpu->kvm), but with less
	 * pointer chasing and no unnecessary memory barriers.
	 */
	return vcpu->arch.apic != NULL;
}

void kvm_pic_reset(struct kvm_kpic_state *s);

void kvm_inject_pending_timer_irqs(struct kvm_vcpu *vcpu);
void kvm_inject_apic_timer_irqs(struct kvm_vcpu *vcpu);
void kvm_apic_nmi_wd_deliver(struct kvm_vcpu *vcpu);
void __kvm_migrate_apic_timer(struct kvm_vcpu *vcpu);
void __kvm_migrate_pit_timer(struct kvm_vcpu *vcpu);
void __kvm_migrate_timers(struct kvm_vcpu *vcpu);

int apic_has_pending_timer(struct kvm_vcpu *vcpu);

#endif
