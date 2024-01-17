/*
 * 8259 interrupt controller emulation
 *
 * Copyright (c) 2003-2004 Fabrice Bellard
 * Copyright (c) 2007 Intel Corporation
 * Copyright 2009 Red Hat, Inc. and/or its affiliates.
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
 * Authors:
 *   Yaozu (Eddie) Dong <Eddie.dong@intel.com>
 *   Port from Qemu.
 */
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/bitops.h>
#include "irq.h"

#include <linux/kvm_host.h>
#include "trace.h"

#define pr_pic_unimpl(fmt, ...)	\
	pr_err_ratelimited("kvm: pic: " fmt, ## __VA_ARGS__)

static void pic_irq_request(struct kvm *kvm, int level);

static void pic_lock(struct kvm_pic *s)
	__acquires(&s->lock)
{
	spin_lock(&s->lock);
}

static void pic_unlock(struct kvm_pic *s)
	__releases(&s->lock)
{
	bool wakeup = s->wakeup_needed;
	struct kvm_vcpu *vcpu, *found = NULL;
	int i;

	s->wakeup_needed = false;

	spin_unlock(&s->lock);

	//如果需要唤醒
	if (wakeup) {
		//遍历kvm中的每个vcpu
		kvm_for_each_vcpu(i, vcpu, s->kvm) {
			//检查vcpu是否接受pic中断
			if (kvm_apic_accept_pic_intr(vcpu)) {
				found = vcpu;
				break;
			}
		}

		if (!found)
			return;
		
		//向找到的vcpu挂起一个事件请求
		kvm_make_request(KVM_REQ_EVENT, found);
		//激活找到的vcpu
		kvm_vcpu_kick(found);
	}
}

static void pic_clear_isr(struct kvm_kpic_state *s, int irq)
{
	s->isr &= ~(1 << irq);
	if (s != &s->pics_state->pics[0]) //从pic
		irq += 8;
/*
 * 我们在调用确认通知器（ack notifiers）时释放锁，因为分配设备的确认通知器回调会递归调用到PIC。
 * 在释放锁的同时，可能有其他中断被传递到PIC，但这是安全的，因为在此阶段PIC状态已经被更新。
 */

	pic_unlock(s->pics_state);
	kvm_notify_acked_irq(s->pics_state->kvm, SELECT_PIC(irq), irq);
	pic_lock(s->pics_state);
}

/*
 * 设置中断请求级别。如果检测到边沿触发，那么IRR将被设置为1。
 */
static inline int pic_set_irq1(struct kvm_kpic_state *s, int irq, int level)
{
    int mask, ret = 1;
    mask = 1 << irq;

    // 如果是电平触发（level triggered）
    if (s->elcr & mask) {
        if (level) {
            ret = !(s->irr & mask);
            s->irr |= mask;
            s->last_irr |= mask;
        } else {
            s->irr &= ~mask;
            s->last_irr &= ~mask;
        }
    } else {  // 如果是边沿触发（edge triggered）
        if (level) {
            if ((s->last_irr & mask) == 0) {
                ret = !(s->irr & mask);
                s->irr |= mask;
            }
            s->last_irr |= mask;
        } else {
            s->last_irr &= ~mask;
        }
    }

    // 如果中断被屏蔽（imr中对应位为1），返回-1；否则，返回ret
    return (s->imr & mask) ? -1 : ret;
}


/*
 * 函数: get_priority
 * ---------------------
 * 从中断掩码中获取最高优先级的中断。
 *
 * 参数:
 *   - struct kvm_kpic_state *s: 指向 KVM PIC 状态的指针。
 *   - int mask: 中断掩码，表示待处理的中断请求。
 *
 * 返回值:
 *   - int: 最高优先级的中断号。如果没有中断请求，返回 8。
 *
 * 描述:
 *   此函数用于从给定的中断掩码中获取最高优先级的中断号。优先级通过掩码中
 *   最小的位数来确定。如果掩码为0，表示没有中断请求，返回8表示没有中断。
 *   函数通过迭代检查掩码中的位，找到第一个被置位的位，即表示最高优先级的
 *   中断。返回此中断号，其中优先级为 0 到 7。
 */
static inline int get_priority(struct kvm_kpic_state *s, int mask)
{
    int priority;

    // 如果中断掩码为0，表示没有中断请求，返回8表示没有中断
    if (mask == 0)
        return 8;

    priority = 0;

    // 迭代检查掩码中的位，找到第一个被置位的位，即表示最高优先级的中断
    while ((mask & (1 << ((priority + s->priority_add) & 7))) == 0)
        priority++;

    return priority;
}


/*
 * 函数: pic_get_irq
 * ---------------------
 * 返回需要处理的中断。
 *
 * 参数:
 *   - struct kvm_kpic_state *s: 指向KVM中断控制器状态的指针。
 *
 * 返回值:
 *   - int: 应该处理的中断号。如果没有挂起的中断，则返回-1。
 *
 * 描述:
 *   此函数计算并返回应由中断控制器处理的最高优先级挂起中断。
 *   它考虑了未被中断屏蔽寄存器（IMR）屏蔽的中断请求（IRR）。
 *   优先级由get_priority函数确定，并根据中断控制器的当前状态和配置进行调整。
 *
 *   如果没有挂起的中断，则函数返回-1。否则，它返回应该处理的中断号。
 */
static int pic_get_irq(struct kvm_kpic_state *s)
{
    int mask, cur_priority, priority;

    // 过滤掉被屏蔽的中断请求
	/*
	IRR（Interrupt Request Register）
	IMR（Interrupt Mask Register）
	*/
    mask = s->irr & ~s->imr;

    // 确定挂起中断的优先级。
    priority = get_priority(s, mask);

    // 如果没有挂起的中断，返回-1。
    if (priority == 8)
        return -1;

    /*
     * 计算当前优先级。如果在主中断控制器上启用了特殊完全嵌套模式，
     * 则从从属中断控制器传递的中断不计入优先级计算。
     */
    mask = s->isr;
    if (s->special_fully_nested_mode && s == &s->pics_state->pics[0])
        mask &= ~(1 << 2);
    cur_priority = get_priority(s, mask);
    if (priority < cur_priority)
        /*
         * 找到更高优先级：应生成中断。
         */
        return (priority + s->priority_add) & 7;
    else
        return -1;
}


/*
 * 如果需要，将中断传递给CPU。必须在每次活动中断可能发生变化时调用。
 */
static void pic_update_irq(struct kvm_pic *s)
{
    int irq2, irq;

    // 获取从虚拟PIC中的中断
    irq2 = pic_get_irq(&s->pics[1]);
    if (irq2 >= 0) {
        /*
         * 如果由从属PIC发起中断请求，则向主PIC发出信号
         */
        pic_set_irq1(&s->pics[0], 2, 1);
        pic_set_irq1(&s->pics[0], 2, 0);
    }

    // 获取主PIC中的中断
    irq = pic_get_irq(&s->pics[0]);

    // 根据主PIC中的中断状态，发起中断请求给KVM
    pic_irq_request(s->kvm, irq >= 0);
}


void kvm_pic_update_irq(struct kvm_pic *s)
{
	pic_lock(s);
	pic_update_irq(s);
	pic_unlock(s);
}

int kvm_pic_set_irq(struct kvm_pic *s, int irq, int irq_source_id, int level)
{
	int ret, irq_level;

	BUG_ON(irq < 0 || irq >= PIC_NUM_PINS);

	pic_lock(s);
	irq_level = __kvm_irq_line_state(&s->irq_states[irq],
					 irq_source_id, level); //计算出中断信号的电平信息
	ret = pic_set_irq1(&s->pics[irq >> 3], irq & 7, irq_level);//设置对应中断芯片的状态
	pic_update_irq(s); //更新中断控制器的状态
	trace_kvm_pic_set_irq(irq >> 3, irq & 7, s->pics[irq >> 3].elcr,
			      s->pics[irq >> 3].imr, ret == 0);
	pic_unlock(s);

	return ret;
}

void kvm_pic_clear_all(struct kvm_pic *s, int irq_source_id)
{
	int i;

	pic_lock(s);
	for (i = 0; i < PIC_NUM_PINS; i++)
		__clear_bit(irq_source_id, &s->irq_states[i]);
	pic_unlock(s);
}

/*
 * 函数: pic_intack
 * ---------------------
 * PIC（Programmable Interrupt Controller）中断确认处理函数。
 *
 * 参数:
 *   - struct kvm_kpic_state *s: 指向KVM PIC状态的指针。
 *   - int irq: 中断号。
 *
 * 描述:
 *   此函数用于处理PIC的中断确认。根据中断的类型和PIC的配置，更新相应的状态。
 *   首先，设置中断服务寄存器（ISR）中相应的中断位。如果中断是电平触发的，
 *   则不清除中断请求寄存器（IRR）中的中断位。如果开启了自动EOI（End of Interrupt），
 *   则根据配置清除ISR中的中断位。如果启用了旋转优先级，调整优先级添加值，并在
 *   自动EOI模式下清除ISR中的中断位。
 */
static inline void pic_intack(struct kvm_kpic_state *s, int irq)
{
    s->isr |= 1 << irq;

    /*
     * 不清除电平触发的中断
     */
    if (!(s->elcr & (1 << irq)))
        s->irr &= ~(1 << irq);

    // 如果开启了自动EOI
    if (s->auto_eoi) {
        // 如果启用了旋转优先级，调整优先级添加值
        if (s->rotate_on_auto_eoi)
            s->priority_add = (irq + 1) & 7;

        // 在自动EOI模式下清除ISR中的中断位
        pic_clear_isr(s, irq);
    }
}


/*
 * 函数: kvm_pic_read_irq
 * ---------------------
 * 从KVM的PIC中读取挂起的中断，并进行中断确认。
 *
 * 参数:
 *   - struct kvm *kvm: 指向KVM主结构的指针。
 *
 * 返回值:
 *   - int: 中断号。
 *
 * 描述:
 *   此函数用于从KVM的PIC中读取挂起的中断，并进行中断确认。首先获取PIC的输出状态，
 *   然后通过pic_get_irq函数获取挂起的中断号，并调用pic_intack函数进行中断确认。
 *   如果中断是IRQ2（级联中断），则继续获取从PIC（slave controller）的中断。
 *   如果存在从PIC中断，则同样进行中断确认。如果没有主PIC中断，则返回7号中断，表示虚假中断。
 *   最后，更新PIC的中断状态，解锁PIC。
 */
int kvm_pic_read_irq(struct kvm *kvm)
{
    int irq, irq2, intno;
    struct kvm_pic *s = pic_irqchip(kvm);

    s->output = 0;

    pic_lock(s);

    // 获取主PIC中的挂起中断
    irq = pic_get_irq(&s->pics[0]);
    if (irq >= 0) {
        pic_intack(&s->pics[0], irq);

        // 如果是IRQ2（级联中断）
        if (irq == 2) {
            // 获取从PIC中的挂起中断
            irq2 = pic_get_irq(&s->pics[1]);
            if (irq2 >= 0)
                pic_intack(&s->pics[1], irq2);
            else
                /*
                 * 从PIC控制器上的虚假IRQ
                 */
                irq2 = 7;

            // 计算实际中断号
            intno = s->pics[1].irq_base + irq2;
            irq = irq2 + 8;
        } else {
            // 计算实际中断号
            intno = s->pics[0].irq_base + irq;
        }
    } else {
        /*
         * 在主控制器上的虚假IRQ
         */
        irq = 7;
        intno = s->pics[0].irq_base + irq;
    }

    // 更新PIC中断状态
    pic_update_irq(s);

    // 解锁PIC
    pic_unlock(s);

    return intno;
}


void kvm_pic_reset(struct kvm_kpic_state *s)
{
	int irq, i;
	struct kvm_vcpu *vcpu;
	u8 edge_irr = s->irr & ~s->elcr;
	bool found = false;

	s->last_irr = 0;
	s->irr &= s->elcr;
	s->imr = 0;
	s->priority_add = 0;
	s->special_mask = 0;
	s->read_reg_select = 0;
	if (!s->init4) {
		s->special_fully_nested_mode = 0;
		s->auto_eoi = 0;
	}
	s->init_state = 1;

	kvm_for_each_vcpu(i, vcpu, s->pics_state->kvm)
		if (kvm_apic_accept_pic_intr(vcpu)) {
			found = true;
			break;
		}


	if (!found)
		return;

	for (irq = 0; irq < PIC_NUM_PINS/2; irq++)
		if (edge_irr & (1 << irq))
			pic_clear_isr(s, irq);
}

static void pic_ioport_write(void *opaque, u32 addr, u32 val)
{
	struct kvm_kpic_state *s = opaque;
	int priority, cmd, irq;

	addr &= 1;
	if (addr == 0) {
		if (val & 0x10) {
			s->init4 = val & 1;
			if (val & 0x02)
				pr_pic_unimpl("single mode not supported");
			if (val & 0x08)
				pr_pic_unimpl(
						"level sensitive irq not supported");
			kvm_pic_reset(s);
		} else if (val & 0x08) {
			if (val & 0x04)
				s->poll = 1;
			if (val & 0x02)
				s->read_reg_select = val & 1;
			if (val & 0x40)
				s->special_mask = (val >> 5) & 1;
		} else {
			cmd = val >> 5;
			switch (cmd) {
			case 0:
			case 4:
				s->rotate_on_auto_eoi = cmd >> 2;
				break;
			case 1:	/* end of interrupt */
			case 5:
				priority = get_priority(s, s->isr);
				if (priority != 8) {
					irq = (priority + s->priority_add) & 7;
					if (cmd == 5)
						s->priority_add = (irq + 1) & 7;
					pic_clear_isr(s, irq);
					pic_update_irq(s->pics_state);
				}
				break;
			case 3:
				irq = val & 7;
				pic_clear_isr(s, irq);
				pic_update_irq(s->pics_state);
				break;
			case 6:
				s->priority_add = (val + 1) & 7;
				pic_update_irq(s->pics_state);
				break;
			case 7:
				irq = val & 7;
				s->priority_add = (irq + 1) & 7;
				pic_clear_isr(s, irq);
				pic_update_irq(s->pics_state);
				break;
			default:
				break;	/* no operation */
			}
		}
	} else
		switch (s->init_state) {
		case 0: { /* normal mode */
			u8 imr_diff = s->imr ^ val,
				off = (s == &s->pics_state->pics[0]) ? 0 : 8;
			s->imr = val;
			for (irq = 0; irq < PIC_NUM_PINS/2; irq++)
				if (imr_diff & (1 << irq))
					kvm_fire_mask_notifiers(
						s->pics_state->kvm,
						SELECT_PIC(irq + off),
						irq + off,
						!!(s->imr & (1 << irq)));
			pic_update_irq(s->pics_state);
			break;
		}
		case 1:
			s->irq_base = val & 0xf8;
			s->init_state = 2;
			break;
		case 2:
			if (s->init4)
				s->init_state = 3;
			else
				s->init_state = 0;
			break;
		case 3:
			s->special_fully_nested_mode = (val >> 4) & 1;
			s->auto_eoi = (val >> 1) & 1;
			s->init_state = 0;
			break;
		}
}

static u32 pic_poll_read(struct kvm_kpic_state *s, u32 addr1)
{
	int ret;

	ret = pic_get_irq(s);
	if (ret >= 0) {
		if (addr1 >> 7) {
			s->pics_state->pics[0].isr &= ~(1 << 2);
			s->pics_state->pics[0].irr &= ~(1 << 2);
		}
		s->irr &= ~(1 << ret);
		pic_clear_isr(s, ret);
		if (addr1 >> 7 || ret != 2)
			pic_update_irq(s->pics_state);
	} else {
		ret = 0x07;
		pic_update_irq(s->pics_state);
	}

	return ret;
}

static u32 pic_ioport_read(void *opaque, u32 addr1)
{
	struct kvm_kpic_state *s = opaque;
	unsigned int addr;
	int ret;

	addr = addr1;
	addr &= 1;
	if (s->poll) {
		ret = pic_poll_read(s, addr1);
		s->poll = 0;
	} else
		if (addr == 0)
			if (s->read_reg_select)
				ret = s->isr;
			else
				ret = s->irr;
		else
			ret = s->imr;
	return ret;
}

static void elcr_ioport_write(void *opaque, u32 addr, u32 val)
{
	struct kvm_kpic_state *s = opaque;
	s->elcr = val & s->elcr_mask;
}

static u32 elcr_ioport_read(void *opaque, u32 addr1)
{
	struct kvm_kpic_state *s = opaque;
	return s->elcr;
}

static int picdev_in_range(gpa_t addr)
{
	switch (addr) {
	case 0x20:
	case 0x21:
	case 0xa0:
	case 0xa1:
	case 0x4d0:
	case 0x4d1:
		return 1;
	default:
		return 0;
	}
}

static int picdev_write(struct kvm_pic *s,
			 gpa_t addr, int len, const void *val)
{
	unsigned char data = *(unsigned char *)val;
	if (!picdev_in_range(addr))
		return -EOPNOTSUPP;

	if (len != 1) {
		pr_pic_unimpl("non byte write\n");
		return 0;
	}
	pic_lock(s);
	switch (addr) {
	case 0x20:
	case 0x21:
	case 0xa0:
	case 0xa1:
		pic_ioport_write(&s->pics[addr >> 7], addr, data);
		break;
	case 0x4d0:
	case 0x4d1:
		elcr_ioport_write(&s->pics[addr & 1], addr, data);
		break;
	}
	pic_unlock(s);
	return 0;
}

static int picdev_read(struct kvm_pic *s,
		       gpa_t addr, int len, void *val)
{
	unsigned char data = 0;
	if (!picdev_in_range(addr))
		return -EOPNOTSUPP;

	if (len != 1) {
		memset(val, 0, len);
		pr_pic_unimpl("non byte read\n");
		return 0;
	}
	pic_lock(s);
	switch (addr) {
	case 0x20:
	case 0x21:
	case 0xa0:
	case 0xa1:
		data = pic_ioport_read(&s->pics[addr >> 7], addr);
		break;
	case 0x4d0:
	case 0x4d1:
		data = elcr_ioport_read(&s->pics[addr & 1], addr);
		break;
	}
	*(unsigned char *)val = data;
	pic_unlock(s);
	return 0;
}

static int picdev_master_write(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			       gpa_t addr, int len, const void *val)
{
	return picdev_write(container_of(dev, struct kvm_pic, dev_master),
			    addr, len, val);
}

static int picdev_master_read(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			      gpa_t addr, int len, void *val)
{
	return picdev_read(container_of(dev, struct kvm_pic, dev_master),
			    addr, len, val);
}

static int picdev_slave_write(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			      gpa_t addr, int len, const void *val)
{
	return picdev_write(container_of(dev, struct kvm_pic, dev_slave),
			    addr, len, val);
}

static int picdev_slave_read(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			     gpa_t addr, int len, void *val)
{
	return picdev_read(container_of(dev, struct kvm_pic, dev_slave),
			    addr, len, val);
}

static int picdev_eclr_write(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			     gpa_t addr, int len, const void *val)
{
	return picdev_write(container_of(dev, struct kvm_pic, dev_eclr),
			    addr, len, val);
}

static int picdev_eclr_read(struct kvm_vcpu *vcpu, struct kvm_io_device *dev,
			    gpa_t addr, int len, void *val)
{
	return picdev_read(container_of(dev, struct kvm_pic, dev_eclr),
			    addr, len, val);
}

/*
 * 函数: pic_irq_request
 * ---------------------
 * 当主PIC中断状态变化时的回调函数。
 *
 * 参数:
 *   - struct kvm *kvm: 指向KVM主结构的指针。
 *   - int level: 中断输出的状态（高电平或低电平）。
 *
 * 描述:
 *   此函数用作主PIC中断状态变化时的回调。它更新KVM中主PIC的状态，
 *   并在需要唤醒时设置相应标志。如果中断输出状态改变，该状态将
 *   被更新为新的状态。
 */
static void pic_irq_request(struct kvm *kvm, int level)
{
    struct kvm_pic *s = pic_irqchip(kvm);

    // 如果输出为空，表示主PIC的中断状态发生变化，需要唤醒。
    if (!s->output)
        s->wakeup_needed = true;

    // 更新主PIC的中断输出状态。
    s->output = level;
}


static const struct kvm_io_device_ops picdev_master_ops = {
	.read     = picdev_master_read,
	.write    = picdev_master_write,
};

static const struct kvm_io_device_ops picdev_slave_ops = {
	.read     = picdev_slave_read,
	.write    = picdev_slave_write,
};

static const struct kvm_io_device_ops picdev_eclr_ops = {
	.read     = picdev_eclr_read,
	.write    = picdev_eclr_write,
};

struct kvm_pic *kvm_create_pic(struct kvm *kvm)
{
    struct kvm_pic *s;
    int ret;

    // 分配并初始化一个新的 kvm_pic 结构
    s = kzalloc(sizeof(struct kvm_pic), GFP_KERNEL);
    if (!s)
        return NULL;
    spin_lock_init(&s->lock);
    s->kvm = kvm;
    s->pics[0].elcr_mask = 0xf8;
    s->pics[1].elcr_mask = 0xde;
    s->pics[0].pics_state = s;
    s->pics[1].pics_state = s;

    /*
     * 初始化 PIO 设备
     */
    kvm_iodevice_init(&s->dev_master, &picdev_master_ops);
    kvm_iodevice_init(&s->dev_slave, &picdev_slave_ops);
    kvm_iodevice_init(&s->dev_eclr, &picdev_eclr_ops);
    mutex_lock(&kvm->slots_lock);

    // 注册主 PIC 设备到 KVM PIO 总线
    ret = kvm_io_bus_register_dev(kvm, KVM_PIO_BUS, 0x20, 2, &s->dev_master);
    if (ret < 0)
        goto fail_unlock;

    // 注册从 PIC 设备到 KVM PIO 总线
    ret = kvm_io_bus_register_dev(kvm, KVM_PIO_BUS, 0xa0, 2, &s->dev_slave);
    if (ret < 0)
        goto fail_unreg_2;

    // 注册 "eclr" PIC 设备到 KVM PIO 总线
    ret = kvm_io_bus_register_dev(kvm, KVM_PIO_BUS, 0x4d0, 2, &s->dev_eclr);
    if (ret < 0)
        goto fail_unreg_1;

    mutex_unlock(&kvm->slots_lock);

    return s;

fail_unreg_1:
    kvm_io_bus_unregister_dev(kvm, KVM_PIO_BUS, &s->dev_slave);

fail_unreg_2:
    kvm_io_bus_unregister_dev(kvm, KVM_PIO_BUS, &s->dev_master);

fail_unlock:
    mutex_unlock(&kvm->slots_lock);

    // 失败时释放分配的资源
    kfree(s);

    return NULL;
}


void kvm_destroy_pic(struct kvm_pic *vpic)
{
	kvm_io_bus_unregister_dev(vpic->kvm, KVM_PIO_BUS, &vpic->dev_master);
	kvm_io_bus_unregister_dev(vpic->kvm, KVM_PIO_BUS, &vpic->dev_slave);
	kvm_io_bus_unregister_dev(vpic->kvm, KVM_PIO_BUS, &vpic->dev_eclr);
	kfree(vpic);
}
