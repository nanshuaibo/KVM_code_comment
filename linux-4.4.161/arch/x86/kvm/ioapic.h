#ifndef __KVM_IO_APIC_H
#define __KVM_IO_APIC_H

#include <linux/kvm_host.h>

#include <kvm/iodev.h>

struct kvm;
struct kvm_vcpu;

#define IOAPIC_NUM_PINS  KVM_IOAPIC_NUM_PINS
#define MAX_NR_RESERVED_IOAPIC_PINS KVM_MAX_IRQ_ROUTES
#define IOAPIC_VERSION_ID 0x11	/* IOAPIC version */
#define IOAPIC_EDGE_TRIG  0
#define IOAPIC_LEVEL_TRIG 1

#define IOAPIC_DEFAULT_BASE_ADDRESS  0xfec00000
#define IOAPIC_MEM_LENGTH            0x100

/* Direct registers. */
#define IOAPIC_REG_SELECT  0x00
#define IOAPIC_REG_WINDOW  0x10

/* Indirect registers. */
#define IOAPIC_REG_APIC_ID 0x00	/* x86 IOAPIC only */
#define IOAPIC_REG_VERSION 0x01
#define IOAPIC_REG_ARB_ID  0x02	/* x86 IOAPIC only */

/*ioapic delivery mode*/
#define	IOAPIC_FIXED			0x0
#define	IOAPIC_LOWEST_PRIORITY		0x1
#define	IOAPIC_PMI			0x2
#define	IOAPIC_NMI			0x4
#define	IOAPIC_INIT			0x5
#define	IOAPIC_EXTINT			0x7

#ifdef CONFIG_X86
#define RTC_GSI 8
#else
#define RTC_GSI -1U
#endif

struct rtc_status {
	int pending_eoi;
	DECLARE_BITMAP(dest_map, KVM_MAX_VCPUS);
};

union kvm_ioapic_redirect_entry {
	u64 bits;
	struct {
		u8 vector; //中断向量号
		u8 delivery_mode:3;//中断发送到cpu的方式
		u8 dest_mode:1; //用来决定如何解释dest_id，如果其值为0，则用local apic的id与dest_id对比，如果为1，则需要进行更复杂的处理
		u8 delivery_status:1; //中断状态，0是空闲，1表示被挂起
		u8 polarity:1; //中断信号的触发极，0表示高电平触发，1表示低电平触发
		u8 remote_irr:1;//用于水平中断，当lapic接受中断后为1，当接收到eoi之后为0
		u8 trig_mode:1; //中断的触发模式，1表示水平触发，0表示边沿触发
		u8 mask:1; //是否屏蔽该中断，1表示屏蔽该中断
		u8 reserve:7;
		u8 reserved[4];
		u8 dest_id; //根据dest_mode解释，如果dest_mode为0，则dest_id包含lapic id，如果为1，dest_id可能包含一组cpu
	} fields;
};

struct kvm_ioapic {
    u64 base_address;                           // IOAPIC 的mmio基址
    u32 ioregsel;                               // I/O 寄存器选择
    u32 id;                                     // IOAPIC 的唯一标识符
    u32 irr;                                    // 中断请求寄存器（Interrupt Request Register）
    u32 pad;                                    // 填充字段

    union kvm_ioapic_redirect_entry redirtbl[IOAPIC_NUM_PINS];  // IOAPIC 的重定向表
    unsigned long irq_states[IOAPIC_NUM_PINS];  // 中断状态数组
    struct kvm_io_device dev;                   // KVM I/O 设备
    struct kvm *kvm;                            // 指向 KVM 结构的指针

    void (*ack_notifier)(void *opaque, int irq);  // 中断应答通知函数指针
    spinlock_t lock;                            // 自旋锁
    struct rtc_status rtc_status;               // RTC（Real-Time Clock）状态
    struct delayed_work eoi_inject;            // 延迟工作队列用于 EOI 注入
    u32 irq_eoi[IOAPIC_NUM_PINS];               // 中断 EOI 记录数组
    u32 irr_delivered;                          // 已传递的中断请求寄存器状态
};


#ifdef DEBUG
#define ASSERT(x)  							\
do {									\
	if (!(x)) {							\
		printk(KERN_EMERG "assertion failed %s: %d: %s\n",	\
		       __FILE__, __LINE__, #x);				\
		BUG();							\
	}								\
} while (0)
#else
#define ASSERT(x) do { } while (0)
#endif

static inline struct kvm_ioapic *ioapic_irqchip(struct kvm *kvm)
{
	return kvm->arch.vioapic;
}

static inline int ioapic_in_kernel(struct kvm *kvm)
{
	int ret;

	ret = (ioapic_irqchip(kvm) != NULL);
	return ret;
}

void kvm_rtc_eoi_tracking_restore_one(struct kvm_vcpu *vcpu);
bool kvm_apic_match_dest(struct kvm_vcpu *vcpu, struct kvm_lapic *source,
		int short_hand, unsigned int dest, int dest_mode);
int kvm_apic_compare_prio(struct kvm_vcpu *vcpu1, struct kvm_vcpu *vcpu2);
void kvm_ioapic_update_eoi(struct kvm_vcpu *vcpu, int vector,
			int trigger_mode);
int kvm_ioapic_init(struct kvm *kvm);
void kvm_ioapic_destroy(struct kvm *kvm);
int kvm_ioapic_set_irq(struct kvm_ioapic *ioapic, int irq, int irq_source_id,
		       int level, bool line_status);
void kvm_ioapic_clear_all(struct kvm_ioapic *ioapic, int irq_source_id);
int kvm_irq_delivery_to_apic(struct kvm *kvm, struct kvm_lapic *src,
		struct kvm_lapic_irq *irq, unsigned long *dest_map);
int kvm_get_ioapic(struct kvm *kvm, struct kvm_ioapic_state *state);
int kvm_set_ioapic(struct kvm *kvm, struct kvm_ioapic_state *state);
void kvm_ioapic_scan_entry(struct kvm_vcpu *vcpu, u64 *eoi_exit_bitmap);
void kvm_scan_ioapic_routes(struct kvm_vcpu *vcpu, u64 *eoi_exit_bitmap);

#endif
