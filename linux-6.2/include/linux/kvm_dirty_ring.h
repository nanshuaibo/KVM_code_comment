#ifndef KVM_DIRTY_RING_H
#define KVM_DIRTY_RING_H

#include <linux/kvm.h>

/**
 * kvm_dirty_ring: KVM 内部脏页环结构
 *
 * @dirty_index: 自由运行计数器，指向 dirty_ring->dirty_gfns 中下一个位置，
 *               用于存放新的脏页
 * @reset_index: 自由运行计数器，指向 dirty_ring->dirty_gfns 中下一个脏页，
 *               需要重新启用脏页陷阱
 * @size:        紧凑列表 dirty_ring->dirty_gfns 的大小
 * @soft_limit:  当列表中脏页的数量达到此限制时，拥有此环的 VCPU 应退出到用户空间，
 *               以允许用户空间收集所有脏页
 * @dirty_gfns:  用于保存脏 GFN（Guest Frame Number）的数组
 * @index:       此脏页环的索引
 */
struct kvm_dirty_ring {
	/* kvm填入PML Buffer的索引，每填入一个dirty index加1 */
    u32 dirty_index;    
    /* kvm复位entry为empty状态的索引，每复位一个
     * 需要将其对应的shadow ept表项对应的dirty位清零
     */
    u32 reset_index;
    u32 size;
   /* kvm在实现dirty ring时软件定义了一个ring size的上限
    * 它小于等于kvm真实分配的ring的大小，即soft_limit <= size
    * 当dirty ring被填充的entry大于soft_limit时，kvm会抛出
    * KVM_EXIT_DIRTY_RING_FULL异常，让vcpu退出到用户态 
    * 这个机制可以用来保证dirty ring不会真正的被填满 */
    u32 soft_limit;
    /* 与用户态共享的dirty ring */
    struct kvm_dirty_gfn *dirty_gfns;   
    int index;
};



#ifndef CONFIG_HAVE_KVM_DIRTY_RING
/*
 * If CONFIG_HAVE_HVM_DIRTY_RING not defined, kvm_dirty_ring.o should
 * not be included as well, so define these nop functions for the arch.
 */
static inline u32 kvm_dirty_ring_get_rsvd_entries(void)
{
	return 0;
}

static inline bool kvm_use_dirty_bitmap(struct kvm *kvm)
{
	return true;
}

static inline int kvm_dirty_ring_alloc(struct kvm_dirty_ring *ring,
				       int index, u32 size)
{
	return 0;
}

static inline int kvm_dirty_ring_reset(struct kvm *kvm,
				       struct kvm_dirty_ring *ring)
{
	return 0;
}

static inline void kvm_dirty_ring_push(struct kvm_vcpu *vcpu,
				       u32 slot, u64 offset)
{
}

static inline struct page *kvm_dirty_ring_get_page(struct kvm_dirty_ring *ring,
						   u32 offset)
{
	return NULL;
}

static inline void kvm_dirty_ring_free(struct kvm_dirty_ring *ring)
{
}

#else /* CONFIG_HAVE_KVM_DIRTY_RING */

int kvm_cpu_dirty_log_size(void);
bool kvm_use_dirty_bitmap(struct kvm *kvm);
bool kvm_arch_allow_write_without_running_vcpu(struct kvm *kvm);
u32 kvm_dirty_ring_get_rsvd_entries(void);
int kvm_dirty_ring_alloc(struct kvm_dirty_ring *ring, int index, u32 size);

/*
 * called with kvm->slots_lock held, returns the number of
 * processed pages.
 */
int kvm_dirty_ring_reset(struct kvm *kvm, struct kvm_dirty_ring *ring);

/*
 * returns =0: successfully pushed
 *         <0: unable to push, need to wait
 */
void kvm_dirty_ring_push(struct kvm_vcpu *vcpu, u32 slot, u64 offset);

bool kvm_dirty_ring_check_request(struct kvm_vcpu *vcpu);

/* for use in vm_operations_struct */
struct page *kvm_dirty_ring_get_page(struct kvm_dirty_ring *ring, u32 offset);

void kvm_dirty_ring_free(struct kvm_dirty_ring *ring);

#endif /* CONFIG_HAVE_KVM_DIRTY_RING */

#endif	/* KVM_DIRTY_RING_H */
