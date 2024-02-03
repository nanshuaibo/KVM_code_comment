// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM dirty ring implementation
 *
 * Copyright 2019 Red Hat, Inc.
 */
#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/vmalloc.h>
#include <linux/kvm_dirty_ring.h>
#include <trace/events/kvm.h>
#include "kvm_mm.h"

int __weak kvm_cpu_dirty_log_size(void)
{
	return 0;
}

u32 kvm_dirty_ring_get_rsvd_entries(void)
{
	return KVM_DIRTY_RING_RSVD_ENTRIES + kvm_cpu_dirty_log_size();
}

bool kvm_use_dirty_bitmap(struct kvm *kvm)
{
	lockdep_assert_held(&kvm->slots_lock);

	return !kvm->dirty_ring_size || kvm->dirty_ring_with_bitmap;
}

#ifndef CONFIG_NEED_KVM_DIRTY_RING_WITH_BITMAP
bool kvm_arch_allow_write_without_running_vcpu(struct kvm *kvm)
{
	return false;
}
#endif

static u32 kvm_dirty_ring_used(struct kvm_dirty_ring *ring)
{
	return READ_ONCE(ring->dirty_index) - READ_ONCE(ring->reset_index);
}

static bool kvm_dirty_ring_soft_full(struct kvm_dirty_ring *ring)
{
	return kvm_dirty_ring_used(ring) >= ring->soft_limit;
}

static bool kvm_dirty_ring_full(struct kvm_dirty_ring *ring)
{
	return kvm_dirty_ring_used(ring) >= ring->size;
}

static void kvm_reset_dirty_gfn(struct kvm *kvm, u32 slot, u64 offset, u64 mask)
{
	struct kvm_memory_slot *memslot;
	int as_id, id;

	as_id = slot >> 16;
	id = (u16)slot;

	if (as_id >= KVM_ADDRESS_SPACE_NUM || id >= KVM_USER_MEM_SLOTS)
		return;

	memslot = id_to_memslot(__kvm_memslots(kvm, as_id), id);

	if (!memslot || (offset + __fls(mask)) >= memslot->npages)
		return;

	KVM_MMU_LOCK(kvm);
	kvm_arch_mmu_enable_log_dirty_pt_masked(kvm, memslot, offset, mask);
	KVM_MMU_UNLOCK(kvm);
}

int kvm_dirty_ring_alloc(struct kvm_dirty_ring *ring, int index, u32 size)
{
	ring->dirty_gfns = vzalloc(size);
	if (!ring->dirty_gfns)
		return -ENOMEM;

	ring->size = size / sizeof(struct kvm_dirty_gfn);
	ring->soft_limit = ring->size - kvm_dirty_ring_get_rsvd_entries();
	ring->dirty_index = 0;
	ring->reset_index = 0;
	ring->index = index;

	return 0;
}

static inline void kvm_dirty_gfn_set_invalid(struct kvm_dirty_gfn *gfn)
{
	smp_store_release(&gfn->flags, 0);
}

static inline void kvm_dirty_gfn_set_dirtied(struct kvm_dirty_gfn *gfn)
{
	gfn->flags = KVM_DIRTY_GFN_F_DIRTY;
}

static inline bool kvm_dirty_gfn_harvested(struct kvm_dirty_gfn *gfn)
{
	return smp_load_acquire(&gfn->flags) & KVM_DIRTY_GFN_F_RESET;
}

int kvm_dirty_ring_reset(struct kvm *kvm, struct kvm_dirty_ring *ring)
{
	u32 cur_slot, next_slot;
	u64 cur_offset, next_offset;
	unsigned long mask;
	int count = 0;
	struct kvm_dirty_gfn *entry;
	bool first_round = true;

	/* This is only needed to make compilers happy */
	cur_slot = cur_offset = mask = 0;

	while (true) {
		entry = &ring->dirty_gfns[ring->reset_index & (ring->size - 1)];

		if (!kvm_dirty_gfn_harvested(entry))
			break;

		next_slot = READ_ONCE(entry->slot);
		next_offset = READ_ONCE(entry->offset);

		/* Update the flags to reflect that this GFN is reset */
		kvm_dirty_gfn_set_invalid(entry);

		ring->reset_index++;
		count++;
		/*
		 * Try to coalesce the reset operations when the guest is
		 * scanning pages in the same slot.
		 */
		if (!first_round && next_slot == cur_slot) {
			s64 delta = next_offset - cur_offset;

			if (delta >= 0 && delta < BITS_PER_LONG) {
				mask |= 1ull << delta;
				continue;
			}

			/* Backwards visit, careful about overflows!  */
			if (delta > -BITS_PER_LONG && delta < 0 &&
			    (mask << -delta >> -delta) == mask) {
				cur_offset = next_offset;
				mask = (mask << -delta) | 1;
				continue;
			}
		}
		kvm_reset_dirty_gfn(kvm, cur_slot, cur_offset, mask);
		cur_slot = next_slot;
		cur_offset = next_offset;
		mask = 1;
		first_round = false;
	}

	kvm_reset_dirty_gfn(kvm, cur_slot, cur_offset, mask);

	/*
	 * The request KVM_REQ_DIRTY_RING_SOFT_FULL will be cleared
	 * by the VCPU thread next time when it enters the guest.
	 */

	trace_kvm_dirty_ring_reset(ring);

	return count;
}

/**
 * kvm_dirty_ring_push - 将脏页信息推送到虚拟机的脏页环中
 * @vcpu: 虚拟CPU指针
 * @slot: 内存槽位
 * @offset: 页面偏移量
 *
 * 此函数将脏页信息推送到虚拟机的脏页环中。该环用于跟踪虚拟机中页面的脏页状态。
 * 函数首先确保脏页环不会变满，然后将脏页信息填入环中的相应槽位，并更新环的索引。
 * 在将数据发布给用户空间程序之前，通过 smp_wmb() 确保数据已填充。同时，如果脏页环
 * 达到软限制，触发 KVM 请求以通知虚拟机处理脏页环的软满状态。
 */
void kvm_dirty_ring_push(struct kvm_vcpu *vcpu, u32 slot, u64 offset)
{
	struct kvm_dirty_ring *ring = &vcpu->dirty_ring;
	struct kvm_dirty_gfn *entry;

	/* It should never get full */
	WARN_ON_ONCE(kvm_dirty_ring_full(ring));

	entry = &ring->dirty_gfns[ring->dirty_index & (ring->size - 1)];

	entry->slot = slot;
	entry->offset = offset;
	/*
	 * Make sure the data is filled in before we publish this to
	 * the userspace program.  There's no paired kernel-side reader.
	 */
	smp_wmb();
	kvm_dirty_gfn_set_dirtied(entry);
	ring->dirty_index++;
	trace_kvm_dirty_ring_push(ring, slot, offset);

	if (kvm_dirty_ring_soft_full(ring))
		kvm_make_request(KVM_REQ_DIRTY_RING_SOFT_FULL, vcpu);
}

/**
 * kvm_dirty_ring_check_request - 检查脏页环的请求情况
 * @vcpu: 指向虚拟 CPU 结构的指针
 *
 * 该函数用于检查虚拟 CPU 的脏页环是否需要关注。如果脏页环软性满了，
 * 它通过设置 KVM_REQ_DIRTY_RING_SOFT_FULL 请求事件来阻止 VCPU 运行。
 * VCPU 的退出原因被设置为 KVM_EXIT_DIRTY_RING_FULL，并生成一个跟踪事件。
 *
 * 返回值：
 * - 如果脏页环需要关注，阻止 VCPU 运行，则返回 true。
 * - 否则返回 false。
 */
bool kvm_dirty_ring_check_request(struct kvm_vcpu *vcpu)
{
	/*
	 * 当脏页环软性满了时，VCPU 不可运行。
	 * 总是设置 KVM_REQ_DIRTY_RING_SOFT_FULL 事件，以防止
	 * VCPU 在脏页被收集且脏页环被用户空间重置之前运行。
	 */
	if (kvm_check_request(KVM_REQ_DIRTY_RING_SOFT_FULL, vcpu) &&
	    kvm_dirty_ring_soft_full(&vcpu->dirty_ring)) {
		kvm_make_request(KVM_REQ_DIRTY_RING_SOFT_FULL, vcpu);
		vcpu->run->exit_reason = KVM_EXIT_DIRTY_RING_FULL;
		trace_kvm_dirty_ring_exit(vcpu);
		return true;
	}

	return false;
}


struct page *kvm_dirty_ring_get_page(struct kvm_dirty_ring *ring, u32 offset)
{
	return vmalloc_to_page((void *)ring->dirty_gfns + offset * PAGE_SIZE);
}

void kvm_dirty_ring_free(struct kvm_dirty_ring *ring)
{
	vfree(ring->dirty_gfns);
	ring->dirty_gfns = NULL;
}
