/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_MMU_INTERNAL_H
#define __KVM_X86_MMU_INTERNAL_H

#include <linux/types.h>
#include <linux/kvm_host.h>
#include <asm/kvm_host.h>

#undef MMU_DEBUG

#ifdef MMU_DEBUG
extern bool dbg;

#define pgprintk(x...) do { if (dbg) printk(x); } while (0)
#define rmap_printk(fmt, args...) do { if (dbg) printk("%s: " fmt, __func__, ## args); } while (0)
#define MMU_WARN_ON(x) WARN_ON(x)
#else
#define pgprintk(x...) do { } while (0)
#define rmap_printk(x...) do { } while (0)
#define MMU_WARN_ON(x) do { } while (0)
#endif

/* Page table builder macros common to shadow (host) PTEs and guest PTEs. */
#define __PT_LEVEL_SHIFT(level, bits_per_level)	\
	(PAGE_SHIFT + ((level) - 1) * (bits_per_level))
#define __PT_INDEX(address, level, bits_per_level) \
	(((address) >> __PT_LEVEL_SHIFT(level, bits_per_level)) & ((1 << (bits_per_level)) - 1))

#define __PT_LVL_ADDR_MASK(base_addr_mask, level, bits_per_level) \
	((base_addr_mask) & ~((1ULL << (PAGE_SHIFT + (((level) - 1) * (bits_per_level)))) - 1))

#define __PT_LVL_OFFSET_MASK(base_addr_mask, level, bits_per_level) \
	((base_addr_mask) & ((1ULL << (PAGE_SHIFT + (((level) - 1) * (bits_per_level)))) - 1))

#define __PT_ENT_PER_PAGE(bits_per_level)  (1 << (bits_per_level))

/*
 * Unlike regular MMU roots, PAE "roots", a.k.a. PDPTEs/PDPTRs, have a PRESENT
 * bit, and thus are guaranteed to be non-zero when valid.  And, when a guest
 * PDPTR is !PRESENT, its corresponding PAE root cannot be set to INVALID_PAGE,
 * as the CPU would treat that as PRESENT PDPTR with reserved bits set.  Use
 * '0' instead of INVALID_PAGE to indicate an invalid PAE root.
 */
#define INVALID_PAE_ROOT	0
#define IS_VALID_PAE_ROOT(x)	(!!(x))

typedef u64 __rcu *tdp_ptep_t;

struct kvm_mmu_page {
	/*
	 * Note, "link" through "spt" fit in a single 64 byte cache line on
	 * 64-bit kernels, keep it that way unless there's a reason not to.
	 */
	struct list_head link;
	struct hlist_node hash_link;

	bool tdp_mmu_page;
	bool unsync;
	u8 mmu_valid_gen;

	 /*
	  * The shadow page can't be replaced by an equivalent huge page
	  * because it is being used to map an executable page in the guest
	  * and the NX huge page mitigation is enabled.
	  */
	bool nx_huge_page_disallowed;

	/*
	 * The following two entries are used to key the shadow page in the
	 * hash table.
	 */
	union kvm_mmu_page_role role;
	gfn_t gfn;

	u64 *spt;

	/*
	 * Stores the result of the guest translation being shadowed by each
	 * SPTE.  KVM shadows two types of guest translations: nGPA -> GPA
	 * (shadow EPT/NPT) and GVA -> GPA (traditional shadow paging). In both
	 * cases the result of the translation is a GPA and a set of access
	 * constraints.
	 *
	 * The GFN is stored in the upper bits (PAGE_SHIFT) and the shadowed
	 * access permissions are stored in the lower bits. Note, for
	 * convenience and uniformity across guests, the access permissions are
	 * stored in KVM format (e.g.  ACC_EXEC_MASK) not the raw guest format.
	 */
	u64 *shadowed_translation;

	/* Currently serving as active root */
	union {
		int root_count;
		refcount_t tdp_mmu_root_count;
	};
	unsigned int unsync_children;
	union {
		struct kvm_rmap_head parent_ptes; /* rmap pointers to parent sptes */
		tdp_ptep_t ptep;
	};
	union {
		DECLARE_BITMAP(unsync_child_bitmap, 512);
		struct {
			struct work_struct tdp_mmu_async_work;
			void *tdp_mmu_async_data;
		};
	};

	/*
	 * Tracks shadow pages that, if zapped, would allow KVM to create an NX
	 * huge page.  A shadow page will have nx_huge_page_disallowed set but
	 * not be on the list if a huge page is disallowed for other reasons,
	 * e.g. because KVM is shadowing a PTE at the same gfn, the memslot
	 * isn't properly aligned, etc...
	 */
	struct list_head possible_nx_huge_page_link;
#ifdef CONFIG_X86_32
	/*
	 * Used out of the mmu-lock to avoid reading spte values while an
	 * update is in progress; see the comments in __get_spte_lockless().
	 */
	int clear_spte_count;
#endif

	/* Number of writes since the last time traversal visited this page.  */
	atomic_t write_flooding_count;

#ifdef CONFIG_X86_64
	/* Used for freeing the page asynchronously if it is a TDP MMU page. */
	struct rcu_head rcu_head;
#endif
};

extern struct kmem_cache *mmu_page_header_cache;

static inline int kvm_mmu_role_as_id(union kvm_mmu_page_role role)
{
	return role.smm ? 1 : 0;
}

static inline int kvm_mmu_page_as_id(struct kvm_mmu_page *sp)
{
	return kvm_mmu_role_as_id(sp->role);
}

static inline bool kvm_mmu_page_ad_need_write_protect(struct kvm_mmu_page *sp)
{
	/*
	 * When using the EPT page-modification log, the GPAs in the CPU dirty
	 * log would come from L2 rather than L1.  Therefore, we need to rely
	 * on write protection to record dirty pages, which bypasses PML, since
	 * writes now result in a vmexit.  Note, the check on CPU dirty logging
	 * being enabled is mandatory as the bits used to denote WP-only SPTEs
	 * are reserved for PAE paging (32-bit KVM).
	 */
	return kvm_x86_ops.cpu_dirty_log_size && sp->role.guest_mode;
}

int mmu_try_to_unsync_pages(struct kvm *kvm, const struct kvm_memory_slot *slot,
			    gfn_t gfn, bool can_unsync, bool prefetch);

void kvm_mmu_gfn_disallow_lpage(const struct kvm_memory_slot *slot, gfn_t gfn);
void kvm_mmu_gfn_allow_lpage(const struct kvm_memory_slot *slot, gfn_t gfn);
bool kvm_mmu_slot_gfn_write_protect(struct kvm *kvm,
				    struct kvm_memory_slot *slot, u64 gfn,
				    int min_level);
void kvm_flush_remote_tlbs_with_address(struct kvm *kvm,
					u64 start_gfn, u64 pages);
unsigned int pte_list_count(struct kvm_rmap_head *rmap_head);

extern int nx_huge_pages;
static inline bool is_nx_huge_page_enabled(struct kvm *kvm)
{
	return READ_ONCE(nx_huge_pages) && !kvm->arch.disable_nx_huge_pages;
}

struct kvm_page_fault {
	/* arguments to kvm_mmu_do_page_fault.  */
	const gpa_t addr; //缺页异常地址
	const u32 error_code; //错误码
	const bool prefetch;  //是否是预取（prefetch）引起的故障

	/* Derived from error_code.  */
	const bool exec;
	const bool write;
	const bool present;
	const bool rsvd;
	const bool user;

	/* Derived from mmu and global state.  */
	const bool is_tdp;
	const bool nx_huge_page_workaround_enabled;

	/*
	 * Whether a >4KB mapping can be created or is forbidden due to NX
	 * hugepages.
	 * 是否可以创建大于4KB的内存映射，
	 * 或者由于不允许使用不可执行（NX）的大页（huge pages）
	 */
	bool huge_page_disallowed; //

	/*
	 * Maximum page size that can be created for this fault; input to
	 * FNAME(fetch), __direct_map and kvm_tdp_mmu_map.
	 */
	u8 max_level; //最大的页表级别

	/*
	 * Page size that can be created based on the max_level and the
	 * page size used by the host mapping.
	 */
	u8 req_level; //请求创建的页表级别

	/*
	 * Page size that will be created based on the req_level and
	 * huge_page_disallowed.
	 */
	u8 goal_level; //最终创建的页表级别

	/* Shifted addr, or result of guest page table walk if addr is a gva.  */
	gfn_t gfn; //虚拟机的页帧号

	/* The memslot containing gfn. May be NULL. */
	struct kvm_memory_slot *slot; 

	/* Outputs of kvm_faultin_pfn.  */
	kvm_pfn_t pfn; //页帧号
	hva_t hva; //主机虚拟地址
	bool map_writable;
};

int kvm_tdp_page_fault(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault);

/*
 * handle_mmio_page_fault()、mmu.page_fault()、fast_page_fault() 以及
 * 当然还有 kvm_mmu_do_page_fault() 的返回值:
 *
 * RET_PF_CONTINUE: 到目前为止一切顺利，继续处理页错误。
 * RET_PF_RETRY: 让 CPU 在相同地址上再次产生故障。
 * RET_PF_EMULATE: mmio 页错误，直接模拟该指令。
 * RET_PF_INVALID: spte 无效，让真实的页错误路径更新它。
 * RET_PF_FIXED: 故障条目已修复。
 * RET_PF_SPURIOUS: 故障条目已经被修复，例如，由另一个 vCPU 修复。
 *
 * 如果将任何名称添加到此枚举类型，应通过 mmutrace.h 中的 TRACE_DEFINE_ENUM()
 * 导出到用户空间以供跟踪点使用。
 *
 * 注意，所有的值必须大于或等于零，以免影响到 -errno 的返回值。为了检查 CONTINUE
 * 的有效性，有些主观的使用 '0'，这将允许在检查 CONTINUE 时产生高效的机器代码，
 * 例如 "TEST %rax, %rax, JNZ"，因为所有的 "stop!" 值都是非零的。
 */

enum {
	RET_PF_CONTINUE = 0,
	RET_PF_RETRY,
	RET_PF_EMULATE,
	RET_PF_INVALID,
	RET_PF_FIXED,
	RET_PF_SPURIOUS,
};

static inline int kvm_mmu_do_page_fault(struct kvm_vcpu *vcpu, gpa_t cr2_or_gpa,
					u32 err, bool prefetch)
{
	struct kvm_page_fault fault = {
		.addr = cr2_or_gpa,
		.error_code = err,
		.exec = err & PFERR_FETCH_MASK,
		.write = err & PFERR_WRITE_MASK,
		.present = err & PFERR_PRESENT_MASK,
		.rsvd = err & PFERR_RSVD_MASK,
		.user = err & PFERR_USER_MASK,
		.prefetch = prefetch,
		.is_tdp = likely(vcpu->arch.mmu->page_fault == kvm_tdp_page_fault),
		.nx_huge_page_workaround_enabled =
			is_nx_huge_page_enabled(vcpu->kvm),

		.max_level = KVM_MAX_HUGEPAGE_LEVEL,
		.req_level = PG_LEVEL_4K,
		.goal_level = PG_LEVEL_4K,
	};
	int r;

	/*
	 * Async #PF "faults", a.k.a. prefetch faults, are not faults from the
	 * guest perspective and have already been counted at the time of the
	 * original fault.
	 */
	if (!prefetch)
		vcpu->stat.pf_taken++;

	if (IS_ENABLED(CONFIG_RETPOLINE) && fault.is_tdp)
		r = kvm_tdp_page_fault(vcpu, &fault);
	else
		r = vcpu->arch.mmu->page_fault(vcpu, &fault);

	/*
	 * Similar to above, prefetch faults aren't truly spurious, and the
	 * async #PF path doesn't do emulation.  Do count faults that are fixed
	 * by the async #PF handler though, otherwise they'll never be counted.
	 */
	if (r == RET_PF_FIXED)
		vcpu->stat.pf_fixed++;
	else if (prefetch)
		;
	else if (r == RET_PF_EMULATE)
		vcpu->stat.pf_emulate++;
	else if (r == RET_PF_SPURIOUS)
		vcpu->stat.pf_spurious++;
	return r;
}

int kvm_mmu_max_mapping_level(struct kvm *kvm,
			      const struct kvm_memory_slot *slot, gfn_t gfn,
			      int max_level);
void kvm_mmu_hugepage_adjust(struct kvm_vcpu *vcpu, struct kvm_page_fault *fault);
void disallowed_hugepage_adjust(struct kvm_page_fault *fault, u64 spte, int cur_level);

void *mmu_memory_cache_alloc(struct kvm_mmu_memory_cache *mc);

void track_possible_nx_huge_page(struct kvm *kvm, struct kvm_mmu_page *sp);
void untrack_possible_nx_huge_page(struct kvm *kvm, struct kvm_mmu_page *sp);

#endif /* __KVM_X86_MMU_INTERNAL_H */
