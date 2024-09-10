// SPDX-License-Identifier: GPL-2.0-only
/*
 * kvm asynchronous fault support
 *
 * Copyright 2010 Red Hat, Inc.
 *
 * Author:
 *      Gleb Natapov <gleb@redhat.com>
 */

#include <linux/kvm_host.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/mmu_context.h>
#include <linux/sched/mm.h>

#include "async_pf.h"
#include <trace/events/kvm.h>

static struct kmem_cache *async_pf_cache;

int kvm_async_pf_init(void)
{
	async_pf_cache = KMEM_CACHE(kvm_async_pf, 0);

	if (!async_pf_cache)
		return -ENOMEM;

	return 0;
}

void kvm_async_pf_deinit(void)
{
	kmem_cache_destroy(async_pf_cache);
	async_pf_cache = NULL;
}

void kvm_async_pf_vcpu_init(struct kvm_vcpu *vcpu)
{
	INIT_LIST_HEAD(&vcpu->async_pf.done);
	INIT_LIST_HEAD(&vcpu->async_pf.queue);
	spin_lock_init(&vcpu->async_pf.lock);
}

static void async_pf_execute(struct work_struct *work)
{
    // 从work_struct指针中提取kvm_async_pf结构体指针
    struct kvm_async_pf *apf =
        container_of(work, struct kvm_async_pf, work);
    
    // 获取相关的mm_struct和kvm_vcpu指针
    struct mm_struct *mm = apf->mm;
    struct kvm_vcpu *vcpu = apf->vcpu;
    
    // 获取异步页表故障地址和CR2/GPA值
    unsigned long addr = apf->addr;
    gpa_t cr2_or_gpa = apf->cr2_or_gpa;
    
    // 初始化锁定标志
    int locked = 1;
    
    // 提示编译器当前上下文可能会睡眠
    might_sleep();

    // 加读锁以访问远程内存
    mmap_read_lock(mm);
    
    // 获取用户页面并锁定
    get_user_pages_remote(mm, addr, 1, FOLL_WRITE, NULL, NULL,
                          &locked);
    
    // 如果锁定成功，解锁
    if (locked)
        mmap_read_unlock(mm);

    // 根据配置同步或异步地处理页表故障
    if (IS_ENABLED(CONFIG_KVM_ASYNC_PF_SYNC))
        kvm_arch_async_page_present(vcpu, apf);

    // 获取并更新异步页表故障链表
    spin_lock(&vcpu->async_pf.lock);
    first = list_empty(&vcpu->async_pf.done);
    list_add_tail(&apf->link, &vcpu->async_pf.done);
    apf->vcpu = NULL;
    spin_unlock(&vcpu->async_pf.lock);

    // 如果异步处理且链表为空，则触发页表填充
    if (!IS_ENABLED(CONFIG_KVM_ASYNC_PF_SYNC) && first)
        kvm_arch_async_page_present_queued(vcpu);

    // 在此点之后，apf可能被释放

    // 记录异步页表故障完成情况
    trace_kvm_async_pf_completed(addr, cr2_or_gpa);

    // 唤醒等待的虚拟CPU
    __kvm_vcpu_wake_up(vcpu);

    // 释放mm和kvm引用
    mmput(mm);
    kvm_put_kvm(vcpu->kvm);
}

void kvm_clear_async_pf_completion_queue(struct kvm_vcpu *vcpu)
{
	spin_lock(&vcpu->async_pf.lock);

	/* cancel outstanding work queue item */
	while (!list_empty(&vcpu->async_pf.queue)) {
		struct kvm_async_pf *work =
			list_first_entry(&vcpu->async_pf.queue,
					 typeof(*work), queue);
		list_del(&work->queue);

		/*
		 * We know it's present in vcpu->async_pf.done, do
		 * nothing here.
		 */
		if (!work->vcpu)
			continue;

		spin_unlock(&vcpu->async_pf.lock);
#ifdef CONFIG_KVM_ASYNC_PF_SYNC
		flush_work(&work->work);
#else
		if (cancel_work_sync(&work->work)) {
			mmput(work->mm);
			kvm_put_kvm(vcpu->kvm); /* == work->vcpu->kvm */
			kmem_cache_free(async_pf_cache, work);
		}
#endif
		spin_lock(&vcpu->async_pf.lock);
	}

	while (!list_empty(&vcpu->async_pf.done)) {
		struct kvm_async_pf *work =
			list_first_entry(&vcpu->async_pf.done,
					 typeof(*work), link);
		list_del(&work->link);
		kmem_cache_free(async_pf_cache, work);
	}
	spin_unlock(&vcpu->async_pf.lock);

	vcpu->async_pf.queued = 0;
}

void kvm_check_async_pf_completion(struct kvm_vcpu *vcpu)
{
	struct kvm_async_pf *work;

	while (!list_empty_careful(&vcpu->async_pf.done) &&
	      kvm_arch_can_dequeue_async_page_present(vcpu)) {
		spin_lock(&vcpu->async_pf.lock);
		work = list_first_entry(&vcpu->async_pf.done, typeof(*work),
					      link);
		list_del(&work->link);
		spin_unlock(&vcpu->async_pf.lock);

		kvm_arch_async_page_ready(vcpu, work);
		if (!IS_ENABLED(CONFIG_KVM_ASYNC_PF_SYNC))
			kvm_arch_async_page_present(vcpu, work);

		list_del(&work->queue);
		vcpu->async_pf.queued--;
		kmem_cache_free(async_pf_cache, work);
	}
}

// 尝试异步调度一个任务来处理页面错误
// 成功返回true，失败（页面错误需要同步处理）返回false
// 定义一个名为kvm_setup_async_pf的函数，接受一个指向kvm_vcpu结构的指针、一个gpa_t类型的值、一个unsigned long类型的值和一个指向kvm_arch_async_pf结构的指针作为参数
bool kvm_setup_async_pf(struct kvm_vcpu *vcpu, gpa_t cr2_or_gpa,
        unsigned long hva, struct kvm_arch_async_pf *arch)
{
    // 声明一个指向kvm_async_pf结构的指针
    struct kvm_async_pf *work;

    // 如果当前虚拟CPU的已排队异步页面错误数量已达到上限，返回false
    if (vcpu->async_pf.queued >= ASYNC_PF_PER_VCPU)
        return false;

    // 如果给定的宿主机虚拟地址是错误地址，返回false
    if (unlikely(kvm_is_error_hva(hva)))
        return false;

    // 使用kmem_cache_zalloc()函数分配一个新的kvm_async_pf结构体，并设置其成员变量
    work = kmem_cache_zalloc(async_pf_cache, GFP_NOWAIT | __GFP_NOWARN);
    if (!work)
        return false;

    // 设置work的成员变量
    work->wakeup_all = false;
    work->vcpu = vcpu;
    work->cr2_or_gpa = cr2_or_gpa;
    work->addr = hva;
    work->arch = *arch;
    work->mm = current->mm;
    mmget(work->mm); //内存描述符用户+1
    kvm_get_kvm(work->vcpu->kvm); //kvm实例用户+1

    // 初始化work的work_struct，并将其设置为async_pf_execute函数
    INIT_WORK(&work->work, async_pf_execute);

    // 将work添加到虚拟CPU的异步页面错误队列中
    list_add_tail(&work->queue, &vcpu->async_pf.queue);
    vcpu->async_pf.queued++;

    // 根据架构设置notpresent_injected成员变量
    work->notpresent_injected = kvm_arch_async_page_not_present(vcpu, work);

    // 调度work以异步处理页面错误
    schedule_work(&work->work);

    // 返回true表示成功设置了异步页面错误处理
    return true;
}

int kvm_async_pf_wakeup_all(struct kvm_vcpu *vcpu)
{
	struct kvm_async_pf *work;
	bool first;

	if (!list_empty_careful(&vcpu->async_pf.done))
		return 0;

	work = kmem_cache_zalloc(async_pf_cache, GFP_ATOMIC);
	if (!work)
		return -ENOMEM;

	work->wakeup_all = true;
	INIT_LIST_HEAD(&work->queue); /* for list_del to work */

	spin_lock(&vcpu->async_pf.lock);
	first = list_empty(&vcpu->async_pf.done);
	list_add_tail(&work->link, &vcpu->async_pf.done);
	spin_unlock(&vcpu->async_pf.lock);

	if (!IS_ENABLED(CONFIG_KVM_ASYNC_PF_SYNC) && first)
		kvm_arch_async_page_present_queued(vcpu);

	vcpu->async_pf.queued++;
	return 0;
}
