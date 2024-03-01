.. SPDX-License-Identifier: GPL-2.0

==============
KVM CPUID bits
==============

:Author: Glauber Costa <glommer@gmail.com>

A guest running on a kvm host, can check some of its features using
cpuid. This is not always guaranteed to work, since userspace can
mask-out some, or even all KVM-related cpuid features before launching
a guest.

KVM cpuid functions are:

function: KVM_CPUID_SIGNATURE (0x40000000)

returns::

   eax = 0x40000001
   ebx = 0x4b4d564b
   ecx = 0x564b4d56
   edx = 0x4d

Note that this value in ebx, ecx and edx corresponds to the string "KVMKVMKVM".
The value in eax corresponds to the maximum cpuid function present in this leaf,
and will be updated if more functions are added in the future.
Note also that old hosts set eax value to 0x0. This should
be interpreted as if the value was 0x40000001.
This function queries the presence of KVM cpuid leafs.

function: define KVM_CPUID_FEATURES (0x40000001)

returns::

          ebx, ecx
          eax = an OR'ed group of (1 << flag)

where ``flag`` is defined as below:

================================== =========== ================================
flag                               value       meaning
================================== =========== ================================
KVM_FEATURE_CLOCKSOURCE            0           kvmclock available at msrs
                                               0x11 and 0x12

KVM_FEATURE_NOP_IO_DELAY           1           not necessary to perform delays
                                               on PIO operations

KVM_FEATURE_MMU_OP                 2           deprecated

KVM_FEATURE_CLOCKSOURCE2           3           kvmclock available at msrs
                                               0x4b564d00 and 0x4b564d01

KVM_FEATURE_ASYNC_PF               4           async pf can be enabled by
                                               writing to msr 0x4b564d02

KVM_FEATURE_STEAL_TIME             5           steal time can be enabled by
                                               writing to msr 0x4b564d03

KVM_FEATURE_PV_EOI                 6           paravirtualized end of interrupt
                                               handler can be enabled by
                                               writing to msr 0x4b564d04

KVM_FEATURE_PV_UNHALT              7           guest checks this feature bit
                                               before enabling paravirtualized
                                               spinlock support

KVM_FEATURE_PV_TLB_FLUSH           9           guest checks this feature bit
                                               before enabling paravirtualized
                                               tlb flush

KVM_FEATURE_ASYNC_PF_VMEXIT        10          paravirtualized async PF VM EXIT
                                               can be enabled by setting bit 2
                                               when writing to msr 0x4b564d02

KVM_FEATURE_PV_SEND_IPI            11          guest checks this feature bit
                                               before enabling paravirtualized
                                               send IPIs

KVM_FEATURE_POLL_CONTROL           12          host-side polling on HLT can
                                               be disabled by writing
                                               to msr 0x4b564d05.

KVM_FEATURE_PV_SCHED_YIELD         13          guest checks this feature bit
                                               before using paravirtualized
                                               sched yield.

KVM_FEATURE_ASYNC_PF_INT           14          guest checks this feature bit
                                               before using the second async
                                               pf control msr 0x4b564d06 and
                                               async pf acknowledgment msr
                                               0x4b564d07.

KVM_FEATURE_MSI_EXT_DEST_ID        15          guest checks this feature bit
                                               before using extended destination
                                               ID bits in MSI address bits 11-5.

KVM_FEATURE_HC_MAP_GPA_RANGE       16          guest checks this feature bit before
                                               using the map gpa range hypercall
                                               to notify the page state change

KVM_FEATURE_MIGRATION_CONTROL      17          guest checks this feature bit before
                                               using MSR_KVM_MIGRATION_CONTROL

KVM_FEATURE_CLOCKSOURCE_STABLE_BIT 24          host will warn if no guest-side
                                               per-cpu warps are expected in
                                               kvmclock
================================== =========== ================================

================================== =========== ================================
flag                               value       meaning
================================== =========== ================================
KVM_FEATURE_CLOCKSOURCE            0           kvmclock可通过MSR 0x11和0x12获得
KVM_FEATURE_NOP_IO_DELAY           1           在PIO操作上无需执行延迟
KVM_FEATURE_MMU_OP                 2           已弃用
KVM_FEATURE_CLOCKSOURCE2           3           kvmclock可通过MSR 0x4b564d00和0x4b564d01获得
KVM_FEATURE_ASYNC_PF               4           通过写入MSR 0x4b564d02可启用异步PF
KVM_FEATURE_STEAL_TIME             5           通过写入MSR 0x4b564d03可启用偷取时间
KVM_FEATURE_PV_EOI                 6           通过写入MSR 0x4b564d04可启用虚拟化的中断结束处理
KVM_FEATURE_PV_UNHALT              7           客户机在启用虚拟化自旋锁支持前检查此功能位
KVM_FEATURE_PV_TLB_FLUSH           9           客户机在启用虚拟化TLB刷新前检查此功能位
KVM_FEATURE_ASYNC_PF_VMEXIT        10          通过设置MSR 0x4b564d02的第2位可启用虚拟化异步PF VM退出
KVM_FEATURE_PV_SEND_IPI            11          客户机在启用虚拟化发送IPI前检查此功能位
KVM_FEATURE_POLL_CONTROL           12          通过写入MSR 0x4b564d05可以禁用宿主侧HLT上的轮询
KVM_FEATURE_PV_SCHED_YIELD         13          客户机在使用虚拟化调度让步前检查此功能位
KVM_FEATURE_ASYNC_PF_INT           14          客户机在使用第二个异步PF控制MSR 0x4b564d06和异步PF确认MSR 0x4b564d07前检查此功能位
KVM_FEATURE_MSI_EXT_DEST_ID        15          客户机在使用MSI地址位11-5中的扩展目的地ID位前检查此功能位
KVM_FEATURE_HC_MAP_GPA_RANGE       16          客户机在使用映射GPA范围超调用以通知页面状态更改前检查此功能位
KVM_FEATURE_MIGRATION_CONTROL      17          客户机在使用MSR_KVM_MIGRATION_CONTROL前检查此功能位
KVM_FEATURE_CLOCKSOURCE_STABLE_BIT 24          如果kvmclock中不期待有客户端每CPU偏差，宿主将发出警告
================================== =========== ================================
``` &#8203;``【oaicite:0】``&#8203;


::

      edx = an OR'ed group of (1 << flag)

Where ``flag`` here is defined as below:

================== ============ =================================
flag               value        meaning
================== ============ =================================
KVM_HINTS_REALTIME 0            guest checks this feature bit to
                                determine that vCPUs are never
                                preempted for an unlimited time
                                allowing optimizations
================== ============ =================================
