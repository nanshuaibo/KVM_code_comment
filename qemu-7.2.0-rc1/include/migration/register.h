/*
 * QEMU migration vmstate registration
 *
 * Copyright IBM, Corp. 2008
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef MIGRATION_REGISTER_H
#define MIGRATION_REGISTER_H

#include "hw/vmstate-if.h"

typedef struct SaveVMHandlers {
    /* 在iothread锁内部运行 */
    SaveStateHandler *save_state;

    void (*save_cleanup)(void *opaque);
    int (*save_live_complete_postcopy)(QEMUFile *f, void *opaque);
    int (*save_live_complete_precopy)(QEMUFile *f, void *opaque);

    /* 在iothread锁外部和内部运行 */
    bool (*is_active)(void *opaque);
    bool (*has_postcopy)(void *opaque);

    /* is_active_iterate
     * 如果它不为NULL，那么qemu_savevm_state_iterate将在返回false时跳过迭代。
     * 例如，对于仅后复制状态，需要在qemu_savevm_state_setup和qemu_savevm_state_pending中处理，
     * 但不需要迭代，直到不在postcopy阶段。
     */
    bool (*is_active_iterate)(void *opaque);

    /* 在迁移情况下，此回调在iothread锁外部运行，
     * 在savevm情况下，它在锁内部运行。
     * 回调最好只使用迁移线程局部数据或受其他锁保护的数据。
     */
    int (*save_live_iterate)(QEMUFile *f, void *opaque);

    /* 这个在iothread锁外部运行！ */
    int (*save_setup)(QEMUFile *f, void *opaque);
    void (*save_live_pending)(QEMUFile *f, void *opaque,
                              uint64_t threshold_size,
                              uint64_t *res_precopy_only,
                              uint64_t *res_compatible,
                              uint64_t *res_postcopy_only);
    /* 关于save_live_pending的注释：
     * - res_precopy_only是必须在precopy阶段或停止状态下迁移的数据，换句话说，是在目标虚拟机启动之前
     * - res_compatible是可以在任何阶段迁移的数据
     * - res_postcopy_only是必须在postcopy阶段或停止状态下迁移的数据，换句话说，是在源虚拟机停止之后
     *
     * res_postcopy_only、res_compatible和res_postcopy_only的总和是待迁移数据的总量。
     */

    LoadStateHandler *load_state;
    int (*load_setup)(QEMUFile *f, void *opaque);
    int (*load_cleanup)(void *opaque);
    /* 当后复制迁移想要从失败中恢复时调用 */
    int (*resume_prepare)(MigrationState *s, void *opaque);
} SaveVMHandlers;

int register_savevm_live(const char *idstr,
                         uint32_t instance_id,
                         int version_id,
                         const SaveVMHandlers *ops,
                         void *opaque);

void unregister_savevm(VMStateIf *obj, const char *idstr, void *opaque);

#endif
