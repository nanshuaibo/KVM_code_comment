/*
 * QEMU live migration channel operations
 *
 * Copyright Red Hat, Inc. 2016
 *
 * Authors:
 *  Daniel P. Berrange <berrange@redhat.com>
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "channel.h"
#include "tls.h"
#include "migration.h"
#include "qemu-file.h"
#include "trace.h"
#include "qapi/error.h"
#include "io/channel-tls.h"
#include "io/channel-socket.h"
#include "qemu/yank.h"
#include "yank_functions.h"

/**
 * @migration_channel_process_incoming - Create new incoming migration channel
 *
 * Notice that TLS is special.  For it we listen in a listener socket,
 * and then create a new client socket from the TLS library.
 *
 * @ioc: Channel to which we are connecting
 */
void migration_channel_process_incoming(QIOChannel *ioc)
{
    MigrationState *s = migrate_get_current();
    Error *local_err = NULL;

    trace_migration_set_incoming_channel(
        ioc, object_get_typename(OBJECT(ioc)));

    if (migrate_channel_requires_tls_upgrade(ioc)) {
        migration_tls_channel_process_incoming(s, ioc, &local_err);
    } else {
        migration_ioc_register_yank(ioc);
        migration_ioc_process_incoming(ioc, &local_err);
    }

    if (local_err) {
        error_report_err(local_err);
    }
}


/**
 * @migration_channel_connect - 创建新的外出迁移通道
 *
 * @s: 当前的迁移状态
 * @ioc: 我们要连接到的通道
 * @hostname: 我们想要连接的目标主机名
 * @error: 表示连接失败的错误，在此处释放
 */
void migration_channel_connect(MigrationState *s,
                               QIOChannel *ioc,
                               const char *hostname,
                               Error *error)
{
    trace_migration_set_outgoing_channel(
        ioc, object_get_typename(OBJECT(ioc)), hostname, error);

    if (!error) {
        // // 如果需要升级到 TLS 连接
        if (migrate_channel_requires_tls_upgrade(ioc)) {
            // 尝试使用 TLS 连接迁移通道
            migration_tls_channel_connect(s, ioc, hostname, &error);

            if (!error) {
                /* tls_channel_connect will call back to this
                 * function after the TLS handshake,
                 * so we mustn't call migrate_fd_connect until then
                 */

                return;
            }
        } else {
             // 否则，创建一个新的输出文件流
            QEMUFile *f = qemu_file_new_output(ioc);

            migration_ioc_register_yank(ioc);

            // 设置迁移状态中的输出文件
            qemu_mutex_lock(&s->qemu_file_lock);
            s->to_dst_file = f;
            qemu_mutex_unlock(&s->qemu_file_lock);
        }
    }

    //当tcp链接成功后，最终会调用到migrate_fd_connect函数中。其中to_dst_file代表的就是传输的文件信息结构体，使用的QEMUFile结构来表示。
    migrate_fd_connect(s, error);
    error_free(error);
}
