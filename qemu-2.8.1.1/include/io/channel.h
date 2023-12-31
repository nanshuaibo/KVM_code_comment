/*
 * QEMU I/O channels
 *
 * Copyright (c) 2015 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef QIO_CHANNEL_H
#define QIO_CHANNEL_H

#include "qemu-common.h"
#include "qom/object.h"

#define TYPE_QIO_CHANNEL "qio-channel"
#define QIO_CHANNEL(obj)                                    \
    OBJECT_CHECK(QIOChannel, (obj), TYPE_QIO_CHANNEL)
#define QIO_CHANNEL_CLASS(klass)                                    \
    OBJECT_CLASS_CHECK(QIOChannelClass, klass, TYPE_QIO_CHANNEL)
#define QIO_CHANNEL_GET_CLASS(obj)                                  \
    OBJECT_GET_CLASS(QIOChannelClass, obj, TYPE_QIO_CHANNEL)

typedef struct QIOChannel QIOChannel;
typedef struct QIOChannelClass QIOChannelClass;

#define QIO_CHANNEL_ERR_BLOCK -2

typedef enum QIOChannelFeature QIOChannelFeature;

enum QIOChannelFeature {
    QIO_CHANNEL_FEATURE_FD_PASS,
    QIO_CHANNEL_FEATURE_SHUTDOWN,
    QIO_CHANNEL_FEATURE_LISTEN,
};


typedef enum QIOChannelShutdown QIOChannelShutdown;

enum QIOChannelShutdown {
    QIO_CHANNEL_SHUTDOWN_BOTH,
    QIO_CHANNEL_SHUTDOWN_READ,
    QIO_CHANNEL_SHUTDOWN_WRITE,
};

typedef gboolean (*QIOChannelFunc)(QIOChannel *ioc,
                                   GIOCondition condition,
                                   gpointer data);

/**
 * QIOChannel:
 *
 * The QIOChannel defines the core API for a generic I/O channel
 * class hierarchy. It is inspired by GIOChannel, but has the
 * following differences
 *
 *  - Use QOM to properly support arbitrary subclassing
 *  - Support use of iovecs for efficient I/O with multiple blocks
 *  - None of the character set translation, binary data exclusively
 *  - Direct support for QEMU Error object reporting
 *  - File descriptor passing
 *
 * This base class is abstract so cannot be instantiated. There
 * will be subclasses for dealing with sockets, files, and higher
 * level protocols such as TLS, WebSocket, etc.
 */

struct QIOChannel {
    Object parent;
    unsigned int features; /* bitmask of QIOChannelFeatures */
    char *name;
#ifdef _WIN32
    HANDLE event; /* For use with GSource on Win32 */
#endif
};

/**
 * QIOChannelClass:
 *
 * This class defines the contract that all subclasses
 * must follow to provide specific channel implementations.
 * The first five callbacks are mandatory to support, others
 * provide additional optional features.
 *
 * Consult the corresponding public API docs for a description
 * of the semantics of each callback
 */
struct QIOChannelClass {
    ObjectClass parent;

    /* Mandatory callbacks */
    ssize_t (*io_writev)(QIOChannel *ioc,
                         const struct iovec *iov,
                         size_t niov,
                         int *fds,
                         size_t nfds,
                         Error **errp);
    ssize_t (*io_readv)(QIOChannel *ioc,
                        const struct iovec *iov,
                        size_t niov,
                        int **fds,
                        size_t *nfds,
                        Error **errp);
    int (*io_close)(QIOChannel *ioc,
                    Error **errp);
    GSource * (*io_create_watch)(QIOChannel *ioc,
                                 GIOCondition condition);
    int (*io_set_blocking)(QIOChannel *ioc,
                           bool enabled,
                           Error **errp);

    /* Optional callbacks */
    int (*io_shutdown)(QIOChannel *ioc,
                       QIOChannelShutdown how,
                       Error **errp);
    void (*io_set_cork)(QIOChannel *ioc,
                        bool enabled);
    void (*io_set_delay)(QIOChannel *ioc,
                         bool enabled);
    off_t (*io_seek)(QIOChannel *ioc,
                     off_t offset,
                     int whence,
                     Error **errp);
};

/* General I/O handling functions */

/**
 * qio_channel_has_feature:
 * @ioc: the channel object
 * @feature: the feature to check support of
 *
 * Determine whether the channel implementation supports
 * the optional feature named in @feature.
 *
 * Returns: true if supported, false otherwise.
 */
bool qio_channel_has_feature(QIOChannel *ioc,
                             QIOChannelFeature feature);

/**
 * qio_channel_set_feature:
 * @ioc: the channel object
 * @feature: the feature to set support for
 *
 * Add channel support for the feature named in @feature.
 */
void qio_channel_set_feature(QIOChannel *ioc,
                             QIOChannelFeature feature);

/**
 * qio_channel_set_name:
 * @ioc: the channel object
 * @name: the name of the channel
 *
 * Sets the name of the channel, which serves as an aid
 * to debugging. The name is used when creating GSource
 * watches for this channel.
 */
void qio_channel_set_name(QIOChannel *ioc,
                          const char *name);

/**
 * qio_channel_readv_full:
 * @ioc: the channel object
 * @iov: the array of memory regions to read data into
 * @niov: the length of the @iov array
 * @fds: pointer to an array that will received file handles
 * @nfds: pointer filled with number of elements in @fds on return
 * @errp: pointer to a NULL-initialized error object
 *
 * Read data from the IO channel, storing it in the
 * memory regions referenced by @iov. Each element
 * in the @iov will be fully populated with data
 * before the next one is used. The @niov parameter
 * specifies the total number of elements in @iov.
 *
 * It is not required for all @iov to be filled with
 * data. If the channel is in blocking mode, at least
 * one byte of data will be read, but no more is
 * guaranteed. If the channel is non-blocking and no
 * data is available, it will return QIO_CHANNEL_ERR_BLOCK
 *
 * If the channel has passed any file descriptors,
 * the @fds array pointer will be allocated and
 * the elements filled with the received file
 * descriptors. The @nfds pointer will be updated
 * to indicate the size of the @fds array that
 * was allocated. It is the callers responsibility
 * to call close() on each file descriptor and to
 * call g_free() on the array pointer in @fds.
 *
 * It is an error to pass a non-NULL @fds parameter
 * unless qio_channel_has_feature() returns a true
 * value for the QIO_CHANNEL_FEATURE_FD_PASS constant.
 *
 * Returns: the number of bytes read, or -1 on error,
 * or QIO_CHANNEL_ERR_BLOCK if no data is available
 * and the channel is non-blocking
 */
ssize_t qio_channel_readv_full(QIOChannel *ioc,
                               const struct iovec *iov,
                               size_t niov,
                               int **fds,
                               size_t *nfds,
                               Error **errp);


/**
 * qio_channel_writev_full:
 * @ioc: the channel object
 * @iov: the array of memory regions to write data from
 * @niov: the length of the @iov array
 * @fds: an array of file handles to send
 * @nfds: number of file handles in @fds
 * @errp: pointer to a NULL-initialized error object
 *
 * Write data to the IO channel, reading it from the
 * memory regions referenced by @iov. Each element
 * in the @iov will be fully sent, before the next
 * one is used. The @niov parameter specifies the
 * total number of elements in @iov.
 *
 * It is not required for all @iov data to be fully
 * sent. If the channel is in blocking mode, at least
 * one byte of data will be sent, but no more is
 * guaranteed. If the channel is non-blocking and no
 * data can be sent, it will return QIO_CHANNEL_ERR_BLOCK
 *
 * If there are file descriptors to send, the @fds
 * array should be non-NULL and provide the handles.
 * All file descriptors will be sent if at least one
 * byte of data was sent.
 *
 * It is an error to pass a non-NULL @fds parameter
 * unless qio_channel_has_feature() returns a true
 * value for the QIO_CHANNEL_FEATURE_FD_PASS constant.
 *
 * Returns: the number of bytes sent, or -1 on error,
 * or QIO_CHANNEL_ERR_BLOCK if no data is can be sent
 * and the channel is non-blocking
 */
ssize_t qio_channel_writev_full(QIOChannel *ioc,
                                const struct iovec *iov,
                                size_t niov,
                                int *fds,
                                size_t nfds,
                                Error **errp);

/**
 * qio_channel_readv:
 * @ioc: the channel object
 * @iov: the array of memory regions to read data into
 * @niov: the length of the @iov array
 * @errp: pointer to a NULL-initialized error object
 *
 * Behaves as qio_channel_readv_full() but does not support
 * receiving of file handles.
 */
ssize_t qio_channel_readv(QIOChannel *ioc,
                          const struct iovec *iov,
                          size_t niov,
                          Error **errp);

/**
 * qio_channel_writev:
 * @ioc: the channel object
 * @iov: the array of memory regions to write data from
 * @niov: the length of the @iov array
 * @errp: pointer to a NULL-initialized error object
 *
 * Behaves as qio_channel_writev_full() but does not support
 * sending of file handles.
 */
ssize_t qio_channel_writev(QIOChannel *ioc,
                           const struct iovec *iov,
                           size_t niov,
                           Error **errp);

/**
 * qio_channel_readv:
 * @ioc: the channel object
 * @buf: the memory region to read data into
 * @buflen: the length of @buf
 * @errp: pointer to a NULL-initialized error object
 *
 * Behaves as qio_channel_readv_full() but does not support
 * receiving of file handles, and only supports reading into
 * a single memory region.
 */
ssize_t qio_channel_read(QIOChannel *ioc,
                         char *buf,
                         size_t buflen,
                         Error **errp);

/**
 * qio_channel_writev:
 * @ioc: the channel object
 * @buf: the memory regions to send data from
 * @buflen: the length of @buf
 * @errp: pointer to a NULL-initialized error object
 *
 * Behaves as qio_channel_writev_full() but does not support
 * sending of file handles, and only supports writing from a
 * single memory region.
 */
ssize_t qio_channel_write(QIOChannel *ioc,
                          const char *buf,
                          size_t buflen,
                          Error **errp);

/**
 * qio_channel_set_blocking:
 * @ioc: the channel object
 * @enabled: the blocking flag state
 * @errp: pointer to a NULL-initialized error object
 *
 * If @enabled is true, then the channel is put into
 * blocking mode, otherwise it will be non-blocking.
 *
 * In non-blocking mode, read/write operations may
 * return QIO_CHANNEL_ERR_BLOCK if they would otherwise
 * block on I/O
 */
int qio_channel_set_blocking(QIOChannel *ioc,
                             bool enabled,
                             Error **errp);

/**
 * qio_channel_close:
 * @ioc: the channel object
 * @errp: pointer to a NULL-initialized error object
 *
 * Close the channel, flushing any pending I/O
 *
 * Returns: 0 on success, -1 on error
 */
int qio_channel_close(QIOChannel *ioc,
                      Error **errp);

/**
 * qio_channel_shutdown:
 * @ioc: the channel object
 * @how: the direction to shutdown
 * @errp: pointer to a NULL-initialized error object
 *
 * Shutdowns transmission and/or receiving of data
 * without closing the underlying transport.
 *
 * Not all implementations will support this facility,
 * so may report an error. To avoid errors, the
 * caller may check for the feature flag
 * QIO_CHANNEL_FEATURE_SHUTDOWN prior to calling
 * this method.
 *
 * Returns: 0 on success, -1 on error
 */
int qio_channel_shutdown(QIOChannel *ioc,
                         QIOChannelShutdown how,
                         Error **errp);

/**
 * qio_channel_set_delay:
 * @ioc: the channel object
 * @enabled: the new flag state
 *
 * Controls whether the underlying transport is
 * permitted to delay writes in order to merge
 * small packets. If @enabled is true, then the
 * writes may be delayed in order to opportunistically
 * merge small packets into larger ones. If @enabled
 * is false, writes are dispatched immediately with
 * no delay.
 *
 * When @enabled is false, applications may wish to
 * use the qio_channel_set_cork() method to explicitly
 * control write merging.
 *
 * On channels which are backed by a socket, this
 * API corresponds to the inverse of TCP_NODELAY flag,
 * controlling whether the Nagle algorithm is active.
 *
 * This setting is merely a hint, so implementations are
 * free to ignore this without it being considered an
 * error.
 */
void qio_channel_set_delay(QIOChannel *ioc,
                           bool enabled);

/**
 * qio_channel_set_cork:
 * @ioc: the channel object
 * @enabled: the new flag state
 *
 * Controls whether the underlying transport is
 * permitted to dispatch data that is written.
 * If @enabled is true, then any data written will
 * be queued in local buffers until @enabled is
 * set to false once again.
 *
 * This feature is typically used when the automatic
 * write coalescing facility is disabled via the
 * qio_channel_set_delay() method.
 *
 * On channels which are backed by a socket, this
 * API corresponds to the TCP_CORK flag.
 *
 * This setting is merely a hint, so implementations are
 * free to ignore this without it being considered an
 * error.
 */
void qio_channel_set_cork(QIOChannel *ioc,
                          bool enabled);


/**
 * qio_channel_seek:
 * @ioc: the channel object
 * @offset: the position to seek to, relative to @whence
 * @whence: one of the (POSIX) SEEK_* constants listed below
 * @errp: pointer to a NULL-initialized error object
 *
 * Moves the current I/O position within the channel
 * @ioc, to be @offset. The value of @offset is
 * interpreted relative to @whence:
 *
 * SEEK_SET - the position is set to @offset bytes
 * SEEK_CUR - the position is moved by @offset bytes
 * SEEK_END - the position is set to end of the file plus @offset bytes
 *
 * Not all implementations will support this facility,
 * so may report an error.
 *
 * Returns: the new position on success, (off_t)-1 on failure
 */
off_t qio_channel_io_seek(QIOChannel *ioc,
                          off_t offset,
                          int whence,
                          Error **errp);


/**
 * qio_channel_create_watch:
 * @ioc: the channel object
 * @condition: the I/O condition to monitor
 *
 * Create a new main loop source that is used to watch
 * for the I/O condition @condition. Typically the
 * qio_channel_add_watch() method would be used instead
 * of this, since it directly attaches a callback to
 * the source
 *
 * Returns: the new main loop source.
 */
GSource *qio_channel_create_watch(QIOChannel *ioc,
                                  GIOCondition condition);

/**
 * qio_channel_add_watch:
 * @ioc: the channel object
 * @condition: the I/O condition to monitor
 * @func: callback to invoke when the source becomes ready
 * @user_data: opaque data to pass to @func
 * @notify: callback to free @user_data
 *
 * Create a new main loop source that is used to watch
 * for the I/O condition @condition. The callback @func
 * will be registered against the source, to be invoked
 * when the source becomes ready. The optional @user_data
 * will be passed to @func when it is invoked. The @notify
 * callback will be used to free @user_data when the
 * watch is deleted
 *
 * The returned source ID can be used with g_source_remove()
 * to remove and free the source when no longer required.
 * Alternatively the @func callback can return a FALSE
 * value.
 *
 * Returns: the source ID
 */
guint qio_channel_add_watch(QIOChannel *ioc,
                            GIOCondition condition,
                            QIOChannelFunc func,
                            gpointer user_data,
                            GDestroyNotify notify);


/**
 * qio_channel_yield:
 * @ioc: the channel object
 * @condition: the I/O condition to wait for
 *
 * Yields execution from the current coroutine until
 * the condition indicated by @condition becomes
 * available.
 *
 * This must only be called from coroutine context
 */
void qio_channel_yield(QIOChannel *ioc,
                       GIOCondition condition);

/**
 * qio_channel_wait:
 * @ioc: the channel object
 * @condition: the I/O condition to wait for
 *
 * Block execution from the current thread until
 * the condition indicated by @condition becomes
 * available.
 *
 * This will enter a nested event loop to perform
 * the wait.
 */
void qio_channel_wait(QIOChannel *ioc,
                      GIOCondition condition);

#endif /* QIO_CHANNEL_H */
