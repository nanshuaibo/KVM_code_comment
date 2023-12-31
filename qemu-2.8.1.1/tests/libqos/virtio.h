/*
 * libqos virtio definitions
 *
 * Copyright (c) 2014 Marc Marí
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef LIBQOS_VIRTIO_H
#define LIBQOS_VIRTIO_H

#include "libqos/malloc.h"
#include "standard-headers/linux/virtio_ring.h"

#define QVIRTIO_F_BAD_FEATURE           0x40000000

typedef struct QVirtioBus QVirtioBus;

typedef struct QVirtioDevice {
    const QVirtioBus *bus;
    /* Device type */
    uint16_t device_type;
} QVirtioDevice;

typedef struct QVirtQueue {
    uint64_t desc; /* This points to an array of struct vring_desc */
    uint64_t avail; /* This points to a struct vring_avail */
    uint64_t used; /* This points to a struct vring_desc */
    uint16_t index;
    uint32_t size;
    uint32_t free_head;
    uint32_t num_free;
    uint32_t align;
    bool indirect;
    bool event;
} QVirtQueue;

typedef struct QVRingIndirectDesc {
    uint64_t desc; /* This points to an array fo struct vring_desc */
    uint16_t index;
    uint16_t elem;
} QVRingIndirectDesc;

struct QVirtioBus {
    uint8_t (*config_readb)(QVirtioDevice *d, uint64_t addr);
    uint16_t (*config_readw)(QVirtioDevice *d, uint64_t addr);
    uint32_t (*config_readl)(QVirtioDevice *d, uint64_t addr);
    uint64_t (*config_readq)(QVirtioDevice *d, uint64_t addr);

    /* Get features of the device */
    uint32_t (*get_features)(QVirtioDevice *d);

    /* Set features of the device */
    void (*set_features)(QVirtioDevice *d, uint32_t features);

    /* Get features of the guest */
    uint32_t (*get_guest_features)(QVirtioDevice *d);

    /* Get status of the device */
    uint8_t (*get_status)(QVirtioDevice *d);

    /* Set status of the device  */
    void (*set_status)(QVirtioDevice *d, uint8_t status);

    /* Get the queue ISR status of the device */
    bool (*get_queue_isr_status)(QVirtioDevice *d, QVirtQueue *vq);

    /* Get the configuration ISR status of the device */
    bool (*get_config_isr_status)(QVirtioDevice *d);

    /* Select a queue to work on */
    void (*queue_select)(QVirtioDevice *d, uint16_t index);

    /* Get the size of the selected queue */
    uint16_t (*get_queue_size)(QVirtioDevice *d);

    /* Set the address of the selected queue */
    void (*set_queue_address)(QVirtioDevice *d, uint32_t pfn);

    /* Setup the virtqueue specified by index */
    QVirtQueue *(*virtqueue_setup)(QVirtioDevice *d, QGuestAllocator *alloc,
                                                                uint16_t index);

    /* Free virtqueue resources */
    void (*virtqueue_cleanup)(QVirtQueue *vq, QGuestAllocator *alloc);

    /* Notify changes in virtqueue */
    void (*virtqueue_kick)(QVirtioDevice *d, QVirtQueue *vq);
};

static inline bool qvirtio_is_big_endian(QVirtioDevice *d)
{
    /* FIXME: virtio 1.0 is always little-endian */
    return qtest_big_endian(global_qtest);
}

static inline uint32_t qvring_size(uint32_t num, uint32_t align)
{
    return ((sizeof(struct vring_desc) * num + sizeof(uint16_t) * (3 + num)
        + align - 1) & ~(align - 1))
        + sizeof(uint16_t) * 3 + sizeof(struct vring_used_elem) * num;
}

uint8_t qvirtio_config_readb(QVirtioDevice *d, uint64_t addr);
uint16_t qvirtio_config_readw(QVirtioDevice *d, uint64_t addr);
uint32_t qvirtio_config_readl(QVirtioDevice *d, uint64_t addr);
uint64_t qvirtio_config_readq(QVirtioDevice *d, uint64_t addr);
uint32_t qvirtio_get_features(QVirtioDevice *d);
void qvirtio_set_features(QVirtioDevice *d, uint32_t features);

void qvirtio_reset(QVirtioDevice *d);
void qvirtio_set_acknowledge(QVirtioDevice *d);
void qvirtio_set_driver(QVirtioDevice *d);
void qvirtio_set_driver_ok(QVirtioDevice *d);

void qvirtio_wait_queue_isr(QVirtioDevice *d,
                            QVirtQueue *vq, gint64 timeout_us);
uint8_t qvirtio_wait_status_byte_no_isr(QVirtioDevice *d,
                                        QVirtQueue *vq,
                                        uint64_t addr,
                                        gint64 timeout_us);
void qvirtio_wait_config_isr(QVirtioDevice *d, gint64 timeout_us);
QVirtQueue *qvirtqueue_setup(QVirtioDevice *d,
                             QGuestAllocator *alloc, uint16_t index);
void qvirtqueue_cleanup(const QVirtioBus *bus, QVirtQueue *vq,
                        QGuestAllocator *alloc);

void qvring_init(const QGuestAllocator *alloc, QVirtQueue *vq, uint64_t addr);
QVRingIndirectDesc *qvring_indirect_desc_setup(QVirtioDevice *d,
                                        QGuestAllocator *alloc, uint16_t elem);
void qvring_indirect_desc_add(QVRingIndirectDesc *indirect, uint64_t data,
                                                    uint32_t len, bool write);
uint32_t qvirtqueue_add(QVirtQueue *vq, uint64_t data, uint32_t len, bool write,
                                                                    bool next);
uint32_t qvirtqueue_add_indirect(QVirtQueue *vq, QVRingIndirectDesc *indirect);
void qvirtqueue_kick(QVirtioDevice *d, QVirtQueue *vq, uint32_t free_head);

void qvirtqueue_set_used_event(QVirtQueue *vq, uint16_t idx);
#endif
