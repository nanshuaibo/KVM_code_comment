/*
 * Virtio 9p backend
 *
 * Copyright IBM, Corp. 2010
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "hw/virtio/virtio.h"
#include "qemu/sockets.h"
#include "virtio-9p.h"
#include "fsdev/qemu-fsdev.h"
#include "coth.h"
#include "hw/virtio/virtio-access.h"
#include "qemu/iov.h"

void virtio_9p_push_and_notify(V9fsPDU *pdu)
{
    V9fsState *s = pdu->s;
    V9fsVirtioState *v = container_of(s, V9fsVirtioState, state);
    VirtQueueElement *elem = v->elems[pdu->idx];

    /* push onto queue and notify */
    virtqueue_push(v->vq, elem, pdu->size);
    g_free(elem);
    v->elems[pdu->idx] = NULL;

    /* FIXME: we should batch these completions */
    virtio_notify(VIRTIO_DEVICE(v), v->vq);
}

static void handle_9p_output(VirtIODevice *vdev, VirtQueue *vq)
{
    V9fsVirtioState *v = (V9fsVirtioState *)vdev;
    V9fsState *s = &v->state;
    V9fsPDU *pdu;
    ssize_t len;
    VirtQueueElement *elem;

    while ((pdu = pdu_alloc(s))) {
        struct {
            uint32_t size_le;
            uint8_t id;
            uint16_t tag_le;
        } QEMU_PACKED out;

        elem = virtqueue_pop(vq, sizeof(VirtQueueElement));
        if (!elem) {
            goto out_free_pdu;
        }

        if (elem->in_num == 0) {
            virtio_error(vdev,
                         "The guest sent a VirtFS request without space for "
                         "the reply");
            goto out_free_req;
        }
        QEMU_BUILD_BUG_ON(sizeof(out) != 7);

        v->elems[pdu->idx] = elem;
        len = iov_to_buf(elem->out_sg, elem->out_num, 0,
                         &out, sizeof(out));
        if (len != sizeof(out)) {
            virtio_error(vdev, "The guest sent a malformed VirtFS request: "
                         "header size is %zd, should be 7", len);
            goto out_free_req;
        }

        pdu->size = le32_to_cpu(out.size_le);

        pdu->id = out.id;
        pdu->tag = le16_to_cpu(out.tag_le);

        qemu_co_queue_init(&pdu->complete);
        pdu_submit(pdu);
    }

    return;

out_free_req:
    virtqueue_detach_element(vq, elem, 0);
    g_free(elem);
out_free_pdu:
    pdu_free(pdu);
}

static uint64_t virtio_9p_get_features(VirtIODevice *vdev, uint64_t features,
                                       Error **errp)
{
    virtio_add_feature(&features, VIRTIO_9P_MOUNT_TAG);
    return features;
}

static void virtio_9p_get_config(VirtIODevice *vdev, uint8_t *config)
{
    int len;
    struct virtio_9p_config *cfg;
    V9fsVirtioState *v = VIRTIO_9P(vdev);
    V9fsState *s = &v->state;

    len = strlen(s->tag);
    cfg = g_malloc0(sizeof(struct virtio_9p_config) + len);
    virtio_stw_p(vdev, &cfg->tag_len, len);
    /* We don't copy the terminating null to config space */
    memcpy(cfg->tag, s->tag, len);
    memcpy(config, cfg, v->config_size);
    g_free(cfg);
}

static void virtio_9p_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    V9fsVirtioState *v = VIRTIO_9P(dev);
    V9fsState *s = &v->state;

    if (v9fs_device_realize_common(s, errp)) {
        goto out;
    }

    v->config_size = sizeof(struct virtio_9p_config) + strlen(s->fsconf.tag);
    virtio_init(vdev, "virtio-9p", VIRTIO_ID_9P, v->config_size);
    v->vq = virtio_add_queue(vdev, MAX_REQ, handle_9p_output);

out:
    return;
}

static void virtio_9p_device_unrealize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    V9fsVirtioState *v = VIRTIO_9P(dev);
    V9fsState *s = &v->state;

    virtio_cleanup(vdev);
    v9fs_device_unrealize_common(s, errp);
}

static void virtio_9p_reset(VirtIODevice *vdev)
{
    V9fsVirtioState *v = (V9fsVirtioState *)vdev;

    v9fs_reset(&v->state);
}

ssize_t virtio_pdu_vmarshal(V9fsPDU *pdu, size_t offset,
                            const char *fmt, va_list ap)
{
    V9fsState *s = pdu->s;
    V9fsVirtioState *v = container_of(s, V9fsVirtioState, state);
    VirtQueueElement *elem = v->elems[pdu->idx];

    return v9fs_iov_vmarshal(elem->in_sg, elem->in_num, offset, 1, fmt, ap);
}

ssize_t virtio_pdu_vunmarshal(V9fsPDU *pdu, size_t offset,
                              const char *fmt, va_list ap)
{
    V9fsState *s = pdu->s;
    V9fsVirtioState *v = container_of(s, V9fsVirtioState, state);
    VirtQueueElement *elem = v->elems[pdu->idx];

    return v9fs_iov_vunmarshal(elem->out_sg, elem->out_num, offset, 1, fmt, ap);
}

void virtio_init_iov_from_pdu(V9fsPDU *pdu, struct iovec **piov,
                              unsigned int *pniov, bool is_write)
{
    V9fsState *s = pdu->s;
    V9fsVirtioState *v = container_of(s, V9fsVirtioState, state);
    VirtQueueElement *elem = v->elems[pdu->idx];

    if (is_write) {
        *piov = elem->out_sg;
        *pniov = elem->out_num;
    } else {
        *piov = elem->in_sg;
        *pniov = elem->in_num;
    }
}

/* virtio-9p device */

static const VMStateDescription vmstate_virtio_9p = {
    .name = "virtio-9p",
    .minimum_version_id = 1,
    .version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_VIRTIO_DEVICE,
        VMSTATE_END_OF_LIST()
    },
};

static Property virtio_9p_properties[] = {
    DEFINE_PROP_STRING("mount_tag", V9fsVirtioState, state.fsconf.tag),
    DEFINE_PROP_STRING("fsdev", V9fsVirtioState, state.fsconf.fsdev_id),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_9p_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    dc->props = virtio_9p_properties;
    dc->vmsd = &vmstate_virtio_9p;
    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    vdc->realize = virtio_9p_device_realize;
    vdc->unrealize = virtio_9p_device_unrealize;
    vdc->get_features = virtio_9p_get_features;
    vdc->get_config = virtio_9p_get_config;
    vdc->reset = virtio_9p_reset;
}

static const TypeInfo virtio_device_info = {
    .name = TYPE_VIRTIO_9P,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(V9fsVirtioState),
    .class_init = virtio_9p_class_init,
};

static void virtio_9p_register_types(void)
{
    type_register_static(&virtio_device_info);
}

type_init(virtio_9p_register_types)
