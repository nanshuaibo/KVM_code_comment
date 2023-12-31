/*
 * Virtio-SCSI implementation for s390 machine loader for qemu
 *
 * Copyright 2015 IBM Corp.
 * Author: Eugene "jno" Dvurechenski <jno@linux.vnet.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at
 * your option) any later version. See the COPYING file in the top-level
 * directory.
 */

#include "s390-ccw.h"
#include "virtio.h"
#include "scsi.h"
#include "virtio-scsi.h"

static ScsiDevice default_scsi_device;
static VirtioScsiCmdReq req;
static VirtioScsiCmdResp resp;

static uint8_t scsi_inquiry_std_response[256];

static inline void vs_assert(bool term, const char **msgs)
{
    if (!term) {
        int i = 0;

        sclp_print("\n! ");
        while (msgs[i]) {
            sclp_print(msgs[i++]);
        }
        panic(" !\n");
    }
}

static void virtio_scsi_verify_response(VirtioScsiCmdResp *resp,
                                        const char *title)
{
    const char *mr[] = {
        title, ": response ", virtio_scsi_response_msg(resp), 0
    };
    const char *ms[] = {
        title,
        CDB_STATUS_VALID(resp->status) ? ": " : ": invalid ",
        scsi_cdb_status_msg(resp->status),
        resp->status == CDB_STATUS_CHECK_CONDITION ? " " : 0,
        resp->sense_len ? scsi_cdb_asc_msg(resp->sense)
                        : "no sense data",
        scsi_sense_response(resp->sense)  == 0x70 ? ", sure" : "?",
        0
    };

    vs_assert(resp->response == VIRTIO_SCSI_S_OK, mr);
    vs_assert(resp->status == CDB_STATUS_GOOD, ms);
}

static void prepare_request(VDev *vdev, const void *cdb, int cdb_size,
                            void *data, uint32_t data_size)
{
    const ScsiDevice *sdev = vdev->scsi_device;

    memset(&req, 0, sizeof(req));
    req.lun = make_lun(sdev->channel, sdev->target, sdev->lun);
    memcpy(&req.cdb, cdb, cdb_size);

    memset(&resp, 0, sizeof(resp));
    resp.status = 0xff;     /* set invalid  */
    resp.response = 0xff;   /*              */

    if (data && data_size) {
        memset(data, 0, data_size);
    }
}

static inline void vs_io_assert(bool term, const char *msg)
{
    if (!term) {
        virtio_scsi_verify_response(&resp, msg);
    }
}

static void vs_run(const char *title, VirtioCmd *cmd, VDev *vdev,
                   const void *cdb, int cdb_size,
                   void *data, uint32_t data_size)
{
    prepare_request(vdev, cdb, cdb_size, data, data_size);
    vs_io_assert(virtio_run(vdev, VR_REQUEST, cmd) == 0, title);
}

/* SCSI protocol implementation routines */

static bool scsi_inquiry(VDev *vdev, void *data, uint32_t data_size)
{
    ScsiCdbInquiry cdb = {
        .command = 0x12,
        .alloc_len = data_size < 65535 ? data_size : 65535,
    };
    VirtioCmd inquiry[] = {
        { &req, sizeof(req), VRING_DESC_F_NEXT },
        { &resp, sizeof(resp), VRING_DESC_F_WRITE | VRING_DESC_F_NEXT },
        { data, data_size, VRING_DESC_F_WRITE },
    };

    vs_run("inquiry", inquiry, vdev, &cdb, sizeof(cdb), data, data_size);

    return virtio_scsi_response_ok(&resp);
}

static bool scsi_test_unit_ready(VDev *vdev)
{
    ScsiCdbTestUnitReady cdb = {
        .command = 0x00,
    };
    VirtioCmd test_unit_ready[] = {
        { &req, sizeof(req), VRING_DESC_F_NEXT },
        { &resp, sizeof(resp), VRING_DESC_F_WRITE },
    };

    prepare_request(vdev, &cdb, sizeof(cdb), 0, 0);
    virtio_run(vdev, VR_REQUEST, test_unit_ready); /* ignore errors here */

    return virtio_scsi_response_ok(&resp);
}

static bool scsi_report_luns(VDev *vdev, void *data, uint32_t data_size)
{
    ScsiCdbReportLuns cdb = {
        .command = 0xa0,
        .select_report = 0x02, /* REPORT ALL */
        .alloc_len = data_size,
    };
    VirtioCmd report_luns[] = {
        { &req, sizeof(req), VRING_DESC_F_NEXT },
        { &resp, sizeof(resp), VRING_DESC_F_WRITE | VRING_DESC_F_NEXT },
        { data, data_size, VRING_DESC_F_WRITE },
    };

    vs_run("report luns", report_luns,
           vdev, &cdb, sizeof(cdb), data, data_size);

    return virtio_scsi_response_ok(&resp);
}

static bool scsi_read_10(VDev *vdev,
                         ulong sector, int sectors, void *data)
{
    int f = vdev->blk_factor;
    unsigned int data_size = sectors * virtio_get_block_size() * f;
    ScsiCdbRead10 cdb = {
        .command = 0x28,
        .lba = sector * f,
        .xfer_length = sectors * f,
    };
    VirtioCmd read_10[] = {
        { &req, sizeof(req), VRING_DESC_F_NEXT },
        { &resp, sizeof(resp), VRING_DESC_F_WRITE | VRING_DESC_F_NEXT },
        { data, data_size * f, VRING_DESC_F_WRITE },
    };

    debug_print_int("read_10  sector", sector);
    debug_print_int("read_10 sectors", sectors);

    vs_run("read(10)", read_10, vdev, &cdb, sizeof(cdb), data, data_size);

    return virtio_scsi_response_ok(&resp);
}

static bool scsi_read_capacity(VDev *vdev,
                               void *data, uint32_t data_size)
{
    ScsiCdbReadCapacity16 cdb = {
        .command = 0x9e, /* SERVICE_ACTION_IN_16 */
        .service_action = 0x10, /* SA_READ_CAPACITY */
        .alloc_len = data_size,
    };
    VirtioCmd read_capacity_16[] = {
        { &req, sizeof(req), VRING_DESC_F_NEXT },
        { &resp, sizeof(resp), VRING_DESC_F_WRITE | VRING_DESC_F_NEXT },
        { data, data_size, VRING_DESC_F_WRITE },
    };

    vs_run("read capacity", read_capacity_16,
           vdev, &cdb, sizeof(cdb), data, data_size);

    return virtio_scsi_response_ok(&resp);
}

/* virtio-scsi routines */

static void virtio_scsi_locate_device(VDev *vdev)
{
    const uint16_t channel = 0; /* again, it's what QEMU does */
    uint16_t target;
    static uint8_t data[16 + 8 * 63];
    ScsiLunReport *r = (void *) data;
    ScsiDevice *sdev = vdev->scsi_device;
    int i, luns;

    /* QEMU has hardcoded channel #0 in many places.
     * If this hardcoded value is ever changed, we'll need to add code for
     * vdev->config.scsi.max_channel != 0 here.
     */
    debug_print_int("config.scsi.max_channel", vdev->config.scsi.max_channel);
    debug_print_int("config.scsi.max_target ", vdev->config.scsi.max_target);
    debug_print_int("config.scsi.max_lun    ", vdev->config.scsi.max_lun);

    if (vdev->scsi_device_selected) {
        sdev->channel = vdev->selected_scsi_device.channel;
        sdev->target = vdev->selected_scsi_device.target;
        sdev->lun = vdev->selected_scsi_device.lun;

        IPL_check(sdev->channel == 0, "non-zero channel requested");
        IPL_check(sdev->target <= vdev->config.scsi.max_target, "target# high");
        IPL_check(sdev->lun <= vdev->config.scsi.max_lun, "LUN# high");
        return;
    }

    for (target = 0; target <= vdev->config.scsi.max_target; target++) {
        sdev->channel = channel;
        sdev->target = target; /* sdev->lun will be 0 here */
        if (!scsi_report_luns(vdev, data, sizeof(data))) {
            if (resp.response == VIRTIO_SCSI_S_BAD_TARGET) {
                continue;
            }
            print_int("target", target);
            virtio_scsi_verify_response(&resp, "SCSI cannot report LUNs");
        }
        if (r->lun_list_len == 0) {
            print_int("no LUNs for target", target);
            continue;
        }
        luns = r->lun_list_len / 8;
        debug_print_int("LUNs reported", luns);
        if (luns == 1) {
            /* There is no ",lun=#" arg for -device or ",lun=0" given.
             * Hence, the only LUN reported.
             * Usually, it's 0.
             */
            sdev->lun = r->lun[0].v16[0]; /* it's returned this way */
            debug_print_int("Have to use LUN", sdev->lun);
            return; /* we have to use this device */
        }
        for (i = 0; i < luns; i++) {
            if (r->lun[i].v64) {
                /* Look for non-zero LUN - we have where to choose from */
                sdev->lun = r->lun[i].v16[0];
                debug_print_int("Will use LUN", sdev->lun);
                return; /* we have found a device */
            }
        }
    }
    panic("\n! Cannot locate virtio-scsi device !\n");
}

int virtio_scsi_read_many(VDev *vdev,
                          ulong sector, void *load_addr, int sec_num)
{
    if (!scsi_read_10(vdev, sector, sec_num, load_addr)) {
        virtio_scsi_verify_response(&resp, "virtio-scsi:read_many");
    }

    return 0;
}

static bool virtio_scsi_inquiry_response_is_cdrom(void *data)
{
    const ScsiInquiryStd *response = data;
    const int resp_data_fmt = response->b3 & 0x0f;
    int i;

    IPL_check(resp_data_fmt == 2, "Wrong INQUIRY response format");
    if (resp_data_fmt != 2) {
        return false; /* cannot decode */
    }

    if ((response->peripheral_qdt & 0x1f) == SCSI_INQ_RDT_CDROM) {
        return true;
    }

    for (i = 0; i < sizeof(response->prod_id); i++) {
        if (response->prod_id[i] != QEMU_CDROM_SIGNATURE[i]) {
            return false;
        }
    }
    return true;
}

static void scsi_parse_capacity_report(void *data,
                                       uint64_t *last_lba, uint32_t *lb_len)
{
    ScsiReadCapacity16Data *p = data;

    if (last_lba) {
        *last_lba = p->ret_lba;
    }

    if (lb_len) {
        *lb_len = p->lb_len;
    }
}

void virtio_scsi_setup(VDev *vdev)
{
    int retry_test_unit_ready = 3;
    uint8_t data[256];
    uint32_t data_size = sizeof(data);

    vdev->scsi_device = &default_scsi_device;
    virtio_scsi_locate_device(vdev);

    /* We have to "ping" the device before it becomes readable */
    while (!scsi_test_unit_ready(vdev)) {

        if (!virtio_scsi_response_ok(&resp)) {
            uint8_t code = resp.sense[0] & SCSI_SENSE_CODE_MASK;
            uint8_t sense_key = resp.sense[2] & SCSI_SENSE_KEY_MASK;

            IPL_assert(resp.sense_len != 0, "virtio-scsi:setup: no SENSE data");

            IPL_assert(retry_test_unit_ready && code == 0x70 &&
                       sense_key == SCSI_SENSE_KEY_UNIT_ATTENTION,
                       "virtio-scsi:setup: cannot retry");

            /* retry on CHECK_CONDITION/UNIT_ATTENTION as it
             * may not designate a real error, but it may be
             * a result of device reset, etc.
             */
            retry_test_unit_ready--;
            sleep(1);
            continue;
        }

        virtio_scsi_verify_response(&resp, "virtio-scsi:setup");
    }

    /* read and cache SCSI INQUIRY response */
    if (!scsi_inquiry(vdev, scsi_inquiry_std_response,
                      sizeof(scsi_inquiry_std_response))) {
        virtio_scsi_verify_response(&resp, "virtio-scsi:setup:inquiry");
    }

    if (virtio_scsi_inquiry_response_is_cdrom(scsi_inquiry_std_response)) {
        sclp_print("SCSI CD-ROM detected.\n");
        vdev->is_cdrom = true;
        vdev->scsi_block_size = VIRTIO_ISO_BLOCK_SIZE;
    }

    if (!scsi_read_capacity(vdev, data, data_size)) {
        virtio_scsi_verify_response(&resp, "virtio-scsi:setup:read_capacity");
    }
    scsi_parse_capacity_report(data, &vdev->scsi_last_block,
                               (uint32_t *) &vdev->scsi_block_size);
}
