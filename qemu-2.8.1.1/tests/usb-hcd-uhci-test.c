/*
 * QTest testcase for USB UHCI controller
 *
 * Copyright (c) 2014 HUAWEI TECHNOLOGIES CO., LTD.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "libqtest.h"
#include "libqos/libqos.h"
#include "libqos/usb.h"
#include "libqos/libqos-pc.h"
#include "libqos/libqos-spapr.h"
#include "hw/usb/uhci-regs.h"

static QOSState *qs;

static void test_uhci_init(void)
{
}

static void test_port(int port)
{
    struct qhc uhci;

    g_assert(port > 0);
    qusb_pci_init_one(qs->pcibus, &uhci, QPCI_DEVFN(0x1d, 0), 4);
    uhci_port_test(&uhci, port - 1, UHCI_PORT_CCS);
}

static void test_port_1(void)
{
    test_port(1);
}

static void test_port_2(void)
{
    test_port(2);
}

static void test_uhci_hotplug(void)
{
    usb_test_hotplug("uhci", 2, test_port_2);
}

static void test_usb_storage_hotplug(void)
{
    QDict *response;

    response = qmp("{'execute': 'device_add',"
                   " 'arguments': {"
                   "   'driver': 'usb-storage',"
                   "   'drive': 'drive0',"
                   "   'id': 'usbdev0'"
                   "}}");
    g_assert(response);
    g_assert(!qdict_haskey(response, "error"));
    QDECREF(response);

    response = qmp("{'execute': 'device_del',"
                           " 'arguments': {"
                           "   'id': 'usbdev0'"
                           "}}");
    g_assert(response);
    g_assert(!qdict_haskey(response, "error"));
    QDECREF(response);

    response = qmp("");
    g_assert(response);
    g_assert(qdict_haskey(response, "event"));
    g_assert(!strcmp(qdict_get_str(response, "event"), "DEVICE_DELETED"));
    QDECREF(response);
}

int main(int argc, char **argv)
{
    const char *arch = qtest_get_arch();
    const char *cmd = "-device piix3-usb-uhci,id=uhci,addr=1d.0"
                      " -drive id=drive0,if=none,file=/dev/null,format=raw"
                      " -device usb-tablet,bus=uhci.0,port=1";
    int ret;

    g_test_init(&argc, &argv, NULL);

    qtest_add_func("/uhci/pci/init", test_uhci_init);
    qtest_add_func("/uhci/pci/port1", test_port_1);
    qtest_add_func("/uhci/pci/hotplug", test_uhci_hotplug);
    qtest_add_func("/uhci/pci/hotplug/usb-storage", test_usb_storage_hotplug);

    if (strcmp(arch, "i386") == 0 || strcmp(arch, "x86_64") == 0) {
        qs = qtest_pc_boot(cmd);
    } else if (strcmp(arch, "ppc64") == 0) {
        qs = qtest_spapr_boot(cmd);
    } else {
        g_printerr("usb-hcd-uhci-test tests are only "
                   "available on x86 or ppc64\n");
        exit(EXIT_FAILURE);
    }
    ret = g_test_run();
    qtest_shutdown(qs);

    return ret;
}
