/*
 * QTest testcase for ivshmem
 *
 * Copyright (c) 2014 SUSE LINUX Products GmbH
 * Copyright (c) 2015 Red Hat, Inc.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include <glib/gstdio.h>
#include "contrib/ivshmem-server/ivshmem-server.h"
#include "libqos/pci-pc.h"
#include "libqtest.h"
#include "qemu-common.h"

#define TMPSHMSIZE (1 << 20)
static char *tmpshm;
static void *tmpshmem;
static char *tmpdir;
static char *tmpserver;

static void save_fn(QPCIDevice *dev, int devfn, void *data)
{
    QPCIDevice **pdev = (QPCIDevice **) data;

    *pdev = dev;
}

static QPCIDevice *get_device(QPCIBus *pcibus)
{
    QPCIDevice *dev;

    dev = NULL;
    qpci_device_foreach(pcibus, 0x1af4, 0x1110, save_fn, &dev);
    g_assert(dev != NULL);

    return dev;
}

typedef struct _IVState {
    QTestState *qtest;
    QPCIBar reg_bar, mem_bar;
    QPCIBus *pcibus;
    QPCIDevice *dev;
} IVState;

enum Reg {
    INTRMASK = 0,
    INTRSTATUS = 4,
    IVPOSITION = 8,
    DOORBELL = 12,
};

static const char* reg2str(enum Reg reg) {
    switch (reg) {
    case INTRMASK:
        return "IntrMask";
    case INTRSTATUS:
        return "IntrStatus";
    case IVPOSITION:
        return "IVPosition";
    case DOORBELL:
        return "DoorBell";
    default:
        return NULL;
    }
}

static inline unsigned in_reg(IVState *s, enum Reg reg)
{
    const char *name = reg2str(reg);
    QTestState *qtest = global_qtest;
    unsigned res;

    global_qtest = s->qtest;
    res = qpci_io_readl(s->dev, s->reg_bar, reg);
    g_test_message("*%s -> %x\n", name, res);
    global_qtest = qtest;

    return res;
}

static inline void out_reg(IVState *s, enum Reg reg, unsigned v)
{
    const char *name = reg2str(reg);
    QTestState *qtest = global_qtest;

    global_qtest = s->qtest;
    g_test_message("%x -> *%s\n", v, name);
    qpci_io_writel(s->dev, s->reg_bar, reg, v);
    global_qtest = qtest;
}

static inline void read_mem(IVState *s, uint64_t off, void *buf, size_t len)
{
    QTestState *qtest = global_qtest;

    global_qtest = s->qtest;
    qpci_memread(s->dev, s->mem_bar, off, buf, len);
    global_qtest = qtest;
}

static inline void write_mem(IVState *s, uint64_t off,
                             const void *buf, size_t len)
{
    QTestState *qtest = global_qtest;

    global_qtest = s->qtest;
    qpci_memwrite(s->dev, s->mem_bar, off, buf, len);
    global_qtest = qtest;
}

static void cleanup_vm(IVState *s)
{
    g_free(s->dev);
    qpci_free_pc(s->pcibus);
    qtest_quit(s->qtest);
}

static void setup_vm_cmd(IVState *s, const char *cmd, bool msix)
{
    uint64_t barsize;

    s->qtest = qtest_start(cmd);
    s->pcibus = qpci_init_pc(NULL);
    s->dev = get_device(s->pcibus);

    s->reg_bar = qpci_iomap(s->dev, 0, &barsize);
    g_assert_cmpuint(barsize, ==, 256);

    if (msix) {
        qpci_msix_enable(s->dev);
    }

    s->mem_bar = qpci_iomap(s->dev, 2, &barsize);
    g_assert_cmpuint(barsize, ==, TMPSHMSIZE);

    qpci_device_enable(s->dev);
}

static void setup_vm(IVState *s)
{
    char *cmd = g_strdup_printf("-object memory-backend-file"
                                ",id=mb1,size=1M,share,mem-path=/dev/shm%s"
                                " -device ivshmem-plain,memdev=mb1", tmpshm);

    setup_vm_cmd(s, cmd, false);

    g_free(cmd);
}

static void test_ivshmem_single(void)
{
    IVState state, *s;
    uint32_t data[1024];
    int i;

    setup_vm(&state);
    s = &state;

    /* initial state of readable registers */
    g_assert_cmpuint(in_reg(s, INTRMASK), ==, 0);
    g_assert_cmpuint(in_reg(s, INTRSTATUS), ==, 0);
    g_assert_cmpuint(in_reg(s, IVPOSITION), ==, 0);

    /* trigger interrupt via registers */
    out_reg(s, INTRMASK, 0xffffffff);
    g_assert_cmpuint(in_reg(s, INTRMASK), ==, 0xffffffff);
    out_reg(s, INTRSTATUS, 1);
    /* check interrupt status */
    g_assert_cmpuint(in_reg(s, INTRSTATUS), ==, 1);
    /* reading clears */
    g_assert_cmpuint(in_reg(s, INTRSTATUS), ==, 0);
    /* TODO intercept actual interrupt (needs qtest work) */

    /* invalid register access */
    out_reg(s, IVPOSITION, 1);
    in_reg(s, DOORBELL);

    /* ring the (non-functional) doorbell */
    out_reg(s, DOORBELL, 8 << 16);

    /* write shared memory */
    for (i = 0; i < G_N_ELEMENTS(data); i++) {
        data[i] = i;
    }
    write_mem(s, 0, data, sizeof(data));

    /* verify write */
    for (i = 0; i < G_N_ELEMENTS(data); i++) {
        g_assert_cmpuint(((uint32_t *)tmpshmem)[i], ==, i);
    }

    /* read it back and verify read */
    memset(data, 0, sizeof(data));
    read_mem(s, 0, data, sizeof(data));
    for (i = 0; i < G_N_ELEMENTS(data); i++) {
        g_assert_cmpuint(data[i], ==, i);
    }

    cleanup_vm(s);
}

static void test_ivshmem_pair(void)
{
    IVState state1, state2, *s1, *s2;
    char *data;
    int i;

    setup_vm(&state1);
    s1 = &state1;
    setup_vm(&state2);
    s2 = &state2;

    data = g_malloc0(TMPSHMSIZE);

    /* host write, guest 1 & 2 read */
    memset(tmpshmem, 0x42, TMPSHMSIZE);
    read_mem(s1, 0, data, TMPSHMSIZE);
    for (i = 0; i < TMPSHMSIZE; i++) {
        g_assert_cmpuint(data[i], ==, 0x42);
    }
    read_mem(s2, 0, data, TMPSHMSIZE);
    for (i = 0; i < TMPSHMSIZE; i++) {
        g_assert_cmpuint(data[i], ==, 0x42);
    }

    /* guest 1 write, guest 2 read */
    memset(data, 0x43, TMPSHMSIZE);
    write_mem(s1, 0, data, TMPSHMSIZE);
    memset(data, 0, TMPSHMSIZE);
    read_mem(s2, 0, data, TMPSHMSIZE);
    for (i = 0; i < TMPSHMSIZE; i++) {
        g_assert_cmpuint(data[i], ==, 0x43);
    }

    /* guest 2 write, guest 1 read */
    memset(data, 0x44, TMPSHMSIZE);
    write_mem(s2, 0, data, TMPSHMSIZE);
    memset(data, 0, TMPSHMSIZE);
    read_mem(s1, 0, data, TMPSHMSIZE);
    for (i = 0; i < TMPSHMSIZE; i++) {
        g_assert_cmpuint(data[i], ==, 0x44);
    }

    cleanup_vm(s1);
    cleanup_vm(s2);
    g_free(data);
}

typedef struct ServerThread {
    GThread *thread;
    IvshmemServer *server;
    int pipe[2]; /* to handle quit */
} ServerThread;

static void *server_thread(void *data)
{
    ServerThread *t = data;
    IvshmemServer *server = t->server;

    while (true) {
        fd_set fds;
        int maxfd, ret;

        FD_ZERO(&fds);
        FD_SET(t->pipe[0], &fds);
        maxfd = t->pipe[0] + 1;

        ivshmem_server_get_fds(server, &fds, &maxfd);

        ret = select(maxfd, &fds, NULL, NULL, NULL);

        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }

            g_critical("select error: %s\n", strerror(errno));
            break;
        }
        if (ret == 0) {
            continue;
        }

        if (FD_ISSET(t->pipe[0], &fds)) {
            break;
        }

        if (ivshmem_server_handle_fds(server, &fds, maxfd) < 0) {
            g_critical("ivshmem_server_handle_fds() failed\n");
            break;
        }
    }

    return NULL;
}

static void setup_vm_with_server(IVState *s, int nvectors, bool msi)
{
    char *cmd = g_strdup_printf("-chardev socket,id=chr0,path=%s,nowait "
                                "-device ivshmem%s,chardev=chr0,vectors=%d",
                                tmpserver,
                                msi ? "-doorbell" : ",size=1M,msi=off",
                                nvectors);

    setup_vm_cmd(s, cmd, msi);

    g_free(cmd);
}

static void test_ivshmem_server(bool msi)
{
    IVState state1, state2, *s1, *s2;
    ServerThread thread;
    IvshmemServer server;
    int ret, vm1, vm2;
    int nvectors = 2;
    guint64 end_time = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;

    ret = ivshmem_server_init(&server, tmpserver, tmpshm, true,
                              TMPSHMSIZE, nvectors,
                              g_test_verbose());
    g_assert_cmpint(ret, ==, 0);

    ret = ivshmem_server_start(&server);
    g_assert_cmpint(ret, ==, 0);

    thread.server = &server;
    ret = pipe(thread.pipe);
    g_assert_cmpint(ret, ==, 0);
    thread.thread = g_thread_new("ivshmem-server", server_thread, &thread);
    g_assert(thread.thread != NULL);

    setup_vm_with_server(&state1, nvectors, msi);
    s1 = &state1;
    setup_vm_with_server(&state2, nvectors, msi);
    s2 = &state2;

    /* check got different VM ids */
    vm1 = in_reg(s1, IVPOSITION);
    vm2 = in_reg(s2, IVPOSITION);
    g_assert_cmpint(vm1, >=, 0);
    g_assert_cmpint(vm2, >=, 0);
    g_assert_cmpint(vm1, !=, vm2);

    /* check number of MSI-X vectors */
    global_qtest = s1->qtest;
    if (msi) {
        ret = qpci_msix_table_size(s1->dev);
        g_assert_cmpuint(ret, ==, nvectors);
    }

    /* TODO test behavior before MSI-X is enabled */

    /* ping vm2 -> vm1 on vector 0 */
    if (msi) {
        ret = qpci_msix_pending(s1->dev, 0);
        g_assert_cmpuint(ret, ==, 0);
    } else {
        g_assert_cmpuint(in_reg(s1, INTRSTATUS), ==, 0);
    }
    out_reg(s2, DOORBELL, vm1 << 16);
    do {
        g_usleep(10000);
        ret = msi ? qpci_msix_pending(s1->dev, 0) : in_reg(s1, INTRSTATUS);
    } while (ret == 0 && g_get_monotonic_time() < end_time);
    g_assert_cmpuint(ret, !=, 0);

    /* ping vm1 -> vm2 on vector 1 */
    global_qtest = s2->qtest;
    if (msi) {
        ret = qpci_msix_pending(s2->dev, 1);
        g_assert_cmpuint(ret, ==, 0);
    } else {
        g_assert_cmpuint(in_reg(s2, INTRSTATUS), ==, 0);
    }
    out_reg(s1, DOORBELL, vm2 << 16 | 1);
    do {
        g_usleep(10000);
        ret = msi ? qpci_msix_pending(s2->dev, 1) : in_reg(s2, INTRSTATUS);
    } while (ret == 0 && g_get_monotonic_time() < end_time);
    g_assert_cmpuint(ret, !=, 0);

    cleanup_vm(s2);
    cleanup_vm(s1);

    if (qemu_write_full(thread.pipe[1], "q", 1) != 1) {
        g_error("qemu_write_full: %s", g_strerror(errno));
    }

    g_thread_join(thread.thread);

    ivshmem_server_close(&server);
    close(thread.pipe[1]);
    close(thread.pipe[0]);
}

static void test_ivshmem_server_msi(void)
{
    test_ivshmem_server(true);
}

static void test_ivshmem_server_irq(void)
{
    test_ivshmem_server(false);
}

#define PCI_SLOT_HP             0x06

static void test_ivshmem_hotplug(void)
{
    gchar *opts;

    qtest_start("");

    opts = g_strdup_printf("'shm': '%s', 'size': '1M'", tmpshm);

    qpci_plug_device_test("ivshmem", "iv1", PCI_SLOT_HP, opts);
    qpci_unplug_acpi_device_test("iv1", PCI_SLOT_HP);

    qtest_end();
    g_free(opts);
}

static void test_ivshmem_memdev(void)
{
    IVState state;

    /* just for the sake of checking memory-backend property */
    setup_vm_cmd(&state, "-object memory-backend-ram,size=1M,id=mb1"
                 " -device ivshmem-plain,memdev=mb1", false);

    cleanup_vm(&state);
}

static void cleanup(void)
{
    if (tmpshmem) {
        munmap(tmpshmem, TMPSHMSIZE);
        tmpshmem = NULL;
    }

    if (tmpshm) {
        shm_unlink(tmpshm);
        g_free(tmpshm);
        tmpshm = NULL;
    }

    if (tmpserver) {
        g_unlink(tmpserver);
        g_free(tmpserver);
        tmpserver = NULL;
    }

    if (tmpdir) {
        g_rmdir(tmpdir);
        tmpdir = NULL;
    }
}

static void abrt_handler(void *data)
{
    cleanup();
}

static gchar *mktempshm(int size, int *fd)
{
    while (true) {
        gchar *name;

        name = g_strdup_printf("/qtest-%u-%u", getpid(), g_random_int());
        *fd = shm_open(name, O_CREAT|O_RDWR|O_EXCL,
                       S_IRWXU|S_IRWXG|S_IRWXO);
        if (*fd > 0) {
            g_assert(ftruncate(*fd, size) == 0);
            return name;
        }

        g_free(name);

        if (errno != EEXIST) {
            perror("shm_open");
            return NULL;
        }
    }
}

int main(int argc, char **argv)
{
    int ret, fd;
    gchar dir[] = "/tmp/ivshmem-test.XXXXXX";

#if !GLIB_CHECK_VERSION(2, 31, 0)
    if (!g_thread_supported()) {
        g_thread_init(NULL);
    }
#endif

    g_test_init(&argc, &argv, NULL);

    qtest_add_abrt_handler(abrt_handler, NULL);
    /* shm */
    tmpshm = mktempshm(TMPSHMSIZE, &fd);
    if (!tmpshm) {
        return 0;
    }
    tmpshmem = mmap(0, TMPSHMSIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    g_assert(tmpshmem != MAP_FAILED);
    /* server */
    if (mkdtemp(dir) == NULL) {
        g_error("mkdtemp: %s", g_strerror(errno));
    }
    tmpdir = dir;
    tmpserver = g_strconcat(tmpdir, "/server", NULL);

    qtest_add_func("/ivshmem/single", test_ivshmem_single);
    qtest_add_func("/ivshmem/hotplug", test_ivshmem_hotplug);
    qtest_add_func("/ivshmem/memdev", test_ivshmem_memdev);
    if (g_test_slow()) {
        qtest_add_func("/ivshmem/pair", test_ivshmem_pair);
        qtest_add_func("/ivshmem/server-msi", test_ivshmem_server_msi);
        qtest_add_func("/ivshmem/server-irq", test_ivshmem_server_irq);
    }

    ret = g_test_run();

    cleanup();

    return ret;
}
