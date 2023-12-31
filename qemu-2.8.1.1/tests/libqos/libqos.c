#include "qemu/osdep.h"
#include <sys/wait.h>

#include "libqtest.h"
#include "libqos/libqos.h"
#include "libqos/pci.h"

/*** Test Setup & Teardown ***/

/**
 * Launch QEMU with the given command line,
 * and then set up interrupts and our guest malloc interface.
 * Never returns NULL:
 * Terminates the application in case an error is encountered.
 */
QOSState *qtest_vboot(QOSOps *ops, const char *cmdline_fmt, va_list ap)
{
    char *cmdline;

    struct QOSState *qs = g_malloc(sizeof(QOSState));

    cmdline = g_strdup_vprintf(cmdline_fmt, ap);
    qs->qts = qtest_start(cmdline);
    qs->ops = ops;
    if (ops) {
        if (ops->init_allocator) {
            qs->alloc = ops->init_allocator(ALLOC_NO_FLAGS);
        }
        if (ops->qpci_init && qs->alloc) {
            qs->pcibus = ops->qpci_init(qs->alloc);
        }
    }

    g_free(cmdline);
    return qs;
}

/**
 * Launch QEMU with the given command line,
 * and then set up interrupts and our guest malloc interface.
 */
QOSState *qtest_boot(QOSOps *ops, const char *cmdline_fmt, ...)
{
    QOSState *qs;
    va_list ap;

    va_start(ap, cmdline_fmt);
    qs = qtest_vboot(ops, cmdline_fmt, ap);
    va_end(ap);

    return qs;
}

/**
 * Tear down the QEMU instance.
 */
void qtest_common_shutdown(QOSState *qs)
{
    if (qs->ops) {
        if (qs->pcibus && qs->ops->qpci_free) {
            qs->ops->qpci_free(qs->pcibus);
            qs->pcibus = NULL;
        }
        if (qs->alloc && qs->ops->uninit_allocator) {
            qs->ops->uninit_allocator(qs->alloc);
            qs->alloc = NULL;
        }
    }
    qtest_quit(qs->qts);
    g_free(qs);
}

void qtest_shutdown(QOSState *qs)
{
    if (qs->ops && qs->ops->shutdown) {
        qs->ops->shutdown(qs);
    } else {
        qtest_common_shutdown(qs);
    }
}

void set_context(QOSState *s)
{
    global_qtest = s->qts;
}

static QDict *qmp_execute(const char *command)
{
    char *fmt;
    QDict *rsp;

    fmt = g_strdup_printf("{ 'execute': '%s' }", command);
    rsp = qmp(fmt);
    g_free(fmt);

    return rsp;
}

void migrate(QOSState *from, QOSState *to, const char *uri)
{
    const char *st;
    char *s;
    QDict *rsp, *sub;
    bool running;

    set_context(from);

    /* Is the machine currently running? */
    rsp = qmp_execute("query-status");
    g_assert(qdict_haskey(rsp, "return"));
    sub = qdict_get_qdict(rsp, "return");
    g_assert(qdict_haskey(sub, "running"));
    running = qdict_get_bool(sub, "running");
    QDECREF(rsp);

    /* Issue the migrate command. */
    s = g_strdup_printf("{ 'execute': 'migrate',"
                        "'arguments': { 'uri': '%s' } }",
                        uri);
    rsp = qmp(s);
    g_free(s);
    g_assert(qdict_haskey(rsp, "return"));
    QDECREF(rsp);

    /* Wait for STOP event, but only if we were running: */
    if (running) {
        qmp_eventwait("STOP");
    }

    /* If we were running, we can wait for an event. */
    if (running) {
        migrate_allocator(from->alloc, to->alloc);
        set_context(to);
        qmp_eventwait("RESUME");
        return;
    }

    /* Otherwise, we need to wait: poll until migration is completed. */
    while (1) {
        rsp = qmp_execute("query-migrate");
        g_assert(qdict_haskey(rsp, "return"));
        sub = qdict_get_qdict(rsp, "return");
        g_assert(qdict_haskey(sub, "status"));
        st = qdict_get_str(sub, "status");

        /* "setup", "active", "completed", "failed", "cancelled" */
        if (strcmp(st, "completed") == 0) {
            QDECREF(rsp);
            break;
        }

        if ((strcmp(st, "setup") == 0) || (strcmp(st, "active") == 0)) {
            QDECREF(rsp);
            g_usleep(5000);
            continue;
        }

        fprintf(stderr, "Migration did not complete, status: %s\n", st);
        g_assert_not_reached();
    }

    migrate_allocator(from->alloc, to->alloc);
    set_context(to);
}

bool have_qemu_img(void)
{
    char *rpath;
    const char *path = getenv("QTEST_QEMU_IMG");
    if (!path) {
        return false;
    }

    rpath = realpath(path, NULL);
    if (!rpath) {
        return false;
    } else {
        free(rpath);
        return true;
    }
}

void mkimg(const char *file, const char *fmt, unsigned size_mb)
{
    gchar *cli;
    bool ret;
    int rc;
    GError *err = NULL;
    char *qemu_img_path;
    gchar *out, *out2;
    char *qemu_img_abs_path;

    qemu_img_path = getenv("QTEST_QEMU_IMG");
    g_assert(qemu_img_path);
    qemu_img_abs_path = realpath(qemu_img_path, NULL);
    g_assert(qemu_img_abs_path);

    cli = g_strdup_printf("%s create -f %s %s %uM", qemu_img_abs_path,
                          fmt, file, size_mb);
    ret = g_spawn_command_line_sync(cli, &out, &out2, &rc, &err);
    if (err) {
        fprintf(stderr, "%s\n", err->message);
        g_error_free(err);
    }
    g_assert(ret && !err);

    /* In glib 2.34, we have g_spawn_check_exit_status. in 2.12, we don't.
     * glib 2.43.91 implementation assumes that any non-zero is an error for
     * windows, but uses extra precautions for Linux. However,
     * 0 is only possible if the program exited normally, so that should be
     * sufficient for our purposes on all platforms, here. */
    if (rc) {
        fprintf(stderr, "qemu-img returned status code %d\n", rc);
    }
    g_assert(!rc);

    g_free(out);
    g_free(out2);
    g_free(cli);
    free(qemu_img_abs_path);
}

void mkqcow2(const char *file, unsigned size_mb)
{
    return mkimg(file, "qcow2", size_mb);
}

void prepare_blkdebug_script(const char *debug_fn, const char *event)
{
    FILE *debug_file = fopen(debug_fn, "w");
    int ret;

    fprintf(debug_file, "[inject-error]\n");
    fprintf(debug_file, "event = \"%s\"\n", event);
    fprintf(debug_file, "errno = \"5\"\n");
    fprintf(debug_file, "state = \"1\"\n");
    fprintf(debug_file, "immediately = \"off\"\n");
    fprintf(debug_file, "once = \"on\"\n");

    fprintf(debug_file, "[set-state]\n");
    fprintf(debug_file, "event = \"%s\"\n", event);
    fprintf(debug_file, "new_state = \"2\"\n");
    fflush(debug_file);
    g_assert(!ferror(debug_file));

    ret = fclose(debug_file);
    g_assert(ret == 0);
}

void generate_pattern(void *buffer, size_t len, size_t cycle_len)
{
    int i, j;
    unsigned char *tx = (unsigned char *)buffer;
    unsigned char p;
    size_t *sx;

    /* Write an indicative pattern that varies and is unique per-cycle */
    p = rand() % 256;
    for (i = 0; i < len; i++) {
        tx[i] = p++ % 256;
        if (i % cycle_len == 0) {
            p = rand() % 256;
        }
    }

    /* force uniqueness by writing an id per-cycle */
    for (i = 0; i < len / cycle_len; i++) {
        j = i * cycle_len;
        if (j + sizeof(*sx) <= len) {
            sx = (size_t *)&tx[j];
            *sx = i;
        }
    }
}
