/*
 * QEMU live migration
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

#ifndef QEMU_MIGRATION_H
#define QEMU_MIGRATION_H

#include "exec/cpu-common.h"
#include "hw/qdev-core.h"
#include "qapi/qapi-types-migration.h"
#include "qemu/thread.h"
#include "qemu/coroutine_int.h"
#include "io/channel.h"
#include "io/channel-buffer.h"
#include "net/announce.h"
#include "qom/object.h"
#include "postcopy-ram.h"

struct PostcopyBlocktimeContext;

#define  MIGRATION_RESUME_ACK_VALUE  (1)

/*
 * 1<<6=64 pages -> 256K chunk when page size is 4K.  This gives us
 * the benefit that all the chunks are 64 pages aligned then the
 * bitmaps are always aligned to LONG.
 */
#define CLEAR_BITMAP_SHIFT_MIN             6
/*
 * 1<<18=256K pages -> 1G chunk when page size is 4K.  This is the
 * default value to use if no one specified.
 */
#define CLEAR_BITMAP_SHIFT_DEFAULT        18
/*
 * 1<<31=2G pages -> 8T chunk when page size is 4K.  This should be
 * big enough and make sure we won't overflow easily.
 */
#define CLEAR_BITMAP_SHIFT_MAX            31

/* This is an abstraction of a "temp huge page" for postcopy's purpose */
typedef struct {
    /*
     * This points to a temporary huge page as a buffer for UFFDIO_COPY.  It's
     * mmap()ed and needs to be freed when cleanup.
     */
    void *tmp_huge_page;
    /*
     * This points to the host page we're going to install for this temp page.
     * It tells us after we've received the whole page, where we should put it.
     */
    void *host_addr;
    /* Number of small pages copied (in size of TARGET_PAGE_SIZE) */
    unsigned int target_pages;
    /* Whether this page contains all zeros */
    bool all_zero;
} PostcopyTmpPage;

/* State for the incoming migration */
struct MigrationIncomingState {
    QEMUFile *from_src_file;
    /* Previously received RAM's RAMBlock pointer */
    RAMBlock *last_recv_block[RAM_CHANNEL_MAX];
    /* A hook to allow cleanup at the end of incoming migration */
    void *transport_data;
    void (*transport_cleanup)(void *data);
    /*
     * Used to sync thread creations.  Note that we can't create threads in
     * parallel with this sem.
     */
    QemuSemaphore  thread_sync_sem;
    /*
     * Free at the start of the main state load, set as the main thread finishes
     * loading state.
     */
    QemuEvent main_thread_load_event;

    /* For network announces */
    AnnounceTimer  announce_timer;

    size_t         largest_page_size;
    bool           have_fault_thread;
    QemuThread     fault_thread;
    /* Set this when we want the fault thread to quit */
    bool           fault_thread_quit;

    bool           have_listen_thread;
    QemuThread     listen_thread;

    /* For the kernel to send us notifications */
    int       userfault_fd;
    /* To notify the fault_thread to wake, e.g., when need to quit */
    int       userfault_event_fd;
    QEMUFile *to_src_file;
    QemuMutex rp_mutex;    /* We send replies from multiple threads */
    /* RAMBlock of last request sent to source */
    RAMBlock *last_rb;
    /*
     * Number of postcopy channels including the default precopy channel, so
     * vanilla postcopy will only contain one channel which contain both
     * precopy and postcopy streams.
     *
     * This is calculated when the src requests to enable postcopy but before
     * it starts.  Its value can depend on e.g. whether postcopy preemption is
     * enabled.
     */
    unsigned int postcopy_channels;
    /* QEMUFile for postcopy only; it'll be handled by a separate thread */
    QEMUFile *postcopy_qemufile_dst;
    /* Postcopy priority thread is used to receive postcopy requested pages */
    QemuThread postcopy_prio_thread;
    bool postcopy_prio_thread_created;
    /*
     * Used to sync between the ram load main thread and the fast ram load
     * thread.  It protects postcopy_qemufile_dst, which is the postcopy
     * fast channel.
     *
     * The ram fast load thread will take it mostly for the whole lifecycle
     * because it needs to continuously read data from the channel, and
     * it'll only release this mutex if postcopy is interrupted, so that
     * the ram load main thread will take this mutex over and properly
     * release the broken channel.
     */
    QemuMutex postcopy_prio_thread_mutex;
    /*
     * An array of temp host huge pages to be used, one for each postcopy
     * channel.
     */
    PostcopyTmpPage *postcopy_tmp_pages;
    /* This is shared for all postcopy channels */
    void     *postcopy_tmp_zero_page;
    /* PostCopyFD's for external userfaultfds & handlers of shared memory */
    GArray   *postcopy_remote_fds;

    QEMUBH *bh;

    int state;

    bool have_colo_incoming_thread;
    QemuThread colo_incoming_thread;
    /* The coroutine we should enter (back) after failover */
    Coroutine *migration_incoming_co;
    QemuSemaphore colo_incoming_sem;

    /*
     * PostcopyBlocktimeContext to keep information for postcopy
     * live migration, to calculate vCPU block time
     * */
    struct PostcopyBlocktimeContext *blocktime_ctx;

    /* notify PAUSED postcopy incoming migrations to try to continue */
    QemuSemaphore postcopy_pause_sem_dst;
    QemuSemaphore postcopy_pause_sem_fault;
    /*
     * This semaphore is used to allow the ram fast load thread (only when
     * postcopy preempt is enabled) fall into sleep when there's network
     * interruption detected.  When the recovery is done, the main load
     * thread will kick the fast ram load thread using this semaphore.
     */
    QemuSemaphore postcopy_pause_sem_fast_load;

    /* List of listening socket addresses  */
    SocketAddressList *socket_address_list;

    /* A tree of pages that we requested to the source VM */
    GTree *page_requested;
    /* For debugging purpose only, but would be nice to keep */
    int page_requested_count;
    /*
     * The mutex helps to maintain the requested pages that we sent to the
     * source, IOW, to guarantee coherent between the page_requests tree and
     * the per-ramblock receivedmap.  Note! This does not guarantee consistency
     * of the real page copy procedures (using UFFDIO_[ZERO]COPY).  E.g., even
     * if one bit in receivedmap is cleared, UFFDIO_COPY could have happened
     * for that page already.  This is intended so that the mutex won't
     * serialize and blocked by slow operations like UFFDIO_* ioctls.  However
     * this should be enough to make sure the page_requested tree always
     * contains valid information.
     */
    QemuMutex page_request_mutex;
};

MigrationIncomingState *migration_incoming_get_current(void);
void migration_incoming_state_destroy(void);
void migration_incoming_transport_cleanup(MigrationIncomingState *mis);
/*
 * Functions to work with blocktime context
 */
void fill_destination_postcopy_migration_info(MigrationInfo *info);

#define TYPE_MIGRATION "migration"

typedef struct MigrationClass MigrationClass;
DECLARE_OBJ_CHECKERS(MigrationState, MigrationClass,
                     MIGRATION_OBJ, TYPE_MIGRATION)

struct MigrationClass {
    /*< private >*/
    DeviceClass parent_class;
};

struct MigrationState {
   < private >*/
    DeviceState parent_obj;

   < public >*/
    QemuThread thread;               // 迁移线程
    QEMUBH *vm_start_bh;             // 虚拟机启动回调
    QEMUBH *cleanup_bh;              // 清理回调
    /* 受 qemu_file_lock 保护 */
    QEMUFile *to_dst_file;           // 目标文件
    /* Postcopy 特定的传输通道 */
    QEMUFile *postcopy_qemufile_src; 
    /* 当建立抢占通道时发出信号量 */
    QemuSemaphore postcopy_qemufile_src_sem;
    QIOChannelBuffer *bioc;          // I/O 通道缓冲区
    /* 保护 to_dst_file/from_dst_file 指针 */
    QemuMutex qemu_file_lock;

    /* 允许紧急请求覆盖速率限制 */
    QemuSemaphore rate_limit_sem;

    /* 当前迭代开始时已发送的页面数 */
    uint64_t iteration_initial_pages;

    /* 每秒传输的页面数 */
    double pages_per_second;

    /* 当前迭代开始时已发送的字节数 */
    uint64_t iteration_initial_bytes;
    /* 当前迭代开始的时间 */
    int64_t iteration_start_time;
    /* 最后阶段发生在剩余数据小于此阈值时 */
    int64_t threshold_size;

    /* 来自 'migrate-set-parameters' 的参数 */
    MigrationParameters parameters;

    int state;

    /* 与返回路径相关的状态 */
    struct {
        /* 受 qemu_file_lock 保护 */
        QEMUFile *from_dst_file;       // 源文件
        QemuThread rp_thread;          // 返回路径线程
        bool error;                    // 是否发生错误
        /* 检查 rp_thread 是否非零也可以，但没有官方的方法可以做到这一点，所以这个布尔值让它更优雅。
         * 检查 from_dst_file 是否为这个是具有竞争性的，因为 from_dst_file 会在 rp_thread 中被清除！
         */
        bool rp_thread_created;
        QemuSemaphore rp_sem;          // 返回路径信号量
    } rp_state;

    double mbps;                      // 迁移速率（Mbps）
    /* 最近迁移开始的时间戳（毫秒） */
    int64_t start_time;
    /* 最新迁移所用的总时间（毫秒） */
    int64_t total_time;
    /* 虚拟机关闭以迁移最后一些数据的时间戳（毫秒） */
    int64_t downtime_start;
    int64_t downtime;
    int64_t expected_downtime;
    bool enabled_capabilities[MIGRATION_CAPABILITY__MAX];
    int64_t setup_time;
    /* 我们进入完成阶段时，客户机是否正在运行
     * 如果迁移因任何原因中断，我们需要继续在源上运行客户机。
     */
    bool vm_was_running;

    /* 一旦迁移被要求进入 postcopy 阶段，就会设置此标志 */
    bool start_postcopy;
    /* 在 postcopy 发送设备状态后设置的标志 */
    bool postcopy_after_devices;

    /* 一旦迁移线程运行（并需要加入），就会设置此标志 */
    bool migration_thread_running;

    /* 一旦迁移线程调用 bdrv_inactivate_all，就会设置此标志 */
    bool block_inactive;

    /* 迁移正在等待客户机拔出设备 */
    QemuSemaphore wait_unplug_sem;

    /* 由于 pause-before-switchover，迁移被暂停 */
    QemuSemaphore pause_sem;

    /* 该信号量用于通知 COLO 线程故障切换已完成 */
    QemuSemaphore colo_exit_sem;

    /* 该事件用于通知 COLO 线程进行检查点操作 */
    QemuEvent colo_checkpoint_event;
    int64_t colo_checkpoint_time;
    QEMUTimer *colo_delay_timer;

    /* 发生的第一个错误
     * 我们使用互斥锁来能够返回第一条错误消息 */
    Error *error;
    /* 保护 errp 的互斥锁 */
    QemuMutex error_mutex;

    /* 我们是否需要清理来自旧迁移参数的 -b/-i */
    /* 此功能已被弃用并将被删除 */
    bool must_remove_block_options;

    /* 我们是否需要存储全局状态
     * 在迁移期间 */
    bool store_global_state;

    /* 我们是否在迁移期间发送 QEMU_VM_CONFIGURATION */
    bool send_configuration;
    /* 我们是否在迁移期间发送节尾 */
    bool send_section_footer;
    /* 当启用 postcopy preempt 时，我们是否允许在发送主机大页时中断发送巨大页面
     * 当禁用时，我们在发送主机大页时不会中断 precopy，这是 vanilla postcopy 的旧行为
     * 注意：如果未启用 postcopy preempt，则忽略此参数。
     */
    bool postcopy_preempt_break_huge;

    /* postcopy-pause 状态所需 */
    QemuSemaphore postcopy_pause_sem;
    QemuSemaphore postcopy_pause_rp_sem;
    /* 我们是否中止迁移，如果在目的地检测到解压缩错误 */
    bool decompress_error_check;

    /* 这决定了用于跟踪脏位图清除的客人内存块的大小
     * 内存块的大小将是 GUEST_PAGE_SIZE << N。比如，N=0 表示我们将为每个要发送的页面清除脏位图（1<<0=1）；N=10 表示我们只为 1<<10=1K 连续客人页面清除一次脏位图
     * （这是在 4M 块中）。
     */
    uint8_t clear_bitmap_shift;

    /* 当外出迁移开始时保存的主机名 */
    char *hostname;
};

void migrate_set_state(int *state, int old_state, int new_state);

void migration_fd_process_incoming(QEMUFile *f, Error **errp);
void migration_ioc_process_incoming(QIOChannel *ioc, Error **errp);
void migration_incoming_process(void);

bool  migration_has_all_channels(void);

uint64_t migrate_max_downtime(void);

void migrate_set_error(MigrationState *s, const Error *error);
void migrate_fd_error(MigrationState *s, const Error *error);

void migrate_fd_connect(MigrationState *s, Error *error_in);

bool migration_is_setup_or_active(int state);
bool migration_is_running(int state);

void migrate_init(MigrationState *s);
bool migration_is_blocked(Error **errp);
/* True if outgoing migration has entered postcopy phase */
bool migration_in_postcopy(void);
MigrationState *migrate_get_current(void);

bool migrate_postcopy(void);

bool migrate_release_ram(void);
bool migrate_postcopy_ram(void);
bool migrate_zero_blocks(void);
bool migrate_dirty_bitmaps(void);
bool migrate_ignore_shared(void);
bool migrate_validate_uuid(void);

bool migrate_auto_converge(void);
bool migrate_use_multifd(void);
bool migrate_pause_before_switchover(void);
int migrate_multifd_channels(void);
MultiFDCompression migrate_multifd_compression(void);
int migrate_multifd_zlib_level(void);
int migrate_multifd_zstd_level(void);

#ifdef CONFIG_LINUX
bool migrate_use_zero_copy_send(void);
#else
#define migrate_use_zero_copy_send() (false)
#endif
int migrate_use_tls(void);
int migrate_use_xbzrle(void);
uint64_t migrate_xbzrle_cache_size(void);
bool migrate_colo_enabled(void);

bool migrate_use_block(void);
bool migrate_use_block_incremental(void);
int migrate_max_cpu_throttle(void);
bool migrate_use_return_path(void);

uint64_t ram_get_total_transferred_pages(void);

bool migrate_use_compression(void);
int migrate_compress_level(void);
int migrate_compress_threads(void);
int migrate_compress_wait_thread(void);
int migrate_decompress_threads(void);
bool migrate_use_events(void);
bool migrate_postcopy_blocktime(void);
bool migrate_background_snapshot(void);
bool migrate_postcopy_preempt(void);

/* Sending on the return path - generic and then for each message type */
void migrate_send_rp_shut(MigrationIncomingState *mis,
                          uint32_t value);
void migrate_send_rp_pong(MigrationIncomingState *mis,
                          uint32_t value);
int migrate_send_rp_req_pages(MigrationIncomingState *mis, RAMBlock *rb,
                              ram_addr_t start, uint64_t haddr);
int migrate_send_rp_message_req_pages(MigrationIncomingState *mis,
                                      RAMBlock *rb, ram_addr_t start);
void migrate_send_rp_recv_bitmap(MigrationIncomingState *mis,
                                 char *block_name);
void migrate_send_rp_resume_ack(MigrationIncomingState *mis, uint32_t value);

void dirty_bitmap_mig_before_vm_start(void);
void dirty_bitmap_mig_cancel_outgoing(void);
void dirty_bitmap_mig_cancel_incoming(void);
bool check_dirty_bitmap_mig_alias_map(const BitmapMigrationNodeAliasList *bbm,
                                      Error **errp);

void migrate_add_address(SocketAddress *address);

int foreach_not_ignored_block(RAMBlockIterFunc func, void *opaque);

#define qemu_ram_foreach_block \
  #warning "Use foreach_not_ignored_block in migration code"

void migration_make_urgent_request(void);
void migration_consume_urgent_request(void);
bool migration_rate_limit(void);
void migration_cancel(const Error *error);

void populate_vfio_info(MigrationInfo *info);
void postcopy_temp_page_reset(PostcopyTmpPage *tmp_page);

bool migrate_multi_channels_is_allowed(void);
void migrate_protocol_allow_multi_channels(bool allow);

#endif
