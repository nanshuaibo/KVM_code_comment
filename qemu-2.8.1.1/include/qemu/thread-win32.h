#ifndef QEMU_THREAD_WIN32_H
#define QEMU_THREAD_WIN32_H

#include <windows.h>

struct QemuMutex {
    CRITICAL_SECTION lock;
    LONG owner;
};

typedef struct QemuRecMutex QemuRecMutex;
struct QemuRecMutex {
    CRITICAL_SECTION lock;
};

void qemu_rec_mutex_destroy(QemuRecMutex *mutex);
void qemu_rec_mutex_lock(QemuRecMutex *mutex);
int qemu_rec_mutex_trylock(QemuRecMutex *mutex);
void qemu_rec_mutex_unlock(QemuRecMutex *mutex);

struct QemuCond {
    LONG waiters, target;
    HANDLE sema;
    HANDLE continue_event;
};

struct QemuSemaphore {
    HANDLE sema;
};

struct QemuEvent {
    int value;
    HANDLE event;
};

typedef struct QemuThreadData QemuThreadData;
struct QemuThread {
    QemuThreadData *data;
    unsigned tid;
};

/* Only valid for joinable threads.  */
HANDLE qemu_thread_get_handle(QemuThread *thread);

#endif
