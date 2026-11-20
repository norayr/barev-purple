/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "post-io.h"
#include "identity-store.h"
#include <glib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { SHORT_IO = 1, WRITE_EINTR, WRITE_ZERO, WRITE_ERROR, READ_EINTR, READ_ERROR,
       READ_EOF, FILE_SYNC, DIR_SYNC, RENAME_ERROR, CLOSE_ERROR };
static unsigned checks;
static GThread *main_thread;
static gint fault, enforce, after_rename, read_complete, gate, blocked;
static GMutex mutex;
static GCond condition;
static gboolean opened;

#define CHECK(test) do { ++checks; if (!(test)) { \
    fprintf(stderr, "PostIOHost:%d: %s\n", __LINE__, #test); return 1; } } while (0)

ssize_t __real_read(int fd, void *bytes, size_t size);
ssize_t __real_write(int fd, const void *bytes, size_t size);
int __real_fsync(int fd);
int __real_close(int fd);
int __real_renameat(int from, const char *old, int to, const char *name);

static void worker_only(void)
{ if (g_atomic_int_get(&enforce)) g_assert(g_thread_self() != main_thread); }

ssize_t __wrap_read(int fd, void *bytes, size_t size)
{
    ssize_t result;
    worker_only();
    if (g_atomic_int_compare_and_exchange(&fault, READ_EINTR, 0)) { errno = EINTR; return -1; }
    if (g_atomic_int_compare_and_exchange(&fault, READ_ERROR, 0)) { errno = EIO; return -1; }
    if (g_atomic_int_compare_and_exchange(&fault, READ_EOF, 0)) return 0;
    if (g_atomic_int_get(&fault) == SHORT_IO && size > 7) size = 7;
    result = __real_read(fd, bytes, size);
    if (result == 0) g_atomic_int_set(&read_complete, 1);
    return result;
}

ssize_t __wrap___read_chk(int fd, void *bytes, size_t size, size_t capacity)
{
    g_assert(size <= capacity);
    return __wrap_read(fd, bytes, size);
}

ssize_t __wrap_write(int fd, const void *bytes, size_t size)
{
    worker_only();
    if (g_atomic_int_compare_and_exchange(&fault, WRITE_EINTR, 0)) { errno = EINTR; return -1; }
    if (g_atomic_int_compare_and_exchange(&fault, WRITE_ZERO, 0)) return 0;
    if (g_atomic_int_compare_and_exchange(&fault, WRITE_ERROR, 0)) { errno = ENOSPC; return -1; }
    if (g_atomic_int_get(&fault) == SHORT_IO && size > 7) size = 7;
    return __real_write(fd, bytes, size);
}

int __wrap_fsync(int fd)
{
    struct stat info;
    worker_only();
    if (g_atomic_int_get(&gate)) {
        g_mutex_lock(&mutex); g_atomic_int_inc(&blocked);
        while (!opened) g_cond_wait(&condition, &mutex);
        g_mutex_unlock(&mutex);
    }
    if (!fstat(fd, &info)) {
        if (S_ISREG(info.st_mode) && g_atomic_int_compare_and_exchange(&fault, FILE_SYNC, 0)) {
            errno = EIO; return -1;
        }
        if (S_ISDIR(info.st_mode) && (g_atomic_int_get(&after_rename) || g_atomic_int_get(&read_complete)) &&
            g_atomic_int_compare_and_exchange(&fault, DIR_SYNC, 0)) { errno = EIO; return -1; }
    }
    return __real_fsync(fd);
}

int __wrap_close(int fd)
{
    struct stat info;
    if (!fstat(fd, &info) && S_ISREG(info.st_mode) &&
        g_atomic_int_compare_and_exchange(&fault, CLOSE_ERROR, 0)) {
        int result = __real_close(fd);
        if (!result) { errno = EIO; return -1; }
        return result;
    }
    return __real_close(fd);
}

int __wrap_renameat(int from, const char *old, int to, const char *name)
{
    int result;
    worker_only();
    if (g_atomic_int_compare_and_exchange(&fault, RENAME_ERROR, 0)) { errno = EIO; return -1; }
    result = __real_renameat(from, old, to, name);
    if (!result) g_atomic_int_set(&after_rename, 1);
    return result;
}

static int finish(int32_t handle)
{
    gint64 deadline = g_get_monotonic_time()+5000000;
    int status;
    if (handle <= 0) return -1;
    while ((status = BarevPostIO_Status(handle)) == BAREV_POST_IO_PENDING && g_get_monotonic_time() < deadline) {
        while (g_main_context_iteration(NULL, FALSE)) {}
        g_usleep(1000);
    }
    return status;
}

static gboolean drain(void)
{
    gint64 deadline = g_get_monotonic_time()+5000000;
    while (!BarevPostIO_Idle() && g_get_monotonic_time() < deadline) g_usleep(1000);
    return BarevPostIO_Idle();
}

static int32_t replace(const char *profile, const char *owner, const unsigned char *before,
                       int32_t length, const unsigned char *next, int32_t size, int failure)
{
    g_atomic_int_set(&fault, failure); g_atomic_int_set(&after_rename, 0); g_atomic_int_set(&read_complete, 0);
    return BarevPostIO_Replace(profile, owner, before, length, next, size);
}

static gboolean contents(const char *path, const void *expected, size_t length)
{
    gchar *bytes = NULL;
    gsize size = 0;
    gboolean result = g_file_get_contents(path, &bytes, &size, NULL) && size == length &&
                      (!length || !memcmp(bytes, expected, length));
    g_free(bytes); return result;
}

static gboolean clean(const char *profile)
{
    gchar *path = g_build_filename(profile, "barev", NULL);
    GDir *dir = g_dir_open(path, 0, NULL);
    const char *name;
    gboolean result = dir != NULL;
    if (dir) {
        while ((name = g_dir_read_name(dir))) if (g_str_has_prefix(name, ".posts-")) result = FALSE;
        g_dir_close(dir);
    }
    g_free(path); return result;
}

static gboolean heartbeat(gpointer data) { ++*(unsigned *)data; return G_SOURCE_CONTINUE; }

static gpointer foreign(gpointer data)
{
    const char *profile = data;
    const char *owner = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    unsigned char byte = 0;
    gboolean good = !BarevPostIO_Start() && !BarevPostIO_Read(profile, owner) &&
        BarevPostIO_Status(1) == BAREV_POST_IO_INVALID && BarevPostIO_Length(1) == -1 &&
        BarevPostIO_Copy(1, &byte, 1) == -1 && !BarevPostIO_Idle();
    BarevPostIO_Stop(); BarevPostIO_Release(1);
    return GINT_TO_POINTER(good);
}

int main(int argc, char **argv)
{
    const char *owner = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    unsigned char before[64], next[64], output[64];
    unsigned char *big;
    gchar *profile, *path, *dir, *outside;
    struct stat info, installed;
    int32_t handle, old, jobs[BAREV_POST_IO_MAX_JOBS];
    unsigned i, beats = 0, timer;
    const int failures[] = { WRITE_ZERO, WRITE_ERROR, FILE_SYNC, RENAME_ERROR, READ_ERROR, READ_EOF, CLOSE_ERROR };
    gint64 deadline;
    int lock;
    CHECK(argc == 2);
    main_thread = g_thread_self();
    profile = g_build_filename(argv[1], "profile", NULL);
    dir = g_build_filename(profile, "barev", NULL);
    path = g_strdup_printf("%s/posts-%s.state", dir, owner);
    outside = g_build_filename(argv[1], "outside", NULL);
    for (i = 0; i < sizeof(before); ++i) { before[i] = (unsigned char)i; next[i] = (unsigned char)(255-i); }
    CHECK(BarevPostIO_Idle());
    CHECK(!BarevPostIO_Read(profile, owner));
    CHECK(BarevPostIO_Start()); CHECK(BarevPostIO_Start());
    CHECK(!BarevPostIO_Read("relative", owner)); CHECK(!BarevPostIO_Read("/", owner));
    CHECK(!BarevPostIO_Read(profile, "short")); CHECK(!BarevPostIO_Read(NULL, owner));
    CHECK(!BarevPostIO_Replace(profile, owner, NULL, 1, next, sizeof(next)));
    CHECK(!BarevPostIO_Replace(profile, owner, NULL, -2, next, sizeof(next)));
    CHECK(!BarevPostIO_Replace(profile, owner, before, sizeof(before), next, BAREV_POST_IO_MAX_BYTES+1));
    CHECK(BarevPostIO_Status(-1) == BAREV_POST_IO_INVALID);
    CHECK(GPOINTER_TO_INT(g_thread_join(g_thread_new("foreign-api", foreign, profile))));
    g_atomic_int_set(&enforce, 1);
    handle = BarevPostIO_Read(profile, owner); CHECK(finish(handle) == BAREV_POST_IO_MISSING);
    CHECK(BarevPostIO_Length(handle) == -1); output[0] = 42;
    CHECK(BarevPostIO_Copy(handle, output, sizeof(output)) == -1 && output[0] == 42);
    old = handle; BarevPostIO_Release(handle); CHECK(BarevPostIO_Status(old) == BAREV_POST_IO_INVALID);
    handle = replace(profile, owner, NULL, -1, before, sizeof(before), WRITE_EINTR);
    CHECK(handle > old && finish(handle) == BAREV_POST_IO_OKAY); BarevPostIO_Release(handle);
    CHECK(contents(path, before, sizeof(before)));
    g_atomic_int_set(&fault, READ_EINTR);
    handle = BarevPostIO_Read(profile, owner); CHECK(finish(handle) == BAREV_POST_IO_OKAY);
    CHECK(BarevPostIO_Length(handle) == (int32_t)sizeof(before)); output[0] = 42;
    CHECK(BarevPostIO_Copy(handle, output, 1) == -1 && output[0] == 42);
    CHECK(BarevPostIO_Copy(handle, output, sizeof(output)) == (int32_t)sizeof(output));
    CHECK(!memcmp(output, before, sizeof(output))); BarevPostIO_Release(handle);
    handle = replace(profile, owner, NULL, -1, next, sizeof(next), 0);
    CHECK(finish(handle) == BAREV_POST_IO_CHANGED); BarevPostIO_Release(handle);
    CHECK(contents(path, before, sizeof(before)));
    for (i = 0; i < G_N_ELEMENTS(failures); ++i) {
        handle = replace(profile, owner, before, sizeof(before), next, sizeof(next), failures[i]);
        CHECK(finish(handle) == BAREV_POST_IO_ERROR); BarevPostIO_Release(handle);
        g_atomic_int_set(&fault, 0);
        CHECK(contents(path, before, sizeof(before))); CHECK(clean(profile));
    }
    handle = replace(profile, owner, before, sizeof(before), next, sizeof(next), DIR_SYNC);
    CHECK(finish(handle) == BAREV_POST_IO_ERROR); BarevPostIO_Release(handle);
    CHECK(contents(path, next, sizeof(next))); CHECK(!stat(path, &installed));
    handle = replace(profile, owner, before, sizeof(before), next, sizeof(next), DIR_SYNC);
    CHECK(finish(handle) == BAREV_POST_IO_ERROR); BarevPostIO_Release(handle);
    handle = replace(profile, owner, before, sizeof(before), next, sizeof(next), 0);
    CHECK(finish(handle) == BAREV_POST_IO_OKAY); BarevPostIO_Release(handle);
    CHECK(!stat(path, &info) && info.st_ino == installed.st_ino);
    CHECK((info.st_mode & 0777) == 0600); CHECK(clean(profile));
    handle = replace(profile, owner, next, sizeof(next), before, sizeof(before), SHORT_IO);
    CHECK(finish(handle) == BAREV_POST_IO_OKAY); BarevPostIO_Release(handle); g_atomic_int_set(&fault, 0);
    CHECK(contents(path, before, sizeof(before)));
    g_atomic_int_set(&enforce, 0); lock = BarevIdentityFile_Open(profile); CHECK(lock >= 0);
    g_atomic_int_set(&enforce, 1); handle = BarevPostIO_Read(profile, owner);
    CHECK(finish(handle) == BAREV_POST_IO_ERROR); BarevPostIO_Release(handle);
    BarevIdentityFile_Close(lock);
    CHECK(!unlink(path)); CHECK(g_file_set_contents(outside, (char *)before, sizeof(before), NULL));
    CHECK(!symlink(outside, path)); handle = BarevPostIO_Read(profile, owner);
    CHECK(finish(handle) == BAREV_POST_IO_ERROR); BarevPostIO_Release(handle);
    CHECK(contents(outside, before, sizeof(before))); CHECK(!unlink(path));
    CHECK(!mkfifo(path, 0600)); handle = BarevPostIO_Read(profile, owner);
    CHECK(finish(handle) == BAREV_POST_IO_ERROR); BarevPostIO_Release(handle); CHECK(!unlink(path));
    CHECK(!mkdir(path, 0700)); handle = BarevPostIO_Read(profile, owner);
    CHECK(finish(handle) == BAREV_POST_IO_ERROR); BarevPostIO_Release(handle); CHECK(!rmdir(path));
    CHECK(g_file_set_contents(path, "", 0, NULL)); handle = BarevPostIO_Read(profile, owner);
    CHECK(finish(handle) == BAREV_POST_IO_OKAY && BarevPostIO_Length(handle) == 0);
    CHECK(BarevPostIO_Copy(handle, NULL, 0) == 0); BarevPostIO_Release(handle);
    handle = replace(profile, owner, NULL, -1, before, sizeof(before), 0);
    CHECK(finish(handle) == BAREV_POST_IO_CHANGED); BarevPostIO_Release(handle);
    handle = replace(profile, owner, NULL, 0, before, sizeof(before), 0);
    CHECK(finish(handle) == BAREV_POST_IO_OKAY); BarevPostIO_Release(handle);
    big = g_malloc(BAREV_POST_IO_MAX_BYTES); memset(big, 42, BAREV_POST_IO_MAX_BYTES);
    handle = replace(profile, owner, before, sizeof(before), big, BAREV_POST_IO_MAX_BYTES, 0);
    CHECK(finish(handle) == BAREV_POST_IO_OKAY); BarevPostIO_Release(handle);
    handle = BarevPostIO_Read(profile, owner); CHECK(finish(handle) == BAREV_POST_IO_OKAY);
    CHECK(BarevPostIO_Length(handle) == BAREV_POST_IO_MAX_BYTES);
    CHECK(BarevPostIO_Copy(handle, big, BAREV_POST_IO_MAX_BYTES) == BAREV_POST_IO_MAX_BYTES);
    CHECK(big[0] == 42 && big[BAREV_POST_IO_MAX_BYTES-1] == 42); BarevPostIO_Release(handle);
    handle = replace(profile, owner, big, BAREV_POST_IO_MAX_BYTES, before, sizeof(before), 0);
    CHECK(finish(handle) == BAREV_POST_IO_OKAY); BarevPostIO_Release(handle); g_free(big);
    CHECK(!truncate(path, BAREV_POST_IO_MAX_BYTES+1)); handle = BarevPostIO_Read(profile, owner);
    CHECK(finish(handle) == BAREV_POST_IO_INVALID); BarevPostIO_Release(handle);
    CHECK(g_file_set_contents(path, (char *)before, sizeof(before), NULL));
    CHECK(!chmod(dir, 0755)); handle = BarevPostIO_Read(profile, owner);
    CHECK(finish(handle) == BAREV_POST_IO_ERROR); BarevPostIO_Release(handle); CHECK(!chmod(dir, 0700));

    /* A held filesystem call leaves the main context and result API responsive. */
    g_atomic_int_set(&gate, 1); opened = FALSE;
    handle = replace(profile, owner, before, sizeof(before), next, sizeof(next), 0);
    timer = g_timeout_add(1, heartbeat, &beats);
    deadline = g_get_monotonic_time()+5000000;
    while ((!g_atomic_int_get(&blocked) || beats < 3) && g_get_monotonic_time() < deadline) {
        while (g_main_context_iteration(NULL, FALSE)) {} g_usleep(1000);
    }
    CHECK(beats >= 3 && g_atomic_int_get(&blocked)); CHECK(BarevPostIO_Status(handle) == BAREV_POST_IO_PENDING);
    CHECK(BarevPostIO_Length(handle) == -1); CHECK(!BarevPostIO_Idle());
    output[0] = 42;
    CHECK(BarevPostIO_Copy(handle, output, sizeof(output)) == -1 && output[0] == 42);
    memset(next, 0, sizeof(next));
    g_mutex_lock(&mutex); opened = TRUE; g_cond_broadcast(&condition); g_mutex_unlock(&mutex);
    g_atomic_int_set(&gate, 0);
    CHECK(finish(handle) == BAREV_POST_IO_OKAY); BarevPostIO_Release(handle);
    for (i = 0; i < sizeof(next); ++i) next[i] = (unsigned char)(255-i);
    CHECK(contents(path, next, sizeof(next))); CHECK(g_source_remove(timer));

    for (i = 0; i < BAREV_POST_IO_MAX_JOBS; ++i) {
        jobs[i] = BarevPostIO_Read(profile, owner); CHECK(jobs[i] > 0);
    }
    CHECK(!BarevPostIO_Read(profile, owner));
    for (i = 0; i < BAREV_POST_IO_MAX_JOBS; ++i) {
        int status = finish(jobs[i]);
        CHECK(status == BAREV_POST_IO_OKAY || status == BAREV_POST_IO_ERROR);
        BarevPostIO_Release(jobs[i]);
    }
    CHECK(drain());

    g_atomic_int_set(&gate, 1); g_atomic_int_set(&blocked, 0); opened = FALSE;
    handle = replace(profile, owner, next, sizeof(next), before, sizeof(before), 0); CHECK(handle > 0);
    deadline = g_get_monotonic_time()+5000000;
    while (!g_atomic_int_get(&blocked) && g_get_monotonic_time() < deadline) g_usleep(1000);
    CHECK(g_atomic_int_get(&blocked));
    BarevPostIO_Release(handle); CHECK(BarevPostIO_Status(handle) == BAREV_POST_IO_INVALID);
    BarevPostIO_Stop(); CHECK(!BarevPostIO_Idle()); CHECK(!BarevPostIO_Start());
    CHECK(!BarevPostIO_Read(profile, owner));
    g_mutex_lock(&mutex); opened = TRUE; g_cond_broadcast(&condition); g_mutex_unlock(&mutex);
    g_atomic_int_set(&gate, 0); CHECK(drain());
    CHECK(contents(path, before, sizeof(before)));
    for (i = 0; i < 16; ++i) {
        CHECK(BarevPostIO_Start()); handle = BarevPostIO_Read(profile, owner);
        CHECK(finish(handle) == BAREV_POST_IO_OKAY); BarevPostIO_Release(handle);
        CHECK(BarevPostIO_Status(handle) == BAREV_POST_IO_INVALID);
        BarevPostIO_Stop(); CHECK(drain());
    }
    CHECK(clean(profile));
    g_free(profile); g_free(path); g_free(dir); g_free(outside);
    printf("Post I/O worker: %u checks passed\n", checks);
    return 0;
}
