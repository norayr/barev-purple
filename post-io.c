/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "post-io.h"
#include "identity-store.h"
#include <glib.h>
#include <string.h>

typedef struct {
    char profile[3801], name[80];
    unsigned char *expected, *replacement, *result;
    int32_t expected_length, replacement_length, result_length, handle, status;
    gboolean replacing;
    gint done;
} Job;
typedef struct { Job *job; gboolean released; } Slot;

static Slot slots[BAREV_POST_IO_MAX_JOBS];
static GThread *owner_thread;
static GThreadPool *pool;
static gboolean accepting;
static int32_t serial;

#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static int read_image(int dir, const char *name, unsigned char **bytes, int32_t *length)
{
    struct stat info;
    unsigned char *data = NULL, extra;
    size_t at = 0, size;
    ssize_t n;
    int fd, status = BAREV_POST_IO_ERROR;
    fd = openat(dir, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? BAREV_POST_IO_MISSING : BAREV_POST_IO_ERROR;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode)) goto done;
    if (info.st_size < 0 || info.st_size > BAREV_POST_IO_MAX_BYTES) {
        status = BAREV_POST_IO_INVALID; goto done;
    }
    size = (size_t)info.st_size;
    data = g_try_malloc(size ? size : 1);
    if (!data) goto done;
    while (at < size) {
        n = read(fd, data+at, size-at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto done;
        at += (size_t)n;
    }
    do { n = read(fd, &extra, 1); } while (n < 0 && errno == EINTR);
    if (n != 0) goto done;
    status = BAREV_POST_IO_OKAY;
done:
    if (close(fd)) status = BAREV_POST_IO_ERROR;
    if (status == BAREV_POST_IO_OKAY) { *bytes = data; *length = (int32_t)at; }
    else g_free(data);
    return status;
}

static int install(int dir, Job *job)
{
    char temporary[96];
    int fd = -1, status = BAREV_POST_IO_ERROR;
    unsigned attempt;
    size_t at = 0;
    gboolean created = FALSE;
    for (attempt = 0; attempt < 32; ++attempt) {
        snprintf(temporary, sizeof(temporary), ".posts-%ld-%d-%u.tmp",
                 (long)getpid(), job->handle, attempt);
        fd = openat(dir, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd >= 0 || errno != EEXIST) break;
    }
    if (fd < 0) return status;
    created = TRUE;
    while (at < (size_t)job->replacement_length) {
        ssize_t n = write(fd, job->replacement+at, (size_t)job->replacement_length-at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto done;
        at += (size_t)n;
    }
    if (fsync(fd)) goto done;
    if (close(fd)) { fd = -1; goto done; }
    fd = -1;
    if (renameat(dir, temporary, dir, job->name)) goto done;
    created = FALSE;
    status = BAREV_POST_IO_OKAY;
done:
    if (fd >= 0 && close(fd)) status = BAREV_POST_IO_ERROR;
    if (created && unlinkat(dir, temporary, 0)) status = BAREV_POST_IO_ERROR;
    return status;
}

static gboolean equal(const unsigned char *left, int32_t length,
                      const unsigned char *right, int32_t other_length)
{
    return length == other_length && (!length || !memcmp(left, right, (size_t)length));
}

static void io(Job *job)
{
    int dir, status;
    unsigned char *current = NULL;
    int32_t length = 0;
    dir = BarevIdentityFile_Open(job->profile);
    if (dir < 0) { job->status = BAREV_POST_IO_ERROR; return; }
    status = read_image(dir, job->name, &current, &length);
    if (!job->replacing) {
        job->result = current; job->result_length = length;
    } else {
        if (status == BAREV_POST_IO_OKAY || status == BAREV_POST_IO_MISSING) {
            if (status == BAREV_POST_IO_OKAY &&
                equal(current, length, job->replacement, job->replacement_length)) status = BAREV_POST_IO_OKAY;
            else if ((status == BAREV_POST_IO_MISSING && job->expected_length == -1) ||
                     (status == BAREV_POST_IO_OKAY && job->expected_length >= 0 &&
                      equal(current, length, job->expected, job->expected_length))) status = install(dir, job);
            else status = BAREV_POST_IO_CHANGED;
            if (status == BAREV_POST_IO_OKAY && fsync(dir)) status = BAREV_POST_IO_ERROR;
        }
        g_free(current);
    }
    if (close(dir)) status = BAREV_POST_IO_ERROR;
    if (status != BAREV_POST_IO_OKAY) {
        g_clear_pointer(&job->result, g_free); job->result_length = 0;
    }
    job->status = status;
}
#else
static void io(Job *job) { job->status = BAREV_POST_IO_ERROR; }
#endif

static void work(gpointer data, gpointer unused)
{
    Job *job = data;
    (void)unused;
    io(job);
    /* Publishing this flag is the worker's final access to the job. */
    g_atomic_int_set(&job->done, 1);
}

static gboolean owned(void) { return owner_thread && owner_thread == g_thread_self(); }

static void destroy(Job *job)
{
    g_free(job->expected); g_free(job->replacement); g_free(job->result); g_free(job);
}

static void reap(void)
{
    unsigned i;
    for (i = 0; i < G_N_ELEMENTS(slots); ++i)
        if (slots[i].job && slots[i].released && g_atomic_int_get(&slots[i].job->done)) {
            destroy(slots[i].job); slots[i].job = NULL; slots[i].released = FALSE;
        }
}

int32_t BarevPostIO_Start(void)
{
    if (owner_thread && !owned()) return 0;
    owner_thread = g_thread_self();
    if (!accepting && !BarevPostIO_Idle()) return 0;
    accepting = TRUE;
    return 1;
}

static Job *lookup(int32_t handle)
{
    unsigned i;
    if (!owned() || handle <= 0) return NULL;
    for (i = 0; i < G_N_ELEMENTS(slots); ++i)
        if (slots[i].job && !slots[i].released && slots[i].job->handle == handle) return slots[i].job;
    return NULL;
}

static unsigned char *copy_bytes(const unsigned char *bytes, int32_t length)
{
    unsigned char *copy;
    if (length <= 0) return NULL;
    copy = g_try_malloc((size_t)length);
    if (copy) memcpy(copy, bytes, (size_t)length);
    return copy;
}

static int32_t submit(const char *profile, const char *owner, gboolean replacing,
                      const unsigned char *expected, int32_t expected_length,
                      const unsigned char *replacement, int32_t replacement_length)
{
    size_t length, i;
    unsigned index;
    Job *job;
    GError *error = NULL;
    if (!owned() || !accepting || !profile || !owner || serial == INT32_MAX) return 0;
    length = strnlen(profile, 3801);
    if (length < 2 || length > 3800 || profile[0] != '/' || strnlen(owner, 65) != 64) return 0;
    while (length > 1 && profile[length-1] == '/') --length;
    if (length == 1) return 0;
    for (i = 0; i < 64; ++i)
        if (!((owner[i] >= '0' && owner[i] <= '9') || (owner[i] >= 'a' && owner[i] <= 'f'))) return 0;
    if (expected_length < -1 || expected_length > BAREV_POST_IO_MAX_BYTES ||
        replacement_length < 0 || replacement_length > BAREV_POST_IO_MAX_BYTES ||
        (expected_length > 0 && !expected) || (replacement_length > 0 && !replacement)) return 0;
    reap();
    for (index = 0; index < G_N_ELEMENTS(slots) && slots[index].job; ++index) {}
    if (index == G_N_ELEMENTS(slots)) return 0;
    job = g_try_new0(Job, 1);
    if (!job) return 0;
    memcpy(job->profile, profile, length); memcpy(job->name, "posts-", 6);
    memcpy(job->name+6, owner, 64); memcpy(job->name+70, ".state", 7);
    job->replacing = replacing; job->expected_length = expected_length;
    job->replacement_length = replacement_length;
    job->expected = copy_bytes(expected, expected_length);
    job->replacement = copy_bytes(replacement, replacement_length);
    if ((expected_length > 0 && !job->expected) || (replacement_length > 0 && !job->replacement)) {
        destroy(job); return 0;
    }
    if (!pool) {
        pool = g_thread_pool_new(work, NULL, 2, TRUE, &error);
        if (error || !pool) {
            g_clear_error(&error);
            if (pool) g_thread_pool_free(pool, FALSE, TRUE);
            pool = NULL; destroy(job); return 0;
        }
    }
    job->handle = ++serial; slots[index].job = job;
    /* GLib enqueues the job even if reporting a thread-creation error. */
    g_thread_pool_push(pool, job, &error); g_clear_error(&error);
    return job->handle;
}

int32_t BarevPostIO_Read(const char *profile, const char *owner)
{ return submit(profile, owner, FALSE, NULL, -1, NULL, 0); }

int32_t BarevPostIO_Replace(const char *profile, const char *owner,
    const unsigned char *expected, int32_t expected_length,
    const unsigned char *replacement, int32_t replacement_length)
{ return submit(profile, owner, TRUE, expected, expected_length, replacement, replacement_length); }

int32_t BarevPostIO_Status(int32_t handle)
{
    Job *job = lookup(handle);
    if (!job) return BAREV_POST_IO_INVALID;
    return g_atomic_int_get(&job->done) ? job->status : BAREV_POST_IO_PENDING;
}

int32_t BarevPostIO_Length(int32_t handle)
{
    Job *job = lookup(handle);
    return job && BarevPostIO_Status(handle) == BAREV_POST_IO_OKAY ? job->result_length : -1;
}

int32_t BarevPostIO_Copy(int32_t handle, unsigned char *bytes, int32_t capacity)
{
    Job *job = lookup(handle);
    if (!job || BarevPostIO_Status(handle) != BAREV_POST_IO_OKAY ||
        capacity < job->result_length || (!bytes && job->result_length)) return -1;
    if (job->result_length) memcpy(bytes, job->result, (size_t)job->result_length);
    return job->result_length;
}

void BarevPostIO_Release(int32_t handle)
{
    unsigned i;
    if (!lookup(handle)) return;
    for (i = 0; i < G_N_ELEMENTS(slots); ++i)
        if (slots[i].job && slots[i].job->handle == handle) slots[i].released = TRUE;
    reap();
}

void BarevPostIO_Stop(void)
{
    unsigned i;
    if (!owned()) return;
    accepting = FALSE;
    for (i = 0; i < G_N_ELEMENTS(slots); ++i) if (slots[i].job) slots[i].released = TRUE;
    reap();
}

int32_t BarevPostIO_Idle(void)
{
    unsigned i;
    if (!owner_thread) return 1;
    if (!owned()) return 0;
    reap();
    for (i = 0; i < G_N_ELEMENTS(slots); ++i) if (slots[i].job) return 0;
    /* No I/O remains; join the worker epilogues before their code can unload. */
    if (pool) { g_thread_pool_free(pool, FALSE, TRUE); pool = NULL; }
    return 1;
}

int32_t BarevPostIO_ProfileBusy(const char *profile)
{
    size_t length;
    unsigned i;
    if (!owned() || !profile) return 0;
    length = strnlen(profile, 3801);
    if (length > 3800) return 0;
    while (length > 1 && profile[length-1] == '/') --length;
    for (i = 0; i < G_N_ELEMENTS(slots); ++i) {
        Job *job = slots[i].job;
        if (job && !g_atomic_int_get(&job->done) && strlen(job->profile) == length &&
            !memcmp(job->profile, profile, length)) return 1;
    }
    return 0;
}
