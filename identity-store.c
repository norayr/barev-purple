/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "identity-store.h"

#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static int directory(int parent, const char *name, int exact_mode)
{
    struct stat info;
    int fd;
    if (mkdirat(parent, name, 0700)) { if (errno != EEXIST) return -1; }
    else if (fsync(parent)) return -1;
    fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, &info) || !S_ISDIR(info.st_mode) || info.st_uid != geteuid() ||
        (exact_mode ? ((info.st_mode & 0777) != 0700) : ((info.st_mode & 0022) != 0))) {
        close(fd); return -1;
    }
    return fd;
}

int32_t BarevIdentityFile_Open(const char *profile)
{
    int root, parent, fd, child;
    char path[4096], *name;
    size_t length;
    if (!profile || profile[0] != '/') return -1;
    length = strlen(profile);
    if (length >= sizeof(path)) return -1;
    while (length > 1 && profile[length-1] == '/') --length;
    memcpy(path, profile, length); path[length] = 0; name = strrchr(path, '/');
    if (!name || !name[1]) return -1;
    *name = 0;
    parent = open(path[0] ? path : "/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0) return -1;
    root = directory(parent, name+1, 0);
    close(parent);
    if (root < 0) return -1;
    fd = directory(root, "barev", 1);
    close(root);
    if (fd < 0) return -1;
    if (flock(fd, LOCK_EX | LOCK_NB)) { close(fd); return -1; }
    child = directory(fd, "identities", 1);
    if (child < 0) { close(fd); return -1; }
    close(child);
    child = directory(fd, "accounts", 1);
    if (child < 0) { close(fd); return -1; }
    close(child);
    if (fsync(fd)) { close(fd); return -1; }
    return fd;
}

void BarevIdentityFile_Close(int32_t handle)
{
    if (handle >= 0) close(handle);
}

static int record_directory(int handle, int kind, const char *name, char filename[80])
{
    unsigned i;
    int fd;
    struct stat info;
    if (kind != 0 && kind != 1) return -1;
    if (!name) return -1;
    for (i = 0; i < 64; ++i)
        if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'a' && name[i] <= 'f'))) return -1;
    if (name[64]) return -1;
    memcpy(filename, name, 64);
    strcpy(filename+64, kind == 0 ? ".key" : ".identity");
    fd = openat(handle, kind == 0 ? "identities" : "accounts",
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, &info) || info.st_uid != geteuid() || (info.st_mode & 0777) != 0700) {
        close(fd); return -1;
    }
    return fd;
}

int32_t BarevIdentityFile_Read(int32_t handle, int32_t kind, const char *name,
    unsigned char *bytes, int32_t length)
{
    char filename[80];
    struct stat info;
    int dir, fd, result = -1;
    size_t at = 0;
    if (!bytes || length != (kind == 0 ? 72 : 40)) return -1;
    memset(bytes, 0, (size_t)length);
    dir = record_directory(handle, kind, name, filename);
    if (dir < 0) return -1;
    fd = openat(dir, filename, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) { result = errno == ENOENT ? 1 : -1; close(dir); return result; }
    close(dir);
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_uid != geteuid() ||
        (info.st_mode & 0777) != 0600 || info.st_nlink != 1 || info.st_size != length) goto done;
    while (at < (size_t)length) {
        ssize_t n = read(fd, bytes+at, (size_t)length-at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto done;
        at += (size_t)n;
    }
    {
        unsigned char extra;
        ssize_t n;
        do { n = read(fd, &extra, 1); } while (n < 0 && errno == EINTR);
        if (n == 0) result = 0;
    }
done:
    if (close(fd)) result = -1;
    if (result) memset(bytes, 0, (size_t)length);
    return result;
}

int32_t BarevIdentityFile_Install(int32_t handle, int32_t kind, const char *name,
    const unsigned char *bytes, int32_t length)
{
    static unsigned serial;
    char filename[80], temporary[80];
    int dir, fd = -1, result = -1;
    unsigned attempts;
    size_t at = 0;
    if (!bytes || length != (kind == 0 ? 72 : 40)) return -1;
    dir = record_directory(handle, kind, name, filename);
    if (dir < 0) return -1;
    for (attempts = 0; attempts < 32; ++attempts) {
        snprintf(temporary, sizeof(temporary), ".new-%ld-%u", (long)getpid(), ++serial);
        fd = openat(dir, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd >= 0 || errno != EEXIST) break;
    }
    if (fd < 0) { close(dir); return -1; }
    if (fchmod(fd, 0600)) goto done;
    while (at < (size_t)length) {
        ssize_t n = write(fd, bytes+at, (size_t)length-at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto done;
        at += (size_t)n;
    }
    if (fsync(fd)) goto done;
    if (close(fd)) { fd = -1; goto done; }
    fd = -1;
    if (linkat(dir, temporary, dir, filename, 0)) result = errno == EEXIST ? 1 : -1;
    else result = 0;
done:
    if (fd >= 0) close(fd);
    if (unlinkat(dir, temporary, 0)) result = -1;
    if (fsync(dir)) result = -1;
    close(dir);
    return result;
}

#else
int32_t BarevIdentityFile_Open(const char *profile) { (void)profile; return -2; }
void BarevIdentityFile_Close(int32_t handle) { (void)handle; }
int32_t BarevIdentityFile_Read(int32_t handle, int32_t kind, const char *name,
    unsigned char *bytes, int32_t length)
{ (void)handle; (void)kind; (void)name; (void)bytes; (void)length; return -1; }
int32_t BarevIdentityFile_Install(int32_t handle, int32_t kind, const char *name,
    const unsigned char *bytes, int32_t length)
{ (void)handle; (void)kind; (void)name; (void)bytes; (void)length; return -1; }
#endif
