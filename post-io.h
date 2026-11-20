/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef BAREV_POST_IO_H
#define BAREV_POST_IO_H
#include <stdint.h>

#define BAREV_POST_IO_MAX_BYTES 6291456
#define BAREV_POST_IO_MAX_JOBS 4
enum { BAREV_POST_IO_OKAY, BAREV_POST_IO_MISSING, BAREV_POST_IO_INVALID,
       BAREV_POST_IO_ERROR, BAREV_POST_IO_CHANGED, BAREV_POST_IO_PENDING };

#if defined(__GNUC__)
#define BAREV_POST_IO_LOCAL __attribute__((visibility("hidden")))
#else
#define BAREV_POST_IO_LOCAL
#endif

/* Calls belong to the thread that starts the service. Submit copies all input;
 * workers retain no caller pointers. Positive handles are never reused.
 * An expected length of -1 means an absent file, distinct from an empty file.
 * Release/Stop abandon results, not writes. Idle must succeed before unloading. */
BAREV_POST_IO_LOCAL int32_t BarevPostIO_Start(void);
BAREV_POST_IO_LOCAL int32_t BarevPostIO_Read(const char *profile, const char *owner);
BAREV_POST_IO_LOCAL int32_t BarevPostIO_Replace(const char *profile, const char *owner,
    const unsigned char *expected, int32_t expected_length,
    const unsigned char *replacement, int32_t replacement_length);
BAREV_POST_IO_LOCAL int32_t BarevPostIO_Status(int32_t handle);
BAREV_POST_IO_LOCAL int32_t BarevPostIO_Length(int32_t handle);
BAREV_POST_IO_LOCAL int32_t BarevPostIO_Copy(int32_t handle, unsigned char *bytes, int32_t capacity);
BAREV_POST_IO_LOCAL void BarevPostIO_Release(int32_t handle);
BAREV_POST_IO_LOCAL void BarevPostIO_Stop(void);
BAREV_POST_IO_LOCAL int32_t BarevPostIO_Idle(void);
BAREV_POST_IO_LOCAL int32_t BarevPostIO_ProfileBusy(const char *profile);
#endif
