/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef BAREV_IDENTITY_STORE_H
#define BAREV_IDENTITY_STORE_H

#include <stdint.h>

#if defined(__GNUC__)
#define BAREV_IDENTITY_LOCAL __attribute__((visibility("hidden")))
#else
#define BAREV_IDENTITY_LOCAL
#endif

/* Open returns a locked handle, -1 on error, or -2 on unsupported platforms.
 * Handles hold an exclusive, nonblocking lock until Close. Names are exactly
 * 64 lowercase hexadecimal digits. Kind 0 selects keys, kind 1 account links.
 * Read/Install return 0 on success, 1 for absent/existing, -1 for any error. */
BAREV_IDENTITY_LOCAL int32_t BarevIdentityFile_Open(const char *profile);
BAREV_IDENTITY_LOCAL void BarevIdentityFile_Close(int32_t handle);
BAREV_IDENTITY_LOCAL int32_t BarevIdentityFile_Read(int32_t handle, int32_t kind,
    const char *name, unsigned char *bytes, int32_t length);
BAREV_IDENTITY_LOCAL int32_t BarevIdentityFile_Install(int32_t handle, int32_t kind,
    const char *name, const unsigned char *bytes, int32_t length);

#endif
