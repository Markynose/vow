/* SPDX-License-Identifier: LGPL-3.0-only */
#ifndef VOW_H
#define VOW_H

#define VOW_VERSION_MAJOR 0
#define VOW_VERSION_MINOR 2
#define VOW_VERSION "0.2.0"

#ifdef __cplusplus
extern "C" {
#endif

int unveil(const char *path, const char *permissions);
int pledge(const char *promises, const char *execpromises);

#ifdef __cplusplus
}
#endif

#endif
