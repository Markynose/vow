#ifndef VOW_H
#define VOW_H

#define VOW_VERSION_MAJOR 0
#define VOW_VERSION_MINOR 1
#define VOW_VERSION "0.1.0"

#ifdef __cplusplus
extern "C" {
#endif

int unveil(const char *path, const char *permissions);
int pledge(const char *promises, const char *execpromises);

#ifdef __cplusplus
}
#endif

#endif
