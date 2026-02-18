#ifndef ZIG_ARENA_H
#define ZIG_ARENA_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void *arena_create(size_t size);
void *arena_alloc(void *handle, size_t size);
void arena_reset(void *handle);
void arena_destroy(void *handle);

#ifdef __cplusplus
}
#endif

#endif /* ZIG_ARENA_H */
