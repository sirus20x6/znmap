#ifndef ZIG_PORTSTATE_H
#define ZIG_PORTSTATE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void *portstate_create(void);
void portstate_set(void *handle, uint16_t port, uint8_t state);
uint8_t portstate_get(void *handle, uint16_t port);
uint32_t portstate_count(void *handle, uint8_t state);
void portstate_destroy(void *handle);

#ifdef __cplusplus
}
#endif

#endif /* ZIG_PORTSTATE_H */
