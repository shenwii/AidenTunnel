#ifndef _CRC32_H
#define _CRC32_H

#include <stdint.h>

#define CRC32(buf, len) \
    crc32_update(0, buf, len)

uint32_t crc32_update(uint32_t crc, __const__ unsigned char *buf, int len);

#endif
