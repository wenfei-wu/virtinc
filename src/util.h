#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <stddef.h>

uint16_t compute_checksum(const void* pkt, size_t n_bytes);

#endif