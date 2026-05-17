/*
 * SBX hash64 helper for SBX XorFilter.
 *
 * Copyright (c) 2026 ECD5A
 * Licensed under the MIT License. See LICENSE in this directory.
 *
 * GitHub: https://github.com/ECD5A/SBX-XorFilter
 */

#ifndef SBX_HASH64_H
#define SBX_HASH64_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t sbx_hash64(const void *data, size_t len, uint64_t seed);
uint64_t sbx_hash64_32(const void *data, uint64_t seed);

#ifdef __cplusplus
}
#endif

#endif
