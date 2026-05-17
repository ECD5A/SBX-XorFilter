/*
 * SBX XorFilter
 * Static XOR filter implementation for compact 64-bit lookup.
 *
 * Copyright (c) 2026 ECD5A
 * Licensed under the MIT License. See LICENSE in this directory.
 *
 * GitHub: https://github.com/ECD5A/SBX-XorFilter
 */

#ifndef _XORFILTER_H
#define _XORFILTER_H

#include <stdint.h>

#ifdef _WIN64
#include <windows.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct xorfilter
{
  uint64_t entries;
  uint64_t bits;
  uint64_t bytes;
  uint8_t hashes;
  long double error;

  uint8_t ready;
  uint8_t major;
  uint8_t minor;
  double bpe;
  uint8_t *bf;

  uint64_t array_length;
  uint64_t block_length;
  uint64_t base_seed;
  uint64_t seed;
  uint8_t finalized;
  uint64_t pending_count;
  uint64_t pending_capacity;
  uint64_t *pending;
};

struct xorfilter_scratch
{
  uint64_t array_capacity;
  uint64_t key_capacity;
  uint64_t *set_masks;
  uint32_t *set_counts;
  uint64_t *stack_hashes;
  uint32_t *stack_indexes;
  uint64_t *queue_hashes;
  uint32_t *queue_indexes;
};

int xorfilter_init2(struct xorfilter *filter, uint64_t entries, long double error);
int xorfilter_init(struct xorfilter *filter, uint64_t entries, long double error);
int xorfilter_check(struct xorfilter *filter, const void *buffer, int len);
int xorfilter_check_hash_fast(const struct xorfilter *filter, uint64_t raw);
int xorfilter_add(struct xorfilter *filter, const void *buffer, int len);
int xorfilter_finalize(struct xorfilter *filter);
int xorfilter_finalize_with_scratch(struct xorfilter *filter, struct xorfilter_scratch *scratch);
void xorfilter_scratch_free(struct xorfilter_scratch *scratch);
void xorfilter_free(struct xorfilter *filter);

static inline uint64_t xorfilter_inline_murmur64(uint64_t h)
{
  h ^= h >> 33U;
  h *= UINT64_C(0xff51afd7ed558ccd);
  h ^= h >> 33U;
  h *= UINT64_C(0xc4ceb9fe1a85ec53);
  h ^= h >> 33U;
  return h;
}

static inline uint64_t xorfilter_inline_mix_split(uint64_t key, uint64_t seed)
{
  return xorfilter_inline_murmur64(key + seed);
}

static inline uint64_t xorfilter_inline_rotl64(uint64_t n, unsigned int c)
{
  return (n << (c & 63U)) | (n >> ((-c) & 63U));
}

static inline uint32_t xorfilter_inline_reduce(uint32_t hash, uint32_t n)
{
  return (uint32_t)(((uint64_t)hash * n) >> 32U);
}

static inline uint16_t xorfilter_inline_fingerprint(uint64_t hash)
{
  return (uint16_t)(hash ^ (hash >> 32U));
}

static inline int xorfilter_check_hash_inline(const struct xorfilter *filter, uint64_t raw)
{
  /* Hot-loop lookup path: caller already prepared the 64-bit key, so this
   * avoids buffer hashing and an out-of-line function call. */
  uint64_t hash = xorfilter_inline_mix_split(raw, filter->seed);
  uint16_t fp = xorfilter_inline_fingerprint(hash);
  const uint16_t *table = (const uint16_t *)filter->bf;
  uint32_t block_length = (uint32_t)filter->block_length;
  uint32_t h0 = xorfilter_inline_reduce((uint32_t)hash, block_length);
  uint32_t h1 = xorfilter_inline_reduce((uint32_t)xorfilter_inline_rotl64(hash, 21U), block_length) + block_length;
  uint32_t h2 = xorfilter_inline_reduce((uint32_t)xorfilter_inline_rotl64(hash, 42U), block_length) + (block_length * 2U);

  fp ^= table[h0] ^ table[h1] ^ table[h2];
  return fp == 0 ? 1 : 0;
}

#ifdef __cplusplus
}
#endif

#endif
