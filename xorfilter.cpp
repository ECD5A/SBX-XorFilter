/*
 * SBX XorFilter
 * Static XOR filter implementation for compact 64-bit lookup.
 *
 * Copyright (c) 2026 ECD5A
 * Licensed under the MIT License. See LICENSE in this directory.
 *
 * GitHub: https://github.com/ECD5A/SBX-XorFilter
 */

#include <algorithm>
#include <cmath>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xorfilter.h"
#include "sbx_hash64.h"

#define XORFILTER_VERSION_MAJOR 1
#define XORFILTER_VERSION_MINOR 0

static const uint64_t XORFILTER_KEY_SEED = UINT64_C(0x59f2815b16f81798);
static const uint64_t XORFILTER_SEED_BASE = UINT64_C(0x9e3779b97f4a7c15);

static inline uint64_t xor_murmur64(uint64_t h)
{
  h ^= h >> 33U;
  h *= UINT64_C(0xff51afd7ed558ccd);
  h ^= h >> 33U;
  h *= UINT64_C(0xc4ceb9fe1a85ec53);
  h ^= h >> 33U;
  return h;
}

static inline uint64_t xor_mix_split(uint64_t key, uint64_t seed)
{
  return xor_murmur64(key + seed);
}

static inline uint64_t xor_splitmix64(uint64_t *seed)
{
  *seed += UINT64_C(0x9e3779b97f4a7c15);
  uint64_t z = *seed;
  z = (z ^ (z >> 30U)) * UINT64_C(0xbf58476d1ce4e5b9);
  z = (z ^ (z >> 27U)) * UINT64_C(0x94d049bb133111eb);
  return z ^ (z >> 31U);
}

static inline uint64_t xor_rotl64(uint64_t n, unsigned int c)
{
  return (n << (c & 63U)) | (n >> ((-c) & 63U));
}

static inline uint32_t xor_reduce(uint32_t hash, uint32_t n)
{
  return (uint32_t)(((uint64_t)hash * n) >> 32U);
}

static inline uint16_t xor_fingerprint(uint64_t hash)
{
  return (uint16_t)(hash ^ (hash >> 32U));
}

static inline uint32_t xor_geth0(uint64_t hash, uint32_t block_length)
{
  return xor_reduce((uint32_t)hash, block_length);
}

static inline uint32_t xor_geth1(uint64_t hash, uint32_t block_length)
{
  return xor_reduce((uint32_t)xor_rotl64(hash, 21U), block_length);
}

static inline uint32_t xor_geth2(uint64_t hash, uint32_t block_length)
{
  return xor_reduce((uint32_t)xor_rotl64(hash, 42U), block_length);
}

static void xorfilter_clear_pending(struct xorfilter *filter)
{
  if (filter->pending != NULL) {
    free(filter->pending);
    filter->pending = NULL;
  }
  filter->pending_capacity = 0;
  filter->pending_count = 0;
}

static void xorfilter_clear_fingerprints(struct xorfilter *filter)
{
  if (filter->bf != NULL && filter->bytes > 0) {
    memset(filter->bf, 0, (size_t)filter->bytes);
  }
}

void xorfilter_scratch_free(struct xorfilter_scratch *scratch)
{
  if (scratch == NULL) {
    return;
  }
  free(scratch->set_masks);
  free(scratch->set_counts);
  free(scratch->stack_hashes);
  free(scratch->stack_indexes);
  free(scratch->queue_hashes);
  free(scratch->queue_indexes);
  memset(scratch, 0, sizeof(struct xorfilter_scratch));
}

static int xorfilter_reserve_u64(uint64_t **buffer, size_t count)
{
  uint64_t *next = (uint64_t *)realloc(*buffer, count * sizeof(uint64_t));
  if (next == NULL) {
    return 1;
  }
  *buffer = next;
  return 0;
}

static int xorfilter_reserve_u32(uint32_t **buffer, size_t count)
{
  uint32_t *next = (uint32_t *)realloc(*buffer, count * sizeof(uint32_t));
  if (next == NULL) {
    return 1;
  }
  *buffer = next;
  return 0;
}

static int xorfilter_scratch_reserve(struct xorfilter_scratch *scratch, size_t array_length, size_t key_count)
{
  if (scratch == NULL) {
    return 1;
  }

  if ((uint64_t)array_length > scratch->array_capacity) {
    if (xorfilter_reserve_u64(&scratch->set_masks, array_length) != 0 ||
        xorfilter_reserve_u32(&scratch->set_counts, array_length) != 0 ||
        xorfilter_reserve_u64(&scratch->queue_hashes, array_length) != 0 ||
        xorfilter_reserve_u32(&scratch->queue_indexes, array_length) != 0) {
      return 1;
    }

    scratch->array_capacity = (uint64_t)array_length;
  }

  if ((uint64_t)key_count > scratch->key_capacity) {
    if (xorfilter_reserve_u64(&scratch->stack_hashes, key_count) != 0 ||
        xorfilter_reserve_u32(&scratch->stack_indexes, key_count) != 0) {
      return 1;
    }

    scratch->key_capacity = (uint64_t)key_count;
  }

  return 0;
}

static int xorfilter_build_limited_with_scratch(struct xorfilter *filter, const uint64_t *keys, size_t key_count, int max_attempts, struct xorfilter_scratch *scratch)
{
  if (filter == NULL || filter->bf == NULL) {
    return 1;
  }
  if (key_count == 0) {
    xorfilter_clear_fingerprints(filter);
    filter->entries = 0;
    filter->ready = 1;
    filter->finalized = 1;
    xorfilter_clear_pending(filter);
    return 0;
  }

  size_t block_length = (size_t)filter->block_length;
  size_t array_length = block_length * 3ULL;
  if (block_length == 0 || array_length == 0) {
    return 1;
  }
  uint16_t *table = (uint16_t *)filter->bf;

  struct xorfilter_scratch local_scratch;
  int own_scratch = 0;
  if (scratch == NULL) {
    memset(&local_scratch, 0, sizeof(local_scratch));
    scratch = &local_scratch;
    own_scratch = 1;
  }

  if (xorfilter_scratch_reserve(scratch, array_length, key_count) != 0) {
    if (own_scratch) {
      xorfilter_scratch_free(scratch);
    }
    return 1;
  }

  uint64_t *set_masks = scratch->set_masks;
  uint32_t *set_counts = scratch->set_counts;
  uint64_t *masks0 = set_masks;
  uint64_t *masks1 = masks0 + block_length;
  uint64_t *masks2 = masks1 + block_length;
  uint32_t *counts0 = set_counts;
  uint32_t *counts1 = counts0 + block_length;
  uint32_t *counts2 = counts1 + block_length;
  uint64_t *stack_hashes = scratch->stack_hashes;
  uint32_t *stack_indexes = scratch->stack_indexes;
  uint64_t *queue_hashes = scratch->queue_hashes;
  uint32_t *queue_indexes = scratch->queue_indexes;
  uint64_t *Q0hashes = queue_hashes;
  uint64_t *Q1hashes = Q0hashes + block_length;
  uint64_t *Q2hashes = Q1hashes + block_length;
  uint32_t *Q0indexes = queue_indexes;
  uint32_t *Q1indexes = Q0indexes + block_length;
  uint32_t *Q2indexes = Q1indexes + block_length;

  int built = 0;
  uint64_t seed_stream = filter->base_seed;
  uint64_t attempt_seed = xor_splitmix64(&seed_stream);
  if (max_attempts <= 0) {
    max_attempts = 1;
  }

  for (int attempt = 0; attempt < max_attempts; ++attempt) {
    memset(set_masks, 0, array_length * sizeof(uint64_t));
    memset(set_counts, 0, array_length * sizeof(uint32_t));

    for (size_t i = 0; i < key_count; ++i) {
      uint64_t hash = xor_mix_split(keys[i], attempt_seed);
      uint32_t h0 = xor_geth0(hash, (uint32_t)block_length);
      uint32_t h1 = xor_geth1(hash, (uint32_t)block_length);
      uint32_t h2 = xor_geth2(hash, (uint32_t)block_length);
      counts0[h0]++;
      masks0[h0] ^= hash;
      counts1[h1]++;
      masks1[h1] ^= hash;
      counts2[h2]++;
      masks2[h2] ^= hash;
    }

    size_t Q0size = 0;
    size_t Q1size = 0;
    size_t Q2size = 0;
    size_t stacksize = 0;

    for (size_t i = 0; i < block_length; ++i) {
      if (counts0[i] == 1) {
        Q0indexes[Q0size] = (uint32_t)i;
        Q0hashes[Q0size] = masks0[i];
        Q0size++;
      }
      if (counts1[i] == 1) {
        Q1indexes[Q1size] = (uint32_t)i;
        Q1hashes[Q1size] = masks1[i];
        Q1size++;
      }
      if (counts2[i] == 1) {
        Q2indexes[Q2size] = (uint32_t)i;
        Q2hashes[Q2size] = masks2[i];
        Q2size++;
      }
    }

    while (Q0size + Q1size + Q2size > 0) {
      while (Q0size > 0) {
        --Q0size;
        uint32_t index = Q0indexes[Q0size];
        if (counts0[index] == 0) {
          continue;
        }

        uint64_t hash = Q0hashes[Q0size];
        uint32_t h1 = xor_geth1(hash, (uint32_t)block_length);
        uint32_t h2 = xor_geth2(hash, (uint32_t)block_length);
        stack_indexes[stacksize] = index;
        stack_hashes[stacksize] = hash;
        stacksize++;

        masks1[h1] ^= hash;
        counts1[h1]--;
        if (counts1[h1] == 1) {
          Q1indexes[Q1size] = h1;
          Q1hashes[Q1size] = masks1[h1];
          Q1size++;
        }

        masks2[h2] ^= hash;
        counts2[h2]--;
        if (counts2[h2] == 1) {
          Q2indexes[Q2size] = h2;
          Q2hashes[Q2size] = masks2[h2];
          Q2size++;
        }
      }

      while (Q1size > 0) {
        --Q1size;
        uint32_t index = Q1indexes[Q1size];
        if (counts1[index] == 0) {
          continue;
        }

        uint64_t hash = Q1hashes[Q1size];
        uint32_t h0 = xor_geth0(hash, (uint32_t)block_length);
        uint32_t h2 = xor_geth2(hash, (uint32_t)block_length);
        stack_indexes[stacksize] = index + (uint32_t)block_length;
        stack_hashes[stacksize] = hash;
        stacksize++;

        masks0[h0] ^= hash;
        counts0[h0]--;
        if (counts0[h0] == 1) {
          Q0indexes[Q0size] = h0;
          Q0hashes[Q0size] = masks0[h0];
          Q0size++;
        }

        masks2[h2] ^= hash;
        counts2[h2]--;
        if (counts2[h2] == 1) {
          Q2indexes[Q2size] = h2;
          Q2hashes[Q2size] = masks2[h2];
          Q2size++;
        }
      }

      while (Q2size > 0) {
        --Q2size;
        uint32_t index = Q2indexes[Q2size];
        if (counts2[index] == 0) {
          continue;
        }

        uint64_t hash = Q2hashes[Q2size];
        uint32_t h0 = xor_geth0(hash, (uint32_t)block_length);
        uint32_t h1 = xor_geth1(hash, (uint32_t)block_length);
        stack_indexes[stacksize] = index + (uint32_t)(block_length * 2ULL);
        stack_hashes[stacksize] = hash;
        stacksize++;

        masks0[h0] ^= hash;
        counts0[h0]--;
        if (counts0[h0] == 1) {
          Q0indexes[Q0size] = h0;
          Q0hashes[Q0size] = masks0[h0];
          Q0size++;
        }

        masks1[h1] ^= hash;
        counts1[h1]--;
        if (counts1[h1] == 1) {
          Q1indexes[Q1size] = h1;
          Q1hashes[Q1size] = masks1[h1];
          Q1size++;
        }
      }
    }

    if (stacksize != key_count) {
      attempt_seed = xor_splitmix64(&seed_stream);
      continue;
    }

    memset(filter->bf, 0, filter->bytes);
    while (stacksize > 0) {
      --stacksize;
      uint64_t hash = stack_hashes[stacksize];
      uint32_t index = stack_indexes[stacksize];
      uint16_t fp = xor_fingerprint(hash);

      if (index < block_length) {
        fp ^= table[xor_geth1(hash, (uint32_t)block_length) + block_length];
        fp ^= table[xor_geth2(hash, (uint32_t)block_length) + (block_length * 2ULL)];
      }
      else if (index < (block_length * 2ULL)) {
        fp ^= table[xor_geth0(hash, (uint32_t)block_length)];
        fp ^= table[xor_geth2(hash, (uint32_t)block_length) + (block_length * 2ULL)];
      }
      else {
        fp ^= table[xor_geth0(hash, (uint32_t)block_length)];
        fp ^= table[xor_geth1(hash, (uint32_t)block_length) + block_length];
      }

      table[index] = fp;
    }

    filter->seed = attempt_seed;
    filter->entries = (uint64_t)key_count;
    filter->bits = filter->bytes * 8ULL;
    filter->bpe = (double)filter->bits / (double)(filter->entries ? filter->entries : 1ULL);
    filter->ready = 1;
    filter->finalized = 1;
    built = 1;
    break;
  }

  if (own_scratch) {
    xorfilter_scratch_free(scratch);
  }

  if (!built) {
    return 1;
  }

  xorfilter_clear_pending(filter);
  return 0;
}

static int xorfilter_build(struct xorfilter *filter, const uint64_t *keys, size_t key_count)
{
  return xorfilter_build_limited_with_scratch(filter, keys, key_count, 1024, NULL);
}

int xorfilter_init(struct xorfilter *filter, uint64_t entries, long double error)
{
  return xorfilter_init2(filter, entries, error);
}

int xorfilter_init2(struct xorfilter *filter, uint64_t entries, long double error)
{
  if (filter == NULL) {
    return 1;
  }

  memset(filter, 0, sizeof(struct xorfilter));
  if (entries == 0 || error <= 0 || error >= 1) {
    return 1;
  }

  filter->entries = entries;
  filter->error = error;
  filter->hashes = 3;
  filter->major = XORFILTER_VERSION_MAJOR;
  filter->minor = XORFILTER_VERSION_MINOR;
  filter->base_seed = XORFILTER_SEED_BASE ^ (entries * UINT64_C(0x9e3779b97f4a7c15));
  filter->seed = filter->base_seed;

  long double load = 32.0L + ceill(1.23L * (long double)entries);
  filter->array_length = (uint64_t)load;
  if (filter->array_length < 3) {
    filter->array_length = 3;
  }
  filter->array_length = (filter->array_length / 3ULL) * 3ULL;
  if (filter->array_length < 3) {
    filter->array_length = 3;
  }
  filter->block_length = filter->array_length / 3ULL;
  if (filter->block_length == 0) {
    filter->block_length = 1;
    filter->array_length = 3;
  }

  filter->bytes = filter->array_length * (uint64_t)sizeof(uint16_t);
  filter->bits = filter->bytes * 8ULL;
  filter->bpe = (double)filter->bits / (double)entries;
  filter->bf = (uint8_t *)malloc((size_t)filter->bytes);
  if (filter->bf == NULL) {
    return 1;
  }

  filter->pending_capacity = 0;
  filter->pending = NULL;
  filter->ready = 1;
  filter->finalized = 0;
  return 0;
}

int xorfilter_add(struct xorfilter *filter, const void *buffer, int len)
{
  if (filter == NULL || filter->ready == 0) {
    return -1;
  }
  if (filter->finalized) {
    return 1;
  }

  if (filter->pending_count >= filter->pending_capacity) {
    uint64_t new_capacity = filter->pending_capacity == 0 ? filter->entries : filter->pending_capacity * 2ULL;
    if (new_capacity < filter->pending_capacity + 1024ULL) {
      new_capacity = filter->pending_capacity + 1024ULL;
    }
    uint64_t *next = filter->pending == NULL ?
      (uint64_t *)malloc((size_t)new_capacity * sizeof(uint64_t)) :
      (uint64_t *)realloc(filter->pending, (size_t)new_capacity * sizeof(uint64_t));
    if (next == NULL) {
      return -1;
    }
    filter->pending = next;
    filter->pending_capacity = new_capacity;
  }

  uint64_t raw = sbx_hash64(buffer, (size_t)len, XORFILTER_KEY_SEED);
  filter->pending[filter->pending_count++] = raw;
  return 0;
}

static size_t xorfilter_sort_unique_u64(uint64_t *values, size_t count)
{
  if (count <= 1) {
    return count;
  }

  if (count < 4096U) {
    std::sort(values, values + count);
  }
  else {
    uint64_t *tmp = (uint64_t *)malloc(count * sizeof(uint64_t));
    size_t *counts = (size_t *)malloc(65536U * sizeof(size_t));
    size_t *offsets = (size_t *)malloc(65536U * sizeof(size_t));

    if (tmp == NULL || counts == NULL || offsets == NULL) {
      free(tmp);
      free(counts);
      free(offsets);
      std::sort(values, values + count);
    }
    else {
      uint64_t *src = values;
      uint64_t *dst = tmp;

      for (unsigned int pass = 0; pass < 4U; pass++) {
        unsigned int shift = pass * 16U;
        memset(counts, 0, 65536U * sizeof(size_t));

        for (size_t i = 0; i < count; i++) {
          counts[(src[i] >> shift) & UINT64_C(0xffff)]++;
        }

        offsets[0] = 0;
        for (size_t i = 1; i < 65536U; i++) {
          offsets[i] = offsets[i - 1] + counts[i - 1];
        }

        for (size_t i = 0; i < count; i++) {
          uint16_t key = (uint16_t)((src[i] >> shift) & UINT64_C(0xffff));
          dst[offsets[key]++] = src[i];
        }

        uint64_t *swap_tmp = src;
        src = dst;
        dst = swap_tmp;
      }

      free(tmp);
      free(counts);
      free(offsets);
    }
  }

  size_t out = 1;
  for (size_t i = 1; i < count; i++) {
    if (values[i] != values[out - 1]) {
      values[out++] = values[i];
    }
  }
  return out;
}

static int xorfilter_prepare_storage(struct xorfilter *filter, size_t key_count)
{
  size_t target_cells = (size_t)(32ULL + (uint64_t)ceill(1.23L * (long double)key_count));
  if (target_cells < 3U) {
    target_cells = 3U;
  }
  target_cells = (target_cells / 3ULL) * 3ULL;
  if (target_cells < 3U) {
    target_cells = 3U;
  }
  size_t target_bytes = target_cells * sizeof(uint16_t);

  if (target_bytes > (size_t)filter->bytes) {
    uint8_t *next = (uint8_t *)realloc(filter->bf, target_bytes);
    if (next == NULL) {
      return 1;
    }
    filter->bf = next;
  }
  filter->bytes = (uint64_t)target_bytes;
  filter->array_length = (uint64_t)target_cells;
  filter->block_length = filter->array_length / 3ULL;
  filter->bits = filter->bytes * 8ULL;
  filter->bpe = (double)filter->bits / (double)(key_count ? key_count : 1ULL);
  return 0;
}

int xorfilter_finalize_with_scratch(struct xorfilter *filter, struct xorfilter_scratch *scratch)
{
  if (filter == NULL || filter->ready == 0) {
    return 1;
  }
  if (filter->finalized) {
    return 0;
  }
  size_t key_count = (size_t)filter->pending_count;
  if (key_count == 0) {
    return xorfilter_build_limited_with_scratch(filter, NULL, 0, 1024, scratch);
  }
  if (filter->pending == NULL) {
    return 1;
  }

  if (xorfilter_prepare_storage(filter, key_count) != 0) {
    return 1;
  }
  if (xorfilter_build_limited_with_scratch(filter, filter->pending, key_count, 8, scratch) == 0) {
    return 0;
  }

  key_count = xorfilter_sort_unique_u64(filter->pending, key_count);
  if (xorfilter_prepare_storage(filter, key_count) != 0) {
    return 1;
  }
  return xorfilter_build_limited_with_scratch(filter, filter->pending, key_count, 1024, scratch);
}

int xorfilter_finalize(struct xorfilter *filter)
{
  return xorfilter_finalize_with_scratch(filter, NULL);
}

int xorfilter_check(struct xorfilter *filter, const void *buffer, int len)
{
  if (filter == NULL || filter->ready == 0) {
    printf("xorfilter at %p not initialized!\n", (void *)filter);
    return -1;
  }

  if (!filter->finalized) {
    if (xorfilter_finalize(filter) != 0) {
      return -1;
    }
  }

  uint64_t raw = sbx_hash64(buffer, (size_t)len, XORFILTER_KEY_SEED);
  uint64_t hash = xor_mix_split(raw, filter->seed);
  uint16_t fp = xor_fingerprint(hash);
  const uint16_t *table = (const uint16_t *)filter->bf;

  uint32_t block_length = (uint32_t)filter->block_length;
  uint32_t h0 = xor_geth0(hash, block_length);
  uint32_t h1 = xor_geth1(hash, block_length) + block_length;
  uint32_t h2 = xor_geth2(hash, block_length) + (block_length * 2U);

  fp ^= table[h0] ^ table[h1] ^ table[h2];
  return fp == 0 ? 1 : 0;
}

int xorfilter_check_hash_fast(const struct xorfilter *filter, uint64_t raw)
{
  uint64_t hash = xor_mix_split(raw, filter->seed);
  uint16_t fp = xor_fingerprint(hash);
  const uint16_t *table = (const uint16_t *)filter->bf;

  uint32_t block_length = (uint32_t)filter->block_length;
  uint32_t h0 = xor_geth0(hash, block_length);
  uint32_t h1 = xor_geth1(hash, block_length) + block_length;
  uint32_t h2 = xor_geth2(hash, block_length) + (block_length * 2U);

  fp ^= table[h0] ^ table[h1] ^ table[h2];
  return fp == 0 ? 1 : 0;
}

void xorfilter_free(struct xorfilter *filter)
{
  if (filter == NULL) {
    return;
  }

  if (filter->bf != NULL) {
    free(filter->bf);
    filter->bf = NULL;
  }
  if (filter->pending != NULL) {
    free(filter->pending);
    filter->pending = NULL;
  }

  filter->ready = 0;
  filter->finalized = 0;
  filter->entries = 0;
  filter->bits = 0;
  filter->bytes = 0;
  filter->pending_count = 0;
  filter->pending_capacity = 0;
}
