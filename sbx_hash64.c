/*
 * SBX hash64 helper for SBX XorFilter.
 *
 * Copyright (c) 2026 ECD5A
 * Licensed under the MIT License. See LICENSE in this directory.
 *
 * GitHub: https://github.com/ECD5A/SBX-XorFilter
 */

#include "sbx_hash64.h"

#include <string.h>

static uint64_t sbx_rotl64(uint64_t x, int r) {
  return (x << r) | (x >> (64 - r));
}

static uint64_t sbx_mix64(uint64_t x) {
  x ^= x >> 30;
  x *= 0xbf58476d1ce4e5b9ULL;
  x ^= x >> 27;
  x *= 0x94d049bb133111ebULL;
  x ^= x >> 31;
  return x;
}

static uint64_t sbx_read64_le(const uint8_t *p) {
  uint64_t v = 0;
  memcpy(&v, p, sizeof(v));
  return v;
}

uint64_t sbx_hash64(const void *data, size_t len, uint64_t seed) {
  const uint8_t *p = (const uint8_t *)data;
  size_t remaining = len;

  uint64_t h = sbx_mix64(seed ^ (uint64_t)len * 0x9e3779b185ebca87ULL);

  while (remaining >= 8) {
    uint64_t v = sbx_read64_le(p);
    h ^= sbx_mix64(v ^ 0xd6e8feb86659fd93ULL);
    h = sbx_rotl64(h, 27) * 0x94d049bb133111ebULL + 0x2545f4914f6cdd1dULL;
    p += 8;
    remaining -= 8;
  }

  if (remaining > 0) {
    uint64_t tail = 0;
    memcpy(&tail, p, remaining);
    h ^= sbx_mix64(tail ^ 0x165667b19e3779f9ULL);
  }

  h ^= (uint64_t)len;
  return sbx_mix64(h);
}

uint64_t sbx_hash64_32(const void *data, uint64_t seed) {
  const uint8_t *p = (const uint8_t *)data;
  uint64_t h = sbx_mix64(seed ^ UINT64_C(32) * UINT64_C(0x9e3779b185ebca87));

  uint64_t v = sbx_read64_le(p);
  h ^= sbx_mix64(v ^ UINT64_C(0xd6e8feb86659fd93));
  h = sbx_rotl64(h, 27) * UINT64_C(0x94d049bb133111eb) + UINT64_C(0x2545f4914f6cdd1d);

  v = sbx_read64_le(p + 8);
  h ^= sbx_mix64(v ^ UINT64_C(0xd6e8feb86659fd93));
  h = sbx_rotl64(h, 27) * UINT64_C(0x94d049bb133111eb) + UINT64_C(0x2545f4914f6cdd1d);

  v = sbx_read64_le(p + 16);
  h ^= sbx_mix64(v ^ UINT64_C(0xd6e8feb86659fd93));
  h = sbx_rotl64(h, 27) * UINT64_C(0x94d049bb133111eb) + UINT64_C(0x2545f4914f6cdd1d);

  v = sbx_read64_le(p + 24);
  h ^= sbx_mix64(v ^ UINT64_C(0xd6e8feb86659fd93));
  h = sbx_rotl64(h, 27) * UINT64_C(0x94d049bb133111eb) + UINT64_C(0x2545f4914f6cdd1d);

  h ^= UINT64_C(32);
  return sbx_mix64(h);
}
