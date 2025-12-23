/*
 * ip6.c -- SSE 4.1 parser for IPv6 addresses
 *
 * Copyright (c) 2025, Jeroen Koekkoek
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <assert.h>
#include <immintrin.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>

#define likely(params) __builtin_expect(!!(params), 1)
#define unlikely(params) __builtin_expect(!!(params), 0)

__attribute__((always_inline))
static inline uint64_t count_ones(uint64_t value)
{
  return _mm_popcnt_u64(value);
}

__attribute__((always_inline))
static inline uint64_t trailing_zeros(uint64_t value)
{
  return _tzcnt_u64(value);
}

__attribute__((always_inline))
static inline uint64_t first_trailing_one(uint64_t value)
{
  return _blsi_u64(value);
}

__attribute__((always_inline))
static inline uint64_t clear_lowest_bit(uint64_t value)
{
  return _blsr_u64(value);
}

// magic (bits: 10, shift_bits: 14, mask_bits: 6, key: 19146)
static const uint8_t pattern_ids[64] = {
    0,   1,   2,   6,   3,   7, 255,  11,
  255,   4,   8,  12, 255,  15,  16,  19,
  255, 255,   5,   9,  23,  13, 255,  17,
  255, 255,  20, 255,  21,  27,  24, 255,
  255, 255, 255, 255, 255, 255,  10,  14,
   28,  30,  18, 255, 255, 255,  22, 255,
  255, 255, 255, 255,  25, 255, 255, 255,
   26, 255, 255, 255, 255,  29, 255, 255
};

static const struct {
  uint32_t mask;
  uint16_t shift;
  uint16_t bytes;
  uint8_t shuffle[8];
} patterns[31] = {
  {   0,  0, 0, { 128, 128, 128, 128, 128, 128, 128, 128 } }, //  0: 0000000000
  {   1,  1, 2, { 128, 128, 128, 128, 128, 128, 128, 128 } }, //  1: 1000000000
  {   2,  2, 2, { 128, 128, 128,   0, 128, 128, 128, 128 } }, //  2: 0100000000
  {   4,  3, 2, { 128, 128,   0,   1, 128, 128, 128, 128 } }, //  3: 0010000000
  {   8,  4, 2, { 128,   0,   1,   2, 128, 128, 128, 128 } }, //  4: 0001000000
  {  16,  5, 2, {   0,   1,   2,   3, 128, 128, 128, 128 } }, //  5: 0000100000
  {   3,  2, 4, { 128, 128, 128, 128, 128, 128, 128, 128 } }, //  6: 1100000000
  {   5,  3, 4, { 128, 128, 128, 128, 128, 128, 128,   1 } }, //  7: 1010000000
  {   9,  4, 4, { 128, 128, 128, 128, 128, 128,   1,   2 } }, //  8: 1001000000
  {  17,  5, 4, { 128, 128, 128, 128, 128,   1,   2,   3 } }, //  9: 1000100000
  {  33,  6, 4, { 128, 128, 128, 128,   1,   2,   3,   4 } }, // 10: 1000010000
  {   6,  3, 4, { 128, 128, 128,   0, 128, 128, 128, 128 } }, // 11: 0110000000
  {  10,  4, 4, { 128, 128, 128,   0, 128, 128, 128,   2 } }, // 12: 0101000000
  {  18,  5, 4, { 128, 128, 128,   0, 128, 128,   2,   3 } }, // 13: 0100100000
  {  34,  6, 4, { 128, 128, 128,   0, 128,   2,   3,   4 } }, // 14: 0100010000
  {  66,  7, 4, { 128, 128, 128,   0,   2,   3,   4,   5 } }, // 15: 0100001000
  {  12,  4, 4, { 128, 128,   0,   1, 128, 128, 128, 128 } }, // 16: 0011000000
  {  20,  5, 4, { 128, 128,   0,   1, 128, 128, 128,   3 } }, // 17: 0010100000
  {  36,  6, 4, { 128, 128,   0,   1, 128, 128,   3,   4 } }, // 18: 0010010000
  {  68,  7, 4, { 128, 128,   0,   1, 128,   3,   4,   5 } }, // 19: 0010001000
  { 132,  8, 4, { 128, 128,   0,   1,   3,   4,   5,   6 } }, // 20: 0010000100
  {  24,  5, 4, { 128,   0,   1,   2, 128, 128, 128, 128 } }, // 21: 0001100000
  {  40,  6, 4, { 128,   0,   1,   2, 128, 128, 128,   4 } }, // 22: 0001010000
  {  72,  7, 4, { 128,   0,   1,   2, 128, 128,   4,   5 } }, // 23: 0001001000
  { 136,  8, 4, { 128,   0,   1,   2, 128,   4,   5,   6 } }, // 24: 0001000100
  { 264,  9, 4, { 128,   0,   1,   2,   4,   5,   6,   7 } }, // 25: 0001000010
  {  48,  6, 4, {   0,   1,   2,   3, 128, 128, 128, 128 } }, // 26: 0000110000
  {  80,  7, 4, {   0,   1,   2,   3, 128, 128, 128,   5 } }, // 27: 0000101000
  { 144,  8, 4, {   0,   1,   2,   3, 128, 128,   5,   6 } }, // 28: 0000100100
  { 272,  9, 4, {   0,   1,   2,   3, 128,   5,   6,   7 } }, // 29: 0000100010
  { 528, 10, 4, {   0,   1,   2,   3,   5,   6,   7,   8 } }  // 30: 0000100001
};

__attribute__((warn_unused_result)) __attribute__((always_inline))
static inline uint32_t load_shuffle_mask(
  __m128i *shuffle, uint32_t *bytes, uint32_t mask)
{
  uint32_t mask0 = clear_lowest_bit(clear_lowest_bit(mask));
  mask0 ^= mask;
  mask0 &= 0x3ffu;
  const uint32_t hash0 = ((mask0 * 19146ull) >> 14u) & 0x3f;
  const uint8_t key0 = pattern_ids[hash0];

  __m128i shuffle0 = _mm_loadu_si128((__m128i*)patterns[key0].shuffle);
  const uint8_t shift0 = patterns[key0].shift;

  mask >>= shift0;

  uint32_t mask1 = clear_lowest_bit(clear_lowest_bit(mask));
  mask1 ^= mask;
  mask1 &= 0x3ffu;
  const uint32_t hash1 = ((mask1 * 19146ull) >> 14u) & 0x3f;
  const uint8_t key1 = pattern_ids[hash1];

  __m128i shuffle1 = _mm_loadu_si128((__m128i*)patterns[key1].shuffle);
          shuffle1 = _mm_add_epi8(shuffle1, _mm_set1_epi8(shift0));
  const uint8_t shift1 = patterns[key1].shift;

  *shuffle = _mm_unpacklo_epi64(shuffle0, shuffle1);
  *bytes += patterns[key0].bytes + patterns[key1].bytes;

  return (patterns[key0].shift + patterns[key1].shift) &
    (((mask0 != patterns[key0].mask) | (mask1 != patterns[key1].mask)) - 1u);
}

__attribute__((noinline))
size_t parse_ip6(const char *src, void *dst)
{
  const __m128i delta_check = _mm_setr_epi8(
    -16, -32, -47, 71, 58, -96, 26, -128, 0, 0, 0, 0, 0, 0, 0, 0);
  const __m128i delta_rebase = _mm_setr_epi8(
    0, 0, -47, -47, -54, 0, -86, 0, 0, 0, 0, 0, 0, 0, 0, 0);

  __m128i input = _mm_loadu_si128((__m128i*)src);
  uint64_t colons = (uint16_t)_mm_movemask_epi8(
    _mm_cmpeq_epi8(input, _mm_set1_epi8(':')));

  // Leading :: requires sepcial handling.
  // :: is allowed, as is abcd:, but not :abcd.
  if (unlikely((colons & 3llu) == 1llu))
    return 0u;

  // TODO: Describe the reasoning behind -1 (credit @aqrit).
  input = _mm_add_epi8(input, _mm_set1_epi8(-1));
  __m128i keys = _mm_and_si128(_mm_srli_epi32(input, 4), _mm_set1_epi8(0x0f));

  uint64_t non_digits = (uint16_t)_mm_movemask_epi8(
    _mm_add_epi8(_mm_shuffle_epi8(delta_check, keys), input));
  input = _mm_add_epi8(input, _mm_shuffle_epi8(delta_rebase, keys));

  uint64_t mask;
  uint64_t delimiter = first_trailing_one(non_digits ^ colons);
  colons &= (delimiter - 1llu);
  mask = colons;
  colons |= delimiter;

  __m128i shuffle;
  uint32_t size, shift, bytes = 0;
  if (!(shift = load_shuffle_mask(&shuffle, &bytes, colons)))
    return 0u;

  input = _mm_shuffle_epi8(input, shuffle);
  input = _mm_maddubs_epi16(input, _mm_set1_epi16(0x0110));
  input = _mm_packus_epi16(input, input);
  _mm_storeu_si128((__m128i *)dst, input);

  size = shift;
  colons >>= shift;

  while (bytes < 16 && !(delimiter && !colons)) {
    input = _mm_loadu_si128((__m128i*)(src + size));
    colons = (uint16_t)_mm_movemask_epi8(
      _mm_cmpeq_epi8(input, _mm_set1_epi8(':')));

    input = _mm_add_epi8(input, _mm_set1_epi8(-1));
    keys = _mm_and_si128(_mm_srli_epi32(input, 4), _mm_set1_epi8(0x0f));
    non_digits = (uint16_t)_mm_movemask_epi8(
      _mm_add_epi8(_mm_shuffle_epi8(delta_check, keys), input));
    input = _mm_add_epi8(input, _mm_shuffle_epi8(delta_rebase, keys));

    delimiter = first_trailing_one(non_digits ^ colons);
    colons &= delimiter - 1;
    mask |= (colons << size);
    colons |= delimiter;

    uint8_t *out = (uint8_t*)dst + bytes;
    if (!(shift = load_shuffle_mask(&shuffle, &bytes, colons)))
      return 0u;
    size += shift;
    colons >>= shift;

    input = _mm_shuffle_epi8(input, shuffle);
    input = _mm_maddubs_epi16(input, _mm_set1_epi16(0x0110));
    input = _mm_packus_epi16(input, input);
    _mm_storeu_si128((__m128i *)out, input);
  }

  size -= 1u; // Account for delimiter.
  assert(size <= INET6_ADDRSTRLEN);

  // TODO: support for IPv4 embedded IPv6 addresses.
  if (unlikely(src[size] == ':' || src[size] == '.'))
    return 0u;

  uint64_t compressed = (mask << 1) & mask;
  if (compressed) {
    if ((count_ones(compressed) > 1) || (bytes > 14))
      return 0u;
    printf("todo, implement final shift\n");
  }

  if (bytes != 16)
    return 0u;

  return size;
}

int main(int argc, char *argv[])
{
  if (argc != 2)
    return 1;

  char str[64] = { 0 };
  uint8_t addr[64];
  size_t size = strlen(argv[1]);
  if (size > 63)
    size = 63;
  memcpy(str, argv[1], size);
  printf("input: %s\n", str);
  size_t len = parse_ip6(str, addr);
  printf("length: %zu\n", len);

  printf("address: { ");
  for (size_t i=0; i < 15; i++)
    printf("%d, ", addr[i]);
  printf("%d }\n", addr[15]);

  return 0;
}
