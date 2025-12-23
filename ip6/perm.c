/*
 * perm.c
 *
 * Copyright (c) 2025, Jeroen Koekkoek
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <immintrin.h>

#define BITS (16)

#define MASK_BITS (9)
#define TABLE_SIZE (1llu << MASK_BITS)
#define MASK ((1llu << MASK_BITS) - 1)

static uint32_t count = 0;

static void print_mask(const uint32_t mask, const uint32_t bits)
{
  count++;
  printf("\"");
  for (size_t i=0; i < bits; i++) {
    printf("%c", (mask & (1lu << i)) != 0 ? '1' : '0');
  }
  printf("\"\n");
}

static void permutate(
  const uint32_t mask,
  const uint32_t bit,
  const uint32_t bits,
  const uint32_t groups,
  const uint32_t compressed)
{
  if (groups && __builtin_popcount(mask) >= groups)
    return;
  for (uint32_t i=bit+1+compressed, n=bit+6; i < n && i < bits; i++) {
    uint32_t m = mask | (1lu << i);
    print_mask(m, bits);
    permutate(m, i, bits, groups, (i == bit+1) | compressed);
  }
}


int main(int argc, char *argv[])
{
  char *str = "", *end = str;

  if (argc > 1)
    str = argv[1];

  errno = 0;
  const uint32_t bits = strtoul(str, &end, 10);
  if (errno || end == str || *end != '\0') {
    fprintf(stderr, "Usage: %s BITS\n", argv[0]);
    return EXIT_FAILURE;
  }

  const uint32_t groups = bits / 4; // maximum number of full hextets

  if (bits) {
    print_mask(0, bits);
    for (uint32_t bit=0; bit < 5 && bit < bits; bit++) {
      const uint32_t mask = 1lu << bit;
      print_mask(mask, bits);
      permutate(mask, bit, bits, groups, 0);
    }
  }

  printf("count: %u\n", count);

  return EXIT_SUCCESS;
}
