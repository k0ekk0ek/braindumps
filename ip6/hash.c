/*
 * hash.c
 *
 * Copyright (c) 2025, Jeroen Koekkoek
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <immintrin.h>

struct key {
  uint32_t mask;
  uint32_t count;
};

struct table {
  uint32_t seed, shift, mask, groups;
  uint32_t total, unique;
  struct key keys[]; // c99 flexible array
};

static void print_mask(const uint32_t mask, const uint32_t bits)
{
  printf("\"");
  for (size_t i=0; i < bits; i++) {
    printf("%c", (mask & (1lu << i)) != 0 ? '1' : '0');
  }
  printf("\"\n");
}

static void print_table(struct table *table)
{
  printf("table {\n");
  printf("  seed: %u\n", table->seed);
  printf("  shift: %u\n", table->shift);
  printf("  mask: %u\n", table->mask);
  printf("  keys {\n");
  const uint32_t count = table->mask + 1;
  for (uint32_t i=0; i < count; i++) {
    printf("    %u: ", i);
    if (table->keys[i].count == 0) {
      printf(" unused\n");
    } else {
      printf("(%u) ", table->keys[i].mask);
      print_mask(table->keys[i].mask, 16);
    }
  }
  printf("  }\n");
  printf("}\n");
}

static bool add_mask(struct table *table, const uint32_t mask)
{
  uint32_t prefix_mask = mask;
  if (__builtin_popcount(mask) > table->groups) {
    // consider prefix bits only
    prefix_mask = 0u;
    uint32_t bits = mask;
    for (uint32_t i=0; i < table->groups; i++) {
      prefix_mask |= (1lu << __builtin_ctz(bits));
      bits = bits & (bits - 1);
    }
    assert(__builtin_popcount(prefix_mask) == table->groups);
    assert((mask & prefix_mask) == prefix_mask);
  }
  uint32_t key = (((prefix_mask * table->seed)) >> table->shift) & table->mask;

//  printf("key: %u, count: %u, mask: %u (mask: %u)\n", key, table->keys[key].count, table->keys[key].mask, mask);
  if (table->keys[key].count > 0) {
    if (table->keys[key].mask != prefix_mask)
      return false;
  } else {
    table->unique++;
  }
  table->total++;
  table->keys[key].mask = prefix_mask;
  table->keys[key].count++;
  return true;
}

static bool permutate(struct table *table, const uint32_t mask, uint32_t bit, const uint32_t bits, const uint32_t compressed)
{
  for (uint32_t i=bit+1+compressed, n=bit+6; i < n && i < bits; i++) {
    const uint32_t m = mask | (1lu << i);
    if (!add_mask(table, m))
      return false;
    if (!permutate(table, m, i, bits, (i == bit+1) | compressed))
      return false;
  }

  return true;
}

static void usage(const char *str)
{
  fprintf(stderr, "Usage: %s BITS SHIFT_BITS MASK_BITS\n", str);
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
  if (argc != 4)
    usage(argv[0]);

  char *end = argv[1];
  uint32_t bits = strtoul(argv[1], &end, 10);
  if (!bits || end == argv[1] || *end)
    usage(argv[0]);

  end = argv[2];
  uint32_t shift_bits = strtoul(argv[2], &end, 10);
  if (end == argv[2] || *end)
    usage(argv[0]);

  end = argv[3];
  uint32_t mask_bits = strtoul(argv[3], &end, 10);
  if (end == argv[3] || *end)
    usage(argv[0]);

  struct table *table;
  const size_t table_size = sizeof(struct table) + (1lu << mask_bits) * sizeof(struct key);
  if (!(table = malloc(table_size)))
    return EXIT_FAILURE;

  const uint32_t mask = (1lu << mask_bits) - 1;

  printf("bits: %u, shift bits: %u, mask bits: %u (0x%x), table size: %u\n", bits, shift_bits, mask_bits, mask, table_size);
  printf("maximum full hextets: %u\n", bits / 4);
  for (uint32_t seed=1llu; seed < UINT32_MAX; seed++) {
    memset(table, 0, table_size);
    table->seed = seed;
    table->mask = mask;
    table->shift = shift_bits;
    table->groups = bits / 4;

    add_mask(table, 0);
    for (uint32_t bit=0; bit < 5; bit++) {
      const uint32_t m = 1lu << bit;
      if (!add_mask(table, m))
        goto next;
      if (!permutate(table, m, bit, bits, 0))
        goto next;
    }

    printf("found magic! bits: %u, shift_bits: %u, mask_bits: %u, key: %u\n", bits, shift_bits, mask_bits, seed);
    printf("total: %u, unique: %u\n", table->total, table->unique);
    print_table(table);
    break;
next:
  }

  free(table);

  return EXIT_SUCCESS;
}
