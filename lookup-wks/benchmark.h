/*
 * benchmark.h -- Benchmark macros by Wojciech Muła and Daniel Lemire
 *
 * Copyright (c) 2018, Wojciech Muła
 * Copyright (c) 2018, Daniel Lemire
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 */

#ifndef _BENCHMARK_H_
#define _BENCHMARK_H_

#include <stdint.h>
#define RDTSC_START(cycles)                                             \
    do {                                                                \
        uint32_t cyc_high, cyc_low;                                     \
        __asm volatile("cpuid\n"                                        \
                       "rdtsc\n"                                        \
                       "mov %%edx, %0\n"                                \
                       "mov %%eax, %1" :                                \
                       "=r" (cyc_high),                                 \
                       "=r"(cyc_low) :                                  \
                       : /* no read only */                             \
                       "%rax", "%rbx", "%rcx", "%rdx" /* clobbers */    \
                       );                                               \
        (cycles) = ((uint64_t)cyc_high << 32) | cyc_low;                \
    } while (0)

#define RDTSC_STOP(cycles)                                              \
    do {                                                                \
        uint32_t cyc_high, cyc_low;                                     \
        __asm volatile("rdtscp\n"                                       \
                       "mov %%edx, %0\n"                                \
                       "mov %%eax, %1\n"                                \
                       "cpuid" :                                        \
                       "=r"(cyc_high),                                  \
                       "=r"(cyc_low) :                                  \
                       /* no read only registers */ :                   \
                       "%rax", "%rbx", "%rcx", "%rdx" /* clobbers */    \
                       );                                               \
        (cycles) = ((uint64_t)cyc_high << 32) | cyc_low;                \
    } while (0)

static __attribute__ ((noinline))
uint64_t rdtsc_overhead_func(uint64_t dummy) {
    return dummy;
}

uint64_t global_rdtsc_overhead = (uint64_t) UINT64_MAX;

#define RDTSC_SET_OVERHEAD(test, repeat)                                \
  do {                                                                  \
    uint64_t cycles_start, cycles_final, cycles_diff;                   \
    uint64_t min_diff = UINT64_MAX;                                     \
    for (unsigned i = 0; i < repeat; i++) {                             \
      __asm volatile("" ::: /* pretend to clobber */ "memory");         \
      RDTSC_START(cycles_start);                                        \
      test;                                                             \
      RDTSC_STOP(cycles_final);                                         \
      cycles_diff = (cycles_final - cycles_start);                      \
      if (cycles_diff < min_diff) min_diff = cycles_diff;               \
    }                                                                   \
    global_rdtsc_overhead = min_diff;                                   \
    printf("rdtsc_overhead set to %d\n", (int)global_rdtsc_overhead);   \
  } while (0)                                                           \


/*
 * Prints the best number of operations per cycle where
 * test is the function call, answer is the expected answer generated by
 * test, repeat is the number of times we should repeat and size is the
 * number of operations represented by test.
 */
#define BEST_TIME(pre, test, test_name, repeat, size)                   \
    do {                                                                \
        if (global_rdtsc_overhead == UINT64_MAX) {                      \
           RDTSC_SET_OVERHEAD(rdtsc_overhead_func(1), repeat);          \
        }                                                               \
        printf("%-30s\t: ", test_name); fflush(stdout);                 \
        uint64_t cycles_start, cycles_final, cycles_diff;               \
        uint64_t min_diff = (uint64_t)-1;                               \
        uint64_t sum_diff = 0;                                          \
        for (size_t i = 0; i < repeat; i++) {                           \
            pre;                                                        \
            __asm volatile("" ::: /* pretend to clobber */ "memory");   \
            RDTSC_START(cycles_start);                                  \
            test;                                                       \
            RDTSC_STOP(cycles_final);                                   \
            cycles_diff = (cycles_final - cycles_start - global_rdtsc_overhead); \
            if (cycles_diff < min_diff) min_diff = cycles_diff;         \
            sum_diff += cycles_diff;                                    \
        }                                                               \
        uint64_t S = size;                                              \
        float cycle_per_op = (min_diff) / (double)S;                    \
        float avg_cycle_per_op = (sum_diff) / ((double)S * repeat);     \
        printf(" %8.3f cycle/op (best) %8.3f cycle/op (avg)\n", cycle_per_op, avg_cycle_per_op); \
 } while (0)

#endif
