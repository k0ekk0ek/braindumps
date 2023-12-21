#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "benchmark.h"

extern bool hash_lookup(const char *str, size_t len, uint16_t *port);
extern bool compile_trie_lookup(const char *str, size_t len, uint16_t *port);

typedef struct service service_t;
struct service { char name[16]; size_t length; };

static const service_t services[] = {
  { "ntp", 3 },
  { "pop3", 4 },
  { "ptp-general", 11 },
  { "imaps", 5 },
  { "imap", 4 },
  { "ssh", 3 },
  { "nicname", 7 },
  { "snmptrap", 8 },
  { "https", 5 },
  { "http", 4 },
  { "ftps-data", 9 },
  { "ptp-event", 9 },
  { "smtp", 4 },
  { "npp", 3 },
  { "domain", 6 },
  { "nntps", 5 },
  { "nntp", 4 },
  { "submission", 10 },
  { "submissions", 11 },
  { "domain-s", 8 },
  { "ftp-data", 8 },
  { "echo", 4 },
  { "snmp", 4 },
  { "bgmp", 4 },
  { "ftps", 4 },
  { "ldaps", 5 },
  { "pop3s", 5 }
};

static const size_t service_count = sizeof(services)/sizeof(services[0]);

#define error(message) (void)(printf(message "\n")), exit(EXIT_FAILURE)

int main(int argc, char *argv[])
{
  (void)argc;
  (void)argv;

  size_t count = 2000000ull;

  service_t *test_data;

  if (!(test_data = calloc(sizeof(service_t), count)))
    error("failed to allocate memory");

  printf("generating test data\n");
  pid_t pid = getpid();
  srandom(pid);
  for (size_t i = 0; i < count; i++) {
    const service_t *service = &services[ random() % service_count ];
    memcpy(test_data[i].name, service->name, service->length);
    test_data[i].length = service->length;
  }

  uint16_t port;

  BEST_TIME(/**/,
    hash_lookup(test_data[i].name, test_data[i].length, &port),
    "hash_lookup", count, 1);
  BEST_TIME(/**/,
    compile_trie_lookup(test_data[i].name, test_data[i].length, &port),
    "compile_trie_lookup", count, 1);
  return 0;
}
