#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>

typedef struct service service_t;
struct service {
  struct {
    const char name[16];
    size_t length;
  } key;
  uint16_t port;
};

#define UNKNOWN_SERVICE() { { "", 0 }, 0 }
#define SERVICE(name, port) { { name, sizeof(name) - 1 }, port }

static const service_t services[64] = {
  SERVICE("imap", 143),
  SERVICE("ftp", 21),
  SERVICE("ntp", 123),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  SERVICE("ptp-general", 320),
  SERVICE("nicname", 43),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  SERVICE("ssh", 22),
  SERVICE("https", 443),
  SERVICE("http", 80),
  UNKNOWN_SERVICE(),
  SERVICE("telnet", 23),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  SERVICE("snmptrap", 162),
  SERVICE("lmtp", 24),
  SERVICE("smtp", 25),
  SERVICE("ftps-data", 989),
  SERVICE("ptp-event", 319),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  SERVICE("nntps", 563),
  SERVICE("nntp", 119),
  UNKNOWN_SERVICE(),
  SERVICE("nnsp", 433),
  UNKNOWN_SERVICE(),
  SERVICE("npp", 92),
  SERVICE("domain", 53),
  UNKNOWN_SERVICE(),
  SERVICE("tcpmux", 1),
  UNKNOWN_SERVICE(),
  SERVICE("submission", 587),
  // submissions cannot be distinguished from submission by hash value because
  // the shared prefix is too long. include length to generate a unique key
  SERVICE("submissions", 465),
  UNKNOWN_SERVICE(),
  SERVICE("echo", 7),
  SERVICE("domain-s", 853),
  UNKNOWN_SERVICE(),
  SERVICE("whoispp", 63),
  SERVICE("snmp", 161),
  UNKNOWN_SERVICE(),
  SERVICE("ftp-data", 20),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  SERVICE("bgmp", 264),
  SERVICE("ftps", 990),
  SERVICE("ldaps", 636),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  SERVICE("pop3s", 995),
  SERVICE("pop3", 110),
  SERVICE("kerberos", 88),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  UNKNOWN_SERVICE(),
  SERVICE("imaps", 993),
};

#undef SERVICE
#undef UNKNOWN_SERVICE

// services: 34, magic: 138261570
__attribute__((always_inline))
static inline uint8_t service_hash(uint64_t input, size_t length)
{
  // le64toh is required for big endian, no-op on little endian
  input = le64toh(input);
  uint32_t input32 = ((input >> 32) ^ input);
  return (((input32 * 138261570llu) >> 32) + length) & 0x3f;
}

bool hash_lookup(const char *str, size_t len, uint16_t *port)
{
  static const int8_t zero_masks[48] = {
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
     0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0
  };

  uint64_t input0, input1;
  static const uint64_t upper_mask = 0xdfdfdfdfdfdfdfdfllu;
  static const uint64_t letter_mask = 0x4040404040404040llu;
  memcpy(&input0, str, 8);
  memcpy(&input1, str+8, 8);
  // convert to upper case, unconditionally transforms digits (0x30-0x39) and
  // dash (0x2d), but does not introduce clashes
  uint64_t key = input0 & upper_mask;
  // zero out non-relevant bytes
  uint64_t zero_mask0, zero_mask1;
  const int8_t *zero_mask = &zero_masks[32 - (len & 0x0f)];
  memcpy(&zero_mask0, zero_mask, 8);
  memcpy(&zero_mask1, zero_mask+8, 8);
  uint8_t index = service_hash(key, len);
  assert(index < 64);

  input0 |= (input0 & letter_mask) >> 1;
  input0 &= zero_mask0;
  input1 |= (input1 & letter_mask) >> 1;
  input1 &= zero_mask1;

  uint64_t name0, name1;
  memcpy(&name0, services[index].key.name, 8);
  memcpy(&name1, services[index].key.name+8, 8);

  *port = services[index].port;
  return
    (input0 == name0) & (input1 == name1) & (services[index].key.length == len);
}
