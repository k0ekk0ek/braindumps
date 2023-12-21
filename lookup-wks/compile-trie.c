#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

bool compile_trie_lookup(const char *str, size_t len, uint16_t *port)
{
  switch (str[0] & 0xdf) {
    case 'B':
      if (strncasecmp(str, "bgmp", len) == 0)
        return (void)(*port = 264), 1;
      return 0;
    case 'D':
      if (strncasecmp(str, "domain-s", len) == 0)
        return (void)(*port = 853), 1;
      if (strncasecmp(str, "domain", len) == 0)
        return (void)(*port = 53), 1;
      return 0;
    case 'E':
      if (strncasecmp(str, "echo", len) == 0)
        return (void)(*port = 7), 1;
      return 0;
    case 'F':
      if (strncasecmp(str, "ftps-data", len) == 0)
        return (void)(*port = 989), 1;
      if (strncasecmp(str, "ftps", len) == 0)
        return (void)(*port = 990), 1;
      if (strncasecmp(str, "ftp-data", len) == 0)
        return (void)(*port = 20), 1;
      if (strncasecmp(str, "ftp", len) == 0)
        return (void)(*port = 21), 1;
      return 0;
    case 'H':
      if (strncasecmp(str, "https", len) == 0)
        return (void)(*port = 443), 1;
      if (strncasecmp(str, "http", len) == 0)
        return (void)(*port = 80), 1;
      return 0;
    case 'I':
      if (strncasecmp(str, "imaps", len) == 0)
        return (void)(*port = 993), 1;
      if (strncasecmp(str, "imap", len) == 0)
        return (void)(*port = 143), 1;
      return 0;
    case 'K':
      if (strncasecmp(str, "kerberos", len) == 0)
        return (void)(*port = 88), 1;
      return 0;
    case 'L':
      if (strncasecmp(str, "lmtp", len) == 0)
        return (void)(*port = 24), 1;
      if (strncasecmp(str, "ldaps", len) == 0)
        return (void)(*port = 636), 1;
      return 0;
    case 'N':
      if (strncasecmp(str, "nicname", len) == 0)
        return (void)(*port = 43), 1;
      if (strncasecmp(str, "npp", len) == 0)
        return (void)(*port = 92), 1;
      if (strncasecmp(str, "nntps", len) == 0)
        return (void)(*port = 563), 1;
      if (strncasecmp(str, "nntp", len) == 0)
        return (void)(*port = 119), 1;
      if (strncasecmp(str, "nnsp", len) == 0)
        return (void)(*port = 433), 1;
      if (strncasecmp(str, "ntp", len) == 0)
        return (void)(*port = 123), 1;
      return 0;
    case 'P':
      if (strncasecmp(str, "ptp-general", len) == 0)
        return (void)(*port = 320), 1;
      if (strncasecmp(str, "ptp-event", len) == 0)
        return (void)(*port = 319), 1;
      if (strncasecmp(str, "pop3s", len) == 0)
        return (void)(*port = 995), 1;
      if (strncasecmp(str, "pop3", len) == 0)
        return (void)(*port = 110), 1;
      return 0;
    case 'S':
      if (strncasecmp(str, "ssh", len) == 0)
        return (void)(*port = 22), 1;
      if (strncasecmp(str, "smtp", len) == 0)
        return (void)(*port = 25), 1;
      if (strncasecmp(str, "snmptrap", len) == 0)
        return (void)(*port = 162), 1;
      if (strncasecmp(str, "snmp", len) == 0)
        return (void)(*port = 161), 1;
      if (strncasecmp(str, "submissions", len) == 0)
        return (void)(*port = 465), 1;
      if (strncasecmp(str, "submission", len) == 0)
        return (void)(*port = 587), 1;
      return 0;
    case 'T':
      if (strncasecmp(str, "tcpmux", len) == 0)
        return (void)(*port = 1), 1;
      if (strncasecmp(str, "telnet", len) == 0)
        return (void)(*port = 23), 1;
      return 0;
    case 'W':
      if (strncasecmp(str, "whoispp", len) == 0)
        return (void)(*port = 80), 1;
      return 0;
  }
  return 0;
}
