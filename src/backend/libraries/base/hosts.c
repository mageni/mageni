/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2013-2019 Greenbone Networks GmbH
 * SPDX-FileComment: Implementation of an API to handle Hosts objects
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#include "hosts.h"

#include "networking.h" /* for ipv4_as_ipv6, addr6_as_str, gvm_resolve */

#include <arpa/inet.h> /* for inet_pton, inet_ntop */
#include <assert.h>    /* for assert */
#include <ctype.h>     /* for isdigit */
#include <malloc.h>
#include <netdb.h>      /* for getnameinfo, NI_NAMEREQD */
#include <stdint.h>     /* for uint8_t, uint32_t */
#include <stdio.h>      /* for sscanf, perror */
#include <stdlib.h>     /* for strtol, atoi */
#include <string.h>     /* for strchr, memcpy, memcmp, bzero, strcasecmp */
#include <sys/socket.h> /* for AF_INET, AF_INET6, sockaddr */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "base hosts"

/* Static variables */

gchar *host_type_str[HOST_TYPE_MAX] = {
  [HOST_TYPE_NAME] = "Hostname",
  [HOST_TYPE_IPV4] = "IPv4",
  [HOST_TYPE_IPV6] = "IPv6",
  [HOST_TYPE_CIDR_BLOCK] = "IPv4 CIDR block",
  [HOST_TYPE_RANGE_SHORT] = "IPv4 short range",
  [HOST_TYPE_RANGE_LONG] = "IPv4 long range"};

/* Function definitions */

/**
 * @brief Checks if a buffer points to a valid IPv4 address.
 * "192.168.11.1" is valid, "192.168.1.300" and "192.168.1.1e" are not.
 *
 * @param[in]   str Buffer to check in.
 *
 * @return 1 if valid IPv4 address, 0 otherwise.
 */
static int
is_ipv4_address (const char *str)
{
  struct sockaddr_in sa;

  return inet_pton (AF_INET, str, &(sa.sin_addr)) == 1;
}

/**
 * @brief Checks if a buffer points to a valid IPv6 address.
 * "0:0:0:0:0:0:0:1", "::1" and "::FFFF:192.168.13.55" are valid "::1g" is not.
 *
 * @param[in]   str Buffer to check in.
 *
 * @return 1 if valid IPv6 address, 0 otherwise.
 */
static int
is_ipv6_address (const char *str)
{
  struct sockaddr_in6 sa6;

  return inet_pton (AF_INET6, str, &(sa6.sin6_addr)) == 1;
}

/**
 * @brief Checks if a buffer points to an IPv4 CIDR-expressed block.
 * "192.168.12.3/24" is valid, "192.168.1.3/31" is not.
 *
 * @param[in]   str Buffer to check in.
 *
 * @return 1 if valid CIDR-expressed block, 0 otherwise.
 */
static int
is_cidr_block (const char *str)
{
  long block;
  char *addr_str, *block_str, *p;

  addr_str = g_strdup (str);
  block_str = strchr (addr_str, '/');
  if (block_str == NULL)
    {
      g_free (addr_str);
      return 0;
    }

  /* Separate the address from the block value. */
  *block_str = '\0';
  block_str++;

  if (!is_ipv4_address (addr_str) || !isdigit (*block_str))
    {
      g_free (addr_str);
      return 0;
    }

  p = NULL;
  block = strtol (block_str, &p, 10);

  if (*p || block <= 0 || block > 32)
    {
      g_free (addr_str);
      return 0;
    }

  g_free (addr_str);
  return 1;
}

/**
 * @brief Gets the network block value from a CIDR-expressed block string.
 * For "192.168.1.1/24" it is 24.
 *
 * @param[in]   str     Buffer containing CIDR-expressed block.
 * @param[out]  block   Variable to store block value.
 *
 * @return -1 if error, 0 otherwise.
 */
static int
cidr_get_block (const char *str, unsigned int *block)
{
  if (str == NULL || block == NULL)
    return -1;

  if (sscanf (str, "%*[0-9.]/%2u", block) != 1)
    return -1;

  return 0;
}

/**
 * @brief Gets the IPv4 value from a CIDR-expressed block.
 * eg. For "192.168.1.10/24" it is "192.168.1.10".
 *
 * @param[in]   str     String containing CIDR-expressed block.
 * @param[out]  addr    Variable to store the IPv4 address value.
 *
 * @return -1 if error, 0 otherwise.
 */
static int
cidr_get_ip (const char *str, struct in_addr *addr)
{
  gchar *addr_str, *tmp;

  if (str == NULL || addr == NULL)
    return -1;

  addr_str = g_strdup (str);
  tmp = strchr (addr_str, '/');
  if (tmp == NULL)
    {
      g_free (addr_str);
      return -1;
    }
  *tmp = '\0';

  if (inet_pton (AF_INET, addr_str, addr) != 1)
    return -1;

  g_free (addr_str);
  return 0;
}

/**
 * @brief Gets the first and last usable IPv4 addresses from a CIDR-expressed
 * block. eg. "192.168.1.0/24" would give 192.168.1.1 as first and 192.168.1.254
 * as last.
 *
 * Both network and broadcast addresses are skipped:
 * - They are _never_ used as a host address. Not being included is the expected
 *   behaviour from users.
 * - When needed, short/long ranges (eg. 192.168.1.0-255) are available.
 *
 * @param[in]   str     Buffer containing CIDR-expressed block.
 * @param[out]  first   First IPv4 address in block.
 * @param[out]  last    Last IPv4 address in block.
 *
 * @return -1 if error, 0 else.
 */
static int
cidr_block_ips (const char *str, struct in_addr *first, struct in_addr *last)
{
  unsigned int block;

  if (str == NULL || first == NULL || last == NULL)
    return -1;

  /* Get IP and block values. */
  if (cidr_get_block (str, &block) == -1)
    return -1;
  if (cidr_get_ip (str, first) == -1)
    return -1;

  /* First IP: And with mask and increment. */
  first->s_addr &= htonl (0xffffffff ^ ((1 << (32 - block)) - 1));
  first->s_addr = htonl (ntohl (first->s_addr) + 1);

  /* Last IP: First IP + Number of usable hosts - 1. */
  last->s_addr = htonl (ntohl (first->s_addr) + (1 << (32 - block)) - 3);
  return 0;
}

/**
 * @brief Checks if a buffer points to a valid long range-expressed network.
 * "192.168.12.1-192.168.13.50" is valid.
 *
 * @param[in]   str Buffer to check in.
 *
 * @return 1 if valid long range-expressed network, 0 otherwise.
 */
static int
is_long_range_network (const char *str)
{
  char *first_str, *second_str;
  int ret;

  first_str = g_strdup (str);
  second_str = strchr (first_str, '-');
  if (second_str == NULL)
    {
      g_free (first_str);
      return 0;
    }

  /* Separate the addresses. */
  *second_str = '\0';
  second_str++;

  ret = is_ipv4_address (first_str) && is_ipv4_address (second_str);
  g_free (first_str);

  return ret;
}

/**
 * @brief Gets the first and last IPv4 addresses from a long range-expressed
 * network. eg. "192.168.1.1-192.168.2.40" would give 192.168.1.1 as first and
 * 192.168.2.40 as last.
 *
 * @param[in]   str     String containing long range-expressed network.
 * @param[out]  first   First IP address in block.
 * @param[out]  last    Last IP address in block.
 *
 * @return -1 if error, 0 else.
 */
static int
long_range_network_ips (const char *str, struct in_addr *first,
                        struct in_addr *last)
{
  char *first_str, *last_str;

  if (str == NULL || first == NULL || last == NULL)
    return -1;

  first_str = g_strdup (str);
  last_str = strchr (first_str, '-');
  if (last_str == NULL)
    {
      g_free (first_str);
      return -1;
    }

  /* Separate the two IPs. */
  *last_str = '\0';
  last_str++;

  if (inet_pton (AF_INET, first_str, first) != 1
      || inet_pton (AF_INET, last_str, last) != 1)
    {
      g_free (first_str);
      return -1;
    }

  g_free (first_str);
  return 0;
}

/**
 * @brief Checks if a buffer points to a valid short range-expressed network.
 * "192.168.11.1-50" is valid, "192.168.1.1-50e" and "192.168.1.1-300" are not.
 *
 * @param   str String to check in.
 *
 * @return 1 if str points to a valid short range-network, 0 otherwise.
 */
static int
is_short_range_network (const char *str)
{
  long end;
  char *ip_str, *end_str, *p;

  ip_str = g_strdup (str);
  end_str = strchr (ip_str, '-');
  if (end_str == NULL)
    {
      g_free (ip_str);
      return 0;
    }

  /* Separate the addresses. */
  *end_str = '\0';
  end_str++;

  if (!is_ipv4_address (ip_str) || !isdigit (*end_str))
    {
      g_free (ip_str);
      return 0;
    }

  p = NULL;
  end = strtol (end_str, &p, 10);
  g_free (ip_str);

  if (*p || end < 0 || end > 255)
    return 0;

  return 1;
}

/**
 * @brief Gets the first and last IPv4 addresses from a short range-expressed
 * network. "192.168.1.1-40" would give 192.168.1.1 as first and 192.168.1.40 as
 * last.
 *
 * @param[in]   str     String containing short range-expressed network.
 * @param[out]  first   First IP address in block.
 * @param[out]  last    Last IP address in block.
 *
 * @return -1 if error, 0 else.
 */
static int
short_range_network_ips (const char *str, struct in_addr *first,
                         struct in_addr *last)
{
  char *first_str, *last_str;
  int end;

  if (str == NULL || first == NULL || last == NULL)
    return -1;

  first_str = g_strdup (str);
  last_str = strchr (first_str, '-');
  if (last_str == NULL)
    {
      g_free (first_str);
      return -1;
    }

  /* Separate the two IPs. */
  *last_str = '\0';
  last_str++;
  end = atoi (last_str);

  /* Get the first IP */
  if (inet_pton (AF_INET, first_str, first) != 1)
    {
      g_free (first_str);
      return -1;
    }

  /* Get the last IP */
  last->s_addr = htonl ((ntohl (first->s_addr) & 0xffffff00) + end);

  g_free (first_str);
  return 0;
}

/**
 * @brief Checks if a buffer points to a valid hostname.
 * Valid characters include: Alphanumerics, dot (.), dash (-) and underscore (_)
 * up to 255 characters.
 *
 * @param[in]   str Buffer to check in.
 *
 * @return 1 if valid hostname, 0 otherwise.
 */
static int
is_hostname (const char *str)
{
  const char *h = str;

  while (*h && (isalnum (*h) || strchr ("-_.", *h)))
    h++;

  /* Valid string if no other chars, and length is 255 at most. */
  if (*h == '\0' && h - str < 256)
    return 1;

  return 0;
}

/**
 * @brief Checks if a buffer points to an IPv6 CIDR-expressed block.
 * "2620:0:2d0:200::7/120" is valid, "2620:0:2d0:200::7/129" is not.
 *
 * @param[in]   str Buffer to check in.
 *
 * @return 1 if valid IPv6 CIDR-expressed block, 0 otherwise.
 */
static int
is_cidr6_block (const char *str)
{
  long block;
  char *addr6_str, *block_str, *p;

  addr6_str = g_strdup (str);
  block_str = strchr (addr6_str, '/');
  if (block_str == NULL)
    {
      g_free (addr6_str);
      return 0;
    }

  /* Separate the address from the block value. */
  *block_str = '\0';
  block_str++;

  if (!is_ipv6_address (addr6_str) || !isdigit (*block_str))
    {
      g_free (addr6_str);
      return 0;
    }

  p = NULL;
  block = strtol (block_str, &p, 10);
  g_free (addr6_str);

  if (*p || block <= 0 || block > 128)
    return 0;

  return 1;
}

/**
 * @brief Gets the network block value from a CIDR-expressed block string.
 * For "192.168.1.1/24" it is 24.
 *
 * @param[in]   str     Buffer containing CIDR-expressed block.
 * @param[out]  block   Variable to store block value.
 *
 * @return -1 if error, 0 otherwise.
 */
static int
cidr6_get_block (const char *str, unsigned int *block)
{
  if (str == NULL || block == NULL)
    return -1;

  if (sscanf (str, "%*[0-9a-fA-F.:]/%3u", block) != 1)
    return -1;

  return 0;
}

/**
 * @brief Gets the IPv4 value from a CIDR-expressed block.
 * eg. For "192.168.1.10/24" it is "192.168.1.10".
 *
 * @param[in]   str     String containing CIDR-expressed block.
 * @param[out]  addr6   Variable to store the IPv4 address value.
 *
 * @return -1 if error, 0 otherwise.
 */
static int
cidr6_get_ip (const char *str, struct in6_addr *addr6)
{
  gchar *addr6_str, *tmp;

  if (str == NULL || addr6 == NULL)
    return -1;

  addr6_str = g_strdup (str);
  tmp = strchr (addr6_str, '/');
  if (tmp == NULL)
    {
      g_free (addr6_str);
      return -1;
    }
  *tmp = '\0';

  if (inet_pton (AF_INET6, addr6_str, addr6) != 1)
    return -1;

  g_free (addr6_str);
  return 0;
}

/**
 * @brief Gets the first and last usable IPv4 addresses from a CIDR-expressed
 * block. eg. "192.168.1.0/24 would give 192.168.1.1 as first and 192.168.1.254
 * as last. Thus, it skips the network and broadcast addresses.
 *
 * @param[in]   str     Buffer containing CIDR-expressed block.
 * @param[out]  first   First IPv4 address in block.
 * @param[out]  last    Last IPv4 address in block.
 *
 * @return -1 if error, 0 else.
 */
static int
cidr6_block_ips (const char *str, struct in6_addr *first, struct in6_addr *last)
{
  unsigned int block;
  int i, j;

  if (str == NULL || first == NULL || last == NULL)
    return -1;

  /* Get IP and block values. */
  if (cidr6_get_block (str, &block) == -1)
    return -1;
  if (cidr6_get_ip (str, first) == -1)
    return -1;
  memcpy (&last->s6_addr, &first->s6_addr, 16);

  /* /128 => Specified address is the first and last one. */
  if (block == 128)
    return 0;

  /* First IP: And with mask and increment to skip network address. */
  j = 15;
  for (i = (128 - block) / 8; i > 0; i--)
    {
      first->s6_addr[j] = 0;
      j--;
    }
  first->s6_addr[j] &= 0xff ^ ((1 << ((128 - block) % 8)) - 1);

  /* Last IP: Broadcast address - 1. */
  j = 15;
  for (i = (128 - block) / 8; i > 0; i--)
    {
      last->s6_addr[j] = 0xff;
      j--;
    }
  last->s6_addr[j] |= (1 << ((128 - block) % 8)) - 1;

  /* /127 => Only two addresses. Don't skip network / broadcast addresses.*/
  if (block == 127)
    return 0;

  /* Increment first IP. */
  for (i = 15; i >= 0; --i)
    if (first->s6_addr[i] < 255)
      {
        first->s6_addr[i]++;
        break;
      }
    else
      first->s6_addr[i] = 0;
  /* Decrement last IP. */
  for (i = 15; i >= 0; --i)
    if (last->s6_addr[i] > 0)
      {
        last->s6_addr[i]--;
        break;
      }
    else
      last->s6_addr[i] = 0xff;

  return 0;
}

/**
 * @brief Checks if a buffer points to a valid long IPv6 range-expressed
 * network. "::fee5-::1:530" is valid.
 *
 * @param[in]   str Buffer to check in.
 *
 * @return 1 if valid long range-expressed network, 0 otherwise.
 */
static int
is_long_range6_network (const char *str)
{
  char *first_str, *second_str;
  int ret;

  first_str = g_strdup (str);
  second_str = strchr (first_str, '-');
  if (second_str == NULL)
    {
      g_free (first_str);
      return 0;
    }

  /* Separate the addresses. */
  *second_str = '\0';
  second_str++;

  ret = is_ipv6_address (first_str) && is_ipv6_address (second_str);
  g_free (first_str);

  return ret;
}

/**
 * @brief Gets the first and last IPv6 addresses from a long range-expressed
 * network. eg. "::1:200:7-::1:205:500" would give ::1:200:7 as first and
 * ::1:205:500 as last.
 *
 * @param[in]   str     String containing long IPv6 range-expressed network.
 * @param[out]  first   First IPv6 address in range.
 * @param[out]  last    Last IPv6 address in range.
 *
 * @return -1 if error, 0 else.
 */
static int
long_range6_network_ips (const char *str, struct in6_addr *first,
                         struct in6_addr *last)
{
  char *first_str, *last_str;

  if (str == NULL || first == NULL || last == NULL)
    return -1;

  first_str = g_strdup (str);
  last_str = strchr (first_str, '-');
  if (last_str == NULL)
    {
      g_free (first_str);
      return -1;
    }

  /* Separate the two IPs. */
  *last_str = '\0';
  last_str++;

  if (inet_pton (AF_INET6, first_str, first) != 1
      || inet_pton (AF_INET6, last_str, last) != 1)
    {
      g_free (first_str);
      return -1;
    }

  g_free (first_str);
  return 0;
}

/**
 * @brief Checks if a buffer points to a valid short IPv6 range-expressed
 * network. "::200:ff:1-fee5" is valid.
 *
 * @param   str String to check in.
 *
 * @return 1 if str points to a valid short-range IPv6 network, 0 otherwise.
 */
static int
is_short_range6_network (const char *str)
{
  char *ip_str, *end_str, *p;

  ip_str = g_strdup (str);
  end_str = strchr (ip_str, '-');
  if (end_str == NULL)
    {
      g_free (ip_str);
      return 0;
    }

  /* Separate the addresses. */
  *end_str = '\0';
  end_str++;

  if (!is_ipv6_address (ip_str) || *end_str == '\0')
    {
      g_free (ip_str);
      return 0;
    }

  p = end_str;
  /* Check that the 2nd part is at most 4 hexadecimal characters. */
  while (isxdigit (*p) && p++)
    ;
  if (*p || p - end_str > 4)
    {
      g_free (ip_str);
      return 0;
    }

  g_free (ip_str);
  return 1;
}

/**
 * @brief Gets the first and last IPv6 addresses from a short range-expressed
 * network. eg. "\::ffee:1:1001-1005" would give \::ffee:1:1001 as first and
 * \::ffee:1:1005 as last.
 *
 * @param[in]   str     String containing short IPv6 range-expressed network.
 * @param[out]  first   First IPv6 address in range.
 * @param[out]  last    Last IPv6 address in range.
 *
 * @return -1 if error, 0 else.
 */
static int
short_range6_network_ips (const char *str, struct in6_addr *first,
                          struct in6_addr *last)
{
  char *first_str, *last_str;
  long int end;

  if (str == NULL || first == NULL || last == NULL)
    return -1;

  first_str = g_strdup (str);
  last_str = strchr (first_str, '-');
  if (last_str == NULL)
    {
      g_free (first_str);
      return -1;
    }

  /* Separate the first IP. */
  *last_str = '\0';
  last_str++;

  if (inet_pton (AF_INET6, first_str, first) != 1)
    {
      g_free (first_str);
      return -1;
    }

  /* Calculate the last IP. */
  memcpy (last, first, sizeof (*last));
  end = strtol (last_str, NULL, 16);
  memcpy (&last->s6_addr[15], &end, 1);
  memcpy (&last->s6_addr[14], ((char *) &end) + 1, 1);

  g_free (first_str);
  return 0;
}

/**
 * @brief Determines the host type in a buffer.
 *
 * @param[in] str_stripped   Buffer that contains host definition, could a be
 * hostname, single IPv4 or IPv6, CIDR-expressed block etc,.
 *
 * @return Host_TYPE_*, -1 if error.
 */
int
gvm_get_host_type (const gchar *str_stripped)
{
  /*
   * We have a single element with no leading or trailing
   * white spaces. This element could represent different host
   * definitions: single IPs, host names, CIDR-expressed blocks,
   * range-expressed networks, IPv6 addresses.
   */

  /* Null or empty string. */
  if (str_stripped == NULL || *str_stripped == '\0')
    return -1;

  /* Check for regular single IPv4 address. */
  if (is_ipv4_address (str_stripped))
    return HOST_TYPE_IPV4;

  /* Check for regular single IPv6 address. */
  if (is_ipv6_address (str_stripped))
    return HOST_TYPE_IPV6;

  /* Check for regular IPv4 CIDR-expressed block like "192.168.12.0/24" */
  if (is_cidr_block (str_stripped))
    return HOST_TYPE_CIDR_BLOCK;

  /* Check for short range-expressed networks "192.168.12.5-40" */
  if (is_short_range_network (str_stripped))
    return HOST_TYPE_RANGE_SHORT;

  /* Check for long range-expressed networks "192.168.1.0-192.168.3.44" */
  if (is_long_range_network (str_stripped))
    return HOST_TYPE_RANGE_LONG;

  /* Check for regular IPv6 CIDR-expressed block like "2620:0:2d0:200::7/120" */
  if (is_cidr6_block (str_stripped))
    return HOST_TYPE_CIDR6_BLOCK;

  /* Check for short range-expressed networks "::1-ef12" */
  if (is_short_range6_network (str_stripped))
    return HOST_TYPE_RANGE6_SHORT;

  /* Check for long IPv6 range-expressed networks like "::1:20:7-::1:25:3" */
  if (is_long_range6_network (str_stripped))
    return HOST_TYPE_RANGE6_LONG;

  /* Check for hostname. */
  if (is_hostname (str_stripped))
    return HOST_TYPE_NAME;

  return -1;
}

/**
 * @brief Creates a new gvm_vhost_t object.
 *
 * @param[in] value     Vhost value.
 * @param[in] source    Source of hostname.
 *
 * @return Pointer to new vhost object.
 */
gvm_vhost_t *
gvm_vhost_new (char *value, char *source)
{
  gvm_vhost_t *vhost;

  vhost = g_malloc0 (sizeof (gvm_vhost_t));
  vhost->value = value;
  vhost->source = source;

  return vhost;
}

/**
 * @brief Frees the memory occupied by an gvm_vhost_t object.
 *
 * @param[in] vhost Vhost to free.
 */
static void
gvm_vhost_free (gpointer vhost)
{
  if (vhost)
    {
      g_free (((gvm_vhost_t *) vhost)->value);
      g_free (((gvm_vhost_t *) vhost)->source);
    }
  g_free (vhost);
}

/**
 * @brief Creates a new gvm_host_t object.
 *
 * @return Pointer to new host object, NULL if creation fails.
 */
static gvm_host_t *
gvm_host_new ()
{
  gvm_host_t *host;

  host = g_malloc0 (sizeof (gvm_host_t));

  return host;
}

/**
 * @brief Frees the memory occupied by an gvm_host_t object.
 *
 * @param[in] host  Host to free.
 */
static void
gvm_host_free (gpointer host)
{
  gvm_host_t *h = host;
  if (h == NULL)
    return;

  /* If host of type hostname, free the name buffer, first. */
  if (h->type == HOST_TYPE_NAME)
    g_free (h->name);

  g_slist_free_full (h->vhosts, gvm_vhost_free);
  g_free (h);
}

/**
 * @brief Inserts a host object at the end of a hosts collection.
 *
 * @param[in] hosts Hosts in which to insert the host.
 * @param[in] host  Host to insert.
 */
static void
gvm_hosts_add (gvm_hosts_t *hosts, gvm_host_t *host)
{
  if (hosts->count == hosts->max_size)
    {
      hosts->max_size *= 4;
      hosts->hosts =
        g_realloc_n (hosts->hosts, hosts->max_size, sizeof (*hosts->hosts));
    }
  hosts->hosts[hosts->count] = host;
  hosts->count++;
}

/**
 * @brief Creates a hosts collection from a hosts string.
 *
 * @param[in] hosts_str String of hosts.
 *
 * @return Hosts collection.
 */
static gvm_hosts_t *
gvm_hosts_init (const char *hosts_str)
{
  gvm_hosts_t *hosts;

  hosts = g_malloc0 (sizeof (gvm_hosts_t));
  hosts->max_size = 1024;
  hosts->hosts = g_malloc0_n (hosts->max_size, sizeof (gvm_host_t *));
  hosts->orig_str = g_strdup (hosts_str);
  return hosts;
}

/**
 * @brief Fill the gaps in the array of a hosts collection, which are caused by
 * the removal of host entries.
 *
 * @param[in] hosts Hosts collection to fill gaps in.
 */
static void
gvm_hosts_fill_gaps (gvm_hosts_t *hosts)
{
  size_t i;
  if (!hosts)
    return;

  for (i = 0; i < hosts->max_size; i++)
    {
      if (!hosts->hosts[i])
        {
          size_t j;

          /* Fill the gap with the closest host entry, in order to keep the
           * sequential ordering. */
          for (j = i + 1; j < hosts->max_size; j++)
            {
              if (hosts->hosts[j])
                {
                  hosts->hosts[i] = hosts->hosts[j];
                  hosts->hosts[j] = NULL;
                  break;
                }
            }
          /* No more entries left, ie. the empty space between count and
           * max_size. */
          if (!hosts->hosts[i])
            return;
        }
    }
}

/**
 * @brief Removes duplicate hosts values from an gvm_hosts_t structure.
 * Also resets the iterator current position.
 *
 * @param[in] hosts hosts collection from which to remove duplicates.
 */
static void
gvm_hosts_deduplicate (gvm_hosts_t *hosts)
{
  /**
   * Uses a hash table in order to deduplicate the hosts list in O(N) time.
   */
  GHashTable *name_table;
  size_t i, duplicates = 0;

  if (hosts == NULL)
    return;
  name_table = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  for (i = 0; i < hosts->count; i++)
    {
      gchar *name;

      if ((name = gvm_host_value_str (hosts->hosts[i])))
        {
          gvm_host_t *host, *removed = hosts->hosts[i];

          host = g_hash_table_lookup (name_table, name);
          if (host)
            {
              /* Remove duplicate host. Add its vhosts to the original host. */
              host->vhosts = g_slist_concat (host->vhosts, removed->vhosts);
              removed->vhosts = NULL;
              gvm_host_free (removed);
              hosts->hosts[i] = NULL;
              duplicates++;
              g_free (name);
            }
          else
            g_hash_table_insert (name_table, name, hosts->hosts[i]);
        }
    }

  if (duplicates)
    gvm_hosts_fill_gaps (hosts);
  g_hash_table_destroy (name_table);
  hosts->count -= duplicates;
  hosts->removed += duplicates;
  hosts->current = 0;
  malloc_trim (0);
}

/**
 * @brief Creates a new gvm_hosts_t structure and the associated hosts
 * objects from the provided hosts_str.
 *
 * @param[in] hosts_str The hosts string. A copy will be created of this within
 *                      the returned struct.
 * @param[in] max_hosts Max number of hosts in hosts_str. 0 means unlimited.
 *
 * @return NULL if error or hosts_str contains more than max hosts. Otherwise, a
 * hosts structure that should be released using @ref gvm_hosts_free.
 */
gvm_hosts_t *
gvm_hosts_new_with_max (const gchar *hosts_str, unsigned int max_hosts)
{
  gvm_hosts_t *hosts;
  gchar **host_element, **split;
  gchar *str;

  if (hosts_str == NULL)
    return NULL;

  /* Normalize separator: Transform newlines into commas. */
  hosts = gvm_hosts_init (hosts_str);
  str = hosts->orig_str;
  while (*str)
    {
      if (*str == '\n')
        *str = ',';
      str++;
    }

  /* Split comma-separated list into single host-specifications */
  split = g_strsplit (hosts->orig_str, ",", 0);

  /* first element of the split list */
  host_element = split;
  while (*host_element)
    {
      int host_type;
      gchar *stripped = g_strstrip (*host_element);

      if (stripped == NULL || *stripped == '\0')
        {
          host_element++;
          continue;
        }

      /* IPv4, hostname, IPv6, collection (short/long range, cidr block) etc,. ?
       */
      /* -1 if error. */
      host_type = gvm_get_host_type (stripped);

      switch (host_type)
        {
        case HOST_TYPE_NAME:
        case HOST_TYPE_IPV4:
        case HOST_TYPE_IPV6:
          {
            /* New host. */
            gvm_host_t *host = gvm_host_new ();
            host->type = host_type;
            if (host_type == HOST_TYPE_NAME)
              host->name = g_ascii_strdown (stripped, -1);
            else if (host_type == HOST_TYPE_IPV4)
              {
                if (inet_pton (AF_INET, stripped, &host->addr) != 1)
                  break;
              }
            else if (host_type == HOST_TYPE_IPV6)
              {
                if (inet_pton (AF_INET6, stripped, &host->addr6) != 1)
                  break;
              }
            gvm_hosts_add (hosts, host);
            break;
          }
        case HOST_TYPE_CIDR_BLOCK:
        case HOST_TYPE_RANGE_SHORT:
        case HOST_TYPE_RANGE_LONG:
          {
            struct in_addr first, last;
            uint32_t current;
            int (*ips_func) (const char *, struct in_addr *, struct in_addr *);

            if (host_type == HOST_TYPE_CIDR_BLOCK)
              ips_func = cidr_block_ips;
            else if (host_type == HOST_TYPE_RANGE_SHORT)
              ips_func = short_range_network_ips;
            else
              ips_func = long_range_network_ips;

            if (ips_func (stripped, &first, &last) == -1)
              break;

            /* Make sure that first actually comes before last */
            if (ntohl (first.s_addr) > ntohl (last.s_addr))
              break;

            /* Add addresses from first to last as single hosts. */
            current = first.s_addr;
            while (ntohl (current) <= ntohl (last.s_addr))
              {
                gvm_host_t *host;
                if (max_hosts > 0 && hosts->count > max_hosts)
                  {
                    g_strfreev (split);
                    gvm_hosts_free (hosts);
                    return NULL;
                  }
                host = gvm_host_new ();
                host->type = HOST_TYPE_IPV4;
                host->addr.s_addr = current;
                gvm_hosts_add (hosts, host);
                /* Next IP address. */
                current = htonl (ntohl (current) + 1);
              }
            break;
          }
        case HOST_TYPE_CIDR6_BLOCK:
        case HOST_TYPE_RANGE6_LONG:
        case HOST_TYPE_RANGE6_SHORT:
          {
            struct in6_addr first, last;
            unsigned char current[16];
            int (*ips_func) (const char *, struct in6_addr *,
                             struct in6_addr *);

            if (host_type == HOST_TYPE_CIDR6_BLOCK)
              ips_func = cidr6_block_ips;
            else if (host_type == HOST_TYPE_RANGE6_SHORT)
              ips_func = short_range6_network_ips;
            else
              ips_func = long_range6_network_ips;

            if (ips_func (stripped, &first, &last) == -1)
              break;

            /* Make sure the first comes before the last. */
            if (memcmp (&first.s6_addr, &last.s6_addr, 16) > 0)
              break;

            /* Add addresses from first to last as single hosts. */
            memcpy (current, &first.s6_addr, 16);
            while (memcmp (current, &last.s6_addr, 16) <= 0)
              {
                int i;
                gvm_host_t *host;

                if (max_hosts > 0 && hosts->count > max_hosts)
                  {
                    g_strfreev (split);
                    gvm_hosts_free (hosts);
                    return NULL;
                  }
                host = gvm_host_new ();
                host->type = HOST_TYPE_IPV6;
                memcpy (host->addr6.s6_addr, current, 16);
                gvm_hosts_add (hosts, host);
                /* Next IPv6 address. */
                for (i = 15; i >= 0; --i)
                  if (current[i] < 255)
                    {
                      current[i]++;
                      break;
                    }
                  else
                    current[i] = 0;
              }
            break;
          }
        case -1:
        default:
          /* Invalid host string. */
          g_strfreev (split);
          gvm_hosts_free (hosts);
          return NULL;
        }
      host_element++; /* move on to next element of split list */
      if (max_hosts > 0 && hosts->count > max_hosts)
        {
          g_strfreev (split);
          gvm_hosts_free (hosts);
          return NULL;
        }
    }

  /* No need to check for duplicates when a hosts string contains a
   * single (IP/Hostname/Range/Subnetwork) entry. */
  if (g_strv_length (split) > 1)
    gvm_hosts_deduplicate (hosts);

  g_strfreev (split);
  malloc_trim (0);
  return hosts;
}

/**
 * @brief Creates a new gvm_hosts_t structure and the associated hosts
 * objects from the provided hosts_str.
 *
 * @param[in] hosts_str The hosts string. A copy will be created of this within
 *                      the returned struct.
 *
 * @return NULL if error, otherwise, a hosts structure that should be released
 * using @ref gvm_hosts_free.
 */
gvm_hosts_t *
gvm_hosts_new (const gchar *hosts_str)
{
  return gvm_hosts_new_with_max (hosts_str, 0);
}

/**
 * @brief Gets the next gvm_host_t from a gvm_hosts_t structure. The
 * state of iteration is kept internally within the gvm_hosts structure.
 *
 * @param[in]   hosts     gvm_hosts_t structure to get next host from.
 *
 * @return Pointer to host. NULL if error or end of hosts.
 */
gvm_host_t *
gvm_hosts_next (gvm_hosts_t *hosts)
{
  if (!hosts || hosts->current == hosts->count)
    return NULL;

  return hosts->hosts[hosts->current++];
}

/**
 * @brief Frees memory occupied by an gvm_hosts_t structure.
 *
 * @param[in] hosts The hosts collection to free.
 *
 */
void
gvm_hosts_free (gvm_hosts_t *hosts)
{
  size_t i;

  if (hosts == NULL)
    return;

  if (hosts->orig_str)
    g_free (hosts->orig_str);
  for (i = 0; i < hosts->count; i++)
    gvm_host_free (hosts->hosts[i]);
  g_free (hosts->hosts);
  g_free (hosts);
}

/**
 * @brief Randomizes the order of the hosts objects in the collection.
 * Not to be used while iterating over the single hosts as it resets the
 * iterator.
 *
 * @param[in] hosts The hosts collection to shuffle.
 */
void
gvm_hosts_shuffle (gvm_hosts_t *hosts)
{
  size_t i = 0;
  GRand *rand;

  if (hosts == NULL)
    return;

  /* Shuffle the array. */
  rand = g_rand_new ();
  for (i = 0; i < hosts->count; i++)
    {
      void *tmp;
      int j = g_rand_int_range (rand, 0, hosts->count);

      tmp = hosts->hosts[i];
      hosts->hosts[i] = hosts->hosts[j];
      hosts->hosts[j] = tmp;
    }

  hosts->current = 0;
  g_rand_free (rand);
}

/**
 * @brief Reverses the order of the hosts objects in the collection.
 * Not to be used while iterating over the single hosts as it resets the
 * iterator.
 *
 * @param[in] hosts The hosts collection to reverse.
 */
void
gvm_hosts_reverse (gvm_hosts_t *hosts)
{
  size_t i, j;
  if (hosts == NULL)
    return;

  for (i = 0, j = hosts->count - 1; i < j; i++, j--)
    {
      gvm_host_t *tmp = hosts->hosts[i];
      hosts->hosts[i] = hosts->hosts[j];
      hosts->hosts[j] = tmp;
    }
  hosts->current = 0;
}

/**
 * @brief Resolves host objects of type name in a hosts collection, replacing
 * hostnames with IPv4 values.
 * Not to be used while iterating over the single hosts as it resets the
 * iterator.
 *
 * @param[in] hosts         The hosts collection from which to exclude.
 */
void
gvm_hosts_resolve (gvm_hosts_t *hosts)
{
  size_t i, new_entries = 0;

  for (i = 0; i < hosts->count; i++)
    {
      GSList *list, *tmp;
      gvm_host_t *host = hosts->hosts[i];

      if (host->type != HOST_TYPE_NAME)
        continue;

      list = tmp = gvm_resolve_list (host->name);
      while (tmp)
        {
          /* Create a new host for each IP address. */
          gvm_host_t *new;
          struct in6_addr *ip6 = tmp->data;
          gvm_vhost_t *vhost;

          new = gvm_host_new ();
          if (ip6->s6_addr32[0] != 0 || ip6->s6_addr32[1] != 0
              || ip6->s6_addr32[2] != htonl (0xffff))
            {
              new->type = HOST_TYPE_IPV6;
              memcpy (&new->addr6, ip6, sizeof (new->addr6));
            }
          else
            {
              new->type = HOST_TYPE_IPV4;
              memcpy (&new->addr6, &ip6->s6_addr32[3], sizeof (new->addr));
            }
          vhost =
            gvm_vhost_new (g_strdup (host->name), g_strdup ("Forward-DNS"));
          new->vhosts = g_slist_prepend (new->vhosts, vhost);
          gvm_hosts_add (hosts, new);
          tmp = tmp->next;
          new_entries = 1;
        }
      /* Remove hostname from list, as it was either replaced by IPs, or
       * is unresolvable. */
      gvm_host_free (host);
      hosts->hosts[i] = NULL;
      hosts->count--;
      hosts->removed++;
      if (!list)
        g_warning ("Couldn't resolve hostname %s", host->name);
      else
        gvm_hosts_fill_gaps (hosts);
      g_slist_free_full (list, g_free);
    }
  if (new_entries)
    gvm_hosts_deduplicate (hosts);
  hosts->current = 0;
}

/**
 * @brief Exclude a list of vhosts from a host's vhosts list.
 *
 * @param[in] host  The host whose vhosts are to be excluded from.
 * @param[in] excluded_str  String of hosts to exclude.
 *
 * @return Number of excluded vhosts.
 */
int
gvm_vhosts_exclude (gvm_host_t *host, const char *excluded_str)
{
  GSList *vhost;
  char **excluded;
  int ret = 0;

  if (!host || !excluded_str)
    return ret;

  vhost = host->vhosts;
  excluded = g_strsplit (excluded_str, ",", 0);
  if (!excluded || !*excluded)
    {
      g_strfreev (excluded);
      return ret;
    }
  while (vhost)
    {
      char **tmp = excluded;
      char *value = ((gvm_vhost_t *) vhost->data)->value;

      while (*tmp)
        {
          if (!strcasecmp (value, g_strstrip (*tmp)))
            {
              gvm_vhost_free (vhost->data);
              host->vhosts = vhost = g_slist_delete_link (host->vhosts, vhost);
              ret++;
              break;
            }
          tmp++;
          if (!*tmp)
            {
              vhost = vhost->next;
              break;
            }
        }
    }
  g_strfreev (excluded);

  return ret;
}

/**
 * @brief Excludes a set of hosts provided as a string from a hosts collection.
 * Not to be used while iterating over the single hosts as it resets the
 * iterator.
 *
 * @param[in] hosts         The hosts collection from which to exclude.
 * @param[in] excluded_str  String of hosts to exclude.
 * @param[in] max_hosts     Max number of hosts in hosts_str. 0 means unlimited.
 *
 * @return Number of excluded hosts, -1 if error.
 */
int
gvm_hosts_exclude_with_max (gvm_hosts_t *hosts, const char *excluded_str,
                            unsigned int max_hosts)
{
  /**
   * Uses a hash table in order to exclude hosts in O(N+M) time.
   */
  gvm_hosts_t *excluded_hosts;
  GHashTable *name_table;
  size_t excluded = 0, i;

  if (hosts == NULL || excluded_str == NULL)
    return -1;

  excluded_hosts = gvm_hosts_new_with_max (excluded_str, max_hosts);
  if (excluded_hosts == NULL)
    return -1;

  if (gvm_hosts_count (excluded_hosts) == 0)
    {
      gvm_hosts_free (excluded_hosts);
      return 0;
    }

  /* Hash host values from excluded hosts list. */
  name_table = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  for (i = 0; i < excluded_hosts->count; i++)
    {
      gchar *name;

      if ((name = gvm_host_value_str (excluded_hosts->hosts[i])))
        g_hash_table_insert (name_table, name, hosts);
    }

  /* Check for hosts values in hash table. */
  for (i = 0; i < hosts->count; i++)
    {
      gchar *name;

      if ((name = gvm_host_value_str (hosts->hosts[i])))
        {
          if (g_hash_table_lookup (name_table, name))
            {
              gvm_host_free (hosts->hosts[i]);
              hosts->hosts[i] = NULL;
              excluded++;
              g_free (name);
              continue;
            }
          g_free (name);
        }
    }

  /* Cleanup. */
  if (excluded)
    gvm_hosts_fill_gaps (hosts);
  hosts->count -= excluded;
  hosts->removed += excluded;
  hosts->current = 0;
  g_hash_table_destroy (name_table);
  gvm_hosts_free (excluded_hosts);
  return excluded;
}

/**
 * @brief Excludes a set of hosts provided as a string from a hosts collection.
 * Not to be used while iterating over the single hosts as it resets the
 * iterator.
 *
 * @param[in] hosts         The hosts collection from which to exclude.
 * @param[in] excluded_str  String of hosts to exclude.
 *
 * @return Number of excluded hosts, -1 if error.
 */
int
gvm_hosts_exclude (gvm_hosts_t *hosts, const char *excluded_str)
{
  return gvm_hosts_exclude_with_max (hosts, excluded_str, 0);
}

/**
 * @brief Checks for a host object reverse dns lookup existence.
 *
 * @param[in] host The host to reverse-lookup.
 *
 * @return Result of look-up, NULL otherwise.
 */
char *
gvm_host_reverse_lookup (gvm_host_t *host)
{
  if (host == NULL)
    return NULL;

  if (host->type == HOST_TYPE_NAME)
    return NULL;
  else if (host->type == HOST_TYPE_IPV4)
    {
      struct sockaddr_in sa;
      int retry = 2;
      gchar hostname[1000];

      bzero (&sa, sizeof (struct sockaddr));
      sa.sin_addr = host->addr;
      sa.sin_family = AF_INET;
      while (retry--)
        {
          int ret = getnameinfo ((struct sockaddr *) &sa, sizeof (sa), hostname,
                                 sizeof (hostname), NULL, 0, NI_NAMEREQD);
          if (!ret)
            return g_ascii_strdown (hostname, -1);
          if (ret != EAI_AGAIN)
            break;
        }
      return NULL;
    }
  else if (host->type == HOST_TYPE_IPV6)
    {
      struct sockaddr_in6 sa;
      char hostname[1000];

      bzero (&sa, sizeof (struct sockaddr));
      memcpy (&sa.sin6_addr, &host->addr6, 16);
      sa.sin6_family = AF_INET6;

      if (getnameinfo ((struct sockaddr *) &sa, sizeof (sa), hostname,
                       sizeof (hostname), NULL, 0, NI_NAMEREQD))
        return NULL;
      else
        return g_ascii_strdown (hostname, -1);
    }
  else
    return NULL;
}

/**
 * @brief Verifies that hostname value resolves to a host's IP.
 *
 * @param[in] host  The host whose IP is to be checked against.
 * @param[in] value Hostname value to verify.
 *
 * @return 0 if hostname resolves to host's IP, -1 otherwise.
 */
static int
host_name_verify (gvm_host_t *host, const char *value)
{
  GSList *list, *tmp;
  char *host_str;
  int ret = -1;

  assert (host);
  assert (value);
  host_str = gvm_host_value_str (host);
  list = tmp = gvm_resolve_list (value);
  while (tmp)
    {
      char buffer[INET6_ADDRSTRLEN];
      addr6_to_str (tmp->data, buffer);
      if (!strcasecmp (host_str, buffer))
        {
          ret = 0;
          break;
        }
      tmp = tmp->next;
    }
  g_free (host_str);
  g_slist_free_full (list, g_free);
  return ret;
}

/**
 * @brief Add a host's reverse-lookup name to the vhosts list.
 *
 * @param[in] host  The host to which we add the vhost.
 */
void
gvm_host_add_reverse_lookup (gvm_host_t *host)
{
  GSList *vhosts;
  gvm_vhost_t *vhost;
  char *value;

  if (!host || host->type == HOST_TYPE_NAME)
    return;

  value = gvm_host_reverse_lookup (host);
  if (!value)
    return;
  if (host_name_verify (host, value))
    {
      g_free (value);
      return;
    }
  /* Don't add vhost, if already in the list. */
  vhosts = host->vhosts;
  while (vhosts)
    {
      if (!strcasecmp (((gvm_vhost_t *) vhosts->data)->value, value))
        {
          g_free (value);
          return;
        }
      vhosts = vhosts->next;
    }
  vhost = gvm_vhost_new (value, g_strdup ("Reverse-DNS"));
  host->vhosts = g_slist_prepend (host->vhosts, vhost);
}

/**
 * @brief Removes hosts that don't reverse-lookup from the hosts collection.
 * Not to be used while iterating over the single hosts as it resets the
 * iterator.
 *
 * @param[in] hosts The hosts collection to filter.
 *
 * @return Number of hosts removed, -1 if error.
 */
int
gvm_hosts_reverse_lookup_only (gvm_hosts_t *hosts)
{
  size_t i, count = 0;

  if (hosts == NULL)
    return -1;

  for (i = 0; i < hosts->count; i++)
    {
      gchar *name = gvm_host_reverse_lookup (hosts->hosts[i]);

      if (name == NULL)
        {
          gvm_host_free (hosts->hosts[i]);
          hosts->hosts[i] = NULL;
          count++;
        }
      else
        g_free (name);
    }

  if (count)
    gvm_hosts_fill_gaps (hosts);
  hosts->count -= count;
  hosts->removed += count;
  hosts->current = 0;
  return count;
}

/**
 * @brief Removes hosts duplicates that reverse-lookup to the same value.
 * Not to be used while iterating over the single hosts as it resets the
 * iterator.
 *
 * @param[in] hosts The hosts collection to filter.
 *
 * @return Number of hosts removed, -1 if error.
 */
int
gvm_hosts_reverse_lookup_unify (gvm_hosts_t *hosts)
{
  /**
   * Uses a hash table in order to unify the hosts list in O(N) time.
   */
  size_t i, count = 0;
  GHashTable *name_table;

  if (hosts == NULL)
    return -1;

  name_table = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  for (i = 0; i < hosts->count; i++)
    {
      gchar *name;

      if ((name = gvm_host_reverse_lookup (hosts->hosts[i])))
        {
          if (g_hash_table_lookup (name_table, name))
            {
              gvm_host_free (hosts->hosts[i]);
              hosts->hosts[i] = NULL;
              count++;
              g_free (name);
            }
          else
            {
              /* Insert in the hash table. Value not important. */
              g_hash_table_insert (name_table, name, hosts);
            }
        }
    }

  if (count)
    gvm_hosts_fill_gaps (hosts);
  g_hash_table_destroy (name_table);
  hosts->removed += count;
  hosts->count -= count;
  hosts->current = 0;
  return count;
}

/**
 * @brief Gets the count of single hosts objects in a hosts collection.
 *
 * @param[in] hosts The hosts collection to count hosts of.
 *
 * @return The number of single hosts.
 */
unsigned int
gvm_hosts_count (const gvm_hosts_t *hosts)
{
  return hosts ? hosts->count : 0;
}

/**
 * @brief Gets the count of single values in hosts string that were removed
 * (duplicates / excluded.)
 *
 * @param[in] hosts The hosts collection.
 *
 * @return The number of removed values.
 */
unsigned int
gvm_hosts_removed (const gvm_hosts_t *hosts)
{
  return hosts ? hosts->removed : 0;
}

/**
 * @brief Returns whether a host has an equal host in a hosts collection.
 * eg. 192.168.10.1 has an equal in list created from
 * "192.168.10.1-5, 192.168.10.10-20" string while 192.168.10.7 doesn't.
 *
 * @param[in] host  The host object.
 * @param[in] addr  Optional pointer to ip address. Could be used so that host
 *                  isn't resolved multiple times when type is HOST_TYPE_NAME.
 * @param[in] hosts Hosts collection.
 *
 * @return 1 if host has equal in hosts, 0 otherwise.
 */
int
gvm_host_in_hosts (const gvm_host_t *host, const struct in6_addr *addr,
                   const gvm_hosts_t *hosts)
{
  char *host_str;
  size_t i;

  if (host == NULL || hosts == NULL)
    return 0;

  host_str = gvm_host_value_str (host);

  for (i = 0; i < hosts->count; i++)
    {
      gvm_host_t *current_host = hosts->hosts[i];
      char *tmp = gvm_host_value_str (current_host);

      if (strcasecmp (host_str, tmp) == 0)
        {
          g_free (host_str);
          g_free (tmp);
          return 1;
        }
      g_free (tmp);

      /* Hostnames in hosts list shouldn't be resolved. */
      if (addr && gvm_host_type (current_host) != HOST_TYPE_NAME)
        {
          struct in6_addr tmpaddr;
          gvm_host_get_addr6 (current_host, &tmpaddr);

          if (memcmp (addr->s6_addr, &tmpaddr.s6_addr, 16) == 0)
            {
              g_free (host_str);
              return 1;
            }
        }
    }

  g_free (host_str);
  return 0;
}

/**
 * @brief Gets a host object's type.
 *
 * @param[in] host  The host object.
 *
 * @return Host type.
 */
enum host_type
gvm_host_type (const gvm_host_t *host)
{
  assert (host);
  return host->type;
}

/**
 * @brief Gets a host's type in printable format.
 *
 * @param[in] host  The host object.
 *
 * @return String representing host type. Statically allocated, thus, not to be
 * freed.
 */
gchar *
gvm_host_type_str (const gvm_host_t *host)
{
  if (host == NULL)
    return NULL;

  return host_type_str[host->type];
}

/**
 * @brief Gets a host's value in printable format.
 *
 * @param[in] host  The host object.
 *
 * @return String representing host value. To be freed with g_free().
 */
gchar *
gvm_host_value_str (const gvm_host_t *host)
{
  if (host == NULL)
    return NULL;

  switch (host->type)
    {
    case HOST_TYPE_NAME:
      return g_strdup (host->name);
      break;
    case HOST_TYPE_IPV4:
    case HOST_TYPE_IPV6:
      /* Handle both cases using inet_ntop(). */
      {
        int family, size;
        gchar *str;
        const void *srcaddr;

        if (host->type == HOST_TYPE_IPV4)
          {
            family = AF_INET;
            size = INET_ADDRSTRLEN;
            srcaddr = &host->addr;
          }
        else
          {
            family = AF_INET6;
            size = INET6_ADDRSTRLEN;
            srcaddr = &host->addr6;
          }

        str = g_malloc0 (size);
        if (inet_ntop (family, srcaddr, str, size) == NULL)
          {
            perror ("inet_ntop");
            g_free (str);
            return NULL;
          }
        return str;
      }
    default:
      return g_strdup ("Erroneous host type: Should be Hostname/IPv4/IPv6.");
    }
}

/**
 * @brief Resolves a host object's name to an IPv4 or IPv6 address. Host object
 * should be of type HOST_TYPE_NAME.
 *
 * @param[in] host      The host object whose name to resolve.
 * @param[out] dst      Buffer to store resolved address. Size must be at least
 *                      4 bytes for AF_INET and 16 bytes for AF_INET6.
 * @param[in] family    Either AF_INET or AF_INET6.
 *
 * @return -1 if error, 0 otherwise.
 */
int
gvm_host_resolve (const gvm_host_t *host, void *dst, int family)
{
  if (host == NULL || dst == NULL || host->type != HOST_TYPE_NAME)
    return -1;

  return gvm_resolve (host->name, dst, family);
}

/**
 * @brief Gives a host object's value as an IPv6 address.
 * If the host type is hostname, it resolves the IPv4 address then gives an
 * IPv4-mapped IPv6 address (eg. \::ffff:192.168.1.1 .)
 * If the host type is IPv4, it gives an IPv4-mapped IPv6 address.
 * If the host's type is IPv6, it gives the value directly.
 *
 * @param[in]  host     The host object whose value to get as IPv6.
 * @param[out] ip6      Buffer to store the IPv6 address.
 *
 * @return -1 if error, 0 otherwise.
 */
int
gvm_host_get_addr6 (const gvm_host_t *host, struct in6_addr *ip6)
{
  if (host == NULL || ip6 == NULL)
    return -1;

  switch (gvm_host_type (host))
    {
    case HOST_TYPE_IPV6:
      memcpy (ip6, &host->addr6, sizeof (struct in6_addr));
      return 0;

    case HOST_TYPE_IPV4:
      ipv4_as_ipv6 (&host->addr, ip6);
      return 0;

    case HOST_TYPE_NAME:
      {
        struct in_addr ip4;

        /* Fail if IPv4 and IPv6 both don't resolve. */
        if (gvm_host_resolve (host, &ip4, AF_INET) == 0)
          ipv4_as_ipv6 (&ip4, ip6);
        else if (gvm_host_resolve (host, ip6, AF_INET6) == -1)
          return -1;
        return 0;
      }

    default:
      return -1;
    }
}
