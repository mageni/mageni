/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2013-2019 Greenbone Networks GmbH
 * SPDX-FileComment: Implementation of networking related API.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef MAGENI_NETWORKING_H
#define MAGENI_NETWORKING_H

#include "array.h" /* for array_t */

#include <netdb.h> /* for struct in6_addr */

/**
 * @brief Possible port types.
 *
 * Used in Manager database. If any symbol changes then a migrator must be
 * added to update existing data.
 */
typedef enum
{
  PORT_PROTOCOL_TCP = 0,
  PORT_PROTOCOL_UDP = 1,
  PORT_PROTOCOL_OTHER = 2
} port_protocol_t;

/**
 * @brief A port range.
 */
struct range
{
  gchar *comment;       /**< Comment. */
  gchar *id;            /**< UUID. */
  int end;              /**< End port.  0 for single port. */
  int exclude;          /**< Whether to exclude range. */
  int start;            /**< Start port. */
  port_protocol_t type; /**< Port protocol. */
};
typedef struct range range_t;

int
gvm_source_iface_init (const char *);

int
gvm_source_iface_is_set (void);

int
gvm_source_set_socket (int, int, int);

void
gvm_source_addr (void *);

void
gvm_source_addr6 (void *);

void
gvm_source_addr_as_addr6 (struct in6_addr *);

char *
gvm_source_addr_str (void);

char *
gvm_source_addr6_str (void);

void
ipv4_as_ipv6 (const struct in_addr *, struct in6_addr *);

void
addr6_to_str (const struct in6_addr *, char *);

char *
addr6_as_str (const struct in6_addr *);

void
sockaddr_as_str (const struct sockaddr_storage *, char *);

int
gvm_resolve (const char *, void *, int);

GSList *
gvm_resolve_list (const char *);

int
gvm_resolve_as_addr6 (const char *, struct in6_addr *);

int
validate_port_range (const char *);

array_t *
port_range_ranges (const char *);

int
port_in_port_ranges (int, port_protocol_t, array_t *);

int
ipv6_is_enabled ();

#endif /* not MAGENI_NETWORKING_H */
