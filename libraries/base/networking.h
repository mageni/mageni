/* Copyright (C) 2013-2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file
 * @brief GVM Networking related API.
 */

#ifndef _GVM_NETWORKING_H
#define _GVM_NETWORKING_H

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

#endif /* not _GVM_NETWORKING_H */
