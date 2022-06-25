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
 * @brief Protos and data structures for Hosts collections and single hosts
 * objects.
 *
 * This file contains the protos for \ref hosts.c
 */

#ifndef _GVM_HOSTS_H
#define _GVM_HOSTS_H

#include <glib.h>       /* for gchar, GList */
#include <netinet/in.h> /* for in6_addr, in_addr */

/* Static values */

enum host_type
{
  HOST_TYPE_NAME = 0,     /* Hostname eg. foo */
  HOST_TYPE_IPV4,         /* eg. 192.168.1.1 */
  HOST_TYPE_CIDR_BLOCK,   /* eg. 192.168.15.0/24 */
  HOST_TYPE_RANGE_SHORT,  /* eg. 192.168.15.10-20 */
  HOST_TYPE_RANGE_LONG,   /* eg. 192.168.15.10-192.168.18.3 */
  HOST_TYPE_IPV6,         /* eg. ::1 */
  HOST_TYPE_CIDR6_BLOCK,  /* eg. ::ffee/120 */
  HOST_TYPE_RANGE6_LONG,  /* eg. ::1:200:7-::1:205:500 */
  HOST_TYPE_RANGE6_SHORT, /* eg. ::1-fe10 */
  HOST_TYPE_MAX           /* Boundary checking. */
};

/* Typedefs */
typedef struct gvm_host gvm_host_t;
typedef struct gvm_vhost gvm_vhost_t;
typedef struct gvm_hosts gvm_hosts_t;

/* Data structures. */

/**
 * @brief The structure for a single host object.
 *
 * The elements of this structure should never be accessed directly.
 * Only the functions corresponding to this module should be used.
 */
struct gvm_host
{
  union
  {
    gchar *name;           /**< Hostname. */
    struct in_addr addr;   /**< IPv4 address */
    struct in6_addr addr6; /**< IPv6 address */
  };
  enum host_type type; /**< HOST_TYPE_NAME, HOST_TYPE_IPV4 or HOST_TYPE_IPV6. */
  GSList *vhosts;      /**< List of hostnames/vhosts attached to this host. */
};

/**
 * @brief The structure for a single vhost object.
 */
struct gvm_vhost
{
  char *value;  /**< Hostname string. */
  char *source; /**< Source of the value eg. DNS-Resolution. */
};

/**
 * @brief The structure for Hosts collection.
 *
 * The elements of this structure should never be accessed directly.
 * Only the functions corresponding to this module should be used.
 */
struct gvm_hosts
{
  gchar *orig_str;    /**< Original hosts definition string. */
  gvm_host_t **hosts; /**< Hosts objects list. */
  size_t max_size;    /**< Current max size of hosts array entries. */
  size_t current;     /**< Current host index in iteration. */
  size_t count;       /**< Number of single host objects in hosts list. */
  size_t removed;     /**< Number of duplicate/excluded values. */
};

/* Function prototypes. */

/* gvm_hosts_t related */
gvm_hosts_t *
gvm_hosts_new (const gchar *);

gvm_hosts_t *
gvm_hosts_new_with_max (const gchar *, unsigned int);

gvm_host_t *
gvm_hosts_next (gvm_hosts_t *);

void
gvm_hosts_free (gvm_hosts_t *);

void
gvm_hosts_shuffle (gvm_hosts_t *);

void
gvm_hosts_reverse (gvm_hosts_t *);

void
gvm_hosts_resolve (gvm_hosts_t *);

int
gvm_hosts_exclude (gvm_hosts_t *, const char *);

int
gvm_vhosts_exclude (gvm_host_t *, const char *);

int
gvm_hosts_exclude_with_max (gvm_hosts_t *, const char *, unsigned int);

char *
gvm_host_reverse_lookup (gvm_host_t *);

int
gvm_hosts_reverse_lookup_only (gvm_hosts_t *);

int
gvm_hosts_reverse_lookup_unify (gvm_hosts_t *);

unsigned int
gvm_hosts_count (const gvm_hosts_t *);

unsigned int
gvm_hosts_removed (const gvm_hosts_t *);

/* gvm_host_t related */

int
gvm_host_in_hosts (const gvm_host_t *, const struct in6_addr *,
                   const gvm_hosts_t *);

gchar *
gvm_host_type_str (const gvm_host_t *);

enum host_type
gvm_host_type (const gvm_host_t *);

gchar *
gvm_host_value_str (const gvm_host_t *);

int
gvm_host_resolve (const gvm_host_t *, void *, int);

int
gvm_host_get_addr6 (const gvm_host_t *, struct in6_addr *);

void
gvm_host_add_reverse_lookup (gvm_host_t *);

/* Miscellaneous functions */

gvm_vhost_t *
gvm_vhost_new (char *, char *);

int
gvm_get_host_type (const gchar *);

#endif /* not _GVM_HOSTS_H */
