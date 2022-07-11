/* Copyright (C) 2009-2019 Greenbone Networks GmbH
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
 * @brief Protos and data structures for NVT Information Cache.
 *
 * This file contains the protos for \ref nvticache.c
 */

#ifndef _GVM_NVTICACHE_H
#define _GVM_NVTICACHE_H

#include "../base/nvti.h" /* for nvti_t */
#include "kb.h"           /* for kb_t */

#include <glib.h> /* for gchar */

#ifndef NVTICACHE_STR
#define NVTICACHE_STR "nvticache10"
#endif

int
nvticache_init (const char *, const char *);

void
nvticache_reset ();

kb_t
nvticache_get_kb ();

void
nvticache_save ();

int
nvticache_initialized (void);

int
nvticache_check (const gchar *);

int
nvticache_add (const nvti_t *, const char *);

char *
nvticache_get_src (const char *);

char *
nvticache_get_oid (const char *);

char *
nvticache_get_name (const char *);

char *
nvticache_get_tags (const char *);

GSList *
nvticache_get_prefs (const char *);

char *
nvticache_get_cves (const char *);

char *
nvticache_get_bids (const char *);

char *
nvticache_get_xrefs (const char *);

char *
nvticache_get_family (const char *);

char *
nvticache_get_filename (const char *);

char *
nvticache_get_required_keys (const char *);

char *
nvticache_get_mandatory_keys (const char *);

char *
nvticache_get_excluded_keys (const char *);

char *
nvticache_get_required_ports (const char *);

char *
nvticache_get_required_udp_ports (const char *);

int
nvticache_get_category (const char *);

int
nvticache_get_timeout (const char *);

char *
nvticache_get_dependencies (const char *);

nvti_t *
nvticache_get_nvt (const char *);

GSList *
nvticache_get_oids (void);

size_t
nvticache_count (void);

void
nvticache_delete (const char *);

char *
nvticache_feed_version (void);

int
nvticache_check_feed (void);

#endif /* not _GVM_NVTICACHE_H */
