/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2009-2019 Greenbone Networks GmbH
 * SPDX-FileComment: Implementation of API to handle NVT Info Cache
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef MAGENI_NVTICACHE_H
#define MAGENI_NVTICACHE_H

#include "../base/nvti.h" /* for nvti_t */
#include "kb.h"           /* for kb_t */

#include <glib.h> /* for gchar */

#ifndef NVTICACHE_STR
#define NVTICACHE_STR "nvticache10"
#endif

int
nvticache_init (const char *, const char *);

void nvticache_reset ();

kb_t nvticache_get_kb ();

void nvticache_save ();

int nvticache_initialized (void);

int  nvticache_check (const gchar *);

int nvticache_add (const nvti_t *, const char *);

char * nvticache_get_src (const char *);

char * nvticache_get_oid (const char *);

char * nvticache_get_name (const char *);

char * nvticache_get_tags (const char *);

GSList * nvticache_get_prefs (const char *);

char * nvticache_get_cves (const char *);

char * nvticache_get_bids (const char *);

char * nvticache_get_xrefs (const char *);

char * nvticache_get_family (const char *);

char * nvticache_get_filename (const char *);

char * nvticache_get_required_keys (const char *);

char * nvticache_get_mandatory_keys (const char *);

char * nvticache_get_excluded_keys (const char *);

char * nvticache_get_required_ports (const char *);

char * nvticache_get_required_udp_ports (const char *);

int nvticache_get_category (const char *);

int nvticache_get_timeout (const char *);

char * nvticache_get_dependencies (const char *);

nvti_t * nvticache_get_nvt (const char *);

GSList * nvticache_get_oids (void);

size_t nvticache_count (void);

void nvticache_delete (const char *);

char * nvticache_feed_version (void);

int nvticache_check_feed (void);

#endif /* not MAGENI_NVTICACHE_H */
