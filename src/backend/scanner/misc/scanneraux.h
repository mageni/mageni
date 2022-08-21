/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: 2009-2019 Greenbone Networks GmbH
 * SPDX-FileComment: Auxiliary structures for scanner.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef _OPENVAS_SCANNERAUX_H
#define _OPENVAS_SCANNERAUX_H

#include <glib.h>
#include "../../libraries/base/nvti.h"
#include "../../libraries/util/kb.h"

struct scan_globals
{
  char *network_targets;
  char *network_scan_status;
  GHashTable *files_translation;
  GHashTable *files_size_translation;
  int global_socket;
  char *scan_id;
};

struct host_info;

struct script_infos
{
  struct scan_globals *globals;
  kb_t key;
  nvti_t *nvti;
  char *oid;
  char *name;
  GHashTable *udp_data;
  struct in6_addr *ip;
  GSList *vhosts;
  int standalone;
  int denial_port;
  int alive;
};
#endif /* not _OPENVAS_SCANNERAUX_H */
