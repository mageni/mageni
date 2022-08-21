/**
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileCopyrightText: Portions Copyright (C) 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
 * SPDX-FileComment: Header of file that loads plugins from disk into memory.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef MAGENI_PLUGINLOAD_H
#define MAGENI_PLUGINLOAD_H

#include "../misc/network.h"
#include "../misc/scanneraux.h"

#include "../../libraries/util/kb.h" /* for struct kb_item */

int plugins_init (void);

void init_loading_shm (void);

void destroy_loading_shm (void);

int current_loading_plugins (void);

int total_loading_plugins (void);

/* From nasl_plugins.c */
int nasl_plugin_add (char *, char *);

int
nasl_plugin_launch (struct scan_globals *, struct in6_addr *, GSList *, kb_t,
                    const char *);

#endif
