/**
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileCopyrightText: Portions Copyright (C) 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
 * SPDX-FileComment: Header of file that Manages the launching of plugins within processes.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef PLUGIN_LAUNCH_H
#define PLUGIN_LAUNCH_H

#include "pluginload.h"      /* for struct pl_class_t */
#include "pluginscheduler.h" /* for struct plugins_scheduler_t */

void pluginlaunch_init (const char *);

void pluginlaunch_wait (kb_t);

void pluginlaunch_wait_for_free_process (kb_t);

void pluginlaunch_stop ();

int plugin_launch (struct scan_globals *, struct scheduler_plugin *,
               struct in6_addr *, GSList *, kb_t, nvti_t *);

void pluginlaunch_disable_parallel_checks (void);

void pluginlaunch_enable_parallel_checks (void);

int wait_for_children (void);

#endif
