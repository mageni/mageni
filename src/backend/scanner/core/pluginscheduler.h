/**
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileCopyrightText: Portions Copyright (C) 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
 * SPDX-FileComment: Header of tile that tells openvassd which plugin should be executed next.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef PLUGINSCHEDULER_H
#define PLUGINSCHEDULER_H

#include <glib.h>

struct plugins_scheduler;

enum plugin_status
{
  PLUGIN_STATUS_UNRUN = 0,
  PLUGIN_STATUS_RUNNING,
  PLUGIN_STATUS_DONE,
};

struct scheduler_plugin
{
  char *oid;
  GSList *deps;
  enum plugin_status running_state;
};

typedef struct plugins_scheduler *plugins_scheduler_t;

#define PLUG_RUNNING ((struct scheduler_plugin *) 0x02)

plugins_scheduler_t
plugins_scheduler_init (const char *, int, int);

struct scheduler_plugin *plugins_scheduler_next (plugins_scheduler_t);

int plugins_scheduler_count_active (plugins_scheduler_t);

void plugins_scheduler_stop (plugins_scheduler_t);

void plugins_scheduler_free (plugins_scheduler_t);

#endif
