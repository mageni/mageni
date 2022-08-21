/**
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileCopyrightText: Portions Copyright (C) 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
 * SPDX-FileComment: Header of file that creates a new process for each tested host.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef MAGENI_HOSTS_H
#define MAGENI_HOSTS_H

#include "../misc/scanneraux.h"

int hosts_init (int, int);

int hosts_new (struct scan_globals *, char *, kb_t);

int hosts_set_pid (char *, pid_t);

int hosts_read (struct scan_globals *);

void hosts_stop_all (void);

#endif
