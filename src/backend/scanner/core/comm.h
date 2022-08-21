/**
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileCopyrightText: Portions Copyright (C) 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef MAGENI_COMM_H
#define MAGENI_COMM_H

#include "../misc/scanneraux.h"

int
comm_init (int);

int
comm_loading (int);

void
comm_terminate (int);

int
comm_wait_order (struct scan_globals *);

void
comm_send_nvt_info (int);

int
send_plug_info (int, const char *);

#endif
