/**
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileCopyrightText: Portions Copyright (C) 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
 * SPDX-FileComment: Header of Mageni Transfer Protocol handling.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef MAGENI_NTP_H
#define MAGENI_NTP_H

#include "../misc/scanneraux.h"

int ntp_parse_input (struct scan_globals *, char *);

int ntp_timestamp_host_scan_starts (int, kb_t, char *);

int ntp_timestamp_host_scan_ends (int, kb_t, char *);

int ntp_timestamp_scan_starts (int);

int ntp_timestamp_scan_ends (int);

#endif
