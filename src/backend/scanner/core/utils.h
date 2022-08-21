/**
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileCopyrightText: Portions Copyright (C) 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef MAGENI_UTILS_H
#define MAGENI_UTILS_H

#include <sys/types.h> /* for pid_t */

int
is_otp_scan (void);
void
set_scan_type (int);

int
get_max_hosts_number (void);

int
get_max_checks_number (void);

int process_alive (pid_t);

int
data_left (int);

void
wait_for_children1 (void);

int
is_scanner_only_pref (const char *);

void
send_printf (int, char *, ...) __attribute__ ((format (printf, 2, 3)));

#endif
