/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileCopyrightText: Based on work Copyright (C) 1998 - 2007 Tenable Network Security, Inc.
 * SPDX-FileComment: Header file for module bpf_share.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef MAGENI_BPF_SHARE_H
#define MAGENI_BPF_SHARE_H

#include <sys/types.h>

int bpf_open_live (char *, char *);

u_char * bpf_next (int, int *);

u_char * bpf_next_tv (int, int *, struct timeval *);

void bpf_close (int);

int bpf_datalink (int);

#endif
