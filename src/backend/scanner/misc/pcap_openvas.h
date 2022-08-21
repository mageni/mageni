/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileCopyrightText: Based on work Copyright (C) 1998 - 2007 Tenable Network Security, Inc.
 * SPDX-FileComment: Header file for module pcap.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef OPENVAS_PCAP_H
#define OPENVAS_PCAP_H

#include <arpa/inet.h>
#include <pcap.h>
#include <sys/param.h>
#ifdef __FreeBSD__
#include <netinet/in.h>
#endif

int
v6_is_local_ip (struct in6_addr *);

int
islocalhost (struct in_addr *);

int
v6_islocalhost (struct in6_addr *);

int
get_datalink_size (int);

char *
routethrough (struct in_addr *, struct in_addr *);

char *
v6_routethrough (struct in6_addr *, struct in6_addr *);

int
v6_getsourceip (struct in6_addr *, struct in6_addr *);

#endif
