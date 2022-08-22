/**
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Copyright (C) 2002 - 2003 Michel Arboi and Renaud Deraison
 * SPDX-FileComment: Unix SMB/CIFS implementation. SMB Byte handling
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef CAPTURE_PACKET_H
#define CAPTURE_PACKET_H

#include <netinet/in.h>
#include <netinet/ip6.h>

int
init_capture_device (struct in_addr, struct in_addr, char *);

struct ip *
capture_next_packet (int, int, int *);

int
init_v6_capture_device (struct in6_addr, struct in6_addr, char *);

struct ip6_hdr *
capture_next_v6_packet (int, int, int *);

#endif
