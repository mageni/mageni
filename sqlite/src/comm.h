/* Copyright (C) 2009-2018 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file comm.h
 * @brief Protos for communication between platform-manager and platform-scanner.
 *
 * This file contains the protos for \ref comm.c
 */

#ifndef _GVMD_COMM_H
#define _GVMD_COMM_H

#include <glib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

int
send_to_server (const char *);

int
sendf_to_server (const char *, ...);

int
sendn_to_server (const void *, size_t);

unsigned int
to_server_buffer_space ();

#endif /* not _GVMD_COMM_H */
