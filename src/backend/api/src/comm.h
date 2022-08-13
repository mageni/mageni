// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Name: comm.h
 * Brief: This file contains the protos for comm.c
 * 
 * Protos for communication between the API and the scanner.
 *
 * Copyright: 
 * Copyright (C) 2009-2018 Greenbone Networks GmbH
 * Copyright (C) 2022, Mageni Security LLC
 */

#ifndef _GVMD_COMM_H
#define _GVMD_COMM_H

#include <glib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

int send_to_server (const char *);

int sendf_to_server (const char *, ...);

int sendn_to_server (const void *, size_t);

unsigned int to_server_buffer_space ();

#endif /* not _GVMD_COMM_H */
