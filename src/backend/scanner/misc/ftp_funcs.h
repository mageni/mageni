/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileCopyrightText: Based on work Copyright (C) 1998 Renaud Deraison
 * SPDX-FileComment: Header file for module ftp_funcs.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef OPENVAS_FTP_FUNCS_H
#define OPENVAS_FTP_FUNCS_H

#include <arpa/inet.h>
#include <sys/param.h>
#include <sys/socket.h>
#ifdef __FreeBSD__
#include <netinet/in.h>
#endif

int
ftp_log_in (int, char *, char *);

int
ftp_get_pasv_address (int, struct sockaddr_in *);

#endif
