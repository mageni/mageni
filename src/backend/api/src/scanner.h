// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Name: scanner.h
 * Brief: Scanner Connection API.
 * 
 * This file provides facilities for working with scanner connections.
 * 
 * Copyright:
 * Copyright (C) 2014-2018 Greenbone Networks GmbH
 * Copyright (C) 2022, Mageni Security LLC
 *
 */

#ifndef _GVMD_SCANNER_H
#define _GVMD_SCANNER_H

#include <gnutls/gnutls.h>

int
openvas_scanner_read ();

int
openvas_scanner_write (int);

int
openvas_scanner_close ();

void
openvas_scanner_fork ();

int
openvas_scanner_connect ();

void
openvas_scanner_free ();

int
openvas_scanner_fd_isset (fd_set *);

void
openvas_scanner_fd_set (fd_set *);

int
openvas_scanner_peek ();

int
openvas_scanner_get_nfds (int);

int
openvas_scanner_session_peek ();

int
openvas_scanner_full ();

int
openvas_scanner_realloc ();

int
openvas_scanner_connected ();

int
openvas_scanner_init (int);

int
openvas_scanner_is_loading ();

int
openvas_scanner_set_address (const char *, int);

int
openvas_scanner_set_unix (const char *);

void
openvas_scanner_set_certs (const char *, const char *, const char *);

#endif /* not _GVMD_SCANNER_H */
