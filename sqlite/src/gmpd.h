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
 * @file gmpd.h
 * @brief Headers for the GMP daemon.
 */

#ifndef _GVMD_GMPD_H
#define _GVMD_GMPD_H

#include "manage.h"
#include "types.h"

#include <glib.h>
#include <gnutls/gnutls.h>
#include "../../libraries/util/serverutils.h"
#include <netinet/in.h>

/**
 * @brief Maximum number of seconds spent trying to read the protocol.
 */
#ifndef READ_PROTOCOL_TIMEOUT
#define READ_PROTOCOL_TIMEOUT 300
#endif

/**
 * @brief Size of \ref from_client and \ref from_scanner data buffers, in bytes.
 */
#define FROM_BUFFER_SIZE 1048576

int
init_gmpd (GSList *,
           int,
           const gchar *,
           int,
           int,
           int,
           int,
           manage_connection_forker_t,
           int);

void
init_gmpd_process (const gchar *, gchar **);

int
serve_gmp (gvm_connection_t *, const gchar *, gchar **);

#endif /* not _GVMD_GMPD_H */
