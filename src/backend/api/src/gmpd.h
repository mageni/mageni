// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Name: gmpd.h
 * Brief: Headers for the GMP daemon.
 *
 * Copyright:
 * Copyright (C) 2009-2018 Greenbone Networks GmbH
 * Copyright (C) 2022, Mageni Security LLC
 *
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
