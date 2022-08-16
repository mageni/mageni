/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2009-2018 Greenbone Networks GmbH
 * SPDX-FileComment: This file defines the protocol for implementing managers
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef _GVMD_GMP_H
#define _GVMD_GMP_H

#include "manage.h"
#include "types.h"

#include <glib.h>
#include <gnutls/gnutls.h>
#include "../../libraries/util/serverutils.h"
#include <sys/types.h>

/**
 * @brief The size of the \ref to_client data buffer, in bytes.
 */
#define TO_CLIENT_BUFFER_SIZE 26214400

/**
 * @brief The maximum length in bytes for long result text like the description.
 */
#define TRUNCATE_TEXT_LENGTH 10000000

/**
 * @brief The text to append when text is truncated.
 */
#define TRUNCATE_TEXT_SUFFIX "[...]\n(text truncated)"

int
init_gmp (GSList *,
          int,
          const gchar *,
          int,
          int,
          int,
          int,
          manage_connection_forker_t,
          int);

void
init_gmp_process (int,
                  const gchar *,
                  int (*) (const char *, void *),
                  void *,
                  gchar **);

int
process_gmp_client_input ();

int
process_gmp_change ();

/** @todo As described in gmp.c, probably should be replaced by gmp_parser_t. */
extern char to_client[];
extern buffer_size_t to_client_start;
extern buffer_size_t to_client_end;

#endif /* not _GVMD_MANAGE_H */
