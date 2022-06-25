/* Copyright (C) 2010-2019 Greenbone Networks GmbH
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
 * @file
 * @brief Credential pairs and triples.
 */

#ifndef _GVM_CREDENTIALS_H
#define _GVM_CREDENTIALS_H

#include <glib.h>

/**
 * @brief A username password pair.
 */
typedef struct
{
  /*@null@ */ gchar *username;
  ///< Login name of user.
  /*@null@ */ gchar *password;
  ///< Password of user.
  /*@null@ */ gchar *uuid;
  ///< UUID of user.
  /*@null@ */ gchar *timezone;
  ///< Timezone of user.
  /*@null@ */ double default_severity;
  ///< Default Severity setting of user.
  /*@null@ */ gchar *severity_class;
  ///< Severity Class setting of user.
  /*@null@ */ int dynamic_severity;
  ///< Dynamic Severity setting of user.
  /*@null@ */ gchar *role;
  ///< Role of user.
} credentials_t;

void
free_credentials (credentials_t *credentials);

void
append_to_credentials_username (credentials_t *credentials, const char *text,
                                gsize length);

void
append_to_credentials_password (credentials_t *credentials, const char *text,
                                gsize length);

#endif /* _GVM_CREDENTIALS_H */
