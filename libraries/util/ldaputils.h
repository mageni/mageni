/* Copyright (C) 2012-2019 Greenbone Networks GmbH
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
 * @brief Header for LDAP-Connect Authentication module.
 */

#ifndef _GVM_LDAPUTILS_H
#define _GVM_LDAPUTILS_H

#include <glib.h>

/** @brief Authentication schema and address type. */
typedef struct ldap_auth_info *ldap_auth_info_t;

/**
 * @brief Schema (dn) and info to use for a basic ldap authentication.
 *
 * Use like an opaque struct, create with ldap_auth_schema_new, do not modify,
 * free with ldap_auth_schema_free.
 */
struct ldap_auth_info
{
  gchar *ldap_host;         ///< Address of the ldap server, might include port.
  gchar *auth_dn;           ///< DN to authenticate with.
  gboolean allow_plaintext; ///< !Whether or not StartTLS is required.
};

int
ldap_connect_authenticate (const gchar *, const gchar *,
                           /* ldap_auth_info_t */ void *, const gchar *);

void ldap_auth_info_free (ldap_auth_info_t);

ldap_auth_info_t
ldap_auth_info_new (const gchar *, const gchar *, gboolean);

#ifdef ENABLE_LDAP_AUTH

#include <ldap.h>

gchar *
ldap_auth_info_auth_dn (const ldap_auth_info_t, const gchar *);

LDAP *
ldap_auth_bind (const gchar *, const gchar *, const gchar *, gboolean,
                const gchar *);

gboolean
ldap_auth_dn_is_good (const gchar *);

#endif /* ENABLE_LDAP_AUTH */

#endif /* not _GVM_LDAPUTILS_H */
