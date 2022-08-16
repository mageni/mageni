/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2009-2019 Greenbone Networks GmbH
 * SPDX-FileComment: Authentication mechanism(s).
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef MAGENI_AUTHUTILS_H
#define MAGENI_AUTHUTILS_H

#include <glib.h>

/**
 * @brief Numerical representation of the supported authentication methods.
 *        Beware to have it in sync with \p authentication_methods in
 *        \ref authutils.c.
 */
enum authentication_method
{
  AUTHENTICATION_METHOD_FILE = 0,
  AUTHENTICATION_METHOD_LDAP_CONNECT,
  AUTHENTICATION_METHOD_RADIUS_CONNECT,
  AUTHENTICATION_METHOD_LAST
};

/** @brief Type for the numerical representation of the supported
 *         authentication methods. */
typedef enum authentication_method auth_method_t;

const gchar *auth_method_name (auth_method_t);

int mgn_auth_init ();

int mgn_authenticate_classic (const gchar *, const gchar *, const gchar *);

gchar * get_password_hashes (const gchar *);

gchar * digest_hex (int, const guchar *);

int mgn_auth_ldap_enabled ();

int mgn_auth_radius_enabled ();

#endif /* not MAGENI_AUTHUTILS_H */
