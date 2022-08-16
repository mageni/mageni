/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2010-2019 Greenbone Networks GmbH
 * SPDX-FileComment: Credential pairs and triples.
 * SPDX-FileContributor: Mageni Security LLC
 * 
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
