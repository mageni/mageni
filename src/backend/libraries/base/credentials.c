/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2010-2019 Greenbone Networks GmbH
 * SPDX-FileComment: Credential pairs and triples.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#include "credentials.h"
#include "strings.h"
#include <string.h>

/**
 * @brief Free credentials.
 *
 * Free the members of a credentials pair.
 *
 * @param[in]  credentials  Pointer to the credentials.
 */
void free_credentials (credentials_t *credentials)
{
  g_free (credentials->username);
  g_free (credentials->password);
  g_free (credentials->uuid);
  g_free (credentials->timezone);
  g_free (credentials->role);
  g_free (credentials->severity_class);
  memset (credentials, '\0', sizeof (*credentials));
}

/**
 * @brief Append text to the username of a credential pair.
 *
 * @param[in]  credentials  Credentials.
 * @param[in]  text         The text to append.
 * @param[in]  length       Length of the text.
 */
void append_to_credentials_username (credentials_t *credentials, const char *text, gsize length)
{
  mgn_append_text (&credentials->username, text, length);
}

/**
 * @brief Append text to the password of a credential pair.
 *
 * @param[in]  credentials  Credentials.
 * @param[in]  text         The text to append.
 * @param[in]  length       Length of the text.
 */
void append_to_credentials_password (credentials_t *credentials, const char *text, gsize length)
{
  mgn_append_text (&credentials->password, text, length);
}
