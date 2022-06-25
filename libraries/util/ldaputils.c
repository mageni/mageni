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
 * @brief LDAP-connect Authentication module.
 */

#include "ldaputils.h"

#ifdef ENABLE_LDAP_AUTH

#include <glib.h>        /* for g_free, gchar, g_warning, g_strdup */
#include <glib/gstdio.h> /* for g_unlink, g_chmod */
#include <lber.h>        /* for berval */
#include <ldap.h> /* for ldap_err2string, LDAP_SUCCESS, ldap_initialize */
#include <stdio.h>
#include <string.h> /* for strlen, strchr, strstr */
#include <unistd.h> /* for close */

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  ldap"

#define KEY_LDAP_HOST "ldaphost"
#define KEY_LDAP_DN_AUTH "authdn"

/**
 * @file ldap_connect_auth.c
 * Contains structs and functions to use for basic authentication (unmanaged,
 * meaning that authorization like role management is file-based) against an
 * LDAP directory server.
 */

/**
 * @brief Authenticate against an ldap directory server.
 *
 * @param[in] info      Schema and address to use.
 * @param[in] username  Username to authenticate.
 * @param[in] password  Password to use.
 * @param[in] cacert    CA Certificate for LDAP_OPT_X_TLS_CACERTFILE, or NULL.
 *
 * @return 0 authentication success, 1 authentication failure, -1 error.
 */
int
ldap_connect_authenticate (
  const gchar *username, const gchar *password,
  /*const */ /*ldap_auth_info_t */ void *ldap_auth_info, const gchar *cacert)
{
  ldap_auth_info_t info = (ldap_auth_info_t) ldap_auth_info;
  LDAP *ldap = NULL;
  gchar *dn = NULL;

  if (info == NULL || username == NULL || password == NULL || !info->ldap_host)
    {
      g_debug ("Not attempting ldap_connect: missing parameter.");
      return -1;
    }

  dn = ldap_auth_info_auth_dn (info, username);

  ldap = ldap_auth_bind (info->ldap_host, dn, password, !info->allow_plaintext,
                         cacert);

  if (ldap == NULL)
    {
      g_debug ("Could not bind to ldap host %s", info->ldap_host);
      return -1;
    }

  ldap_unbind_ext_s (ldap, NULL, NULL);

  return 0;
}

/**
 * @brief Create a new ldap authentication schema and info.
 *
 * @param ldap_host         Host to authenticate against. Might not be NULL,
 *                          but empty.
 * @param auth_dn           DN where the actual user name is to be inserted at
 *                          "%s", e.g. uid=%s,cn=users. Might not be NULL,
 *                          but empty, has to contain a single %s.
 * @param allow_plaintext   If FALSE, require StartTLS initialization to
 *                          succeed.
 *
 * @return Fresh ldap_auth_info_t, or NULL on error.  Free with
 *         ldap_auth_info_free.
 */
ldap_auth_info_t
ldap_auth_info_new (const gchar *ldap_host, const gchar *auth_dn,
                    gboolean allow_plaintext)
{
  // Certain parameters might not be NULL.
  if (!ldap_host || !auth_dn)
    return NULL;

  if (ldap_auth_dn_is_good (auth_dn) == FALSE)
    return NULL;

  ldap_auth_info_t info = g_malloc0 (sizeof (struct ldap_auth_info));
  info->ldap_host = g_strdup (ldap_host);
  info->auth_dn = g_strdup (auth_dn);
  info->allow_plaintext = allow_plaintext;

  return info;
}

/**
 * @brief Free an ldap_auth_info and all associated memory.
 *
 * @param info ldap_auth_schema_t to free, can be NULL.
 */
void
ldap_auth_info_free (ldap_auth_info_t info)
{
  if (!info)
    return;

  g_free (info->ldap_host);
  g_free (info->auth_dn);

  g_free (info);
}

/**
 * @brief Create the dn to authenticate with.
 *
 * @param info     Info and schema to use.
 * @param username Name of the user.
 *
 * @return Freshly allocated dn or NULL if one of the parameters was NULL. Free
 *         with g_free.
 */
gchar *
ldap_auth_info_auth_dn (const ldap_auth_info_t info, const gchar *username)
{
  if (info == NULL || username == NULL)
    return NULL;

  gchar *dn = g_strdup_printf (info->auth_dn, username);

  return dn;
}

/**
 * @brief Setup and bind to an LDAP.
 *
 * @param[in] host              Host to connect to.
 * @param[in] userdn            DN to authenticate against
 * @param[in] password          Password for userdn.
 * @param[in] force_encryption  Whether or not to abort if connection
 *                              encryption via StartTLS or ldaps failed.
 * @param[in] cacert            CA Certificate for LDAP_OPT_X_TLS_CACERTFILE,
 *                              or NULL.
 *
 * @return LDAP Handle or NULL if an error occurred, authentication failed etc.
 */
LDAP *
ldap_auth_bind (const gchar *host, const gchar *userdn, const gchar *password,
                gboolean force_encryption, const gchar *cacert)
{
  LDAP *ldap = NULL;
  int ldap_return = 0;
  int ldapv3 = LDAP_VERSION3;
  gchar *ldapuri = NULL;
  struct berval credential;
  gchar *name;
  gint fd;

  if (host == NULL || userdn == NULL || password == NULL)
    return NULL;

  // Prevent empty password, bind against ADS will succeed with
  // empty password by default.
  if (strlen (password) == 0)
    return NULL;

  if (force_encryption == FALSE)
    g_warning ("Allowed plaintext LDAP authentication.");

  if (cacert)
    {
      GError *error;

      error = NULL;
      fd = g_file_open_tmp (NULL, &name, &error);
      if (fd == -1)
        {
          g_warning ("Could not open temp file for LDAP CACERTFILE: %s",
                     error->message);
          g_error_free (error);
        }
      else
        {
          if (g_chmod (name, 0600))
            g_warning ("Could not chmod for LDAP CACERTFILE");

          g_file_set_contents (name, cacert, strlen (cacert), &error);
          if (error)
            {
              g_warning ("Could not write LDAP CACERTFILE: %s", error->message);
              g_error_free (error);
            }
          else
            {
              if (ldap_set_option (NULL, LDAP_OPT_X_TLS_CACERTFILE, name)
                  != LDAP_OPT_SUCCESS)
                g_warning ("Could not set LDAP CACERTFILE option.");
            }
        }
    }
  else
    fd = -1;

  ldapuri = g_strconcat ("ldap://", host, NULL);

  ldap_return = ldap_initialize (&ldap, ldapuri);

  if (ldap == NULL || ldap_return != LDAP_SUCCESS)
    {
      g_warning ("Could not open LDAP connection for authentication.");
      g_free (ldapuri);
      goto fail;
    }

  /* Fail if server doesn't talk LDAPv3 or StartTLS initialization fails. */
  ldap_return = ldap_set_option (ldap, LDAP_OPT_PROTOCOL_VERSION, &ldapv3);
  if (ldap_return != LDAP_SUCCESS)
    {
      g_warning ("Aborting, could not set ldap protocol version to 3: %s.",
                 ldap_err2string (ldap_return));
      g_free (ldapuri);
      goto fail;
    }

  ldap_return = ldap_start_tls_s (ldap, NULL, NULL);
  if (ldap_return != LDAP_SUCCESS)
    {
      // Try ldaps.
      g_warning ("StartTLS failed, trying to establish ldaps connection.");
      g_free (ldapuri);
      ldapuri = g_strconcat ("ldaps://", host, NULL);

      ldap_return = ldap_initialize (&ldap, ldapuri);
      if (ldap == NULL || ldap_return != LDAP_SUCCESS)
        {
          if (force_encryption == TRUE)
            {
              g_warning ("Aborting ldap authentication: Could not init LDAP "
                         "StartTLS nor ldaps: %s.",
                         ldap_err2string (ldap_return));
              g_free (ldapuri);
              goto fail;
            }
          else
            {
              g_warning ("Could not init LDAP StartTLS, nor ldaps: %s.",
                         ldap_err2string (ldap_return));
              g_warning (
                "Reinit LDAP connection to do plaintext authentication");
              ldap_unbind_ext_s (ldap, NULL, NULL);

              // Note that for connections to default ADS, a failed
              // StartTLS negotiation breaks the future bind, so retry.
              ldap_return = ldap_initialize (&ldap, ldapuri);
              if (ldap == NULL || ldap_return != LDAP_SUCCESS)
                {
                  g_warning (
                    "Could not reopen LDAP connection for authentication.");
                  g_free (ldapuri);
                  goto fail;
                }
            }
        }
    }
  else
    g_debug ("LDAP StartTLS initialized.");

  g_free (ldapuri);

  int do_search = 0;
  LDAPDN dn = NULL;
  gchar *use_dn = NULL;
  gchar **uid = NULL;

  /* Validate the DN with the LDAP library. */
  if (ldap_str2dn (userdn, &dn, LDAP_DN_FORMAT_LDAPV3) == LDAP_SUCCESS)
    {
      gchar **use_uid = NULL;
      ldap_memfree (dn);
      dn = NULL;
      uid = g_strsplit (userdn, ",", 2);
      use_uid = g_strsplit (uid[0], "=", 2);

      if (!g_strcmp0 (use_uid[0], "uid"))
        do_search = 1;
      else
        {
          g_strfreev (uid);
          uid = NULL;
        }
      g_strfreev (use_uid);
      use_uid = NULL;
    }

  /* The uid attribute was given, so a search is performed. */
  if (do_search)
    {
      /* Perform anonymous bind to search. */
      credential.bv_val = NULL;
      credential.bv_len = 0U;
      ldap_return = ldap_sasl_bind_s (ldap, NULL, LDAP_SASL_SIMPLE, &credential,
                                      NULL, NULL, NULL);
      if (ldap_return != LDAP_SUCCESS)
        {
          g_warning ("LDAP anonymous authentication failure: %s",
                     ldap_err2string (ldap_return));
          goto fail;
        }
      else
        {
          char *attrs[2] = {"dn", NULL};
          LDAPMessage *result = NULL;
          gchar **base = g_strsplit (userdn, ",", 2);

          /* search for the DN and unbind */
          ldap_return =
            ldap_search_ext_s (ldap, base[1], LDAP_SCOPE_SUBTREE, uid[0], attrs,
                               0, NULL, NULL, NULL, 1, &result);
          g_strfreev (base);
          base = NULL;
          g_strfreev (uid);
          uid = NULL;
          if (ldap_return != LDAP_SUCCESS)
            use_dn = g_strdup (userdn);
          else
            {
              gchar *found_dn;
              found_dn = ldap_get_dn (ldap, result);
              if ((found_dn == NULL) || (strlen (found_dn) == 0U))
                use_dn = g_strdup (userdn);
              else
                use_dn = g_strdup (found_dn);
              ldap_memfree (found_dn);
            }
          ldap_msgfree (result);
        }
    }
  else
    use_dn = g_strdup (userdn);

  if (use_dn != NULL)
    {
      credential.bv_val = g_strdup (password);
      credential.bv_len = strlen (password);
      ldap_return = ldap_sasl_bind_s (ldap, use_dn, LDAP_SASL_SIMPLE,
                                      &credential, NULL, NULL, NULL);
      g_free (credential.bv_val);
      g_free (use_dn);
      if (ldap_return != LDAP_SUCCESS)
        {
          g_warning ("LDAP authentication failure: %s.",
                     ldap_err2string (ldap_return));
          goto fail;
        }
      else {
          g_warning ("LDAP authentication success for: %s.",
                    userdn);
      }

      if (fd > -1)
        {
          g_unlink (name);
          close (fd);
          g_free (name);
        }
      return ldap;
    }

fail:
  if (fd > -1)
    {
      g_unlink (name);
      close (fd);
      g_free (name);
    }
  return NULL;
}

/**
 * @brief True if parameter contains just one %s and no evil other characters.
 *
 * @param authdn The string to check.
 *
 * @return TRUE if authdn is considered safe enough to be sprintf'ed into.
 */
gboolean
ldap_auth_dn_is_good (const gchar *authdn)
{
  gchar *eg;
  LDAPDN dn;
  int ln = 0;

  if (authdn == NULL || authdn[0] == '\0')
    return FALSE;

  // Must contain %s
  if (!strstr (authdn, "%s"))
    return FALSE;

  // Must not contain other %-signs
  char *pos = strchr (authdn, '%');
  pos = strchr (pos + 1, '%');
  if (pos != NULL)
    return FALSE;

  ln = strlen (authdn);

  // As a special exception allow ADS-style domain\user - pairs.
  if (strchr (authdn, '\\') && authdn[ln - 2] == '%' && authdn[ln - 1] == 's')
    return TRUE;

  // Also allow user@domain - pairs.
  if (authdn[0] == '%' && authdn[1] == 's' && authdn[2] == '@')
    return TRUE;

  /* Validate the DN with the LDAP library. */
  eg = g_strdup_printf (authdn, "example");
  dn = NULL;
  if (ldap_str2dn (eg, &dn, LDAP_DN_FORMAT_LDAPV3))
    {
      g_free (eg);
      return FALSE;
    }
  g_free (eg);
  ldap_memfree (dn);

  return TRUE;
}

#else

/**
 * @brief Dummy function for manager.
 *
 * @param ldap_host         Host to authenticate against. Might not be NULL,
 *                          but empty.
 * @param auth_dn           DN where the actual user name is to be inserted at
 *                          "%s", e.g. uid=%s,cn=users. Might not be NULL,
 *                          but empty, has to contain a single %s.
 * @param allow_plaintext   If FALSE, require StartTLS initialization to
 *                          succeed.
 *
 * @return NULL.
 */
ldap_auth_info_t
ldap_auth_info_new (const gchar *ldap_host, const gchar *auth_dn,
                    gboolean allow_plaintext)
{
  (void) ldap_host;
  (void) auth_dn;
  (void) allow_plaintext;
  return NULL;
}

/**
 * @brief Dummy function for Manager.
 *
 * @param ldap_auth_info      Schema and address to use.
 * @param username            Username to authenticate.
 * @param password            Password to use.
 * @param cacert         CA Certificate for LDAP_OPT_X_TLS_CACERTFILE, or NULL.
 *
 * @return -1.
 */
int
ldap_connect_authenticate (
  const gchar *username, const gchar *password,
  /*const */ /*ldap_auth_info_t */ void *ldap_auth_info, const gchar *cacert)
{
  (void) username;
  (void) password;
  (void) ldap_auth_info;
  (void) cacert;
  return -1;
}

/**
 * @brief Dummy function for Manager.
 *
 * @param info ldap_auth_schema_t to free, can be NULL.
 */
void
ldap_auth_info_free (ldap_auth_info_t info)
{
  (void) info;
}

#endif /* ENABLE_LDAP_AUTH */
