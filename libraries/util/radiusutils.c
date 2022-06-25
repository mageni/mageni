/* Copyright (C) 2015-2019 Greenbone Networks GmbH
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
 * @brief Implementation of an API for Radius authentication.
 */

#ifdef ENABLE_RADIUS_AUTH

#include <arpa/inet.h> /* for inet_pton */

#if defined(RADIUS_AUTH_FREERADIUS)
#include <freeradius-client.h>
#ifndef RC_CONFIG_FILE
#define RC_DICTIONARY_FILE "/etc/radiusclient/dictionary"
#endif
#elif defined(RADIUS_AUTH_RADCLI)
#include <errno.h>
#include <radcli/radcli.h>
#include <stdlib.h> /* for mkstemp */
#include <string.h> /* for strerror */
#include <unistd.h>
#ifndef RC_CONFIG_FILE
#define RC_DICTIONARY_FILE "/etc/radcli/dictionary"
#endif
#endif

#include "../base/networking.h" /* for gvm_resolve */

#include <glib.h> /* for g_warning */

#ifndef PW_MAX_MSG_SIZE
#define PW_MAX_MSG_SIZE 4096
#endif

/**
 * Initialize the Radius client configuration.
 *
 * @param[in]   hostname    Server hostname.
 * @param[in]   secret      Radius secret key.
 *
 * @return Radius Client handle if success, NULL otherwise.
 */
static rc_handle *
radius_init (const char *hostname, const char *secret)
{
  rc_handle *rh;
  char authserver[4096];
  struct sockaddr_in6 ip6;

  rh = NULL;

  if (inet_pton (AF_INET6, hostname, &(ip6.sin6_addr)) == 1)
    snprintf (authserver, sizeof (authserver), "[%s]::%s", hostname, secret);
  else
    snprintf (authserver, sizeof (authserver), "%s::%s", hostname, secret);

#if defined(RADIUS_AUTH_RADCLI)
  // Create config from file for older radcli versions
  FILE *config_file = NULL;
  char config_filename[35] = "/tmp/gvm_radius_conf_XXXXXX";
  int config_fd = mkstemp (config_filename);

  if (config_fd == -1)
    {
      g_warning ("%s: Couldn't create temp radius config file: %s\n",
                 __FUNCTION__, strerror (errno));
      goto radius_init_fail;
    }

  config_file = fdopen (config_fd, "w");
  if (config_file == NULL)
    {
      close (config_fd);
      g_warning ("%s: Couldn't open temp radius config file %s: %s\n",
                 __FUNCTION__, config_filename, strerror (errno));
      goto radius_init_fail;
    }

  if (fprintf (config_file,
               "auth_order  radius\n"
               "login_tries  4\n"
               "dictionary  %s\n"
               "seqfile  /var/run/radius.seq\n"
               "radius_retries  3\n"
               "radius_timeout  5\n"
               "radius_deadtime  0\n"
               "authserver  %s\n"
               "acctserver  %s\n",
               RC_DICTIONARY_FILE, authserver, authserver)
      < 0)
    {
      fclose (config_file);
      g_warning ("%s: Couldn't write to temp radius config file %s:%s\n",
                 __FUNCTION__, config_filename, strerror (errno));
      unlink (config_filename);
      goto radius_init_fail;
    }
  fclose (config_file);

  rh = rc_read_config (config_filename);
  if (rh == NULL)
    {
      g_warning ("%s: Couldn't read temp radius config file %s\n", __FUNCTION__,
                 config_filename);
      unlink (config_filename);
      goto radius_init_fail;
    }
  unlink (config_filename);
#else  // defined(RADIUS_AUTH_RADCLI)
  if ((rh = rc_new ()) == NULL)
    {
      g_warning ("radius_init: Couldn't allocate memory");
      return NULL;
    }
  if (!rc_config_init (rh))
    {
      g_warning ("radius_init: Couldn't initialize the config");
      return NULL;
    }

  /* Set the basic configuration options. */
  if (rc_add_config (rh, "auth_order", "radius", "config", 0))
    {
      g_warning ("radius_init: Couldn't set auth_order");
      goto radius_init_fail;
    }
  if (rc_add_config (rh, "login_tries", "4", "config", 0))
    {
      g_warning ("radius_init: Couldn't set login_tries");
      goto radius_init_fail;
    }
  if (rc_add_config (rh, "dictionary", RC_DICTIONARY_FILE, "config", 0))
    {
      g_warning ("radius_init: Couldn't set dictionary");
      goto radius_init_fail;
    }
  if (rc_add_config (rh, "seqfile", "/var/run/radius.seq", "config", 0))
    {
      g_warning ("radius_init: Couldn't set seqfile");
      goto radius_init_fail;
    }
  if (rc_add_config (rh, "radius_retries", "3", "config", 0))
    {
      g_warning ("radius_init: Couldn't set radius_retries");
      goto radius_init_fail;
    }
  if (rc_add_config (rh, "radius_timeout", "5", "config", 0))
    {
      g_warning ("radius_init: Couldn't set radius_timeout");
      goto radius_init_fail;
    }
  if (rc_add_config (rh, "radius_deadtime", "0", "config", 0))
    {
      g_warning ("radius_init: Couldn't set radius_deadtime");
      goto radius_init_fail;
    }
  if (rc_add_config (rh, "authserver", authserver, "config", 0) != 0)
    {
      g_warning ("radius_init: Couldn't set authserver %s", authserver);
      goto radius_init_fail;
    }
  if (rc_read_dictionary (rh, RC_DICTIONARY_FILE) != 0)
    {
      g_warning ("radius_init: Couldn't read the dictionary file %s",
                 RC_DICTIONARY_FILE);
      goto radius_init_fail;
    }
#endif // defined(RADIUS_AUTH_RADCLI)

  return rh;

radius_init_fail:
  rc_destroy (rh);
  return NULL;
}

/**
 * @brief Authenticate against a Radius server.
 *
 * @param[in]   hostname    Server hostname.
 * @param[in]   secret      Radius secret key.
 * @param[in]   username    Username to authenticate.
 * @param[in]   password    Password to use with username.
 *
 * @return 0 authentication success, 1 authentication failure, -1 error.
 */
int
radius_authenticate (const char *hostname, const char *secret,
                     const char *username, const char *password)
{
  uint32_t service = PW_AUTHENTICATE_ONLY;
  char msg[PW_MAX_MSG_SIZE];
  VALUE_PAIR *send = NULL, *received = NULL;
  rc_handle *rh;
  int rc = -1;
  struct sockaddr_in ip4;
  struct sockaddr_in6 ip6;

  rh = radius_init (hostname, secret);
  if (!rh)
    return -1;
  if (rc_avpair_add (rh, &send, PW_USER_NAME, (char *) username, -1, 0) == NULL)
    {
      g_warning ("radius_authenticate: Couldn't set the username");
      goto authenticate_leave;
    }
  if (rc_avpair_add (rh, &send, PW_USER_PASSWORD, (char *) password, -1, 0)
      == NULL)
    {
      g_warning ("radius_authenticate: Couldn't set the password");
      goto authenticate_leave;
    }
  if (rc_avpair_add (rh, &send, PW_SERVICE_TYPE, &service, -1, 0) == NULL)
    {
      g_warning ("radius_authenticate: Couldn't set the service type");
      goto authenticate_leave;
    }
  if (gvm_resolve (hostname, &ip4, AF_INET)
      && gvm_resolve (hostname, &ip6, AF_INET6))
    {
      g_warning ("radius_authenticate: Couldn't resolve %s", hostname);
      goto authenticate_leave;
    }

  rc = 1;
  if (rc_auth (rh, 0, send, &received, msg) == OK_RC)
    rc = 0;

authenticate_leave:
  rc_destroy (rh);
  if (send)
    rc_avpair_free (send);
  if (received)
    rc_avpair_free (received);
  return rc;
}

#else /* ENABLE_RADIUS_AUTH */

/**
 * @brief Dummy function for manager.
 *
 * @param[in]   hostname    Server hostname.
 * @param[in]   secret      Radius secret key.
 * @param[in]   username    Username to authenticate.
 * @param[in]   password    Password to use with username.
 *
 * @return -1.
 */
int
radius_authenticate (const char *hostname, const char *secret,
                     const char *username, const char *password)
{
  (void) hostname;
  (void) secret;
  (void) username;
  (void) password;

  return -1;
}

#endif /* ENABLE_RADIUS_AUTH */
