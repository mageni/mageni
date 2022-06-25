/* Copyright (C) 2014-2018 Greenbone Networks GmbH
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
 * @file  scanner.c
 * @brief GVM management layer: Scanner connection handling
 *
 * This file provides facilities for working with scanner connections.
 */

#include "scanner.h"

#include "comm.h"
#include "gmpd.h"
#include "otp.h"
#include "utils.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h> /* for errno */
#include <fcntl.h>
#include "../../libraries/util/serverutils.h"
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md   main"

/**
 * @brief Current OpenVAS Scanner session.
 */
static gnutls_session_t openvas_scanner_session = NULL;

/**
 * @brief Current OpenVAS Scanner credentials.
 */
static gnutls_certificate_credentials_t openvas_scanner_credentials = NULL;

/**
 * @brief Current OpenVAS Scanner socket.
 */
static int openvas_scanner_socket = -1;

/**
 * @brief Current OpenVAS Scanner address.
 */
static struct sockaddr_in openvas_scanner_address;

/**
 * @brief Current OpenVAS Scanner CA Cert.
 */
static char *openvas_scanner_ca_pub = NULL;

/**
 * @brief Current OpenVAS Scanner public key.
 */
static char *openvas_scanner_key_pub = NULL;

/**
 * @brief Current OpenVAS Scanner private key.
 */
static char *openvas_scanner_key_priv = NULL;

/**
 * @brief Current OpenVAS Scanner UNIX path.
 */
static char *openvas_scanner_unix_path = NULL;

/**
 * @brief Buffer of input from the scanner.
 */
char *from_scanner = NULL;

/**
 * @brief The start of the data in the \ref from_scanner buffer.
 */
buffer_size_t from_scanner_start = 0;

/**
 * @brief The end of the data in the \ref from_scanner buffer.
 */
buffer_size_t from_scanner_end = 0;

/**
 * @brief The current size of the \ref from_scanner buffer.
 */
static buffer_size_t from_scanner_size = 1048576;

/**
 * @brief The max size of the \ref from_scanner buffer.
 */
static buffer_size_t from_scanner_max_size = 1073741824;

/** @cond STATIC */

/* XXX: gvm-comm.c content should be moved to scanner.c to better abstract
 * scanner reading/writing. */
extern char to_server[];
extern int to_server_end;
extern int to_server_start;

/** @endcond */

/**
 * @brief Write as much as possible from a string to the server.
 *
 * @param[in]  string          The string.
 *
 * @return 0 wrote everything, -1 error, or the number of bytes written
 *         when the server accepted fewer bytes than given in string.
 */
static int
write_string_to_server (char *const string)
{
  char *point = string;
  char *end = string + strlen (string);
  while (point < end)
    {
      ssize_t count;

      if (openvas_scanner_unix_path)
        {
          count = send (openvas_scanner_socket, point, end - point, 0);
          if (count < 0)
            {
              if (errno == EAGAIN)
                return point - string;
              else if (errno == EINTR)
                continue;
              else
                {
                  g_warning ("%s: Failed to write to scanner: %s",
                             __FUNCTION__,
                             strerror (errno));
                  return -1;
                }
            }
        }
      else
        {
          count = gnutls_record_send (
            openvas_scanner_session, point, (size_t) (end - point));
          if (count < 0)
            {
              if (count == GNUTLS_E_AGAIN)
                /* Wrote as much as server accepted. */
                return point - string;
              if (count == GNUTLS_E_INTERRUPTED)
                /* Interrupted, try write again. */
                continue;
              if (count == GNUTLS_E_REHANDSHAKE)
                /** @todo Rehandshake. */
                continue;
              g_warning ("%s: failed to write to server: %s",
                         __FUNCTION__,
                         gnutls_strerror ((int) count));
              return -1;
            }
        }
      g_debug ("s> server  (string) %.*s", (int) count, point);
      point += count;
      g_debug ("=> server  (string) %zi bytes", count);
    }
  g_debug ("=> server  (string) done");
  /* Wrote everything. */
  return 0;
}

/**
 * @brief Write as much as possible from the internal buffer to the server.
 *
 * @return 0 wrote everything, -1 error, -2 wrote as much as server accepted,
 *         -3 interrupted.
 */
static int
write_to_server_buffer ()
{
  while (to_server_start < to_server_end)
    {
      ssize_t count;

      if (openvas_scanner_unix_path)
        {
          count = send (openvas_scanner_socket,
                        to_server + to_server_start,
                        to_server_end - to_server_start,
                        0);
          if (count < 0)
            {
              if (errno == EAGAIN)
                return -2;
              else if (errno == EINTR)
                return -3;
              else
                {
                  g_warning ("%s: Failed to write to scanner: %s",
                             __FUNCTION__,
                             strerror (errno));
                  return -1;
                }
            }
        }
      else
        {
          count = gnutls_record_send (openvas_scanner_session,
                                      to_server + to_server_start,
                                      (size_t) to_server_end - to_server_start);
          if (count < 0)
            {
              if (count == GNUTLS_E_AGAIN)
                /* Wrote as much as server accepted. */
                return -2;
              if (count == GNUTLS_E_INTERRUPTED)
                /* Interrupted, try write again. */
                return -3;
              if (count == GNUTLS_E_REHANDSHAKE)
                /** @todo Rehandshake. */
                continue;
              g_warning ("%s: failed to write to server: %s",
                         __FUNCTION__,
                         gnutls_strerror ((int) count));
              return -1;
            }
        }
      g_debug ("s> server  %.*s", (int) count, to_server + to_server_start);
      to_server_start += count;
      g_debug ("=> server  %zi bytes", count);
    }
  g_debug ("=> server  done");
  to_server_start = to_server_end = 0;
  /* Wrote everything. */
  return 0;
}

/**
 * @brief Read as much from the server as the \ref from_scanner buffer will
 * @brief hold.
 *
 * @return 0 on reading everything available, -1 on error, -2 if
 * from_scanner buffer is full or -3 on reaching end of file.
 */
int
openvas_scanner_read ()
{
  if (openvas_scanner_socket == -1)
    return -1;

  while (!openvas_scanner_full ())
    {
      ssize_t count;

      if (openvas_scanner_unix_path)
        {
          count = recv (openvas_scanner_socket,
                        from_scanner + from_scanner_end,
                        from_scanner_size - from_scanner_end,
                        0);
          if (count < 0)
            {
              if (errno == EINTR)
                continue;
              else if (errno == EAGAIN)
                return 0;
              else
                {
                  g_warning ("%s: Failed to read from scanner: %s",
                             __FUNCTION__,
                             strerror (errno));
                  return -1;
                }
            }
        }
      else
        {
          count = gnutls_record_recv (openvas_scanner_session,
                                      from_scanner + from_scanner_end,
                                      from_scanner_size - from_scanner_end);
          if (count < 0)
            {
              if (count == GNUTLS_E_AGAIN)
                /* Got everything available, return to `select'. */
                return 0;
              if (count == GNUTLS_E_INTERRUPTED)
                /* Interrupted, try read again. */
                continue;
              if (count == GNUTLS_E_REHANDSHAKE)
                {
                  /** @todo Rehandshake. */
                  g_debug ("   should rehandshake");
                  continue;
                }
              if (gnutls_error_is_fatal (count) == 0
                  && (count == GNUTLS_E_WARNING_ALERT_RECEIVED
                      || count == GNUTLS_E_FATAL_ALERT_RECEIVED))
                {
                  int alert = gnutls_alert_get (openvas_scanner_session);
                  const char *alert_name = gnutls_alert_get_name (alert);
                  g_warning (
                    "%s: TLS Alert %d: %s", __FUNCTION__, alert, alert_name);
                }
              g_warning ("%s: failed to read from server: %s",
                         __FUNCTION__,
                         gnutls_strerror (count));
              return -1;
            }
        }
      if (count == 0)
        /* End of file. */
        return -3;
      assert (count > 0);
      from_scanner_end += count;
    }

  /* Buffer full. */
  return -2;
}

/**
 * @brief Check whether the buffer for data from Scanner is full.
 *
 * @return 1 if full, 0 otherwise.
 */
int
openvas_scanner_full ()
{
  return !(from_scanner_end < from_scanner_size);
}

/**
 * @brief Reallocates the from_scanner buffer to a higher size.
 *
 * @return 1 if max size reached, 0 otherwise.
 */
int
openvas_scanner_realloc ()
{
  if (from_scanner_size >= from_scanner_max_size)
    return 1;
  from_scanner_size *= 2;
  g_warning ("Reallocing to %d", from_scanner_size);
  from_scanner = g_realloc (from_scanner, from_scanner_size);
  return 0;
}

/**
 * @brief Write as much as possible from the to_scanner buffer to the scanner.
 *
 * @param[in]  nvt_cache_mode  NVT cache mode.
 *
 * @return 0 wrote everything, -1 error, -2 wrote as much as scanner accepted,
 *         -3 did an initialisation step.
 */
int
openvas_scanner_write (int nvt_cache_mode)
{
  if (openvas_scanner_socket == -1)
    return -1;
  switch (scanner_init_state)
    {
    case SCANNER_INIT_TOP:
      if (!openvas_scanner_unix_path)
        return -1;
      else
        {
          set_scanner_init_state (SCANNER_INIT_CONNECTED);
          /* The socket must have O_NONBLOCK set, in case an "asynchronous
           * network error" removes the data between `select' and `read'. */
          if (fcntl (openvas_scanner_socket, F_SETFL, O_NONBLOCK) == -1)
            {
              g_warning ("%s: failed to set scanner socket flag: %s",
                         __FUNCTION__,
                         strerror (errno));
              return -1;
            }
          /* Fall through to SCANNER_INIT_CONNECTED case below, to write
           * version string. */
        }
      /* fallthrough */
    case SCANNER_INIT_CONNECTED:
      {
        char *string = "< OTP/2.0 >\n";

        scanner_init_offset =
          write_string_to_server (string + scanner_init_offset);
        if (scanner_init_offset == 0)
          set_scanner_init_state (SCANNER_INIT_SENT_VERSION);
        else if (scanner_init_offset == -1)
          {
            scanner_init_offset = 0;
            return -1;
          }
        if (nvt_cache_mode)
          {
            string = "CLIENT <|> NVT_INFO <|> CLIENT\n";
            scanner_init_offset =
              write_string_to_server (string + scanner_init_offset);
            if (scanner_init_offset == -1)
              {
                scanner_init_offset = 0;
                return -1;
              }
          }
        break;
      }
    case SCANNER_INIT_SENT_VERSION:
      return 0;
    case SCANNER_INIT_SENT_COMPLETE_LIST:
    case SCANNER_INIT_SENT_COMPLETE_LIST_UPDATE:
      return 0;
    case SCANNER_INIT_GOT_FEED_VERSION:
      if (nvt_cache_mode)
        {
          static char *const ack = "CLIENT <|> COMPLETE_LIST <|> CLIENT\n";
          scanner_init_offset =
            write_string_to_server (ack + scanner_init_offset);
          if (scanner_init_offset == 0)
            set_scanner_init_state (nvt_cache_mode == -1
                                      ? SCANNER_INIT_SENT_COMPLETE_LIST_UPDATE
                                      : SCANNER_INIT_SENT_COMPLETE_LIST);
          else if (scanner_init_offset == -1)
            {
              scanner_init_offset = 0;
              return -1;
            }
          break;
        }
      /* fallthrough */
    case SCANNER_INIT_GOT_PLUGINS:
      {
        static char *const ack = "\n";
        scanner_init_offset =
          write_string_to_server (ack + scanner_init_offset);
        if (scanner_init_offset == 0)
          {
            if (nvt_cache_mode == -1)
              set_scanner_init_state (SCANNER_INIT_DONE_CACHE_MODE_UPDATE);
            else if (nvt_cache_mode == -2)
              set_scanner_init_state (SCANNER_INIT_DONE_CACHE_MODE);
            else
              set_scanner_init_state (SCANNER_INIT_DONE);
          }
        else if (scanner_init_offset == -1)
          {
            scanner_init_offset = 0;
            return -1;
          }
        else
          break;
      }
      /* fallthrough */
    case SCANNER_INIT_DONE:
    case SCANNER_INIT_DONE_CACHE_MODE:
    case SCANNER_INIT_DONE_CACHE_MODE_UPDATE:
      while (1)
        switch (write_to_server_buffer ())
          {
          case 0:
            return 0;
          case -1:
            return -1;
          case -2:
            return -2;
          case -3:
            continue; /* Interrupted. */
          }
    }
  return -3;
}

/**
 * @brief Wait for the scanner socket to be writable.
 *
 * @return 0 on success, -1 on error.
 */
static int
openvas_scanner_wait ()
{
  if (openvas_scanner_socket == -1)
    return -1;

  while (1)
    {
      int ret;
      struct timeval timeout;
      fd_set writefds;

      timeout.tv_usec = 0;
      timeout.tv_sec = 1;
      FD_ZERO (&writefds);
      FD_SET (openvas_scanner_socket, &writefds);

      ret =
        select (1 + openvas_scanner_socket, NULL, &writefds, NULL, &timeout);
      if (ret < 0)
        {
          if (errno == EINTR)
            continue;
          g_warning (
            "%s: select failed (connect): %s", __FUNCTION__, strerror (errno));
          return -1;
        }

      if (FD_ISSET (openvas_scanner_socket, &writefds))
        break;
    }
  return 0;
}

/**
 * @brief Load certificates from the CA directory.
 *
 * @param[in]  scanner_credentials  Scanner credentials.
 *
 * @return 0 success, -1 error.
 */
static int
load_cas (gnutls_certificate_credentials_t *scanner_credentials)
{
  DIR *dir;
  struct dirent *ent;

  dir = opendir (CA_DIR);
  if (dir == NULL)
    {
      if (errno != ENOENT)
        {
          g_warning ("%s: failed to open " CA_DIR ": %s",
                     __FUNCTION__,
                     strerror (errno));
          return -1;
        }
    }
  else
    while ((ent = readdir (dir)))
      {
        gchar *name;
        struct stat state;

        if ((strcmp (ent->d_name, ".") == 0)
            || (strcmp (ent->d_name, "..") == 0))
          continue;

        name = g_build_filename (CA_DIR, ent->d_name, NULL);
        stat (name, &state);
        if (S_ISREG (state.st_mode)
            && (gnutls_certificate_set_x509_trust_file (
                  *scanner_credentials, name, GNUTLS_X509_FMT_PEM)
                < 0))
          {
            g_warning ("%s: gnutls_certificate_set_x509_trust_file failed: %s",
                       __FUNCTION__,
                       name);
            g_free (name);
            closedir (dir);
            return -1;
          }
        g_free (name);
      }
  if (dir != NULL)
    closedir (dir);
  return 0;
}

/**
 * @brief Finish the connection to the Scanner and free internal buffers.
 *
 * @return -1 if error, 0 if success.
 */
int
openvas_scanner_close ()
{
  int rc = 0;
  if (openvas_scanner_socket == -1)
    return -1;
  if (openvas_scanner_unix_path)
    close (openvas_scanner_socket);
  else
    rc = gvm_server_free (openvas_scanner_socket,
                          openvas_scanner_session,
                          openvas_scanner_credentials);
  openvas_scanner_socket = -1;
  openvas_scanner_session = NULL;
  openvas_scanner_credentials = NULL;
  g_free (from_scanner);
  from_scanner = NULL;
  return rc;
}

/**
 * @brief Reset Scanner variables after a fork.
 *
 * This other side of the fork will do the actual cleanup.
 */
void
openvas_scanner_fork ()
{
  openvas_scanner_socket = -1;
  openvas_scanner_session = NULL;
  openvas_scanner_credentials = NULL;
  from_scanner_start = 0;
  from_scanner_end = 0;
  reset_scanner_states ();
}

/**
 * @brief Create a new connection to the scanner and set it as current scanner.
 *
 * Use a UNIX socket for the connection.
 *
 * @return 0 on success, -1 on error.
 */
static int
mageni_scanner_connect_unix ()
{
  struct sockaddr_un addr;
  int len;

  openvas_scanner_socket = socket (AF_UNIX, SOCK_STREAM, 0);
  if (openvas_scanner_socket == -1)
    {
      g_warning ("%s: failed to create scanner socket: %s",
                 __FUNCTION__,
                 strerror (errno));
      return -1;
    }

  addr.sun_family = AF_UNIX;
  strncpy (addr.sun_path, openvas_scanner_unix_path, 108);
  len = strlen (addr.sun_path) + sizeof (addr.sun_family);
  if (connect (openvas_scanner_socket, (struct sockaddr *) &addr, len) == -1)
    {
      g_warning ("%s: Failed to connect to scanner (%s): %s",
                 __FUNCTION__,
                 openvas_scanner_unix_path,
                 strerror (errno));
      return -1;
    }

  init_otp_data ();
  return 0;
}

/**
 * @brief Create a new connection to the scanner and set it as current scanner.
 *
 * @return 0 on success, -1 on error.
 */
int
openvas_scanner_connect ()
{
  if (openvas_scanner_unix_path)
    return mageni_scanner_connect_unix ();

  openvas_scanner_socket = socket (PF_INET, SOCK_STREAM, 0);
  if (openvas_scanner_socket == -1)
    {
      g_warning ("%s: failed to create scanner socket: %s",
                 __FUNCTION__,
                 strerror (errno));
      return -1;
    }

  /* Make the scanner socket. */
  if (gvm_server_new_mem (GNUTLS_CLIENT,
                          openvas_scanner_ca_pub,
                          openvas_scanner_key_pub,
                          openvas_scanner_key_priv,
                          &openvas_scanner_session,
                          &openvas_scanner_credentials))
    {
      close (openvas_scanner_socket);
      openvas_scanner_socket = -1;
      return -1;
    }

  if (load_cas (&openvas_scanner_credentials))
    {
      openvas_scanner_close ();
      return -1;
    }

  init_otp_data ();

  return 0;
}

/**
 * @brief Free the scanner allocated data. Doesn't close socket and terminate
 *        the session.
 */
void
openvas_scanner_free ()
{
  close (openvas_scanner_socket);
  openvas_scanner_socket = -1;
  if (openvas_scanner_session)
    gnutls_deinit (openvas_scanner_session);
  openvas_scanner_session = NULL;
  if (openvas_scanner_credentials)
    gnutls_certificate_free_credentials (openvas_scanner_credentials);
  openvas_scanner_credentials = NULL;
  memset (&openvas_scanner_address, '\0', sizeof (openvas_scanner_address));
  g_free (openvas_scanner_ca_pub);
  g_free (openvas_scanner_key_pub);
  g_free (openvas_scanner_key_priv);
  g_free (openvas_scanner_unix_path);
  openvas_scanner_ca_pub = NULL;
  openvas_scanner_key_pub = NULL;
  openvas_scanner_key_priv = NULL;
  openvas_scanner_unix_path = NULL;
}

/**
 * @brief Check if connected to Scanner is set in an fd_set.
 *
 * @param[in]  fd       File descriptor set.
 *
 * @return 1 if scanner socket in fd_set, 0 if not connected or or not set.
 */
int
openvas_scanner_fd_isset (fd_set *fd)
{
  if (openvas_scanner_socket == -1)
    return 0;
  return FD_ISSET (openvas_scanner_socket, fd);
}

/**
 * @brief Add connected to Scanner's socket to an fd_set.
 *
 * @param[in]  fd   File Descriptor set.
 */
void
openvas_scanner_fd_set (fd_set *fd)
{
  if (openvas_scanner_socket == -1)
    return;
  FD_SET (openvas_scanner_socket, fd);
}

/**
 * @brief Check if there is any data to receive from connected Scanner socket.
 *
 * @return 1 if there is data in socket buffer, 0 if no data or not connected
 *         to a scanner.
 */
int
openvas_scanner_peek ()
{
  char chr;
  if (openvas_scanner_socket == -1)
    return 0;
  return recv (openvas_scanner_socket, &chr, 1, MSG_PEEK);
}

/**
 * @brief Get the nfds value to use for a select() call.
 *
 * @param[in]  socket       Socket to compare to.
 *
 * @return socket + 1 if socket value is higher then scanner's or not
 *         connected to a scanner, scanner socket + 1 otherwise.
 */
int
openvas_scanner_get_nfds (int socket)
{
  if (socket > openvas_scanner_socket)
    return 1 + socket;
  else
    return 1 + openvas_scanner_socket;
}

/**
 * @brief Check if there is any data to receive from connected Scanner session.
 *
 * @return 1 if there is data in session buffer, 0 if no data or not connected
 *         to a scanner.
 */
int
openvas_scanner_session_peek ()
{
  if (openvas_scanner_socket == -1)
    return 0;
  if (openvas_scanner_unix_path)
    return 0;
  else
    return !!gnutls_record_check_pending (openvas_scanner_session);
}

/**
 * @brief Whether we have started a connection to the Scanner using
 *        openvas_scanner_connect().
 *
 * @return 1 if connected, 0 otherwise.
 */
int
openvas_scanner_connected ()
{
  return openvas_scanner_socket == -1 ? 0 : 1;
}

/**
 * @brief Initializes the already setup connection with the Scanner.
 *
 * @param[in]  cache_mode   NVT Cache mode if true, which means sending NVT_INFO
 *                          command to scanner in initial negotiation.
 *
 * @return 0 success, -1 error.
 */
int
openvas_scanner_init (int cache_mode)
{
  int ret;

  if (openvas_scanner_socket == -1)
    return -1;
  from_scanner = g_malloc0 (from_scanner_size);
  ret = openvas_scanner_write (cache_mode);
  if (ret != -3)
    {
      openvas_scanner_free ();
      return -1;
    }
  if (openvas_scanner_wait ())
    return -2;

  return 0;
}

/**
 * @brief Set the scanner's address and port. Will try to resolve addr if it is
 *        a hostname.
 *
 * @param[in]  addr     Scanner address string.
 * @param[in]  port     Scanner port.
 *
 * @return 0 success, -1 error.
 */
int
openvas_scanner_set_address (const char *addr, int port)
{
  if (openvas_scanner_unix_path)
    {
      g_free (openvas_scanner_unix_path);
      openvas_scanner_unix_path = NULL;
    }
  if (port < 1 || port > 65535)
    return -1;
  memset (&openvas_scanner_address, '\0', sizeof (openvas_scanner_address));
  openvas_scanner_address.sin_family = AF_INET;
  openvas_scanner_address.sin_port = htons (port);
  if (gvm_resolve (addr, &openvas_scanner_address.sin_addr, AF_INET))
    return -1;

  return 0;
}

/**
 * @brief Set the scanner's unix socket path.
 *
 * @param[in]  path     Path to scanner unix socket.
 *
 * @return 0 success, -1 error.
 */
int
openvas_scanner_set_unix (const char *path)
{
  if (!path)
    return -1;

  openvas_scanner_free ();
  memset (&openvas_scanner_address, '\0', sizeof (openvas_scanner_address));
  openvas_scanner_unix_path = g_strdup (path);

  return 0;
}

/**
 * @brief Set the scanner's CA Certificate, and public/private key pair.
 *
 * @param[in]  ca_pub       CA Certificate.
 * @param[in]  key_pub      Scanner Certificate.
 * @param[in]  key_priv     Scanner private key.
 */
void
openvas_scanner_set_certs (const char *ca_pub,
                           const char *key_pub,
                           const char *key_priv)
{
  if (openvas_scanner_unix_path)
    {
      g_free (openvas_scanner_unix_path);
      openvas_scanner_unix_path = NULL;
    }
  if (ca_pub)
    openvas_scanner_ca_pub = g_strdup (ca_pub);
  if (key_pub)
    openvas_scanner_key_pub = g_strdup (key_pub);
  if (key_priv)
    openvas_scanner_key_priv = g_strdup (key_priv);
}

/**
 * @brief Checks whether the connected to OpenVAS Scanner is still loading
 *        plugins. To be called right after openvas_scanner_init().
 *
 * @return 1 if loading, 0 if not loading or error.
 */
int
openvas_scanner_is_loading ()
{
  int attempts = 5;
  int ret = 0;
  while (attempts >= 0)
    {
      /* Add little delay in case we read before scanner write, as the socket is
       * non-blocking. */
      attempts = attempts - 1;
      gvm_usleep (500000);
      openvas_scanner_read ();

      switch (process_otp_scanner_input (NULL))
        {
        case 3:
          /* Still loading. */
          return 1;
        case 5:
          /* Empty message. Try again. */
          ret = 1;
          break;
        default:
          return 0;
        }
    }
  return ret;
}
