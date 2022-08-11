/* Copyright (C) 2009-2018 Greenbone Networks GmbH
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
 * @file  gmpd.c
 * @brief The Greenbone Vulnerability Manager GMP daemon.
 *
 * This file defines the Greenbone Vulnerability Manager daemon.  The Manager
 * serves the Greenbone Management Protocol (GMP) to clients such as the
 * Greenbone Security Assistant (GSA). The Manager and GMP give clients full
 * access to an OpenVAS Scanner.
 *
 * The library provides two functions: \ref init_gmpd and \ref serve_gmp.
 * \ref init_gmpd initialises the daemon.
 * \ref serve_gmp serves GMP to a single client socket until end of file is
 * reached on the socket.
 */

#include "gmpd.h"

#include "gmp.h"
#include "scanner.h"
/** @todo For scanner_init_state. */
#include "comm.h"
#include "otp.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include "../../libraries/util/serverutils.h"
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#if FROM_BUFFER_SIZE > SSIZE_MAX
#error FROM_BUFFER_SIZE too big for "read"
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md   main"

/**
 * @brief Buffer of input from the client.
 */
char from_client[FROM_BUFFER_SIZE];

/**
 * @brief Size of \ref from_client data buffer, in bytes.
 */
buffer_size_t from_buffer_size = FROM_BUFFER_SIZE;

/**
 * @brief The start of the data in the \ref from_client buffer.
 */
buffer_size_t from_client_start = 0;

/**
 * @brief The end of the data in the \ref from_client buffer.
 */
buffer_size_t from_client_end = 0;

/**
 * @brief Flag for running in NVT cache mode.
 */
static int gmpd_nvt_cache_mode = 0;

/**
 * @brief Initialise the GMP library for the GMP daemon.
 *
 * @param[in]  log_config      Log configuration
 * @param[in]  nvt_cache_mode  0 operate normally, -1 just update NVT cache.
 * @param[in]  database        Location of manage database.
 * @param[in]  max_ips_per_target  Max number of IPs per target.
 * @param[in]  max_email_attachment_size  Max size of email attachments.
 * @param[in]  max_email_include_size     Max size of email inclusions.
 * @param[in]  max_email_message_size     Max size of email user message text.
 * @param[in]  fork_connection  Function to fork a connection to the GMP
 *                              daemon layer, or NULL.
 * @param[in]  skip_db_check    Skip DB check.
 *
 * @return 0 success, -1 error, -2 database is wrong version,
 *         -4 max_ips_per_target out of range.
 */
int
init_gmpd (GSList *log_config,
           int nvt_cache_mode,
           const gchar *database,
           int max_ips_per_target,
           int max_email_attachment_size,
           int max_email_include_size,
           int max_email_message_size,
           manage_connection_forker_t fork_connection,
           int skip_db_check)
{
  return init_gmp (log_config,
                   nvt_cache_mode,
                   database,
                   max_ips_per_target,
                   max_email_attachment_size,
                   max_email_include_size,
                   max_email_message_size,
                   fork_connection,
                   skip_db_check);
}

/**
 * @brief Initialise a process forked within the GMP daemon.
 *
 * @param[in]  database  Location of manage database.
 * @param[in]  disable   Commands to disable.
 */
void
init_gmpd_process (const gchar *database, gchar **disable)
{
  openvas_scanner_fork ();
  from_client_start = 0;
  from_client_end = 0;
  init_gmp_process (0, database, NULL, NULL, disable);
}

/**
 * @brief Read as much from the client as the \ref from_client buffer will hold.
 *
 * @param[in]  client_socket  The socket.
 *
 * @return 0 on reading everything available, -1 on error, -2 if
 *         from_client buffer is full or -3 on reaching end of file.
 */
static int
read_from_client_unix (int client_socket)
{
  while (from_client_end < from_buffer_size)
    {
      int count;
      count = read (client_socket,
                    from_client + from_client_end,
                    from_buffer_size - from_client_end);
      if (count < 0)
        {
          if (errno == EAGAIN)
            /* Got everything available, return to `select'. */
            return 0;
          if (errno == EINTR)
            /* Interrupted, try read again. */
            continue;
          g_warning ("%s: failed to read from client: %s",
                     __FUNCTION__,
                     strerror (errno));
          return -1;
        }
      if (count == 0)
        {
          /* End of file. */

          if (from_client_end)
            /* There's still client input to process, so pretend we read
             * something, to prevent serve_gmp from exiting.
             *
             * This should instead be dealt with in serve_gmp, but that function
             * has got quite complex. */
            return 0;

          return -3;
        }
      from_client_end += count;
    }

  /* Buffer full. */
  return -2;
}

/**
 * @brief Read as much from the client as the \ref from_client buffer will hold.
 *
 * @param[in]  client_session  The TLS session with the client.
 *
 * @return 0 on reading everything available, -1 on error, -2 if
 * from_client buffer is full or -3 on reaching end of file.
 */
static int
read_from_client_tls (gnutls_session_t *client_session)
{
  while (from_client_end < from_buffer_size)
    {
      ssize_t count;
      count = gnutls_record_recv (*client_session,
                                  from_client + from_client_end,
                                  from_buffer_size - from_client_end);
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
          if (gnutls_error_is_fatal ((int) count) == 0
              && (count == GNUTLS_E_WARNING_ALERT_RECEIVED
                  || count == GNUTLS_E_FATAL_ALERT_RECEIVED))
            {
              int alert = gnutls_alert_get (*client_session);
              const char *alert_name = gnutls_alert_get_name (alert);
              g_warning (
                "%s: TLS Alert %d: %s", __FUNCTION__, alert, alert_name);
            }
          g_warning ("%s: failed to read from client: %s",
                     __FUNCTION__,
                     gnutls_strerror ((int) count));
          return -1;
        }
      if (count == 0)
        {
          /* End of file. */

          if (from_client_end)
            /* There's still client input to process, so pretend we read
             * something, to prevent serve_gmp from exiting.
             *
             * This should instead be dealt with in serve_gmp, but that function
             * has got quite complex. */
            return 0;

          return -3;
        }
      from_client_end += count;
    }

  /* Buffer full. */
  return -2;
}

/**
 * @brief Read as much from the client as the \ref from_client buffer will hold.
 *
 * @param[in]  client_connection  The connection with the client.
 *
 * @return 0 on reading everything available, -1 on error, -2 if
 * from_client buffer is full or -3 on reaching end of file.
 */
static int
read_from_client (gvm_connection_t *client_connection)
{
  if (client_connection->tls)
    return read_from_client_tls (&client_connection->session);
  return read_from_client_unix (client_connection->socket);
}

/** @todo Move to openvas-libraries? */
/**
 * @brief Write as much as possible from \ref to_client to the client.
 *
 * @param[in]  client_session  The client session.
 *
 * @return 0 wrote everything, -1 error, -2 wrote as much as client accepted.
 */
static int
write_to_client_tls (gnutls_session_t *client_session)
{
  while (to_client_start < to_client_end)
    {
      ssize_t count;
      count = gnutls_record_send (*client_session,
                                  to_client + to_client_start,
                                  to_client_end - to_client_start);
      if (count < 0)
        {
          if (count == GNUTLS_E_AGAIN)
            /* Wrote as much as client would accept. */
            return -2;
          if (count == GNUTLS_E_INTERRUPTED)
            /* Interrupted, try write again. */
            continue;
          if (count == GNUTLS_E_REHANDSHAKE)
            /** @todo Rehandshake. */
            continue;
          g_warning ("%s: failed to write to client: %s",
                     __FUNCTION__,
                     gnutls_strerror ((int) count));
          return -1;
        }
      to_client_start += count;
      g_debug ("=> client  %u bytes", (unsigned int) count);
    }
  g_debug ("=> client  done");
  to_client_start = to_client_end = 0;

  /* Wrote everything. */
  return 0;
}

/**
 * @brief Write as much as possible from \ref to_client to the client.
 *
 * @param[in]  client_socket  The client socket.
 *
 * @return 0 wrote everything, -1 error, -2 wrote as much as client accepted.
 */
static int
write_to_client_unix (int client_socket)
{
  while (to_client_start < to_client_end)
    {
      ssize_t count;
      count = write (client_socket,
                     to_client + to_client_start,
                     to_client_end - to_client_start);
      if (count < 0)
        {
          if (errno == EAGAIN)
            /* Wrote as much as client would accept. */
            return -2;
          if (errno == EINTR)
            /* Interrupted, try write again. */
            continue;
          g_warning ("%s: failed to write to client: %s",
                     __FUNCTION__,
                     strerror (errno));
          return -1;
        }
      to_client_start += count;
      g_debug ("=> client  %u bytes", (unsigned int) count);
    }
  g_debug ("=> client  done");
  to_client_start = to_client_end = 0;

  /* Wrote everything. */
  return 0;
}

/**
 * @brief Write as much as possible from \ref to_client to the client.
 *
 * @param[in]  client_connection  The client connection.
 *
 * @return 0 wrote everything, -1 error, -2 wrote as much as client accepted.
 */
static int
write_to_client (gvm_connection_t *client_connection)
{
  if (client_connection->tls)
    return write_to_client_tls (&client_connection->session);
  return write_to_client_unix (client_connection->socket);
}

/**
 * @brief Send a response message to the client.
 *
 * Queue a message in \ref to_client.
 *
 * @param[in]  msg                   The message, a string.
 * @param[in]  write_to_client_data  Argument to \p write_to_client.
 *
 * @return TRUE if write to client failed, else FALSE.
 */
static gboolean
gmpd_send_to_client (const char *msg, void *write_to_client_data)
{
  assert (to_client_end <= TO_CLIENT_BUFFER_SIZE);
  assert (msg);

  while (((buffer_size_t) TO_CLIENT_BUFFER_SIZE) - to_client_end < strlen (msg))
    {
      buffer_size_t length;

      /* Too little space in to_client buffer for message. */

      switch (write_to_client (write_to_client_data))
        {
        case 0: /* Wrote everything in to_client. */
          break;
        case -1: /* Error. */
          g_debug ("   %s full (%i < %zu); client write failed",
                   __FUNCTION__,
                   ((buffer_size_t) TO_CLIENT_BUFFER_SIZE) - to_client_end,
                   strlen (msg));
          return TRUE;
        case -2: /* Wrote as much as client was willing to accept. */
          break;
        default: /* Programming error. */
          assert (0);
        }

      length = ((buffer_size_t) TO_CLIENT_BUFFER_SIZE) - to_client_end;

      if (length > strlen (msg))
        break;

      memmove (to_client + to_client_end, msg, length);
      g_debug ("-> client: %.*s", (int) length, msg);
      to_client_end += length;
      msg += length;
    }

  if (strlen (msg))
    {
      assert (strlen (msg)
              <= (((buffer_size_t) TO_CLIENT_BUFFER_SIZE) - to_client_end));
      memmove (to_client + to_client_end, msg, strlen (msg));
      g_debug ("-> client: %s", msg);
      to_client_end += strlen (msg);
    }

  return FALSE;
}

/**
 * @brief Clean session.
 *
 * @param[in]  client_connection  Connection.
 */
static void
session_clean (gvm_connection_t *client_connection)
{
  if (client_connection->session)
    {
      gnutls_deinit (client_connection->session);
      client_connection->session = NULL;
    }
  if (client_connection->credentials)
    {
      gnutls_certificate_free_credentials (client_connection->credentials);
      client_connection->credentials = NULL;
    }
}

/**
 * @brief Serve the Greenbone Management Protocol (GMP).
 *
 * Loop reading input from the sockets, processing
 * the input, and writing any results to the appropriate socket.
 * Exit the loop on reaching end of file on the client socket.
 *
 * Read input from the client and scanner.
 * Process the input with \ref process_gmp_client_input and
 * \ref process_otp_scanner_input.  Write the results to the client.
 *
 * \if STATIC
 *
 * Read input with \ref read_from_client and \ref openvas_scanner_read.
 * Write the results with \ref write_to_client.  Write to the server
 * with \ref openvas_scanner_write.
 *
 * \endif
 *
 * If client socket is 0 or less, then update the NVT cache and exit.
 *
 * @param[in]  client_connection    Connection.
 * @param[in]  database             Location of manage database.
 * @param[in]  disable              Commands to disable.
 *
 * @return 0 success, 1 scanner still loading, -1 error, -2 scanner has no cert.
 */
int
serve_gmp (gvm_connection_t *client_connection,
           const gchar *database,
           gchar **disable)
{
  int nfds, scan_handler = 0, rc = 0;
  /* True if processing of the client input is waiting for space in the
   * to_scanner or to_client buffer. */
  short client_input_stalled;
  /* Client status flag.  Set to 0 when the client closes the connection
   * while the scanner is active. */
  short client_active = client_connection->socket > 0;

  if (client_connection->socket < 0)
    gmpd_nvt_cache_mode = client_connection->socket;

  if (gmpd_nvt_cache_mode == 0)
    g_debug ("   Serving GMP");

  /* Initialise the XML parser and the manage library. */
  init_gmp_process (gmpd_nvt_cache_mode,
                    database,
                    (int (*) (const char *, void *)) gmpd_send_to_client,
                    (void *) client_connection,
                    disable);

  /* Setup the scanner address and try to connect. */
  if (gmpd_nvt_cache_mode && !openvas_scanner_connected ())
    {
      int ret;

      /* Is here because it queries the DB and needs it initialized.
       * XXX: Move outside serve_gmp ().
       */

      ret = manage_scanner_set_default ();
      if (ret)
        return ret;
      if (openvas_scanner_connect () || openvas_scanner_init (1))
        {
          openvas_scanner_close ();
          return -1;
        }
    }

  client_input_stalled = 0;

  /** @todo Confirm and clarify complications, especially last one. */
  /* Loop handling input from the sockets.
   *
   * That is, select on all the socket fds and then, as necessary
   *   - read from the client into buffer from_client
   *   - write to the scanner from buffer to_scanner
   *   - read from the scanner into buffer from_scanner
   *   - write to the client from buffer to_client.
   *
   * On reading from an fd, immediately try react to the input.  On reading
   * from the client call process_gmp_client_input, which parses GMP
   * commands and may write to to_scanner and to_client.  On reading from
   * the scanner call process_otp_scanner_input, which updates information
   * kept about the scanner.
   *
   * There are a few complications here
   *   - the program must read from or write to an fd returned by select
   *     before selecting on the fd again,
   *   - the program need only select on the fds for writing if there is
   *     something to write,
   *   - similarly, the program need only select on the fds for reading
   *     if there is buffer space available,
   *   - the buffers from_client and from_scanner can become full during
   *     reading
   *   - a read from the client can be stalled by the to_scanner buffer
   *     filling up, or the to_client buffer filling up (in which case
   *     process_gmp_client_input will try to write the to_client buffer
   *     itself),
   *   - a read from the scanner can, theoretically, be stalled by the
   *     to_scanner buffer filling up (during initialisation).
   */

  nfds = openvas_scanner_get_nfds (client_connection->socket);
  while (1)
    {
      int ret;
      fd_set readfds, writefds;
      int termination_signal = get_termination_signal ();

      if (termination_signal)
        {
          g_debug ("%s: Received %s signal.",
                   __FUNCTION__,
                   strsignal (get_termination_signal ()));

          if (openvas_scanner_connected ())
            {
              openvas_scanner_close ();
            }

          goto client_free;
        }

      /* Setup for select. */

      /** @todo nfds must only include a socket if it's in >= one set. */

      FD_ZERO (&readfds);
      FD_ZERO (&writefds);

      /** @todo Shutdown on failure (for example, if a read fails). */

      if (client_active)
        {
          /* See whether to read from the client.  */
          if (from_client_end < from_buffer_size)
            FD_SET (client_connection->socket, &readfds);
          /* See whether to write to the client.  */
          if (to_client_start < to_client_end)
            FD_SET (client_connection->socket, &writefds);
        }

      /* See whether we need to read from the scannner.  */
      if (openvas_scanner_connected ()
          && (scanner_init_state == SCANNER_INIT_DONE
              || scanner_init_state == SCANNER_INIT_DONE_CACHE_MODE
              || scanner_init_state == SCANNER_INIT_DONE_CACHE_MODE_UPDATE
              || scanner_init_state == SCANNER_INIT_SENT_COMPLETE_LIST
              || scanner_init_state == SCANNER_INIT_SENT_COMPLETE_LIST_UPDATE
              || scanner_init_state == SCANNER_INIT_SENT_VERSION)
          && !openvas_scanner_full ())
        openvas_scanner_fd_set (&readfds);

      /* See whether we need to write to the scanner.  */
      if (openvas_scanner_connected ()
          && (((scanner_init_state == SCANNER_INIT_TOP
                || scanner_init_state == SCANNER_INIT_DONE
                || scanner_init_state == SCANNER_INIT_DONE_CACHE_MODE
                || scanner_init_state == SCANNER_INIT_DONE_CACHE_MODE_UPDATE)
               && to_server_buffer_space () > 0)
              || scanner_init_state == SCANNER_INIT_CONNECTED
              || scanner_init_state == SCANNER_INIT_GOT_FEED_VERSION
              || scanner_init_state == SCANNER_INIT_GOT_PLUGINS))
        openvas_scanner_fd_set (&writefds);

      /* Select, then handle result.  Due to GNUTLS internal buffering
       * we test for pending records first and emulate a select call
       * in that case.  Note, that GNUTLS guarantees that writes are
       * not buffered.  Note also that GNUTLS versions < 3 did not
       * exhibit a problem in Scanner due to a different buffering
       * strategy.  */
      ret = 0;
      if (client_connection->socket > 0 && client_connection->tls
          && FD_ISSET (client_connection->socket, &readfds)
          && gnutls_record_check_pending (client_connection->session))
        {
          FD_ZERO (&readfds);
          FD_ZERO (&writefds);
          ret++;
          FD_SET (client_connection->socket, &readfds);
        }
      if (openvas_scanner_fd_isset (&readfds))
        {
          if (openvas_scanner_session_peek ())
            {
              if (!ret)
                {
                  FD_ZERO (&readfds);
                  FD_ZERO (&writefds);
                }
              ret++;
              openvas_scanner_fd_set (&readfds);
            }
          else if (openvas_scanner_peek () == 0)
            {
              /* Scanner has gone down.  Exit. */
              rc = -1;
              goto client_free;
            }
        }

      if (!ret)
        {
          /* Timeout periodically, so that process_gmp_change runs
           * periodically. */
          struct timeval timeout;

          timeout.tv_usec = 0;
          timeout.tv_sec = 1;
          ret = select (nfds, &readfds, &writefds, NULL, &timeout);
        }
      if ((ret < 0 && errno == EINTR) || ret == 0)
        {
          if (process_gmp_change () == -1)
            {
              rc = -1;
              goto client_free;
            }
          if (!scan_handler && !gmpd_nvt_cache_mode)
            continue;
        }
      else if (ret < 0)
        {
          g_warning (
            "%s: child select failed: %s", __FUNCTION__, strerror (errno));
          rc = -1;
          goto client_free;
        }

      /* Read any data from the client. */
      if (client_connection->socket > 0
          && FD_ISSET (client_connection->socket, &readfds))
        {
          buffer_size_t initial_start = from_client_end;

          switch (read_from_client (client_connection))
            {
            case 0: /* Read everything. */
              break;
            case -1: /* Error. */
              rc = -1;
              goto client_free;
            case -2: /* from_client buffer full. */
              /* There may be more to read. */
              break;
            case -3: /* End of file. */
              g_debug ("   EOF reading from client");
              if (client_connection->socket > 0
                  && FD_ISSET (client_connection->socket, &writefds))
                /* Write rest of to_client to client, so that the client gets
                 * any buffered output and the response to the error. */
                write_to_client (client_connection);
              rc = 0;
              goto client_free;
            default: /* Programming error. */
              assert (0);
            }

          /* This check prevents output in the "asynchronous network
           * error" case. */
          if (from_client_end > initial_start)
            {
              if (g_strstr_len (from_client + initial_start,
                                from_client_end - initial_start,
                                "<password>"))
                g_debug ("<= client  Input may contain password, suppressed");
              else
                g_debug ("<= client  \"%.*s\"",
                         from_client_end - initial_start,
                         from_client + initial_start);
            }

          ret = process_gmp_client_input ();
          if (ret == 0)
            /* Processed all input. */
            client_input_stalled = 0;
          else if (ret == 3)
            {
              /* In the parent after a start_task fork. Free the scanner session
               * without closing it, for usage by the child process. */
              set_scanner_init_state (SCANNER_INIT_TOP);
              openvas_scanner_free ();
              nfds = openvas_scanner_get_nfds (client_connection->socket);
              client_input_stalled = 0;
              /* Skip the rest of the loop because the scanner socket is
               * a new socket.  This is asking for select trouble, really. */
              continue;
            }
          else if (ret == 2)
            {
              /* Now in a process forked to run a task, which has
               * successfully started the task.  Close the client
               * connection, as the parent process has continued the
               * session with the client. */
              session_clean (client_connection);
              client_active = 0;
              client_input_stalled = 0;
              scan_handler = 1;
            }
          else if (ret == 4)
            {
              /* Now in a process forked for some operation which has
               * successfully completed.  Close the client connection,
               * and exit, as the parent process has continued the
               * session with the client. */
              session_clean (client_connection);
              return 0;
            }
          else if (ret == -10)
            {
              /* Now in a process forked to run a task, which has
               * failed in starting the task. */
              session_clean (client_connection);
              return -1;
            }
          else if (ret == -1 || ret == -4)
            {
              /* Error.  Write rest of to_client to client, so that the
               * client gets any buffered output and the response to the
               * error. */
              write_to_client (client_connection);
              rc = -1;
              goto client_free;
            }
          else if (ret == -2)
            {
              /* to_scanner buffer full. */
              g_debug ("   client input stalled 1");
              client_input_stalled = 1;
              /* Carry on to write to_scanner. */
            }
          else if (ret == -3)
            {
              /* to_client buffer full. */
              g_debug ("   client input stalled 2");
              client_input_stalled = 2;
              /* Carry on to write to_client. */
            }
          else
            {
              /* Programming error. */
              assert (0);
              client_input_stalled = 0;
            }
        }

      /* Read any data from the scanner. */
      if (openvas_scanner_connected ()
          && (openvas_scanner_fd_isset (&readfds) || scan_handler))
        {
          switch (openvas_scanner_read ())
            {
            case 0: /* Read everything. */
              break;
            case -1: /* Error. */
              /* This may be because the scanner closed the connection
               * at the end of a command. */
              /** @todo Then should get EOF (-3). */
              set_scanner_init_state (SCANNER_INIT_TOP);
              rc = -1;
              goto client_free;
            case -2: /* from_scanner buffer full. */
              /* There may be more to read. */
              break;
            case -3: /* End of file. */
              set_scanner_init_state (SCANNER_INIT_TOP);
              if (client_active == 0)
                /* The client has closed the connection, so exit. */
                return 0;
              /* Scanner went down, exit. */
              rc = -1;
              goto client_free;
            default: /* Programming error. */
              assert (0);
            }
        }

      /* Write any data to the scanner. */
      if (openvas_scanner_connected ()
          && (openvas_scanner_fd_isset (&writefds) || scan_handler))
        {
          /* Write as much as possible to the scanner. */

          switch (openvas_scanner_write (gmpd_nvt_cache_mode))
            {
            case 0: /* Wrote everything in to_scanner. */
              break;
            case -1: /* Error. */
              /** @todo This may be because the scanner closed the connection
               * at the end of a command? */
              rc = -1;
              goto client_free;
            case -2: /* Wrote as much as scanner was willing to accept. */
              break;
            case -3: /* Did an initialisation step. */
              break;
            default: /* Programming error. */
              assert (0);
            }
        }

      /* Write any data to the client. */
      if (client_connection->socket > 0
          && FD_ISSET (client_connection->socket, &writefds))
        {
          /* Write as much as possible to the client. */

          switch (write_to_client (client_connection))
            {
            case 0: /* Wrote everything in to_client. */
              break;
            case -1: /* Error. */
              rc = -1;
              goto client_free;
            case -2: /* Wrote as much as client was willing to accept. */
              break;
            default: /* Programming error. */
              assert (0);
            }
        }

      if (client_input_stalled)
        {
          /* Try process the client input, in case writing to the scanner
           * or client has freed some space in to_scanner or to_client. */

          ret = process_gmp_client_input ();
          if (ret == 0)
            /* Processed all input. */
            client_input_stalled = 0;
          else if (ret == 3)
            {
              /* In the parent after a start_task fork. Free the scanner session
               * without closing it, for usage by the child process. */
              openvas_scanner_free ();
              set_scanner_init_state (SCANNER_INIT_TOP);
              nfds = openvas_scanner_get_nfds (client_connection->socket);
              /* Skip the rest of the loop because the scanner socket is
               * a new socket.  This is asking for select trouble, really. */
              continue;
            }
          else if (ret == 2)
            {
              /* Now in a process forked to run a task, which has
               * successfully started the task.  Close the client
               * connection, as the parent process has continued the
               * session with the client. */
              session_clean (client_connection);
              scan_handler = 1;
              client_active = 0;
            }
          else if (ret == 4)
            {
              /* Now in a process forked for some operation which has
               * successfully completed.  Close the client connection,
               * and exit, as the parent process has continued the
               * session with the client. */
              session_clean (client_connection);
              return 0;
            }
          else if (ret == -10)
            {
              /* Now in a process forked to run a task, which has
               * failed in starting the task. */
              session_clean (client_connection);
              return -1;
            }
          else if (ret == -1)
            {
              /* Error.  Write rest of to_client to client, so that the
               * client gets any buffered output and the response to the
               * error. */
              write_to_client (client_connection);
              rc = -1;
              goto client_free;
            }
          else if (ret == -2)
            {
              /* to_scanner buffer full. */
              g_debug ("   client input still stalled (1)");
              client_input_stalled = 1;
            }
          else if (ret == -3)
            {
              /* to_client buffer full. */
              g_debug ("   client input still stalled (2)");
              client_input_stalled = 2;
            }
          else
            {
              /* Programming error. */
              assert (0);
              client_input_stalled = 0;
            }
        }

      if (openvas_scanner_connected ())
        {
          /* Try process the scanner input, in case writing to the scanner
           * has freed some space in to_scanner. */

          ret = process_otp_scanner_input ();
          if (ret == 1)
            {
              /* Received scanner BYE.  Write out the rest of to_scanner (the
               * BYE ACK).
               */
              openvas_scanner_write (gmpd_nvt_cache_mode);
              set_scanner_init_state (SCANNER_INIT_TOP);
              if (client_active == 0)
                return 0;
              openvas_scanner_free ();
              nfds = openvas_scanner_get_nfds (client_connection->socket);
            }
          else if (ret == 2)
            {
              /* Bad login to scanner. */
              if (client_active == 0)
                return 0;
              rc = -1;
              goto client_free;
            }
          else if (ret == 3)
            {
              /* Calls via serve_client() should continue. */
              if (gmpd_nvt_cache_mode)
                return 1;
              openvas_scanner_close ();
            }
          else if (ret == 4)
            {
              /* NVT update requested and NVTS are already at that version. */
              assert (gmpd_nvt_cache_mode);
              return 0;
            }
          else if (ret == -1)
            {
              /* Error. */
              rc = -1;
              goto client_free;
            }
          else if (ret == -3)
            /* to_scanner buffer still full. */
            g_debug ("   scanner input stalled");
          else
            {
              /* Programming error. */
              assert (ret == 0 || ret == 5);
            }
        }

      if (process_gmp_change () == -1)
        {
          rc = -1;
          goto client_free;
        }

    } /* while (1) */

client_free:
  if (client_active)
    gvm_connection_free (client_connection);
  return rc;
}
