/* 
 * Most new code since 2022 by Mageni Security LLC
 * Copyright (C) 2009-2018 Greenbone Networks GmbH
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
 * @file  gvmd.c
 * @brief The Greenbone Vulnerability Manager daemon.
 *
 * This file defines the Greenbone Vulnerability Manager daemon.  The Manager
 * serves the Greenbone Management Protocol (GMP) to clients such as Greenbone
 * Security Assistant (the web interface).  The Manager and GMP give clients
 * full access to an OpenVAS Scanner.
 *
 * The entry point to the daemon is the \ref main function.  From there
 * the references in the function documentation describe the flow of
 * control in the program.
 */

/**
 * \mainpage
 *
 * \section Introduction
 * \verbinclude README.md
 *
 * \section manpages Manual Pages
 * \subpage manpage
 *
 * \section Installation
 * \verbinclude INSTALL.md
 *
 * \section Implementation
 *
 * The command line entry to the manager is defined in
 * src/\ref gvmd.c.  The manager is a GMP server.
 *
 * The GMP server is defined in src/\ref gmpd.c.  It uses the OTP library
 * to handle the OTP server and the GMP library to handle the GMP client.
 * The OTP library is defined in src/\ref otp.c.  The GMP library is defined
 * in src/\ref gmp.c.  Both the GMP and OTP libraries use the Manage library
 * to manage credentials and tasks.  The manage
 * library is defined in src/\ref manage.c and src/\ref manage_sql.c .
 *
 * The OTP and Manage libraries both use the Comm library to communication
 * with the OTP server (src/\ref comm.c).
 *
 * \subsection Forking
 *
 * The main daemon manager process will fork for every incoming connection and
 * for every scheduled task.
 *
 * \section copying License Information
 * \verbinclude COPYING
 */

/**
 * \page manpage gvmd
 * \htmlinclude doc/gvmd.html
 */

#include "comm.h"
#include "gmpd.h"
#include "manage.h"
#include "manage_sql_secinfo.h"
#include "scanner.h"
#include "utils.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <gnutls/gnutls.h>
#include <grp.h>
#include "../../libraries/base/logging.h"
#include "../../libraries/base/pidfile.h"
#include "../../libraries/base/proctitle.h"
#include "../../libraries/base/pwpolicy.h"
#include "../../libraries/util/serverutils.h"
#include <locale.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef GIT_REV_AVAILABLE
#include "gitrevision.h"
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md   main"

/**
 * @brief The version number of this program.
 */
#ifndef APID_VERSION
#define APID_VERSION "-1"
#endif

/**
 * @brief The name of the underlying Operating System.
 */
#ifndef GVM_OS_NAME
#define GVM_OS_NAME "-1"
#endif

/**
 * @brief Scanner (openvassd) address.
 */
#define OPENVASSD_ADDRESS MAGENI_RUN_DIR "/mageni-vscand.sock"

/**
 * @brief Location of scanner certificate.
 */
#ifndef MAGENI_SCANNER_CERTIFICATE
#define MAGENI_SCANNER_CERTIFICATE "/var/lib/openvas/CA/servercert.pem"
#endif

/**
 * @brief Location of scanner certificate private key.
 */
#ifndef MAGENI_SCANNER_KEY
#define MAGENI_SCANNER_KEY "/var/lib/openvas/private/CA/serverkey.pem"
#endif

/**
 * @brief Location of Certificate Authority certificate.
 */
#ifndef MAGENI_CA_CERTIFICATE
#define MAGENI_CA_CERTIFICATE "/usr/local/var/lib/mageni/private/CA/cacert.pem"
#endif

/**
 * @brief Location of client certificate.
 */
#ifndef MAGENI_CLIENT_CERTIFICATE
#define MAGENI_CLIENT_CERTIFICATE "/usr/local/var/lib/mageni/private/CA/clientcert.pem"
#endif

/**
 * @brief Location of client certificate private key.
 */
#ifndef MAGENI_CLIENT_KEY
#define MAGENI_CLIENT_KEY "/usr/local/var/lib/mageni/private/CA/clientkey.pem"
#endif

/**
 * @brief Scanner port.
 *
 * Used if /etc/services "otp" and --port missing.
 */
#define OPENVASSD_PORT 9391

/**
 * @brief Manager port.
 *
 * Used if /etc/services "gmp" and --sport are missing.
 */
#define GVMD_PORT 9390

/**
 * @brief Second argument to `listen'.
 */
#define MAX_CONNECTIONS 512

/**
 * @brief Default value for client_watch_interval
 */
#define DEFAULT_CLIENT_WATCH_INTERVAL 1

/**
 * @brief Interval in seconds to check whether client connection was closed.
 */
static int client_watch_interval = DEFAULT_CLIENT_WATCH_INTERVAL;

/**
 * @brief The socket accepting GMP connections from clients.
 */
static int manager_socket = -1;

/**
 * @brief The optional, second socket accepting GMP connections from clients.
 */
static int manager_socket_2 = -1;

#if LOG
/**
 * @brief The log stream.
 */
FILE *log_stream = NULL;
#endif

/**
 * @brief Whether to use TLS for client connections.
 */
static int use_tls = 0;

/**
 * @brief The client session.
 */
static gnutls_session_t client_session;

/**
 * @brief The client credentials.
 */
static gnutls_certificate_credentials_t client_credentials;

/**
 * @brief Location of the manage database.
 */
static gchar *database = NULL;

/**
 * @brief Is this process parent or child?
 */
static int is_parent = 1;

/**
 * @brief Flag for signal handlers.
 */
volatile int termination_signal = 0;

/**
 * @brief The address of the Scanner.
 */
static gchar **disabled_commands = NULL;

/**
 * @brief Flag indicating that encrypted credentials are disabled.
 *
 * Setting this flag does not change any existing encrypted tuples but
 * simply won't encrypt or decrypt anything.  The variable is
 * controlled by the command line option --disable-encrypted-credentials.
 */
gboolean disable_encrypted_credentials;

/**
 * @brief Flag indicating that task scheduling is enabled.
 */
static gboolean scheduling_enabled;

/**
 * @brief The GMP client's address.
 */
char client_address[INET6_ADDRSTRLEN];

/**
 * @brief Signal mask to restore when going from blocked to normal signaling.
 */
static sigset_t *sigmask_normal = NULL;

/**
 * @brief GnuTLS priorities.
 */
static gchar *priorities_option = "NORMAL";

/**
 * @brief GnuTLS DH params file.
 */
static gchar *dh_params_option = NULL;

/**
 * @brief Whether an NVT update is in progress.
 */
static int update_in_progress = 0;

/**
 * @brief Logging parameters, as passed to setup_log_handlers.
 */
GSList *log_config = NULL;

/* Helpers. */

/**
 * @brief Sets the GnuTLS priorities for a given session.
 *
 * @param[in]   session     Session for which to set the priorities.
 * @param[in]   priority    Priority string.
 */
static void
set_gnutls_priority (gnutls_session_t *session, const char *priority)
{
  const char *errp = NULL;
  if (gnutls_priority_set_direct (*session, priority, &errp)
      == GNUTLS_E_INVALID_REQUEST)
    g_warning ("Invalid GnuTLS priority: %s", errp);
}

/**
 * @brief Lock gvm-helping for an option.
 *
 * @param[in]  lockfile_checking  The gvm-checking lockfile.
 *
 * @return 0 success, -1 failed.
 */
static int
option_lock (lockfile_t *lockfile_checking)
{
  static lockfile_t lockfile_helping;

  if (lockfile_lock_shared_nb (&lockfile_helping, "mageni-sqlite-helping"))
    {
      g_critical ("%s: Error getting helping lock", __FUNCTION__);
      return -1;
    }

  if (lockfile_unlock (lockfile_checking))
    {
      g_critical ("%s: Error releasing checking lock", __FUNCTION__);
      return -1;
    }

  return 0;
}

/* Forking, serving the client. */

/**
 * @brief Connection watcher thread data.
 */
typedef struct
{
  gvm_connection_t *client_connection; ///< Client connection.
  int connection_closed;               ///< Whether connection is closed.
  pthread_mutex_t mutex;               ///< Mutex.
} connection_watcher_data_t;

/**
 * @brief  Create a new connection watcher thread data structure.
 *
 * @param[in]  client_connection   GVM connection to client to watch.
 *
 * @return  Newly allocated watcher thread data.
 */
static connection_watcher_data_t *
connection_watcher_data_new (gvm_connection_t *client_connection)
{
  connection_watcher_data_t *watcher_data;
  watcher_data = g_malloc (sizeof (connection_watcher_data_t));

  watcher_data->client_connection = client_connection;
  watcher_data->connection_closed = 0;
  pthread_mutex_init (&(watcher_data->mutex), NULL);

  return watcher_data;
}

/**
 * @brief   Thread start routine watching the client connection.
 *
 * @param[in] data  The connection data watcher struct.
 *
 * @return  Always NULL.
 */
static void *
watch_client_connection (void *data)
{
  int active;
  connection_watcher_data_t *watcher_data;
  gvm_connection_t *client_connection;

  pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, NULL);
  watcher_data = (connection_watcher_data_t *) data;
  client_connection = watcher_data->client_connection;

  pthread_mutex_lock (&(watcher_data->mutex));
  active = 1;
  pthread_mutex_unlock (&(watcher_data->mutex));

  while (active)
    {
      pthread_setcancelstate (PTHREAD_CANCEL_ENABLE, NULL);
      sleep (client_watch_interval);
      pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, NULL);

      pthread_mutex_lock (&(watcher_data->mutex));

      if (watcher_data->connection_closed)
        {
          active = 0;
          pthread_mutex_unlock (&(watcher_data->mutex));
          continue;
        }
      int ret;
      char buf[1];
      errno = 0;

      ret = recv (client_connection->socket, buf, 1, MSG_PEEK);

      if (ret >= 0)
        {
          if (watcher_data->connection_closed == 0)
            {
              g_debug ("%s: Client connection closed", __FUNCTION__);
              sql_cancel ();
              active = 0;
              watcher_data->connection_closed = 1;
            }
        }

      pthread_mutex_unlock (&(watcher_data->mutex));
    }

  return NULL;
}

/**
 * @brief Serve the client.
 *
 * Connect to the openvassd scanner, then call \ref serve_gmp to serve GMP.
 *
 * In all cases, close client_socket before returning.
 *
 * @param[in]  server_socket      The socket connected to the Manager.
 * @param[in]  client_connection  The connection to the client.
 *
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
static int
serve_client (int server_socket, gvm_connection_t *client_connection)
{
  pthread_t watch_thread;
  connection_watcher_data_t *watcher_data;

  if (server_socket > 0)
    {
      int optval;

      optval = 1;
      if (setsockopt (
            server_socket, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof (int)))
        {
          g_critical ("%s: failed to set SO_KEEPALIVE on scanner socket: %s",
                      __FUNCTION__,
                      strerror (errno));
          exit (EXIT_FAILURE);
        }
    }

  if (client_watch_interval)
    {
      watcher_data = connection_watcher_data_new (client_connection);
      pthread_create (
        &watch_thread, NULL, watch_client_connection, watcher_data);
    }
  else
    {
      watcher_data = NULL;
    }

  if (client_connection->tls
      && gvm_server_attach (client_connection->socket, &client_session))
    {
      g_debug ("%s: failed to attach client session to socket %i",
               __FUNCTION__,
               client_connection->socket);
      goto fail;
    }

  /* The socket must have O_NONBLOCK set, in case an "asynchronous network
   * error" removes the data between `select' and `read'. */
  if (fcntl (client_connection->socket, F_SETFL, O_NONBLOCK) == -1)
    {
      g_warning ("%s: failed to set real client socket flag: %s",
                 __FUNCTION__,
                 strerror (errno));
      goto fail;
    }

  /* Serve GMP. */

  /* It's up to serve_gmp to gvm_server_free client_*. */
  if (serve_gmp (client_connection, database, disabled_commands))
    goto server_fail;

  if (watcher_data)
    {
      pthread_mutex_lock (&(watcher_data->mutex));
      watcher_data->connection_closed = 1;
      pthread_mutex_unlock (&(watcher_data->mutex));
      pthread_cancel (watch_thread);
      pthread_join (watch_thread, NULL);
      g_free (watcher_data);
    }
  return EXIT_SUCCESS;

fail:
  if (watcher_data)
    {
      pthread_mutex_lock (&(watcher_data->mutex));
      gvm_connection_free (client_connection);
      watcher_data->connection_closed = 1;
      pthread_mutex_unlock (&(watcher_data->mutex));
    }
  else
    {
      gvm_connection_free (client_connection);
    }
server_fail:
  if (watcher_data)
    {
      pthread_mutex_lock (&(watcher_data->mutex));
      watcher_data->connection_closed = 1;
      pthread_mutex_unlock (&(watcher_data->mutex));
      pthread_cancel (watch_thread);
      pthread_join (watch_thread, NULL);
      g_free (watcher_data);
    }
  return EXIT_FAILURE;
}

/**
 * @brief Accept and fork.
 *
 * @param[in]  server_socket    Manager socket.
 * @param[in]  sigmask_current  Sigmask to restore in child.
 *
 * Accept the client connection and fork a child process to serve the client.
 * The child calls \ref serve_client to do the rest of the work.
 */
static void
accept_and_maybe_fork (int server_socket, sigset_t *sigmask_current)
{
  /* Accept the client connection. */
  pid_t pid;
  int client_socket;
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof (addr);

  while ((client_socket =
            accept (server_socket, (struct sockaddr *) &addr, &addrlen))
         == -1)
    {
      if (errno == EINTR)
        continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        /* The connection is gone, return to select. */
        return;
      g_critical ("%s: failed to accept client connection: %s",
                  __FUNCTION__,
                  strerror (errno));
      exit (EXIT_FAILURE);
    }
  sockaddr_as_str (&addr, client_address);

  /* Fork a child to serve the client. */
  pid = fork ();
  switch (pid)
    {
    case 0:
      /* Child. */
      {
        int ret;
        struct sigaction action;
        gvm_connection_t client_connection;

        is_parent = 0;

        proctitle_set ("mageni-sqlite: Serving client");

        /* Restore the sigmask that was blanked for pselect. */
        pthread_sigmask (SIG_SETMASK, sigmask_current, NULL);

        memset (&action, '\0', sizeof (action));
        sigemptyset (&action.sa_mask);
        action.sa_handler = SIG_DFL;
        if (sigaction (SIGCHLD, &action, NULL) == -1)
          {
            g_critical ("%s: failed to set client SIGCHLD handler: %s",
                        __FUNCTION__,
                        strerror (errno));
            shutdown (client_socket, SHUT_RDWR);
            close (client_socket);
            exit (EXIT_FAILURE);
          }

        /* The socket must have O_NONBLOCK set, in case an "asynchronous
         * network error" removes the data between `select' and `read'.
         */
        if (fcntl (client_socket, F_SETFL, O_NONBLOCK) == -1)
          {
            g_critical ("%s: failed to set client socket flag: %s",
                        __FUNCTION__,
                        strerror (errno));
            shutdown (client_socket, SHUT_RDWR);
            close (client_socket);
            exit (EXIT_FAILURE);
          }
        /* Reopen the database (required after fork). */
        cleanup_manage_process (FALSE);
        memset (&client_connection, 0, sizeof (client_connection));
        client_connection.tls = use_tls;
        client_connection.socket = client_socket;
        client_connection.session = client_session;
        client_connection.credentials = client_credentials;
        ret = serve_client (server_socket, &client_connection);
        exit (ret);
      }
    case -1:
      /* Parent when error, return to select. */
      g_warning (
        "%s: failed to fork child: %s", __FUNCTION__, strerror (errno));
      close (client_socket);
      break;
    default:
      /* Parent.  Return to select. */
      close (client_socket);
      break;
    }
}

/* Connection forker for scheduler. */

/**
 * @brief Fork a child connected to the Manager.
 *
 * @param[in]  client_connection       Client connection.
 * @param[in]  uuid                    UUID of schedule user.
 * @param[in]  scheduler               Whether this is for the scheduler.
 *
 * @return PID parent on success, 0 child on success, -1 error.
 */
static int
fork_connection_internal (gvm_connection_t *client_connection,
                          const gchar *uuid,
                          int scheduler)
{
  int pid, parent_client_socket, ret;
  int sockets[2];
  struct sigaction action;

  /* Fork a child to use as scheduler client and server. */

  pid = fork ();
  switch (pid)
    {
    case 0:
      /* Child. */
      cleanup_manage_process (FALSE);
      break;

    case -1:
      /* Parent when error. */
      g_warning ("%s: fork: %s", __FUNCTION__, strerror (errno));
      return -1;
      break;

    default:
      /* Parent.  Return to caller. */
      g_debug ("%s: %i forked %i", __FUNCTION__, getpid (), pid);
      return pid;
      break;
    }

  /* This is now a child of the main Manager process.  It forks again.  The
   * only case that returns is the process that the caller can use for GMP
   * commands.  The caller must exit this process.
   */

  /* Restore the sigmask that was blanked for pselect. */
  if (sigmask_normal)
    pthread_sigmask (SIG_SETMASK, sigmask_normal, NULL);

  /* Create a connected pair of sockets. */
  if (socketpair (AF_UNIX, SOCK_STREAM, 0, sockets))
    {
      g_warning ("%s: socketpair: %s", __FUNCTION__, strerror (errno));
      exit (EXIT_FAILURE);
    }

  /* Split into a Manager client for the scheduler, and a Manager serving
   * GMP to that client. */

  is_parent = 0;

  pid = fork ();
  switch (pid)
    {
    case 0:
      /* Child.  Serve the scheduler GMP, then exit. */

      proctitle_set ("mageni-sqlite: Serving GMP internally");

      parent_client_socket = sockets[0];

      memset (&action, '\0', sizeof (action));
      sigemptyset (&action.sa_mask);
      action.sa_handler = SIG_DFL;
      if (sigaction (SIGCHLD, &action, NULL) == -1)
        {
          g_critical ("%s: failed to set client SIGCHLD handler: %s",
                      __FUNCTION__,
                      strerror (errno));
          shutdown (parent_client_socket, SHUT_RDWR);
          close (parent_client_socket);
          exit (EXIT_FAILURE);
        }

      /* The socket must have O_NONBLOCK set, in case an "asynchronous
       * network error" removes the data between `select' and `read'.
       */
      if (fcntl (parent_client_socket, F_SETFL, O_NONBLOCK) == -1)
        {
          g_critical ("%s: failed to set client socket flag: %s",
                      __FUNCTION__,
                      strerror (errno));
          shutdown (parent_client_socket, SHUT_RDWR);
          close (parent_client_socket);
          exit (EXIT_FAILURE);
        }

      init_gmpd_process (database, disabled_commands);

      /* Make any further authentications to this process succeed.  This
       * enables the scheduler to login as the owner of the scheduled
       * task. */
      manage_auth_allow_all (scheduler);
      set_scheduled_user_uuid (uuid);

      /* For TLS, create a new session, because the parent may have been in
       * the middle of using the old one. */

      if (use_tls)
        {
          if (gvm_server_new (GNUTLS_SERVER,
                              CACERT,
                              SCANNERCERT,
                              SCANNERKEY,
                              &client_session,
                              &client_credentials))
            {
              g_critical ("%s: client server initialisation failed",
                          __FUNCTION__);
              exit (EXIT_FAILURE);
            }
          set_gnutls_priority (&client_session, priorities_option);
          if (dh_params_option
              && set_gnutls_dhparams (client_credentials, dh_params_option))
            g_warning ("Couldn't set DH parameters from %s", dh_params_option);
        }

      /* Serve client. */

      g_debug ("%s: serving GMP to client on socket %i",
               __FUNCTION__,
               parent_client_socket);

      memset (client_connection, 0, sizeof (*client_connection));
      client_connection->tls = use_tls;
      client_connection->socket = parent_client_socket;
      client_connection->session = client_session;
      client_connection->credentials = client_credentials;
      ret = serve_client (manager_socket, client_connection);

      exit (ret);
      break;

    case -1:
      /* Parent when error. */

      g_warning ("%s: fork: %s", __FUNCTION__, strerror (errno));
      exit (EXIT_FAILURE);
      break;

    default:
      /* Parent.  */

      g_debug ("%s: %i forked %i", __FUNCTION__, getpid (), pid);

      proctitle_set ("mageni-sqlite: Requesting GMP internally");

      /* This process is returned as the child of
       * fork_connection_for_scheduler so that the returned parent can wait
       * on this process. */

      /** @todo Give the parent time to prepare. */
      gvm_sleep (5);

      memset (client_connection, 0, sizeof (*client_connection));
      client_connection->tls = use_tls;
      client_connection->socket = sockets[1];

      if (use_tls)
        {
          if (gvm_server_new (GNUTLS_CLIENT,
                              MAGENI_CA_CERTIFICATE,
                              MAGENI_CLIENT_CERTIFICATE,
                              MAGENI_CLIENT_KEY,
                              &client_connection->session,
                              &client_connection->credentials))
            exit (EXIT_FAILURE);

          if (gvm_server_attach (client_connection->socket,
                                 &client_connection->session))
            exit (EXIT_FAILURE);
        }

      g_debug ("%s: all set to request GMP on socket %i",
               __FUNCTION__,
               client_connection->socket);

      return 0;
      break;
    }

  exit (EXIT_FAILURE);
  return -1;
}

/**
 * @brief Fork a child connected to the Manager.
 *
 * @param[in]  client_connection   Client connection.
 * @param[in]  uuid                UUID of schedule user.
 *
 * @return PID parent on success, 0 child on success, -1 error.
 */
static int
fork_connection_for_scheduler (gvm_connection_t *client_connection,
                               const gchar *uuid)
{
  return fork_connection_internal (client_connection, uuid, 1);
}

/**
 * @brief Fork a child connected to the Manager.
 *
 * @param[in]  client_connection  Client connection.
 * @param[in]  uuid               UUID of user.
 *
 * @return PID parent on success, 0 child on success, -1 error.
 */
static int
fork_connection_for_event (gvm_connection_t *client_connection,
                           const gchar *uuid)
{
  return fork_connection_internal (client_connection, uuid, 0);
}

/* Maintenance functions. */

/**
 * @brief Free logging configuration.
 */
static void
log_config_free ()
{
  free_log_configuration (log_config);
  log_config = NULL;
}

/**
 * @brief Clean up for exit.
 *
 * Close sockets and streams.
 */
static void
cleanup ()
{
  g_debug ("   Cleaning up");
  /** @todo These should happen via gmp, maybe with "cleanup_gmp ();". */
  cleanup_manage_process (TRUE);
  g_strfreev (disabled_commands);
  if (manager_socket > -1)
    close (manager_socket);
  if (manager_socket_2 > -1)
    close (manager_socket_2);
#if LOG
  if (log_stream != NULL)
    {
      if (fclose (log_stream))
        g_critical (
          "%s: failed to close log stream: %s", __FUNCTION__, strerror (errno));
    }
#endif /* LOG */
  g_debug ("   Exiting");
  if (log_config)
    log_config_free ();

  /* Delete pidfile if this process is the parent. */
  if (is_parent == 1)
    pidfile_remove ("gvmd");
}

/**
 * @brief Setup signal handler.
 *
 * Exit on failure.
 *
 * @param[in]  signal   Signal.
 * @param[in]  handler  Handler.
 * @param[in]  block    Whether to block all other signals during handler.
 */
static void
setup_signal_handler (int signal, void (*handler) (int), int block)
{
  struct sigaction action;

  memset (&action, '\0', sizeof (action));
  if (block)
    sigfillset (&action.sa_mask);
  else
    sigemptyset (&action.sa_mask);
  action.sa_handler = handler;
  if (sigaction (signal, &action, NULL) == -1)
    {
      g_critical (
        "%s: failed to register %s handler", __FUNCTION__, strsignal (signal));
      exit (EXIT_FAILURE);
    }
}

/**
 * @brief Setup signal handler.
 *
 * Exit on failure.
 *
 * @param[in]  signal   Signal.
 * @param[in]  handler  Handler.
 * @param[in]  block    Whether to block all other signals during handler.
 */
static void
setup_signal_handler_info (int signal,
                           void (*handler) (int, siginfo_t *, void *),
                           int block)
{
  struct sigaction action;

  memset (&action, '\0', sizeof (action));
  if (block)
    sigfillset (&action.sa_mask);
  else
    sigemptyset (&action.sa_mask);
  action.sa_flags |= SA_SIGINFO;
  action.sa_sigaction = handler;
  if (sigaction (signal, &action, NULL) == -1)
    {
      g_critical (
        "%s: failed to register %s handler", __FUNCTION__, strsignal (signal));
      exit (EXIT_FAILURE);
    }
}

#ifndef NDEBUG
#include <execinfo.h>

/**
 * @brief Maximum number of frames in backtrace.
 *
 * For debugging backtrace in \ref handle_sigabrt.
 */
#define BA_SIZE 100
#endif

/**
 * @brief Handle a SIGABRT signal.
 *
 * @param[in]  given_signal  The signal that caused this function to run.
 */
static void
handle_sigabrt (int given_signal)
{
  static int in_sigabrt = 0;

  if (in_sigabrt)
    _exit (EXIT_FAILURE);
  in_sigabrt = 1;

#ifndef NDEBUG
  void *frames[BA_SIZE];
  int frame_count, index;
  char **frames_text;

  /* Print a backtrace. */
  frame_count = backtrace (frames, BA_SIZE);
  frames_text = backtrace_symbols (frames, frame_count);
  if (frames_text == NULL)
    {
      perror ("backtrace symbols");
      frame_count = 0;
    }
  for (index = 0; index < frame_count; index++)
    g_debug ("%s", frames_text[index]);
  free (frames_text);
#endif

  manage_cleanup_process_error (given_signal);
  cleanup ();
  /* Raise signal again, to exit with the correct return value. */
  setup_signal_handler (given_signal, SIG_DFL, 0);
  raise (given_signal);
}

/**
 * @brief Handle a termination signal.
 *
 * @param[in]  signal  The signal that caused this function to run.
 */
static void
handle_termination_signal (int signal)
{
  termination_signal = signal;

  sql_cancel ();
}

/**
 * @brief Handle a SIGSEGV signal.
 *
 * @param[in]  given_signal  The signal that caused this function to run.
 */
static void
handle_sigsegv (/* unused */ int given_signal)
{
  manage_cleanup_process_error (given_signal);

  /* This previously called "cleanup", but it seems that the regular manager
   * code runs again before the default handler is invoked, at least when the
   * SIGKILL is sent from the command line.  This was leading to errors which
   * were preventing the default handler from running and dumping core. */

  /* Raise signal again, to exit with the correct return value. */
  setup_signal_handler (given_signal, SIG_DFL, 0);
  raise (given_signal);
}

/**
 * @brief Handle a SIGCHLD signal.
 *
 * @param[in]  given_signal  The signal that caused this function to run.
 * @param[in]  info          Signal info.
 * @param[in]  ucontext      User context.
 */
static void
handle_sigchld (/* unused */ int given_signal, siginfo_t *info, void *ucontext)
{
  int status, pid;
  while ((pid = waitpid (-1, &status, WNOHANG)) > 0)
    if (update_in_progress == pid)
      /* This was the NVT update child, so allow updates again. */
      update_in_progress = 0;
}

/**
 * @brief Handle a SIGABRT signal.
 *
 * @param[in]  signal  The signal that caused this function to run.
 */
static void
handle_sigabrt_simple (int signal)
{
  exit (EXIT_FAILURE);
}

/**
 * @brief Updates the NVT Cache and exits or returns exit code.
 *
 * @param[in]  register_cleanup        Whether to register cleanup with atexit.
 *
 * @return If this function did not exit itself, returns exit code.
 */
static int
update_nvt_cache (int register_cleanup)
{
  int ret;
  gvm_connection_t connection;

  /* Initialise GMP daemon. */

  proctitle_set ("mageni-sqlite: Updating vulnerabilities cache");

  switch (init_gmpd (log_config,
                     -1,
                     database,
                     manage_max_hosts (),
                     0, /* Max email attachment size. */
                     0, /* Max email include size. */
                     0, /* Max email message size. */
                     NULL,
                     1 /* Skip DB check (including table creation). */))
    {
    case 0:
      break;
    case -2:
      g_critical ("%s: database is wrong version", __FUNCTION__);
      log_config_free ();
      exit (EXIT_FAILURE);
      break;
    case -1:
    default:
      g_critical ("%s: failed to initialise GMP daemon", __FUNCTION__);
      log_config_free ();
      exit (EXIT_FAILURE);
    }

  /* Register the `cleanup' function. */

  if (register_cleanup && atexit (&cleanup))
    {
      g_critical ("%s: failed to register `atexit' cleanup function",
                  __FUNCTION__);
      log_config_free ();
      exit (EXIT_FAILURE);
    }

  /* Register the signal handlers. */

  setup_signal_handler (SIGTERM, handle_termination_signal, 0);
  setup_signal_handler (SIGABRT, handle_sigabrt, 1);
  setup_signal_handler (SIGINT, handle_termination_signal, 0);
  setup_signal_handler (SIGHUP, SIG_IGN, 0);
  setup_signal_handler (SIGQUIT, handle_termination_signal, 0);
  setup_signal_handler (SIGSEGV, handle_sigsegv, 1);
  setup_signal_handler (SIGCHLD, SIG_IGN, 0);

  /* Call the GMP client serving function with a special client socket
   * value.  This invokes a scanner-only manager loop which will
   * request and cache the plugins, then exit. */

  connection.socket = -1;
  ret = serve_gmp (&connection, database, NULL);
  openvas_scanner_close ();
  switch (ret)
    {
    case 0:
      return EXIT_SUCCESS;
    case 1:
      return 2;
    case -2:
      g_critical ("%s: scanner OpenVAS Default has no cert", __FUNCTION__);
      return EXIT_FAILURE;
    default:
    case -1:
      return EXIT_FAILURE;
    }
}

/**
 * @brief Update NVT cache in forked child, retrying if scanner loading.
 *
 * Forks a child process to rebuild the nvt cache, retrying again if the
 * child process reports that the scanner is still loading.
 *
 * @return Exit status of child spawned to do rebuild.
 */
static int
update_nvt_cache_retry ()
{
  proctitle_set ("mageni-sqlite: Reloading vulnerabilities");

  /* Don't ignore SIGCHLD, in order to wait for child process. */
  setup_signal_handler (SIGCHLD, SIG_DFL, 0);
  while (1)
    {
      pid_t child_pid = fork ();
      if (child_pid > 0)
        {
          int status, i;
          /* Parent: Wait for child. */
          if (waitpid (child_pid, &status, 0) > 0 && WEXITSTATUS (status) != 2)
            return WEXITSTATUS (status);
          /* Child exit status == 2 means that the scanner is still loading. */
          for (i = 0; i < 10; i++)
            gvm_sleep (1);
        }
      else if (child_pid == 0)
        {
          /* Child: Try reload. */
          int ret = update_nvt_cache (0);

          exit (ret);
        }
    }
}

/**
 * @brief Update the NVT cache in a child process.
 *
 * @return 0 success, 1 update in progress, -1 error.  Always exits with
 *         EXIT_SUCCESS in child.
 */
static int
fork_update_nvt_cache ()
{
  int pid;
  sigset_t sigmask_all, sigmask_current;

  if (update_in_progress)
    {
      g_debug ("%s: Update skipped because an update is in progress",
               __FUNCTION__);
      return 1;
    }

  update_in_progress = 1;

  /* Block SIGCHLD until parent records the value of the child PID. */
  if (sigemptyset (&sigmask_all))
    {
      g_critical ("%s: Error emptying signal set", __FUNCTION__);
      return -1;
    }
  if (pthread_sigmask (SIG_BLOCK, &sigmask_all, &sigmask_current))
    {
      g_critical ("%s: Error setting signal mask", __FUNCTION__);
      return -1;
    }

  pid = fork ();
  switch (pid)
    {
    case 0:
      /* Child.   */

      proctitle_set ("mageni-sqlite: Updating vulnerabilities cache");

      /* Clean up the process. */

      pthread_sigmask (SIG_SETMASK, &sigmask_current, NULL);
      /** @todo This should happen via gmp, maybe with "cleanup_gmp ();". */
      cleanup_manage_process (FALSE);
      if (manager_socket > -1)
        close (manager_socket);
      if (manager_socket_2 > -1)
        close (manager_socket_2);

      /* Update the cache. */

      update_nvt_cache_retry ();

      /* Exit. */

      cleanup_manage_process (FALSE);
      exit (EXIT_SUCCESS);

      break;

    case -1:
      /* Parent when error. */
      g_warning ("%s: fork: %s", __FUNCTION__, strerror (errno));
      update_in_progress = 0;
      if (pthread_sigmask (SIG_SETMASK, &sigmask_current, NULL))
        g_warning ("%s: Error resetting signal mask", __FUNCTION__);
      return -1;

    default:
      /* Parent.  Unblock signals and continue. */
      g_debug ("%s: %i forked %i", __FUNCTION__, getpid (), pid);
      update_in_progress = pid;
      if (pthread_sigmask (SIG_SETMASK, &sigmask_current, NULL))
        g_warning ("%s: Error resetting signal mask", __FUNCTION__);
      return 0;
    }
}

/**
 * @brief Serve incoming connections, scheduling periodically.
 *
 * Enter an infinite loop, waiting for connections and passing the work to
 * `accept_and_maybe_fork'.
 *
 * Periodically, call the manage scheduler to start and stop scheduled tasks.
 */
static void
serve_and_schedule ()
{
  time_t last_schedule_time, last_sync_time;
  sigset_t sigmask_all;
  static sigset_t sigmask_current;

  last_schedule_time = 0;
  last_sync_time = 0;

  if (sigfillset (&sigmask_all))
    {
      g_critical ("%s: Error filling signal set", __FUNCTION__);
      exit (EXIT_FAILURE);
    }
  if (pthread_sigmask (SIG_BLOCK, &sigmask_all, &sigmask_current))
    {
      g_critical ("%s: Error setting signal mask", __FUNCTION__);
      exit (EXIT_FAILURE);
    }
  sigmask_normal = &sigmask_current;
  while (1)
    {
      int ret, nfds;
      fd_set readfds, exceptfds;
      struct timespec timeout;

      FD_ZERO (&readfds);
      FD_SET (manager_socket, &readfds);
      if (manager_socket_2 > -1)
        FD_SET (manager_socket_2, &readfds);
      FD_ZERO (&exceptfds);
      FD_SET (manager_socket, &exceptfds);
      if (manager_socket_2 > -1)
        FD_SET (manager_socket_2, &exceptfds);
      if (manager_socket >= manager_socket_2)
        nfds = manager_socket + 1;
      else
        nfds = manager_socket_2 + 1;

      if (termination_signal)
        {
          g_debug ("Received %s signal", strsignal (termination_signal));
          cleanup ();
          /* Raise signal again, to exit with the correct return value. */
          setup_signal_handler (termination_signal, SIG_DFL, 0);
          pthread_sigmask (SIG_SETMASK, sigmask_normal, NULL);
          raise (termination_signal);
        }

      if ((time (NULL) - last_schedule_time) >= SCHEDULE_PERIOD)
        switch (manage_schedule (
          fork_connection_for_scheduler, scheduling_enabled, sigmask_normal))
          {
          case 0:
            last_schedule_time = time (NULL);
            g_debug (
              "%s: last_schedule_time: %li", __FUNCTION__, last_schedule_time);
            break;
          case 1:
            break;
          default:
            exit (EXIT_FAILURE);
          }

      if ((time (NULL) - last_sync_time) >= SCHEDULE_PERIOD)
        {
          manage_sync (sigmask_normal, fork_update_nvt_cache);
          last_sync_time = time (NULL);
        }

      timeout.tv_sec = SCHEDULE_PERIOD;
      timeout.tv_nsec = 0;
      ret =
        pselect (nfds, &readfds, NULL, &exceptfds, &timeout, sigmask_normal);

      if (ret == -1)
        {
          /* Error occurred while selecting socket. */
          if (errno == EINTR)
            continue;
          g_critical ("%s: select failed: %s", __FUNCTION__, strerror (errno));
          exit (EXIT_FAILURE);
        }

      if (ret > 0)
        {
          /* Have an incoming connection. */
          if (FD_ISSET (manager_socket, &exceptfds))
            {
              g_critical ("%s: exception in select", __FUNCTION__);
              exit (EXIT_FAILURE);
            }
          if ((manager_socket_2 > -1)
              && FD_ISSET (manager_socket_2, &exceptfds))
            {
              g_critical ("%s: exception in select (2)", __FUNCTION__);
              exit (EXIT_FAILURE);
            }
          if (FD_ISSET (manager_socket, &readfds))
            accept_and_maybe_fork (manager_socket, sigmask_normal);
          if ((manager_socket_2 > -1) && FD_ISSET (manager_socket_2, &readfds))
            accept_and_maybe_fork (manager_socket_2, sigmask_normal);
        }

      if ((time (NULL) - last_schedule_time) >= SCHEDULE_PERIOD)
        switch (manage_schedule (
          fork_connection_for_scheduler, scheduling_enabled, sigmask_normal))
          {
          case 0:
            last_schedule_time = time (NULL);
            g_debug ("%s: last_schedule_time 2: %li",
                     __FUNCTION__,
                     last_schedule_time);
            break;
          case 1:
            break;
          default:
            exit (EXIT_FAILURE);
          }

      if ((time (NULL) - last_sync_time) >= SCHEDULE_PERIOD)
        {
          manage_sync (sigmask_normal, fork_update_nvt_cache);
          last_sync_time = time (NULL);
        }

      if (termination_signal)
        {
          g_debug ("Received %s signal", strsignal (termination_signal));
          cleanup ();
          /* Raise signal again, to exit with the correct return value. */
          setup_signal_handler (termination_signal, SIG_DFL, 0);
          pthread_sigmask (SIG_SETMASK, sigmask_normal, NULL);
          raise (termination_signal);
        }
    }
}

/**
 * @brief Set a socket to listen for connections.
 *
 * @param[in]   address_str_unix  File name to bind to.  NULL for TLS.
 * @param[in]   address_str_tls   IP or hostname to bind to.
 * @param[in]   port_str          Port to bind to, for TLS.
 * @param[out]  socket_owner      Owner of socket, for UNIX.
 * @param[out]  socket_group      Group of socket, for UNIX.
 * @param[out]  socket_mode       Mode of socket, in octal, for UNIX.
 * @param[out]  soc               Socket listened on.
 *
 * @return 0 success, -1 error.
 */
static int
manager_listen (const char *address_str_unix,
                const char *address_str_tls,
                const char *port_str,
                const char *socket_owner,
                const char *socket_group,
                const char *socket_mode,
                int *soc)
{
  struct sockaddr *address;
  struct sockaddr_un address_unix;
  struct sockaddr_storage address_tls;
  int address_size;

  memset (&address_tls, 0, sizeof (struct sockaddr_storage));
  memset (&address_unix, 0, sizeof (struct sockaddr_un));

  g_debug ("%s: address_str_unix: %s", __FUNCTION__, address_str_unix);
  if (address_str_unix)
    {
      struct stat state;

      /* UNIX file socket. */

      address_unix.sun_family = AF_UNIX;
      strncpy (address_unix.sun_path,
               address_str_unix,
               sizeof (address_unix.sun_path) - 1);

      g_debug (
        "%s: address_unix.sun_path: %s", __FUNCTION__, address_unix.sun_path);

      *soc = socket (AF_UNIX, SOCK_STREAM, 0);
      if (*soc == -1)
        {
          g_warning ("Failed to create manager socket (UNIX): %s",
                     strerror (errno));
          return -1;
        }

      if (stat (address_unix.sun_path, &state) == 0)
        {
          /* Remove socket so we can bind(). */
          unlink (address_unix.sun_path);
        }

      address = (struct sockaddr *) &address_unix;
      address_size = sizeof (address_unix);
    }
  else if (address_str_tls)
    {
      struct sockaddr_in *addr4;
      struct sockaddr_in6 *addr6;
      int port, optval;

      /* TLS TCP socket. */

      if (port_str)
        {
          port = atoi (port_str);
          if (port <= 0 || port >= 65536)
            {
              g_warning ("Manager port must be a number between 1 and 65535");
              log_config_free ();
              return -1;
            }
          port = htons (port);
        }
      else
        {
          struct servent *servent = getservbyname ("otp", "tcp");
          if (servent)
            port = servent->s_port;
          else
            port = htons (GVMD_PORT);
        }

      addr4 = (struct sockaddr_in *) &address_tls;
      addr6 = (struct sockaddr_in6 *) &address_tls;
      if (inet_pton (AF_INET6, address_str_tls, &addr6->sin6_addr) > 0)
        {
          address_tls.ss_family = AF_INET6;
          addr6->sin6_port = port;
        }
      else if (inet_pton (AF_INET, address_str_tls, &addr4->sin_addr) > 0)
        {
          address_tls.ss_family = AF_INET;
          addr4->sin_port = port;
        }
      else
        {
          g_warning ("Failed to create manager address %s", address_str_tls);
          return -1;
        }

      if (address_tls.ss_family == AF_INET6)
        *soc = socket (PF_INET6, SOCK_STREAM, 0);
      else
        *soc = socket (PF_INET, SOCK_STREAM, 0);
      if (*soc == -1)
        {
          g_warning ("Failed to create manager socket (TLS): %s",
                     strerror (errno));
          return -1;
        }

      optval = 1;
      if (setsockopt (*soc, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (int)))
        {
          g_warning ("Failed to set SO_REUSEADDR on socket: %s",
                     strerror (errno));
          return -1;
        }

      address = (struct sockaddr *) &address_tls;
      address_size = sizeof (address_tls);
    }
  else
    return 0;

  /* The socket must have O_NONBLOCK set, in case an "asynchronous network
   * error" removes the connection between `select' and `accept'. */
  if (fcntl (*soc, F_SETFL, O_NONBLOCK) == -1)
    {
      g_warning ("Failed to set manager socket flag: %s", strerror (errno));
      return -1;
    }

  if (bind (*soc, address, address_size) == -1)
    {
      g_warning ("Failed to bind manager socket: %s", strerror (errno));
      return -1;
    }

  if (address_str_unix)
    {
      mode_t omode;

      if (socket_owner)
        {
          struct passwd *passwd;

          passwd = getpwnam (socket_owner);
          if (passwd == NULL)
            {
              g_warning ("%s: User %s not found.", __FUNCTION__, socket_owner);
              return -1;
            }
          if (chown (address_str_unix, passwd->pw_uid, -1) == -1)
            {
              g_warning ("%s: chown: %s", __FUNCTION__, strerror (errno));
              return -1;
            }
        }

      if (socket_group)
        {
          struct group *group;

          group = getgrnam (socket_group);
          if (group == NULL)
            {
              g_warning ("%s: Group %s not found.", __FUNCTION__, socket_group);
              return -1;
            }
          if (chown (address_str_unix, -1, group->gr_gid) == -1)
            {
              g_warning ("%s: chown: %s", __FUNCTION__, strerror (errno));
              return -1;
            }
        }

      if (!socket_mode)
        socket_mode = "660";
      omode = strtol (socket_mode, 0, 8);
      if (omode <= 0 || omode > 4095)
        {
          g_warning ("%s: Erroneous --listen-mode value", __FUNCTION__);
          return -1;
        }
      if (chmod (address_str_unix, omode) == -1)
        {
          g_warning ("%s: chmod: %s", __FUNCTION__, strerror (errno));
          return -1;
        }
    }

  if (listen (*soc, MAX_CONNECTIONS) == -1)
    {
      g_warning ("Failed to listen on manager socket: %s", strerror (errno));
      return -1;
    }

  return 0;
}

/**
 * @brief Entry point to the manager.
 *
 * \if STATIC
 *
 * Setup the manager and then loop forever passing connections to
 * \ref accept_and_maybe_fork .
 *
 * \endif
 *
 * @param[in]  argc  The number of arguments in argv.
 * @param[in]  argv  The list of arguments to the program.
 *
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
int
main (int argc, char **argv)
{
  /* Process options. */

  static gboolean backup_database = FALSE;
  static gboolean check_alerts = FALSE;
  static gboolean migrate_database = FALSE;
  static gboolean encrypt_all_credentials = FALSE;
  static gboolean decrypt_all_credentials = FALSE;
  static gboolean disable_password_policy = FALSE;
  static gboolean disable_scheduling = FALSE;
  static gboolean get_users = FALSE;
  static gboolean get_scanners = FALSE;
  static gboolean foreground = FALSE;
  static gboolean print_version = FALSE;
  static int max_ips_per_target = MANAGE_MAX_HOSTS;
  static int max_email_attachment_size = 0;
  static int max_email_include_size = 0;
  static int max_email_message_size = 0;
  static int verbose = 0;
  static gchar *create_user = NULL;
  static gchar *delete_user = NULL;
  static gchar *inheritor = NULL;
  static gchar *user = NULL;
  static gchar *create_scanner = NULL;
  static gchar *modify_scanner = NULL;
  static gchar *scanner_host = NULL;
  static gchar *scanner_port = NULL;
  static gchar *scanner_type = NULL;
  static gchar *scanner_ca_pub = NULL;
  static gchar *scanner_key_pub = NULL;
  static gchar *scanner_key_priv = NULL;
  static int schedule_timeout = SCHEDULE_TIMEOUT_DEFAULT;
  static int secinfo_commit_size = SECINFO_COMMIT_SIZE_DEFAULT;
  static int slave_commit_size = SLAVE_COMMIT_SIZE_DEFAULT;
  static gchar *delete_scanner = NULL;
  static gchar *verify_scanner = NULL;
  static gchar *priorities = "NORMAL";
  static gchar *dh_params = NULL;
  static gchar *listen_owner = NULL;
  static gchar *listen_group = NULL;
  static gchar *listen_mode = NULL;
  static gchar *new_password = NULL;
  static gchar *optimize = NULL;
  static gchar *password = NULL;
  static gchar *manager_address_string = NULL;
  static gchar *manager_address_string_2 = NULL;
  static gchar *manager_address_string_unix = NULL;
  static gchar *manager_port_string = NULL;
  static gchar *manager_port_string_2 = NULL;
  static gchar *modify_setting = NULL;
  static gchar *scanner_name = NULL;
  static gchar *rc_name = NULL;
  static gchar *role = NULL;
  static gchar *disable = NULL;
  static gchar *value = NULL;
  GError *error = NULL;
  lockfile_t lockfile_checking, lockfile_serving;
  GOptionContext *option_context;
  static GOptionEntry option_entries[] = {
    {"backup",
     '\0',
     0,
     G_OPTION_ARG_NONE,
     &backup_database,
     "Backup the database.",
     NULL},
    {"check-alerts",
     '\0',
     0,
     G_OPTION_ARG_NONE,
     &check_alerts,
     "Check SecInfo alerts.",
     NULL},
    {"client-watch-interval",
     '\0',
     0,
     G_OPTION_ARG_INT,
     &client_watch_interval,
     "Check if client connection was closed every <number> seconds."
     " 0 to disable. Defaults to " G_STRINGIFY (
       DEFAULT_CLIENT_WATCH_INTERVAL) " seconds.",
     "<number>"},
    {"database",
     'd',
     0,
     G_OPTION_ARG_STRING,
     &database,
     "Use <file/name> as database for SQLite/Postgres.",
     "<file/name>"},
    {"disable-cmds",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &disable,
     "Disable comma-separated <commands>.",
     "<commands>"},
    {"disable-encrypted-credentials",
     '\0',
     0,
     G_OPTION_ARG_NONE,
     &disable_encrypted_credentials,
     "Do not encrypt or decrypt credentials.",
     NULL},
    {"disable-password-policy",
     '\0',
     0,
     G_OPTION_ARG_NONE,
     &disable_password_policy,
     "Do not restrict passwords to the policy.",
     NULL},
    {"disable-scheduling",
     '\0',
     0,
     G_OPTION_ARG_NONE,
     &disable_scheduling,
     "Disable task scheduling.",
     NULL},
    {"create-user",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &create_user,
     "Create admin user <username> and exit.",
     "<username>"},
    {"delete-user",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &delete_user,
     "Delete user <username> and exit.",
     "<username>"},
    {"get-users",
     '\0',
     0,
     G_OPTION_ARG_NONE,
     &get_users,
     "List users and exit.",
     NULL},
    {"create-scanner",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &create_scanner,
     "Create global scanner <scanner> and exit.",
     "<scanner>"},
    {"modify-scanner",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &modify_scanner,
     "Modify scanner <scanner-uuid> and exit.",
     "<scanner-uuid>"},
    {"scanner-name",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &scanner_name,
     "Name for --modify-scanner.",
     "<name>"},
    {"scanner-host",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &scanner_host,
     "Scanner host for --create-scanner and --modify-scanner. Default "
     "is " OPENVASSD_ADDRESS ".",
     "<scanner-host>"},
    {"scanner-port",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &scanner_port,
     "Scanner port for --create-scanner and --modify-scanner. Default "
     "is " G_STRINGIFY (OPENVASSD_PORT) ".",
     "<scanner-port>"},
    {"scanner-type",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &scanner_type,
     "Scanner type for --create-scanner and --modify-scanner. Either 'OpenVAS' "
     "or 'OSP'.",
     "<scanner-type>"},
    {"scanner-ca-pub",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &scanner_ca_pub,
     "Scanner CA Certificate path for --[create|modify]-scanner.",
     "<scanner-ca-pub>"},
    {"scanner-key-pub",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &scanner_key_pub,
     "Scanner Certificate path for --[create|modify]-scanner.",
     "<scanner-key-public>"},
    {"scanner-key-priv",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &scanner_key_priv,
     "Scanner private key path for --[create|modify]-scanner.",
     "<scanner-key-private>"},
    {"verify-scanner",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &verify_scanner,
     "Verify scanner <scanner-uuid> and exit.",
     "<scanner-uuid>"},
    {"delete-scanner",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &delete_scanner,
     "Delete scanner <scanner-uuid> and exit.",
     "<scanner-uuid>"},
    {"get-scanners",
     '\0',
     0,
     G_OPTION_ARG_NONE,
     &get_scanners,
     "List scanners and exit.",
     NULL},
    {"secinfo-commit-size",
     '\0',
     0,
     G_OPTION_ARG_INT,
     &secinfo_commit_size,
     "During CERT and SCAP sync, commit updates to the database every <number> "
     "items, 0 for unlimited, default: " G_STRINGIFY (
       SECINFO_COMMIT_SIZE_DEFAULT),
     "<number>"},
    {"slave-commit-size",
     '\0',
     0,
     G_OPTION_ARG_INT,
     &secinfo_commit_size,
     "During slave updates, commit after every <number> updated results and"
     " hosts, 0 for unlimited",
     "<number>"},
    {"schedule-timeout",
     '\0',
     0,
     G_OPTION_ARG_INT,
     &schedule_timeout,
     "Time out tasks that are more than <time> minutes overdue. -1 to disable, "
     "0 for minimum time, default: " G_STRINGIFY (SCHEDULE_TIMEOUT_DEFAULT),
     "<time>"},
    {"foreground",
     'f',
     0,
     G_OPTION_ARG_NONE,
     &foreground,
     "Run in foreground.",
     NULL},
    {"inheritor",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &inheritor,
     "Have <username> inherit from deleted user.",
     "<username>"},
    {"listen",
     'a',
     0,
     G_OPTION_ARG_STRING,
     &manager_address_string,
     "Listen on <address>.",
     "<address>"},
    {"listen2",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &manager_address_string_2,
     "Listen also on <address>.",
     "<address>"},
    {"listen-owner",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &listen_owner,
     "Owner of the unix socket",
     "<string>"},
    {"listen-group",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &listen_group,
     "Group of the unix socket",
     "<string>"},
    {"listen-mode",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &listen_mode,
     "File mode of the unix socket",
     "<string>"},
    {"max-ips-per-target",
     '\0',
     0,
     G_OPTION_ARG_INT,
     &max_ips_per_target,
     "Maximum number of IPs per target.",
     "<number>"},
    {"max-email-attachment-size",
     '\0',
     0,
     G_OPTION_ARG_INT,
     &max_email_attachment_size,
     "Maximum size of alert email attachments, in bytes.",
     "<number>"},
    {"max-email-include-size",
     '\0',
     0,
     G_OPTION_ARG_INT,
     &max_email_include_size,
     "Maximum size of inlined content in alert emails, in bytes.",
     "<number>"},
    {"max-email-message-size",
     '\0',
     0,
     G_OPTION_ARG_INT,
     &max_email_message_size,
     "Maximum size of user-defined message text in alert emails, in bytes.",
     "<number>"},
    {"migrate",
     'm',
     0,
     G_OPTION_ARG_NONE,
     &migrate_database,
     "Migrate the database and exit.",
     NULL},
    {"modify-setting",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &modify_setting,
     "Modify setting <uuid> and exit.",
     "<uuid>"},
    {"encrypt-all-credentials",
     '\0',
     0,
     G_OPTION_ARG_NONE,
     &encrypt_all_credentials,
     "(Re-)Encrypt all credentials.",
     NULL},
    {"decrypt-all-credentials",
     '\0',
     G_OPTION_FLAG_HIDDEN,
     G_OPTION_ARG_NONE,
     &decrypt_all_credentials,
     NULL,
     NULL},
    {"new-password",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &new_password,
     "Modify user's password and exit.",
     "<password>"},
    {"optimize",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &optimize,
     "Run an optimization: vacuum, analyze, cleanup-config-prefs, "
     "cleanup-port-names, cleanup-result-severities, cleanup-schedule-times, "
     "rebuild-report-cache or update-report-cache.",
     "<name>"},
    {"password",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &password,
     "Password, for --create-user.",
     "<password>"},
    {"port",
     'p',
     0,
     G_OPTION_ARG_STRING,
     &manager_port_string,
     "Use port number <number>.",
     "<number>"},
    {"port2",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &manager_port_string_2,
     "Use port number <number> for address 2.",
     "<number>"},
    {"role",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &role,
     "Role for --create-user and --get-users.",
     "<role>"},
    {"unix-socket",
     'c',
     0,
     G_OPTION_ARG_STRING,
     &manager_address_string_unix,
     "Listen on UNIX socket at <filename>.",
     "<filename>"},
    {"user",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &user,
     "User for --new-password.",
     "<username>"},
    {"gnutls-priorities",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &priorities,
     "Sets the GnuTLS priorities for the Manager socket.",
     "<priorities-string>"},
    {"dh-params",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &dh_params,
     "Diffie-Hellman parameters file",
     "<file>"},
    {"value",
     '\0',
     0,
     G_OPTION_ARG_STRING,
     &value,
     "Value for --modify-setting.",
     "<value>"},
    {"verbose",
     'v',
     0,
     G_OPTION_ARG_NONE,
     &verbose,
     "Has no effect.  See INSTALL.md for logging config.",
     NULL},
    {"version",
     '\0',
     0,
     G_OPTION_ARG_NONE,
     &print_version,
     "Print version and exit.",
     NULL},
    {NULL}};

  /* Set locale based on environment variables. */

  setlocale (LC_ALL, "C.UTF-8");

  /* Process options. */

  option_context = g_option_context_new (
    "- Mageni Security Platform Controller");
  g_option_context_add_main_entries (option_context, option_entries, NULL);
  if (!g_option_context_parse (option_context, &argc, &argv, &error))
    {
      g_option_context_free (option_context);
      g_critical (
        "%s: g_option_context_parse: %s", __FUNCTION__, error->message);
      exit (EXIT_FAILURE);
    }
  g_option_context_free (option_context);

  if (print_version)
    {
        printf ("Mageni Vulnerability Scanner SQLite Database %s\n", APID_VERSION);
        printf ("SQLite3 DB revision %i\n", manage_db_supported_version ());
        printf ("Most new code since 2020 by Mageni Security, LLC\n");
        printf ("======================================================================\n");
        printf ("Mageni Vulnerability Scanner SQLite Database was forked in 2020 from Greenbone Vulnerability Manager (gvmd) 8.0.0\n");
        printf ("Greenbone Vulnerability Manager: Copyright (C) 2010-2017 Greenbone Networks GmbH\n");
        printf ("======================================================================\n");
        printf ("License GPLv2+: GNU GPL version 2 or later\n");
        printf ("This is free software: you are free to change and redistribute it.\n");
        printf ("There is NO WARRANTY, to the extent permitted by law.\n");
        printf ("======================================================================\n");
        printf ("The GPLv2 requires the maker of a version to place his or her name on it,\n");
        printf ("to distinguish it from other versions and to protect the reputations of other maintainers.\n");
        printf ("Source: https://www.gnu.org/licenses/old-licenses/gpl-2.0-faq.en.html#WhyDoesTheGPLPermitUsersToPublishTheirModifiedVersions\n");
        exit (EXIT_SUCCESS);
    }

  /* Ensure client_watch_interval is not negative */

  if (client_watch_interval < 0)
    {
      client_watch_interval = 0;
    }

  /* Set schedule_timeout */

  set_schedule_timeout (schedule_timeout);

  /* Set slave commit size */
  set_slave_commit_size (slave_commit_size);

  /* Set SecInfo update commit size */

  set_secinfo_commit_size (secinfo_commit_size);

  /* Check which type of socket to use. */

  if (manager_address_string_unix == NULL)
    {
      if (manager_address_string || manager_address_string_2)
        use_tls = 1;
      else
        {
          use_tls = 0;
          manager_address_string_unix =
            g_build_filename (MAGENI_RUN_DIR, "mageni-sqlite.sock", NULL);
        }
    }
  else
    {
      use_tls = 0;
      if (manager_address_string || manager_address_string_2)
        {
          g_critical ("%s: --listen or --listen2 given with --unix-socket",
                      __FUNCTION__);
          return EXIT_FAILURE;
        }
    }

  if (use_tls == 0 && (manager_port_string || manager_port_string_2))
    {
      g_critical ("%s: --port or --port2 given when listening on UNIX socket",
                  __FUNCTION__);
      return EXIT_FAILURE;
    }

  /* Set process title. */

  proctitle_init (argc, argv);
  proctitle_set ("mageni-sqlite: Initializing");

  /* Setup initial signal handlers. */

  setup_signal_handler (SIGABRT, handle_sigabrt_simple, 1);

  /* Switch to UTC for scheduling. */

  if (migrate_database && manage_migrate_needs_timezone (log_config, database))
    g_info ("%s: leaving TZ as is, for migrator", __FUNCTION__);
  else if (setenv ("TZ", "utc 0", 1) == -1)
    {
      g_critical ("%s: failed to set timezone", __FUNCTION__);
      exit (EXIT_FAILURE);
    }
  tzset ();

  /* Set umask to hoard created files, including the database. */

  umask (S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH);

  /* Setup logging. */

  rc_name = g_build_filename (MAGENI_SYSCONF_DIR, "sqlite_log.conf", NULL);
  if (g_file_test (rc_name, G_FILE_TEST_EXISTS))
    log_config = load_log_configuration (rc_name);
  g_free (rc_name);
  setup_log_handlers (log_config);
  /* Enable GNUTLS debugging if requested via env variable.  */
  {
    const char *s;
    if ((s = getenv ("GVM_GNUTLS_DEBUG")))
      {
        gnutls_global_set_log_function (log_func_for_gnutls);
        gnutls_global_set_log_level (atoi (s));
      }
  }

  g_message ("Mageni SQLite Manager Version %s (DB revision %i)",
             APID_VERSION,
             manage_db_supported_version ());

  /* Get exclusivity on the startup locks.
   *
   * The main process keeps this open until after init_gmpd, so that check_db
   * has exclusive access to the db.
   *
   * Helper and migrator processes just keep this open long enough to check the
   * other startup locks.
   *
   * There are 3 startup locks:
   *  1 gvm-serving: the main process (exclusive)
   *  2 gvm-helping: an option process, like --create-user (shared)
   *  3 gvm-migrating: a --migrate process (exclusive).
   *
   * The locks are inherited by forked processes, and are only released when all
   * associated files are closed (i.e. when all processes exit). */

  switch (lockfile_lock_nb (&lockfile_checking, "mageni-sqlite-checking"))
    {
    case 0:
      break;
    case 1:
      g_warning ("%s: Another process is busy starting up", __FUNCTION__);
      return EXIT_FAILURE;
    case -1:
    default:
      g_critical ("%s: Error trying to get checking lock", __FUNCTION__);
      return EXIT_FAILURE;
    }

  if (migrate_database)
    {
      lockfile_t lockfile_migrating;

      /* Migrate the database to the version supported by this manager. */

      switch (lockfile_locked ("mageni-sqlite-serving"))
        {
        case 1:
          g_warning ("%s: Main process is running, refusing to migrate",
                     __FUNCTION__);
          return EXIT_FAILURE;
        case -1:
          g_warning ("%s: Error checking serving lock", __FUNCTION__);
          return EXIT_FAILURE;
        }

      switch (lockfile_locked ("mageni-sqlite-helping"))
        {
        case 1:
          g_warning ("%s: An option process is running, refusing to migrate",
                     __FUNCTION__);
          return EXIT_FAILURE;
        case -1:
          g_warning ("%s: Error checking helping lock", __FUNCTION__);
          return EXIT_FAILURE;
        }

      switch (lockfile_lock_nb (&lockfile_migrating, "mageni-sqlite-upgradedb"))
        {
        case 1:
          g_warning ("%s: A migrate is already running", __FUNCTION__);
          return EXIT_FAILURE;
        case -1:
          g_critical ("%s: Error getting migrating lock", __FUNCTION__);
          return EXIT_FAILURE;
        }

      if (lockfile_unlock (&lockfile_checking))
        {
          g_critical ("%s: Error releasing checking lock", __FUNCTION__);
          return EXIT_FAILURE;
        }

      proctitle_set ("mageni-sqlite: Migrating database");

      g_info ("   Migrating database.");

      switch (manage_migrate (log_config, database))
        {
        case 0:
          g_info ("   Migration succeeded.");
          return EXIT_SUCCESS;
        case 1:
          g_warning ("%s: databases are already at the supported version",
                     __FUNCTION__);
          return EXIT_SUCCESS;
        case 2:
          g_warning ("%s: database migration too hard", __FUNCTION__);
          return EXIT_FAILURE;
        case 11:
          g_warning ("%s: cannot migrate SCAP database", __FUNCTION__);
          return EXIT_FAILURE;
        case 12:
          g_warning ("%s: cannot migrate CERT database", __FUNCTION__);
          return EXIT_FAILURE;
        case -1:
          g_critical ("%s: database migration failed", __FUNCTION__);
          return EXIT_FAILURE;
        case -11:
          g_critical ("%s: SCAP database migration failed", __FUNCTION__);
          return EXIT_FAILURE;
        case -12:
          g_critical ("%s: CERT database migration failed", __FUNCTION__);
          return EXIT_FAILURE;
        default:
          assert (0);
          g_critical ("%s: strange return from manage_migrate", __FUNCTION__);
          return EXIT_FAILURE;
        }
    }

  /* For the main process and for option processes, refuse to start when a
   * migrate is in process. */

  if (lockfile_locked ("mageni-sqlite-upgradedb"))
    {
      g_warning ("%s: An upgrade is in progress", __FUNCTION__);
      return EXIT_FAILURE;
    }

  /* Handle non-migrate options.
   *
   * These can run concurrently, so they set the shared lock gvm-helping, and
   * release gvm-checking, via option_lock. */

  if (backup_database)
    {
      /* Backup the database and then exit. */

      proctitle_set ("mageni-sqlite: Backing up database");

      g_info ("   Backing up database.");

      /* TODO Not sure about locking.  Not used by Postgres.  Perhaps remove. */

      switch (manage_backup_db (database))
        {
        case 0:
          g_info ("   Backup succeeded.");
          return EXIT_SUCCESS;
        case -1:
          g_critical ("%s: database backup failed", __FUNCTION__);
          return EXIT_FAILURE;
        default:
          assert (0);
          g_critical ("%s: strange return from manage_backup_db", __FUNCTION__);
          return EXIT_FAILURE;
        }
    }

  if (disable_password_policy)
    gvm_disable_password_policy ();
  else
    {
      gchar *password_policy;
      password_policy =
        g_build_filename (MAGENI_SYSCONF_DIR, "pwpolicy.conf", NULL);
      if (g_file_test (password_policy, G_FILE_TEST_EXISTS) == FALSE)
        g_warning (
          "%s: password policy missing: %s", __FUNCTION__, password_policy);
      g_free (password_policy);
    }

  if (optimize)
    {
      int ret;

      proctitle_set ("mageni-sqlite: Optimizing");

      if (option_lock (&lockfile_checking))
        return EXIT_FAILURE;

      ret = manage_optimize (log_config, database, optimize);
      log_config_free ();
      if (ret)
        return EXIT_FAILURE;
      return EXIT_SUCCESS;
    }

  if (create_scanner)
    {
      int ret;
      scanner_type_t type;
      char *stype;

      /* Create the scanner and then exit. */

      proctitle_set ("mageni-sqlite: Creating scanner");

      if (option_lock (&lockfile_checking))
        return EXIT_FAILURE;

      if (!scanner_host)
        scanner_host = OPENVASSD_ADDRESS;
      if (!scanner_port)
        scanner_port = G_STRINGIFY (OPENVASSD_PORT);
      if (!scanner_ca_pub)
        scanner_ca_pub = MAGENI_CA_CERTIFICATE;
      if (!scanner_key_pub)
        scanner_key_pub = MAGENI_CLIENT_CERTIFICATE;
      if (!scanner_key_priv)
        scanner_key_priv = MAGENI_CLIENT_KEY;

      if (!scanner_type || !strcasecmp (scanner_type, "OpenVAS"))
        type = SCANNER_TYPE_OPENVAS;
      else if (!strcasecmp (scanner_type, "OSP"))
        type = SCANNER_TYPE_OSP;
      else
        {
          printf ("Invalid scanner type value.\n");
          return EXIT_FAILURE;
        }
      stype = g_strdup_printf ("%u", type);
      ret = manage_create_scanner (log_config,
                                   database,
                                   create_scanner,
                                   scanner_host,
                                   scanner_port,
                                   stype,
                                   scanner_ca_pub,
                                   scanner_key_pub,
                                   scanner_key_priv);
      g_free (stype);
      log_config_free ();
      if (ret)
        return EXIT_FAILURE;
      return EXIT_SUCCESS;
    }

  if (modify_scanner)
    {
      int ret;
      char *stype;

      /* Modify the scanner and then exit. */

      proctitle_set ("mageni-sqlite: Modifying scanner");

      if (option_lock (&lockfile_checking))
        return EXIT_FAILURE;

      if (scanner_type)
        {
          scanner_type_t type;

          if (strcasecmp (scanner_type, "OpenVAS") == 0)
            type = SCANNER_TYPE_OPENVAS;
          else if (strcasecmp (scanner_type, "OSP") == 0)
            type = SCANNER_TYPE_OSP;
          else
            {
              g_warning ("Invalid scanner type value");
              return EXIT_FAILURE;
            }

          stype = g_strdup_printf ("%u", type);
        }
      else
        stype = NULL;

      ret = manage_modify_scanner (log_config,
                                   database,
                                   modify_scanner,
                                   scanner_name,
                                   scanner_host,
                                   scanner_port,
                                   stype,
                                   scanner_ca_pub,
                                   scanner_key_pub,
                                   scanner_key_priv);
      g_free (stype);
      log_config_free ();
      if (ret)
        return EXIT_FAILURE;
      return EXIT_SUCCESS;
    }

  if (check_alerts)
    {
      int ret;

      proctitle_set ("mageni-sqlite: Checking alerts");

      if (option_lock (&lockfile_checking))
        return EXIT_FAILURE;

      ret = manage_check_alerts (log_config, database);
      log_config_free ();
      if (ret)
        return EXIT_FAILURE;
      return EXIT_SUCCESS;
    }

  if (create_user)
    {
      int ret;

      proctitle_set ("mageni-sqlite: Creating user");

      if (option_lock (&lockfile_checking))
        return EXIT_FAILURE;

      ret =
        manage_create_user (log_config, database, create_user, password, role);
      log_config_free ();
      if (ret)
        return EXIT_FAILURE;
      return EXIT_SUCCESS;
    }

  if (delete_user)
    {
      int ret;

      proctitle_set ("mageni-sqlite: Deleting user");

      if (option_lock (&lockfile_checking))
        return EXIT_FAILURE;

      ret = manage_delete_user (log_config, database, delete_user, inheritor);
      log_config_free ();
      if (ret)
        return EXIT_FAILURE;
      return EXIT_SUCCESS;
    }

  if (get_users)
    {
      int ret;

      proctitle_set ("mageni-sqlite: Getting users");

      if (option_lock (&lockfile_checking))
        return EXIT_FAILURE;

      ret = manage_get_users (log_config, database, role);
      log_config_free ();
      if (ret)
        return EXIT_FAILURE;
      return EXIT_SUCCESS;
    }

  if (get_scanners)
    {
      int ret;

      proctitle_set ("mageni-sqlite: Getting scanners");

      if (option_lock (&lockfile_checking))
        return EXIT_FAILURE;

      ret = manage_get_scanners (log_config, database);
      log_config_free ();
      if (ret)
        return EXIT_FAILURE;
      return EXIT_SUCCESS;
    }

  if (delete_scanner)
    {
      int ret;

      proctitle_set ("mageni-sqlite: Deleting scanner");

      if (option_lock (&lockfile_checking))
        return EXIT_FAILURE;

      ret = manage_delete_scanner (log_config, database, delete_scanner);
      log_config_free ();
      if (ret)
        return EXIT_FAILURE;
      return EXIT_SUCCESS;
    }

  if (verify_scanner)
    {
      int ret;

      proctitle_set ("mageni-sqlite: Verifying scanner");

      if (option_lock (&lockfile_checking))
        return EXIT_FAILURE;

      ret = manage_verify_scanner (log_config, database, verify_scanner);
      log_config_free ();
      if (ret)
        return EXIT_FAILURE;
      return EXIT_SUCCESS;
    }

  if (new_password)
    {
      int ret;

      proctitle_set ("mageni-sqlite: Modifying user password");

      if (option_lock (&lockfile_checking))
        return EXIT_FAILURE;

      ret = manage_set_password (log_config, database, user, new_password);
      log_config_free ();
      if (ret)
        return EXIT_FAILURE;
      return EXIT_SUCCESS;
    }

  if (modify_setting)
    {
      int ret;

      proctitle_set ("mageni-sqlite: Modifying setting");

      if (option_lock (&lockfile_checking))
        return EXIT_FAILURE;

      ret = manage_modify_setting (
        log_config, database, user, modify_setting, value);
      log_config_free ();
      if (ret)
        return EXIT_FAILURE;
      return EXIT_SUCCESS;
    }

  if (encrypt_all_credentials)
    {
      int ret;

      proctitle_set ("mageni-sqlite: Encrypting all credentials");

      if (option_lock (&lockfile_checking))
        return EXIT_FAILURE;

      ret = manage_encrypt_all_credentials (log_config, database);
      log_config_free ();
      if (ret)
        return EXIT_FAILURE;
      return EXIT_SUCCESS;
    }

  if (decrypt_all_credentials)
    {
      int ret;

      proctitle_set ("mageni-sqlite: Decrypting all credentials");

      if (option_lock (&lockfile_checking))
        return EXIT_FAILURE;

      ret = manage_decrypt_all_credentials (log_config, database);
      log_config_free ();
      if (ret)
        return EXIT_FAILURE;
      return EXIT_SUCCESS;
    }

  /* Run the standard manager. */

  if (lockfile_locked ("mageni-sqlite-helping"))
    {
      g_warning ("%s: An option process is running", __FUNCTION__);
      return EXIT_FAILURE;
    }

  switch (lockfile_lock_nb (&lockfile_serving, "mageni-sqlite-serving"))
    {
    case 0:
      break;
    case 1:
      g_warning ("%s: Main process is already running", __FUNCTION__);
      return EXIT_FAILURE;
    case -1:
    default:
      g_critical ("%s: Error trying to get serving lock", __FUNCTION__);
      return EXIT_FAILURE;
    }

  if (foreground == FALSE)
    {
      /* Fork into the background. */
      pid_t pid = fork ();
      switch (pid)
        {
        case 0:
          /* Child. */
          break;
        case -1:
          /* Parent when error. */
          g_critical ("%s: failed to fork into background: %s",
                      __FUNCTION__,
                      strerror (errno));
          log_config_free ();
          exit (EXIT_FAILURE);
          break;
        default:
          /* Parent. */
          log_config_free ();
          exit (EXIT_SUCCESS);
          break;
        }
    }

  /* Initialise GMP daemon. */

  switch (init_gmpd (log_config,
                     0,
                     database,
                     max_ips_per_target,
                     max_email_attachment_size,
                     max_email_include_size,
                     max_email_message_size,
                     fork_connection_for_event,
                     0))
    {
    case 0:
      break;
    case -2:
      g_critical ("%s: database is wrong version", __FUNCTION__);
      log_config_free ();
      exit (EXIT_FAILURE);
      break;
    case -4:
      g_critical ("%s: --max-ips-per-target out of range"
                  " (min=1, max=%i, requested=%i)",
                  __FUNCTION__,
                  MANAGE_ABSOLUTE_MAX_IPS_PER_TARGET,
                  max_ips_per_target);
      log_config_free ();
      exit (EXIT_FAILURE);
      break;
    case -1:
    default:
      g_critical ("%s: failed to initialise GMP daemon", __FUNCTION__);
      log_config_free ();
      exit (EXIT_FAILURE);
    }

  /* Release the checking lock, so that option processes may start. */

  if (lockfile_unlock (&lockfile_checking))
    {
      g_critical ("%s: Error releasing checking lock", __FUNCTION__);
      return EXIT_FAILURE;
    }

  /* Register the `cleanup' function. */

  if (atexit (&cleanup))
    {
      g_critical ("%s: failed to register `atexit' cleanup function",
                  __FUNCTION__);
      log_config_free ();
      exit (EXIT_FAILURE);
    }

  /* Set our pidfile. */

  if (pidfile_create ("mageni-sqlite"))
    exit (EXIT_FAILURE);

  /* Setup global variables. */

  if (disable)
    disabled_commands = g_strsplit (disable, ",", 0);

  scheduling_enabled = (disable_scheduling == FALSE);

  /* Create the manager socket(s). */

#if LOG
  /* Open the log file. */

  if (g_mkdir_with_parents (MAGENI_LOG_DIR, 0755) /* "rwxr-xr-x" */
      == -1)
    {
      g_critical ("%s: failed to create log directory: %s",
                  __FUNCTION__,
                  strerror (errno));
      exit (EXIT_FAILURE);
    }

  log_stream = fopen (LOG_FILE, "w");
  if (log_stream == NULL)
    {
      g_critical (
        "%s: failed to open log file: %s", __FUNCTION__, strerror (errno));
      exit (EXIT_FAILURE);
    }
#endif

  /* Register the signal handlers. */

  setup_signal_handler (SIGTERM, handle_termination_signal, 0);
  setup_signal_handler (SIGABRT, handle_sigabrt, 1);
  setup_signal_handler (SIGINT, handle_termination_signal, 0);
  setup_signal_handler (SIGHUP, SIG_IGN, 0);
  setup_signal_handler (SIGQUIT, handle_termination_signal, 0);
  setup_signal_handler (SIGSEGV, handle_sigsegv, 1);
  setup_signal_handler_info (SIGCHLD, handle_sigchld, 0);

  /* Setup security. */

  if (use_tls)
    {
      if (gvm_server_new (GNUTLS_SERVER,
                          CACERT,
                          SCANNERCERT,
                          SCANNERKEY,
                          &client_session,
                          &client_credentials))
        {
          g_critical ("%s: client server initialisation failed", __FUNCTION__);
          exit (EXIT_FAILURE);
        }
      priorities_option = priorities;
      set_gnutls_priority (&client_session, priorities);
      dh_params_option = dh_params;
      if (dh_params && set_gnutls_dhparams (client_credentials, dh_params))
        g_warning ("Couldn't set DH parameters from %s", dh_params);
    }

  if (disable_encrypted_credentials)
    g_message ("Encryption of credentials has been disabled.");

  if (manager_listen (use_tls ? NULL : manager_address_string_unix,
                      use_tls ? (manager_address_string
                                   ? manager_address_string
                                   : (ipv6_is_enabled () ? "::" : "0.0.0.0"))
                              : NULL,
                      manager_port_string,
                      listen_owner,
                      listen_group,
                      listen_mode,
                      &manager_socket))
    return EXIT_FAILURE;
  if (manager_listen (NULL,
                      manager_address_string_2,
                      manager_port_string_2,
                      NULL,
                      NULL,
                      NULL,
                      &manager_socket_2))
    return EXIT_FAILURE;

  /* Initialise the process for manage_schedule. */

  init_manage_process (0, database);

  /* Initialize the authentication system. */

  // TODO Should be part of manage init.
  if (gvm_auth_init ())
    exit (EXIT_FAILURE);

  /* Enter the main forever-loop. */

  proctitle_set ("mageni-sqlite: Waiting for incoming connections");
  serve_and_schedule ();

  return EXIT_SUCCESS;
}
