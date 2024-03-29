/**
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileCopyrightText: Portions Copyright (C) 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
 * SPDX-FileComment: Scanner main module, runs the scanner.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#include "../misc/plugutils.h"
#include "../misc/vendorversion.h"
#include "attack.h"
#include "comm.h"
#include "ntp.h"
#include "pluginlaunch.h"
#include "processes.h"
#include "sighand.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <gcrypt.h>
#include <glib.h>
#include <grp.h>
#include "../../libraries/base/logging.h"
#include "../../libraries/base/nvti.h"
#include "../../libraries/base/pidfile.h"
#include "../../libraries/base/prefs.h"
#include "../../libraries/base/proctitle.h"
#include "../../libraries/util/kb.h"
#include "../../libraries/util/nvticache.h"
#include "../../libraries/util/uuidutils.h"
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef GIT_REV_AVAILABLE
#include "gitrevision.h"
#endif

#if GNUTLS_VERSION_NUMBER < 0x030300
#include "../misc/network.h" /* openvas_SSL_init */
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "mageni-vscand   scanner"

#define PROCTITLE_WAITING "mageni-vscand: Waiting for incoming connections"
#define PROCTITLE_LOADING "mageni-vscand: Loading Handler"
#define PROCTITLE_RELOADING "mageni-vscand: Reloading"
#define PROCTITLE_SERVING "mageni-vscand: Serving %s"

/**
 * Globals that should not be touched (used in utils module).
 */
int global_max_hosts = 15;
int global_max_checks = 10;

/**
 * @brief Logging parameters, as passed to setup_log_handlers.
 */
GSList *log_config = NULL;

static int global_iana_socket = -1;

static volatile int loading_stop_signal = 0;
static volatile int termination_signal = 0;
static char *global_scan_id = NULL;

typedef struct
{
  char *option;
  char *value;
} openvassd_option;

/**
 * @brief Default values for scanner options. Must be NULL terminated.
 */
static openvassd_option openvassd_defaults[] = {
  {"plugins_folder", MAGENI_NVT_DIR},
  {"include_folders", MAGENI_NVT_DIR},
  {"max_hosts", "30"},
  {"max_checks", "10"},
  {"be_nice", "yes"},
  {"log_whole_attack", "no"},
  {"log_plugins_name_at_load", "no"},
  {"optimize_test", "yes"},
  {"network_scan", "no"},
  {"non_simult_ports", "139, 445, 3389, Services/irc"},
  {"plugins_timeout", G_STRINGIFY (NVT_TIMEOUT)},
  {"scanner_plugins_timeout", G_STRINGIFY (SCANNER_NVT_TIMEOUT)},
  {"safe_checks", "yes"},
  {"auto_enable_dependencies", "yes"},
  {"drop_privileges", "no"},
  // Empty options must be "\0", not NULL, to match the behavior of
  // prefs_init.
  {"report_host_details", "yes"},
  {"db_address", KB_PATH_DEFAULT},
  {NULL, NULL}};

gchar *unix_socket_path = NULL;

static void
start_daemon_mode (void)
{
  /* do not block the listener port for subsequent scanners */
  close (global_iana_socket);

  /* become process group leader */
  if (setsid () < 0)
    {
      g_warning ("Cannot set process group leader (%s)\n", strerror (errno));
    }
}

static void
end_daemon_mode (void)
{
  /* clean up all processes the process group */
  make_em_die (SIGTERM);
}

static void
set_globals_from_preferences (void)
{
  const char *str;

  if ((str = prefs_get ("max_hosts")) != NULL)
    {
      global_max_hosts = atoi (str);
      if (global_max_hosts <= 0)
        global_max_hosts = 15;
    }

  if ((str = prefs_get ("max_checks")) != NULL)
    {
      global_max_checks = atoi (str);
      if (global_max_checks <= 0)
        global_max_checks = 10;
    }
}

static void
reload_openvassd (void);

static void
handle_reload_signal (int sig)
{
  (void) sig;
  reload_openvassd ();
}

static void
handle_termination_signal (int sig)
{
  termination_signal = sig;
}

/*
 * @brief Handles a client request when the scanner is still loading.
 *
 * @param[in]   soc Client socket to send and receive from.
 */
static void
loading_client_handle (int soc)
{
  int opt = 1;
  if (soc <= 0)
    return;

  if (setsockopt (soc, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof (opt)) < 0)
    g_warning ("setsockopt: %s", strerror (errno));
  comm_loading (soc);
}

/*
 * @brief Handles term signal received by loading handler child process.
 */
static void
handle_loading_stop_signal (int sig)
{
  loading_stop_signal = sig;
}

static void
remove_pidfile ()
{
  pidfile_remove ("mageni-vscand");
}

/*
 * @brief Starts a process to handle client requests while the scanner is
 * loading.
 *
 * @return process id of loading handler.
 */
static pid_t
loading_handler_start ()
{
  pid_t child_pid, parent_pid;

  init_loading_shm ();
  parent_pid = getpid ();
  child_pid = fork ();
  if (child_pid != 0)
    return child_pid;

  proctitle_set (PROCTITLE_WAITING);
  openvas_signal (SIGTERM, handle_loading_stop_signal);

  /*
   * Forked process will handle client requests until parent dies or stops it
   * with loading_handler_stop ().
   */
  while (1)
    {
      unsigned int lg_address;
      struct sockaddr_un address;
      int soc;
      fd_set set;
      struct timeval timeout;
      int rv, ret;
      pid_t child_pid1;

      if (loading_stop_signal || kill (parent_pid, 0) < 0)
        break;
      lg_address = sizeof (struct sockaddr_un);

      if (listen (global_iana_socket, 5) < 0)
        continue;

      FD_ZERO (&set);
      FD_SET (global_iana_socket, &set);

      timeout.tv_sec = 0;
      timeout.tv_usec = 500000;

      rv = select (global_iana_socket + 1, &set, NULL, NULL, &timeout);
      if (rv == -1) /* Select error. */
        continue;
      else if (rv == 0) /* Timeout. */
        continue;
      else
        soc = accept (global_iana_socket, (struct sockaddr *) (&address),
                      &lg_address);
      if (soc == -1)
        continue;

      child_pid1 = fork ();
      if (child_pid1 == 0)
        {
          loading_client_handle (soc);
          shutdown (soc, 2);
          close (soc);
          exit (0);
        }
      waitpid (child_pid1, &ret, WNOHANG);
    }
  exit (0);
}

/*
 * @brief Stops the loading handler process.
 *
 * @param[in]   handler_pid Pid of loading handler.
 */
void
loading_handler_stop (pid_t handler_pid)
{
  terminate_process (handler_pid);
  destroy_loading_shm ();
}

/**
 * @brief Initializes main scanner process' signal handlers.
 */
static void
init_signal_handlers ()
{
  openvas_signal (SIGTERM, handle_termination_signal);
  openvas_signal (SIGINT, handle_termination_signal);
  openvas_signal (SIGQUIT, handle_termination_signal);
  openvas_signal (SIGHUP, handle_reload_signal);
  openvas_signal (SIGCHLD, sighand_chld);
}

/* Restarts the scanner by reloading the configuration. */
static void
reload_openvassd ()
{
  static gchar *rc_name = NULL;
  const char *config_file;
  pid_t handler_pid;
  int i, ret;

  /* Ignore SIGHUP while reloading. */
  openvas_signal (SIGHUP, SIG_IGN);

  proctitle_set (PROCTITLE_RELOADING);
  /* Setup logging. */
  rc_name = g_build_filename (MAGENI_SYSCONF_DIR, "vscand_log.conf", NULL);
  if (g_file_test (rc_name, G_FILE_TEST_EXISTS))
    log_config = load_log_configuration (rc_name);
  g_free (rc_name);
  setup_log_handlers (log_config);
  g_message ("Reloading the scanner.\n");

  handler_pid = loading_handler_start ();
  if (handler_pid < 0)
    return;
  /* Reload config file. */
  config_file = prefs_get ("config_file");
  for (i = 0; openvassd_defaults[i].option != NULL; i++)
    prefs_set (openvassd_defaults[i].option, openvassd_defaults[i].value);
  prefs_config (config_file);

  /* Reload the plugins */
  ret = plugins_init ();
  set_globals_from_preferences ();
  loading_handler_stop (handler_pid);

  g_message ("Finished reloading the scanner.");
  openvas_signal (SIGHUP, handle_reload_signal);
  proctitle_set (PROCTITLE_WAITING);
  if (ret)
    exit (1);
}

/**
 * @brief Read the scan preferences from redis
 * @input scan_id Scan ID used as key to find the corresponding KB where
 *                to take the preferences from.
 * @return 0 on success, -1 if the kb is not found or no prefs are found in
 *         the kb.
 */
static int
load_scan_preferences (const char *scan_id)
{
  char key[1024];
  kb_t kb;
  struct kb_item *res = NULL;

  g_debug ("Start loading scan preferences.");
  if (!scan_id)
    return -1;

  snprintf (key, sizeof (key), "internal/%s/scanprefs", scan_id);
  kb = kb_find (prefs_get ("db_address"), key);
  if (!kb)
    return -1;

  res = kb_item_get_all (kb, key);
  if (!res)
    return -1;

  while (res)
    {
      gchar **pref = g_strsplit (res->v_str, "|||", 2);
      if (pref[0])
        prefs_set (pref[0], pref[1] ?: "");
      g_strfreev (pref);
      res = res->next;
    }
  snprintf (key, sizeof (key), "internal/%s", scan_id);
  kb_item_set_str (kb, key, "ready", 0);
  g_debug ("End loading scan preferences.");

  kb_item_free (res);
  return 0;
}

static void
handle_client (struct scan_globals *globals)
{
  kb_t net_kb = NULL;
  int soc = globals->global_socket;

  /* Become process group leader and the like ... */
  if (is_otp_scan ())
    {
      start_daemon_mode ();
      if (comm_wait_order (globals))
        return;
      ntp_timestamp_scan_starts (soc);
    }
  else
    {
      /* Load preferences from Redis. Scan started with a scan_id. */
      if (load_scan_preferences (globals->scan_id))
        {
          g_warning ("No preferences found for the scan %s", globals->scan_id);
          exit (0);
        }
    }
  attack_network (globals, &net_kb);
  if (net_kb != NULL)
    {
      kb_delete (net_kb);
      net_kb = NULL;
    }
  if (is_otp_scan ())
    {
      ntp_timestamp_scan_ends (soc);
      comm_terminate (soc);
    }
}

static void
scanner_thread (struct scan_globals *globals)
{
  int opt = 1;
  int soc = -1;

  nvticache_reset ();

  if (is_otp_scan () && !global_scan_id)
    {
      globals->scan_id = (char *) gvm_uuid_make ();
      soc = globals->global_socket;
      proctitle_set (PROCTITLE_SERVING, unix_socket_path);

      /* Close the scanner thread - it is useless for us now */
      close (global_iana_socket);

      if (soc < 0)
        goto shutdown_and_exit;

      if (setsockopt (soc, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof (opt)) < 0)
        goto shutdown_and_exit;

      globals->global_socket = soc;

      if (comm_init (soc) < 0)
        exit (0);
    }
  else
    globals->scan_id = g_strdup (global_scan_id);

  /* Everyone runs with a nicelevel of 10 */
  if (prefs_get_bool ("be_nice"))
    {
      errno = 0;
      if (nice (10) == -1 && errno != 0)
        {
          g_warning ("Unable to renice process: %d", errno);
        }
    }

  handle_client (globals);

shutdown_and_exit:
  if (is_otp_scan () && !global_scan_id)
    {
      shutdown (soc, 2);
      close (soc);
      /* Kill left overs */
      end_daemon_mode ();
    }
  exit (0);
}

/**
 * @brief Free logging configuration.
 */
static void
log_config_free ()
{
  free_log_configuration (log_config);
  log_config = NULL;
}

/*
 * @brief Terminates the scanner if a termination signal was received.
 */
static void
check_termination ()
{
  if (termination_signal)
    {
      g_debug ("Received the %s signal", strsignal (termination_signal));
      if (log_config)
        log_config_free ();
      remove_pidfile ();
      make_em_die (SIGTERM);
      _exit (0);
    }
}

/*
 * @brief Reloads the scanner if a reload was requested or the feed was updated.
 */
static void
check_reload ()
{
  if (nvticache_check_feed ())
    reload_openvassd ();
}

/**
 * @brief Get the pid and ppid from /proc to find the running scan pids.
 *        Send SIGUSR2 kill signal to all running scans to stop them.
 */
static void
stop_all_scans (void)
{
  int i, ispid;
  GDir *proc = NULL;
  const gchar *piddir = NULL;
  gchar *pidstatfn = NULL;
  gchar **contents_split = NULL;
  gchar *contents = NULL;
  GError *error = NULL;
  gchar *parentID = NULL;
  gchar *processID = NULL;

  proc = g_dir_open ("/proc", 0, &error);
  if (error != NULL)
    {
      g_message ("Unable to open directory: %s\n", error->message);
      g_error_free (error);
      return;
    }
  while ((piddir = g_dir_read_name (proc)) != NULL)
    {
      ispid = 1;
      for (i = 0; i < (int) strlen (piddir); i++)
        if (!g_ascii_isdigit (piddir[i]))
          {
            ispid = 0;
            break;
          }
      if (!ispid)
        continue;

      pidstatfn = g_strconcat ("/proc/", piddir, "/stat", NULL);
      if (g_file_get_contents (pidstatfn, &contents, NULL, NULL))
        {
          contents_split = g_strsplit (contents, " ", 6);
          parentID = g_strdup (contents_split[3]);
          processID = g_strdup (contents_split[0]);

          g_free (pidstatfn);
          pidstatfn = NULL;
          g_free (contents);
          contents = NULL;
          g_strfreev (contents_split);
          contents_split = NULL;

          if (atoi (parentID) == (int) getpid ())
            {
              g_message ("Stopping running scan with PID: %s", processID);
              kill (atoi (processID), SIGUSR2);
            }
          g_free (parentID);
          parentID = NULL;
          g_free (processID);
          processID = NULL;
        }
      else
        {
          g_free (pidstatfn);
          pidstatfn = NULL;
          continue;
        }
    }

  if (proc)
    g_dir_close (proc);
}

/**
 * @brief Check if Redis Server is up and if the KB exists. If KB does not
 * exist,force a reload and stop all the running scans.
 */
void
check_kb_status ()
{
  int waitredis = 5, waitkb = 5, ret = 0;

  kb_t kb_access_aux;

  while (waitredis != 0)
    {
      ret = kb_new (&kb_access_aux, prefs_get ("db_address"));
      if (ret)
        {
          g_message ("Redis connection lost. Trying to reconnect.");
          waitredis--;
          sleep (5);
          continue;
        }
      else
        {
          kb_delete (kb_access_aux);
          break;
        }
    }

  if (waitredis == 0)
    {
      g_message ("Critical Redis connection error.");
      exit (1);
    }
  while (waitkb != 0)
    {
      kb_access_aux = kb_find (prefs_get ("db_address"), NVTICACHE_STR);
      if (!kb_access_aux)
        {
          g_message ("Redis kb not found. Trying again in 2 seconds.");
          waitkb--;
          sleep (2);
          continue;
        }
      else
        {
          kb_lnk_reset (kb_access_aux);
          g_free (kb_access_aux);
          break;
        }
    }

  if (waitredis != 5 || waitkb == 0)
    {
      g_message ("Redis connection error. Stopping all the running scans.");
      stop_all_scans ();
      reload_openvassd ();
    }
}

static void
main_loop ()
{
  g_message ("mageni-vscand %s started", SCANNER_VERSION);
  proctitle_set (PROCTITLE_WAITING);
  for (;;)
    {
      int soc;
      unsigned int lg_address;
      struct sockaddr_un address;
      struct scan_globals *globals;

      check_termination ();
      wait_for_children1 ();
      lg_address = sizeof (struct sockaddr_un);
      soc = accept (global_iana_socket, (struct sockaddr *) (&address),
                    &lg_address);
      if (soc == -1)
        continue;

      globals = g_malloc0 (sizeof (struct scan_globals));
      globals->global_socket = soc;
      /* Set scan type 1:OTP, 0:OSP */
      set_scan_type (1);

      /* Check for reload after accept() but before we fork, to ensure that
       * Manager gets full updated feed in case of NVT update connection.
       */
      check_kb_status ();
      check_reload ();
      if (create_process ((process_func_t) scanner_thread, globals) < 0)
        {
          g_debug ("Could not fork - client won't be served");
          sleep (2);
        }
      close (soc);
      g_free (globals);
    }
}

/**
 * Initialization of the network in unix socket case:
 * we setup the socket that will listen for incoming connections on
 * unix_socket_path.
 *
 * @param[out] sock Socket to be initialized.
 *
 * @return 0 on success. -1 on failure.
 */
static int
init_unix_network (int *sock, const char *owner, const char *group,
                   const char *mode)
{
  struct sockaddr_un addr;
  struct stat ustat;
  int unix_socket;
  mode_t omode;

  unix_socket = socket (AF_UNIX, SOCK_STREAM, 0);
  if (unix_socket == -1)
    {
      g_debug ("%s: Couldn't create UNIX socket", __FUNCTION__);
      return -1;
    }
  addr.sun_family = AF_UNIX;
  strncpy (addr.sun_path, unix_socket_path, sizeof (addr.sun_path) - 1);
  if (!stat (addr.sun_path, &ustat))
    {
      /* Remove socket so we can bind(). */
      unlink (addr.sun_path);
    }
  if (bind (unix_socket, (struct sockaddr *) &addr, sizeof (struct sockaddr_un))
      == -1)
    {
      g_debug ("%s: Error on bind(%s): %s", __FUNCTION__, unix_socket_path,
               strerror (errno));
      goto init_unix_err;
    }

  if (owner)
    {
      struct passwd *pwd = getpwnam (owner);
      if (!pwd)
        {
          g_debug ("%s: User %s not found.", __FUNCTION__, owner);
          goto init_unix_err;
        }
      if (chown (unix_socket_path, pwd->pw_uid, -1) == -1)
        {
          g_debug ("%s: chown: %s", __FUNCTION__, strerror (errno));
          goto init_unix_err;
        }
    }

  if (group)
    {
      struct group *grp = getgrnam (group);
      if (!grp)
        {
          g_debug ("%s: Group %s not found.", __FUNCTION__, group);
          goto init_unix_err;
        }
      if (chown (unix_socket_path, -1, grp->gr_gid) == -1)
        {
          g_debug ("%s: chown: %s", __FUNCTION__, strerror (errno));
          goto init_unix_err;
        }
    }

  if (!mode)
    mode = "660";
  omode = strtol (mode, 0, 8);
  if (omode <= 0 || omode > 4095)
    {
      g_debug ("%s: Erroneous liste-mode value", __FUNCTION__);
      goto init_unix_err;
    }
  if (chmod (unix_socket_path, strtol (mode, 0, 8)) == -1)
    {
      g_debug ("%s: chmod: %s", __FUNCTION__, strerror (errno));
      goto init_unix_err;
    }

  if (listen (unix_socket, 128) == -1)
    {
      g_debug ("%s: Error on listen(): %s", __FUNCTION__, strerror (errno));
      goto init_unix_err;
    }

  *sock = unix_socket;
  return 0;

init_unix_err:
  close (unix_socket);
  return -1;
}

/**
 * @brief Initialize everything.
 *
 * @param config_file Path to config file for initialization
 */
static int
init_openvassd (const char *config_file)
{
  static gchar *rc_name = NULL;
  int i;

  for (i = 0; openvassd_defaults[i].option != NULL; i++)
    prefs_set (openvassd_defaults[i].option, openvassd_defaults[i].value);
  prefs_config (config_file);

  /* Setup logging. */
  rc_name = g_build_filename (MAGENI_SYSCONF_DIR, "vscand_log.conf", NULL);
  if (g_file_test (rc_name, G_FILE_TEST_EXISTS))
    log_config = load_log_configuration (rc_name);
  g_free (rc_name);
  setup_log_handlers (log_config);
  set_globals_from_preferences ();

  return 0;
}

static void
set_daemon_mode ()
{
  if (fork ())
    { /* Parent. */
      log_config_free ();
      exit (0);
    }
  setsid ();
}

static int
flush_all_kbs ()
{
  kb_t kb;
  int rc;

  rc = kb_new (&kb, prefs_get ("db_address"));
  if (rc)
    return rc;

  rc = kb_flush (kb, NVTICACHE_STR);
  return rc;
}

static void
gcrypt_init ()
{
  if (gcry_control (GCRYCTL_ANY_INITIALIZATION_P))
    return;
  gcry_check_version (NULL);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
  gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED);
}

void
start_single_task_scan ()
{
  struct scan_globals *globals;
  int ret = 0;

#if GNUTLS_VERSION_NUMBER < 0x030300
  if (openvas_SSL_init () < 0)
    g_message ("Could not initialize openvas SSL!");
#endif

  g_message ("mageni-vscand %s started", SCANNER_VERSION);

  pidfile_create ("mageni-vscand");
  openvas_signal (SIGHUP, SIG_IGN);
  ret = plugins_init ();
  if (ret)
    exit (0);
  init_signal_handlers ();

  globals = g_malloc0 (sizeof (struct scan_globals));

  /* Set scan type 1:OTP, 0:OSP */
  set_scan_type (0);
  scanner_thread (globals);
  exit (0);
}

/**
 * @brief openvassd.
 * @param argc Argument count.
 * @param argv Argument vector.
 */
int
main (int argc, char *argv[])
{
  int ret;
  pid_t handler_pid;

  proctitle_init (argc, argv);
  gcrypt_init ();

  static gboolean display_version = FALSE;
  static gboolean dont_fork = FALSE;
  static gchar *config_file = NULL;
  static gchar *vendor_version_string = NULL;
  static gchar *listen_owner = NULL;
  static gchar *listen_group = NULL;
  static gchar *listen_mode = NULL;
  static gchar *scan_id = NULL;
  static gboolean print_specs = FALSE;
  static gboolean print_sysconfdir = FALSE;
  static gboolean only_cache = FALSE;
  GError *error = NULL;
  GOptionContext *option_context;
  static GOptionEntry entries[] = {
    {"version", 'V', 0, G_OPTION_ARG_NONE, &display_version,
     "Display version information", NULL},
    {"foreground", 'f', 0, G_OPTION_ARG_NONE, &dont_fork,
     "Do not run in daemon mode but stay in foreground", NULL},
    {"config-file", 'c', 0, G_OPTION_ARG_FILENAME, &config_file,
     "Configuration file", "<filename>"},
    {"vendor-version", '\0', 0, G_OPTION_ARG_STRING, &vendor_version_string,
     "Use <string> as vendor version.", "<string>"},
    {"cfg-specs", 's', 0, G_OPTION_ARG_NONE, &print_specs,
     "Print configuration settings", NULL},
    {"sysconfdir", 'y', 0, G_OPTION_ARG_NONE, &print_sysconfdir,
     "Print system configuration directory (set at compile time)", NULL},
    {"only-cache", 'C', 0, G_OPTION_ARG_NONE, &only_cache,
     "Exit once the NVT cache has been initialized or updated", NULL},
    {"unix-socket", 'c', 0, G_OPTION_ARG_FILENAME, &unix_socket_path,
     "Path of unix socket to listen on", "<filename>"},
    {"listen-owner", '\0', 0, G_OPTION_ARG_STRING, &listen_owner,
     "Owner of the unix socket", "<string>"},
    {"listen-group", '\0', 0, G_OPTION_ARG_STRING, &listen_group,
     "Group of the unix socket", "<string>"},
    {"listen-mode", '\0', 0, G_OPTION_ARG_STRING, &listen_mode,
     "File mode of the unix socket", "<string>"},
    {"scan-start", '\0', 0, G_OPTION_ARG_STRING, &scan_id,
     "ID for this scan task", "<string>"},
    {NULL, 0, 0, 0, NULL, NULL, NULL}};

  option_context = g_option_context_new (
    "- Scanner of the Open Vulnerability Assessment System");
  g_option_context_add_main_entries (option_context, entries, NULL);
  if (!g_option_context_parse (option_context, &argc, &argv, &error))
    {
      g_print ("%s\n\n", error->message);
      exit (0);
    }
  g_option_context_free (option_context);

  if (print_sysconfdir)
    {
      g_print ("%s\n", SYSCONFDIR);
      exit (0);
    }

  /* Switch to UTC so that OTP times are always in UTC. */
  if (setenv ("TZ", "utc 0", 1) == -1)
    {
      g_print ("%s\n\n", strerror (errno));
      exit (0);
    }
  tzset ();

  if (!unix_socket_path)
    unix_socket_path =
      g_build_filename (MAGENI_PID_DIR, "mageni-vscand.sock", NULL);

  if (display_version)
    {
      printf ("Mageni Vulnerability Scanner (VSCAN) %s\n", SCANNER_VERSION);
      printf ("Most new code since 2020 by Mageni Security LLC\n");
      printf ("======================================================================\n");
      printf ("VSCAN was forked from openvassd 6.0.0 in 2020. openvassd was forked\n");
      printf ("by Greenbone Networks GmbH from nessusd in 2005.\n");
      printf ("Nessusd was written by Renaud Deraison <deraison@cvs.nessus.org>\n");
      printf ("Most new code since 2005: (C) 2018 Greenbone Networks GmbH\n");
      printf ("Nessus origin: (C) 2004 Renaud Deraison <deraison@nessus.org>\n");
      printf ("======================================================================\n");
      printf ("License GPLv2: GNU GPL version 2\n");
      printf ("This is free software: you are free to change and redistribute it.\n");
      printf ("There is NO WARRANTY, to the extent permitted by law.\n");
      printf ("======================================================================\n");
      printf ("The GPLv2 requires the maker of a version to place his or her name on it,\n");
      printf ("to distinguish it from other versions and to protect the reputations of other maintainers.\n");
      printf ("Source: https://www.gnu.org/licenses/old-licenses/gpl-2.0-faq.en.html#WhyDoesTheGPLPermitUsersToPublishTheirModifiedVersions\n");
      exit (0);
    }

  if (vendor_version_string)
    vendor_version_set (vendor_version_string);

  if (!config_file)
    config_file = MAGENI_CONF_DIR;
  if (only_cache)
    {
      if (init_openvassd (config_file))
        return 1;
      if (plugins_init ())
        return 1;
      return 0;
    }

  if (init_openvassd (config_file))
    return 1;

  if (scan_id)
    {
      global_scan_id = g_strdup (scan_id);
      start_single_task_scan ();
      exit (0);
    }

  if (!print_specs)
    {
      if (init_unix_network (&global_iana_socket, listen_owner, listen_group,
                             listen_mode))
        return 1;
    }

  /* special treatment */
  if (print_specs)
    {
      prefs_dump ();
      exit (0);
    }
  if (flush_all_kbs ())
    exit (1);

#if GNUTLS_VERSION_NUMBER < 0x030300
  if (openvas_SSL_init () < 0)
    g_message ("Could not initialize openvas SSL!");
#endif

  // Daemon mode:
  if (dont_fork == FALSE)
    set_daemon_mode ();
  pidfile_create ("mageni-vscand");

  /* Ignore SIGHUP while reloading. */
  openvas_signal (SIGHUP, SIG_IGN);

  handler_pid = loading_handler_start ();
  if (handler_pid < 0)
    return 1;
  ret = plugins_init ();
  loading_handler_stop (handler_pid);
  if (ret)
    return 1;
  init_signal_handlers ();
  main_loop ();
  exit (0);
}
