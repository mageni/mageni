/**
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileCopyrightText: Portions Copyright (C) 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
 * SPDX-FileComment: Creates new threads.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#include "processes.h"

#include "sighand.h"

#include <errno.h> /* for errno() */
#include <glib.h>  /* for g_error */
#include <setjmp.h>
#include <signal.h>   /* for kill() */
#include <stdlib.h>   /* for exit() */
#include <string.h>   /* for strerror() */
#include <sys/wait.h> /* for waitpid() */
#include <time.h>     /* for time() */
#include <unistd.h>   /* for fork() */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "mageni-vscand   scanner"

int
terminate_process (pid_t pid)
{
  int ret;

  if (pid == 0)
    return 0;

  ret = kill (pid, SIGTERM);

  if (ret == 0)
    {
      usleep (500);
      if (waitpid (pid, NULL, WNOHANG) >= 0)
        kill (pid, SIGKILL);
    }
  return -1;
}

static void
init_child_signal_handlers ()
{
  /* SIGHUP is only for reloading main scanner process. */
  openvas_signal (SIGHUP, SIG_IGN);
  openvas_signal (SIGTERM, make_em_die);
  openvas_signal (SIGINT, make_em_die);
  openvas_signal (SIGQUIT, make_em_die);
  openvas_signal (SIGSEGV, sighand_segv);
  openvas_signal (SIGPIPE, SIG_IGN);
}

/**
 * @brief Create a new process (fork).
 */
pid_t
create_process (process_func_t function, void *argument)
{
  int pid;

  pid = fork ();

  if (pid == 0)
    {
      init_child_signal_handlers ();
      srand48 (getpid () + getppid () + (long) time (NULL));
      (*function) (argument);
      exit (0);
    }
  if (pid < 0)
    g_error ("Error : could not fork ! Error : %s", strerror (errno));
  return pid;
}
