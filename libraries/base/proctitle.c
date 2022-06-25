/* Copyright (C) 2014-2019 Greenbone Networks GmbH
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
 * @brief Implementation of an API to set process title.
 */

#include "proctitle.h"

#include <glib.h> /* for g_free, g_malloc0, g_strdup */
#include <stdio.h>
#include <string.h> /* for strlen, strdup, bzero, strncpy */
#include <sys/param.h>

/**
 * @brief Access to the executable's name.
 */
extern const char *__progname;
#ifndef __FreeBSD__
extern const char *__progname_full;
#endif
static int argv_len;
static char **old_argv;
extern char **environ;
void *current_environ = NULL;

/**
 * @brief Initializes the process setting variables.
 *
 * @param[in]   argc    Argc argument from main.
 * @param[in]   argv    Argv argument from main.
 */
void
proctitle_init (int argc, char **argv)
{
  int i = 0;
  char **envp = environ;
#ifndef __FreeBSD__
  char *new_progname, *new_progname_full;
#else
  char *new_progname;
#endif

  if (argv == NULL)
    return;

  new_progname = strdup (__progname);
#ifndef __FreeBSD__
  new_progname_full = strdup (__progname_full);
#endif

  /* Move environ to new memory, to be able to reuse older one. */
  while (envp[i])
    i++;
  environ = g_malloc0 (sizeof (char *) * (i + 1));
  if (current_environ)
    g_free (current_environ);
  current_environ = environ;
  for (i = 0; envp[i]; i++)
    environ[i] = g_strdup (envp[i]);
  environ[i] = NULL;

  old_argv = argv;
  if (i > 0)
    argv_len = envp[i - 1] + strlen (envp[i - 1]) - old_argv[0];
  else
    argv_len = old_argv[argc - 1] + strlen (old_argv[argc - 1]) - old_argv[0];

  /* Seems like these are in the moved environment, so reset them.  Idea from
   * proctitle.cpp in KDE libs.  */
  __progname = new_progname;
#ifndef __FreeBSD__
  __progname_full = new_progname_full;
#endif
}

/**
 * @brief Sets the process' title.
 *
 * @param[in]   new_title   Format string for new process title.
 * @param[in]   args        Format string arguments variable list.
 */
static void
proctitle_set_args (const char *new_title, va_list args)
{
  int i;
  char *formatted;

  if (old_argv == NULL)
    /* Called setproctitle before initproctitle ? */
    return;

  formatted = g_strdup_vprintf (new_title, args);

  i = strlen (formatted);
  if (i > argv_len - 2)
    {
      i = argv_len - 2;
      formatted[i] = '\0';
    }
  bzero (old_argv[0], argv_len);
  strncpy (old_argv[0], formatted, argv_len);
  old_argv[1] = NULL;
  g_free (formatted);
}

/**
 * @brief Sets the process' title.
 *
 * @param[in]   new_title   Format string for new process title.
 * @param[in]   ...         Arguments for format string.
 */
void
proctitle_set (const char *new_title, ...)
{
  va_list args;

  va_start (args, new_title);
  proctitle_set_args (new_title, args);
  va_end (args);
}
