/* Copyright (C) 2009-2019 Greenbone Networks GmbH
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
 * @brief PID-file management.
 */

#include "pidfile.h"

#include <errno.h>       /* for errno */
#include <glib.h>        /* for g_free, gchar, g_build_filename, g_strconcat */
#include <glib/gstdio.h> /* for g_unlink, g_fopen */
#include <stdio.h>       /* for fclose, FILE */
#include <stdlib.h>      /* for atoi */
#include <string.h>      /* for strerror */
#include <unistd.h>      /* for getpid */

/**
 * @brief GLib log domain.
 */
#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "base pidfile"

/**
 * @brief Create a PID-file.
 *
 * A standard PID file will be created for the
 * given daemon name.
 *
 * @param[in]  daemon_name The name of the daemon
 *
 * @return 0 for success, anything else indicates an error.
 */
int
pidfile_create (gchar *daemon_name)
{
  gchar *name_pid = g_strconcat (daemon_name, ".pid", NULL);
  gchar *pidfile_name = g_build_filename (GVM_PID_DIR, name_pid, NULL);
  FILE *pidfile = g_fopen (pidfile_name, "w");

  g_free (name_pid);

  if (pidfile == NULL)
    {
      g_critical ("%s: failed to open pidfile: %s\n", __FUNCTION__,
                  strerror (errno));
      return 1;
    }
  else
    {
      g_fprintf (pidfile, "%d\n", getpid ());
      fclose (pidfile);
      g_free (pidfile_name);
    }
  return 0;
}

/**
 * @brief Remove PID file.
 *
 * @param[in]  daemon_name The name of the daemon
 */
void
pidfile_remove (gchar *daemon_name)
{
  gchar *name_pid = g_strconcat (daemon_name, ".pid", NULL);
  gchar *pidfile_name = g_build_filename (GVM_PID_DIR, name_pid, NULL);
  gchar *pidfile_contents;

  g_free (name_pid);

  if (g_file_get_contents (pidfile_name, &pidfile_contents, NULL, NULL))
    {
      int pid = atoi (pidfile_contents);

      if (pid == getpid ())
        {
          g_unlink (pidfile_name);
        }
      g_free (pidfile_contents);
    }

  g_free (pidfile_name);
}
