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
 * @brief File utilities.
 */

/* time.h in glibc2 needs this for strptime. */
#define _GNU_SOURCE

#include "fileutils.h"

#include <errno.h>       /* for errno */
#include <gio/gio.h>     /* for g_file_new_for_path, GFile */
#include <glib/gstdio.h> /* for g_lstat, g_remove */
#include <glib/gtypes.h> /* for gsize */
#include <string.h>      /* for strlen, memset, strcmp */
#include <sys/stat.h>    /* for stat, S_ISDIR */
#include <time.h>        /* for tm, strptime, localtime, time, time_t */

/**
 * @brief Checks whether a file is a directory or not.
 *
 * This is a replacement for the g_file_test functionality which is reported
 * to be unreliable under certain circumstances, for example if this
 * application and glib are compiled with a different libc.
 *
 * Symbolic links are not followed.
 *
 * @param[in]  name  Name of file or directory.
 *
 * @return 1 if parameter is directory, 0 if it is not, -1 if it does not
 *         exist or could not be accessed.
 */
int
gvm_file_check_is_dir (const char *name)
{
  struct stat sb;

  if (g_lstat (name, &sb))
    {
      g_warning ("g_lstat(%s) failed - %s\n", name, g_strerror (errno));
      return -1;
    }

  return (S_ISDIR (sb.st_mode));
}

/**
 * @brief Recursively removes files and directories.
 *
 * This function will recursively call itself to delete a path and any
 * contents of this path.
 *
 * @param[in]  pathname  The name of the file to be deleted from the filesystem.
 *
 * @return 0 if the name was successfully deleted, -1 if an error occurred.
 */
int
gvm_file_remove_recurse (const gchar *pathname)
{
  if (gvm_file_check_is_dir (pathname) == 1)
    {
      GError *error = NULL;
      GDir *directory = g_dir_open (pathname, 0, &error);

      if (directory == NULL)
        {
          g_warning ("g_dir_open(%s) failed - %s\n", pathname, error->message);
          g_error_free (error);
          return -1;
        }
      else
        {
          int ret = 0;
          const gchar *entry = NULL;

          while ((entry = g_dir_read_name (directory)) && (ret == 0))
            {
              gchar *entry_path = g_build_filename (pathname, entry, NULL);
              ret = gvm_file_remove_recurse (entry_path);
              g_free (entry_path);
              if (ret != 0)
                {
                  g_warning ("Failed to remove %s from %s!", entry, pathname);
                  g_dir_close (directory);
                  return ret;
                }
            }
          g_dir_close (directory);
        }
    }

  return g_remove (pathname);
}

/**
 * @brief Copies a source file into a destination file.
 *
 * If the destination file does exist already, it will be overwritten.
 *
 * @param[in]  source_file  Source file name.
 * @param[in]  dest_file    Destination file name.
 *
 * @return TRUE if successful, FALSE otherwise.
 */
gboolean
gvm_file_copy (const gchar *source_file, const gchar *dest_file)
{
  gboolean rc;
  GFile *sfile, *dfile;
  GError *error;

  sfile = g_file_new_for_path (source_file);
  dfile = g_file_new_for_path (dest_file);
  error = NULL;

  rc =
    g_file_copy (sfile, dfile, G_FILE_COPY_OVERWRITE, NULL, NULL, NULL, &error);
  if (!rc)
    {
      g_warning ("%s: g_file_copy(%s, %s) failed - %s\n", __FUNCTION__,
                 source_file, dest_file, error->message);
      g_error_free (error);
    }

  g_object_unref (sfile);
  g_object_unref (dfile);
  return rc;
}

/**
 * @brief Moves a source file into a destination file.
 *
 * If the destination file does exist already, it will be overwritten.
 *
 * @param[in]  source_file  Source file name.
 * @param[in]  dest_file    Destination file name.
 *
 * @return TRUE if successful, FALSE otherwise.
 */
gboolean
gvm_file_move (const gchar *source_file, const gchar *dest_file)
{
  gboolean rc;
  GFile *sfile, *dfile;
  GError *error;

  sfile = g_file_new_for_path (source_file);
  dfile = g_file_new_for_path (dest_file);
  error = NULL;

  rc =
    g_file_move (sfile, dfile, G_FILE_COPY_OVERWRITE, NULL, NULL, NULL, &error);
  if (!rc)
    {
      g_warning ("%s: g_file_move(%s, %s) failed - %s\n", __FUNCTION__,
                 source_file, dest_file, error->message);
      g_error_free (error);
    }

  g_object_unref (sfile);
  g_object_unref (dfile);
  return rc;
}

/**
 * @brief Get the content of a file in base64 format.
 *
 * @param[in]  path     Path to file.
 *
 * @return Allocated nul-terminated string, NULL otherwise.
 */
char *
gvm_file_as_base64 (const char *path)
{
  GError *error = NULL;
  char *content, *encoded;
  gsize len;

  if (!g_file_get_contents (path, &content, &len, &error))
    {
      g_error_free (error);
      return NULL;
    }
  encoded = g_base64_encode ((guchar *) content, len);
  g_free (content);
  return encoded;
}

/**
 * @brief Generates a file name for exporting.
 *
 * @param[in]   fname_format      Format string.
 * @param[in]   username          Current user name.
 * @param[in]   type              Type of resource.
 * @param[in]   uuid              UUID of resource.
 * @param[in]   creation_iso_time     Creation time of resource in ISO format.
 * @param[in]   modification_iso_time Modification time of resource (ISO).
 * @param[in]   name              Name of resource.
 * @param[in]   format_name       Name of format plugin.
 *
 * @return The file name.
 */
gchar *
gvm_export_file_name (const char *fname_format, const char *username,
                      const char *type, const char *uuid,
                      const char *creation_iso_time,
                      const char *modification_iso_time, const char *name,
                      const char *format_name)
{
  time_t now;
  struct tm *now_broken;
  gchar *now_date_str, *creation_date_str, *modification_date_str;
  gchar *now_time_str, *creation_time_str, *modification_time_str;
  struct tm creation_time, modification_time;
  gchar *creation_date_short, *modification_date_short;
  gchar *fname_point;
  GString *file_name_buf;
  int format_state = 0;
  char *ret;

  creation_date_str = NULL;
  modification_date_str = NULL;
  creation_time_str = NULL;
  modification_time_str = NULL;

  now = time (NULL);
  now_broken = localtime (&now);
  now_date_str =
    g_strdup_printf ("%04d%02d%02d", (now_broken->tm_year + 1900),
                     (now_broken->tm_mon + 1), now_broken->tm_mday);
  now_time_str = g_strdup_printf ("%02d%02d%02d", now_broken->tm_hour,
                                  now_broken->tm_min, now_broken->tm_sec);

  memset (&creation_time, 0, sizeof (struct tm));
  memset (&modification_time, 0, sizeof (struct tm));
  creation_date_short = NULL;
  modification_date_short = NULL;

  if (creation_iso_time && (strlen (creation_iso_time) >= 19))
    creation_date_short = g_strndup (creation_iso_time, 19);

  if (creation_date_short
      && (((ret = strptime (creation_date_short, "%Y-%m-%dT%H:%M:%S",
                            &creation_time))
           == NULL)
          || (strlen (ret) == 0)))
    {
      creation_date_str =
        g_strdup_printf ("%04d%02d%02d", (creation_time.tm_year + 1900),
                         (creation_time.tm_mon + 1), creation_time.tm_mday);
      creation_time_str =
        g_strdup_printf ("%02d%02d%02d", creation_time.tm_hour,
                         creation_time.tm_min, creation_time.tm_sec);
    }

  if (modification_iso_time && (strlen (modification_iso_time) >= 19))
    modification_date_short = g_strndup (modification_iso_time, 19);

  if (modification_date_short
      && (((ret = strptime (modification_date_short, "%Y-%m-%dT%H:%M:%S",
                            &modification_time))
           == NULL)
          || (strlen (ret) == 0)))
    {
      modification_date_str = g_strdup_printf (
        "%04d%02d%02d", (modification_time.tm_year + 1900),
        (modification_time.tm_mon + 1), modification_time.tm_mday);

      modification_time_str =
        g_strdup_printf ("%02d%02d%02d", modification_time.tm_hour,
                         modification_time.tm_min, modification_time.tm_sec);
    }

  if (creation_date_str == NULL)
    creation_date_str = g_strdup (now_date_str);
  if (modification_date_str == NULL)
    modification_date_str = g_strdup (creation_date_str);
  if (creation_time_str == NULL)
    creation_time_str = g_strdup (now_time_str);
  if (modification_time_str == NULL)
    modification_time_str = g_strdup (creation_time_str);

  file_name_buf = g_string_new ("");

  fname_point = (char *) fname_format;

  while (format_state >= 0 && *fname_point != '\0')
    {
      if (format_state == 0)
        {
          if (*fname_point == '%')
            format_state = 1;
          else if (*fname_point == '"')
            g_string_append (file_name_buf, "\\\"");
          else if (*fname_point <= ' ')
            g_string_append_c (file_name_buf, '_');
          else
            g_string_append_c (file_name_buf, *fname_point);
        }
      else if (format_state == 1)
        {
          format_state = 0;
          switch (*fname_point)
            {
            case 'C':
              g_string_append (file_name_buf, creation_date_str);
              break;
            case 'c':
              g_string_append (file_name_buf, creation_time_str);
              break;
            case 'd':
              g_string_append_printf (file_name_buf, "%02d",
                                      modification_time.tm_mday);
              break;
            case 'D':
              g_string_append (file_name_buf, now_date_str);
              break;
            case 'F':
              g_string_append (file_name_buf,
                               format_name ? format_name : "XML");
              break;
            case 'M':
              g_string_append (file_name_buf, modification_date_str);
              break;
            case 'm':
              g_string_append (file_name_buf, modification_time_str);
              break;
            case 'N':
              g_string_append (file_name_buf,
                               name ? name : (type ? type : "unnamed"));
              break;
            case 'o':
              g_string_append_printf (file_name_buf, "%02d",
                                      modification_time.tm_mon + 1);
              break;
            case 'T':
              g_string_append (file_name_buf, type ? type : "resource");
              break;
            case 't':
              g_string_append (file_name_buf, now_time_str);
              break;
            case 'U':
              g_string_append (file_name_buf, uuid ? uuid : "list");
              break;
            case 'u':
              g_string_append (file_name_buf, username ? username : "");
              break;
            case 'Y':
              g_string_append_printf (file_name_buf, "%04d",
                                      modification_time.tm_year + 1900);
              break;
            case '%':
              g_string_append_c (file_name_buf, '%');
              break;
            default:
              g_warning ("%s : Unknown file name format placeholder: %%%c.",
                         __FUNCTION__, *fname_point);
              format_state = -1;
            }
        }
      fname_point += sizeof (char);
    }

  if (format_state || strcmp (file_name_buf->str, "") == 0)
    {
      g_warning ("%s : Invalid file name format", __FUNCTION__);
      g_string_free (file_name_buf, TRUE);
      return NULL;
    }

  fname_point = file_name_buf->str;
  while (*fname_point != '\0')
    {
      if (*fname_point <= ' ')
        *fname_point = '_';
      fname_point++;
    }

  g_free (now_date_str);
  g_free (creation_date_str);
  g_free (creation_time_str);
  g_free (modification_date_str);
  return g_string_free (file_name_buf, FALSE);
}
