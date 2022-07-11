/* Copyright (C) 2010-2019 Greenbone Networks GmbH
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
 * @file settings.c
 * @brief Implementation of API to handle configuration file management
 */

#include "settings.h"

#include <stdio.h>
#include <string.h> /* for strlen */

/**
 * @brief Initialise a settings struct from a file.
 *
 * @param[in]  settings  Settings.
 * @param[in]  filename  Complete name of the configuration file.
 * @param[in]  group     Name of the group in the file.
 *
 * @return 0 success, -1 error.
 */
int
settings_init_from_file (settings_t *settings, const gchar *filename,
                         const gchar *group)
{
  GError *error = NULL;

  if (filename == NULL || group == NULL)
    return -1;

  gchar *contents = NULL;

  if (!g_file_get_contents (filename, &contents, NULL, &error))
    {
      g_error_free (error);
      return -1;
    }

  if (contents != NULL)
    {
      gchar *contents_with_group = g_strjoin ("\n", "[Misc]", contents, NULL);
      settings->key_file = g_key_file_new ();

      if (!g_key_file_load_from_data (
            settings->key_file, contents_with_group,
            strlen (contents_with_group),
            G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS, &error))
        {
          g_warning ("Failed to load configuration from %s: %s", filename,
                     error->message);
          g_error_free (error);
          g_free (contents_with_group);
          g_free (contents);
          return -1;
        }
      g_free (contents_with_group);
      g_free (contents);
    }

  settings->group_name = g_strdup (group);
  settings->file_name = g_strdup (filename);

  return 0;
}

/**
 * @brief Cleanup a settings structure.
 *
 * @param[in]  settings  Settings structure.
 */
void
settings_cleanup (settings_t *settings)
{
  g_free (settings->group_name);
  g_free (settings->file_name);
  g_key_file_free (settings->key_file);
}

/**
 * @brief Initialise a settings iterator from a file.
 *
 * @param[in]  iterator  Settings iterator.
 * @param[in]  filename  Complete name of the configuration file.
 * @param[in]  group     Name of the group in the file.
 *
 * @return 0 success, -1 error.
 */
int
init_settings_iterator_from_file (settings_iterator_t *iterator,
                                  const gchar *filename, const gchar *group)
{
  int ret;
  gsize keys_length;
  GError *error = NULL;

  ret = settings_init_from_file (&iterator->settings, filename, group);
  if (ret)
    return ret;

  iterator->keys = g_key_file_get_keys (iterator->settings.key_file, group,
                                        &keys_length, &error);

  if (iterator->keys == NULL)
    {
      if (error)
        {
          g_warning ("Failed to retrieve keys of group %s from %s: %s", group,
                     filename, error->message);
          g_error_free (error);
        }
      g_key_file_free (iterator->settings.key_file);
      return -1;
    }

  iterator->current_key = iterator->keys - 1;
  iterator->last_key = iterator->keys + keys_length - 1;

  return 0;
}

/**
 * @brief Cleanup a settings iterator.
 *
 * @param[in]  iterator  Settings iterator.
 */
void
cleanup_settings_iterator (settings_iterator_t *iterator)
{
  g_strfreev (iterator->keys);
  settings_cleanup (&iterator->settings);
}

/**
 * @brief Increment an iterator.
 *
 * @param[in]  iterator  Settings iterator.
 *
 * @return TRUE if there was a next item, else FALSE.
 */
gboolean
settings_iterator_next (settings_iterator_t *iterator)
{
  if (iterator->current_key == iterator->last_key)
    return FALSE;
  iterator->current_key++;
  return TRUE;
}

/**
 * @brief Get the name from a settings iterator.
 *
 * @param[in]  iterator  Settings iterator.
 *
 * @return Name of current key.
 */
const gchar *
settings_iterator_name (settings_iterator_t *iterator)
{
  return *iterator->current_key;
}

/**
 * @brief Get the value from a settings iterator.
 *
 * @param[in]  iterator  Settings iterator.
 *
 * @return Value of current key.
 */
const gchar *
settings_iterator_value (settings_iterator_t *iterator)
{
  return g_key_file_get_value (iterator->settings.key_file,
                               iterator->settings.group_name,
                               *iterator->current_key, NULL);
}
