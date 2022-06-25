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
 * @brief String utilities.
 */

#include "strings.h"

#include <assert.h> /* for assert */
#include <glib.h>   /* for g_free, g_strconcat, gchar, g_strdup, g_strndup */

/**
 * @brief Append a string to a string variable.
 *
 * When the variable is NULL store a copy of the given string in the variable.
 *
 * When the variable already contains a string replace the string with a new
 * string that is the concatenation of the two, freeing the old string.  It is
 * up to the caller to free the given string if it was dynamically allocated.
 *
 * @param[in]  var     The address of a string variable, that is, a pointer to
 *                     a string.
 * @param[in]  string  The string to append to the string in the variable.
 */
void
gvm_append_string (gchar **var, const gchar *string)
{
  if (*var)
    {
      char *old = *var;
      *var = g_strconcat (old, string, NULL);
      g_free (old);
    }
  else
    *var = g_strdup (string);
}

/**
 * @brief Append a string of a known length to a string variable.
 *
 * When the variable is NULL store a copy of the given string in the variable.
 *
 * When the variable already contains a string replace the string with a new
 * string that is the concatenation of the two, freeing the old string.  It is
 * up to the caller to free the given string if it was dynamically allocated.
 *
 * The string must be NULL terminated, and the given length must be the
 * actual length of the string.
 *
 * @param[in]  var     The address of a string variable, that is, a pointer to
 *                     a string.
 * @param[in]  string  The string to append to the string in the variable.
 * @param[in]  length  The length of string.
 */
void
gvm_append_text (gchar **var, const gchar *string, gsize length)
{
  if (*var)
    {
      char *old = *var;
      *var = g_strconcat (old, string, NULL);
      g_free (old);
    }
  else
    *var = g_strndup (string, length);
}

/**
 * @brief Free a string variable.
 *
 * Free the string in the variable and set the variable to NULL.
 *
 * @param[in]  var  The address of a string variable, that is, a pointer to
 *                  a string.
 */
void
gvm_free_string_var (gchar **var)
{
  g_free (*var);
  *var = NULL;
}

/**
 * @brief "Strip" space and newline characters from either end of some memory.
 *
 * Return the given pointer moved forward past any spaces, replacing the
 * first of any contiguous spaces at or before the end of the memory with
 * a terminating NULL.
 *
 * This is for use when string points into a static buffers.
 *
 * @param[in,out]  string  The start of the memory.
 * @param[in]      end     Pointer to the byte after the end of the memory.
 *
 * @return A new pointer into the string.
 */
char *
gvm_strip_space (char *string, char *end)
{
  assert (string <= end);
  if (string >= end)
    return string;
  end--;
  while (string[0] == ' ' || string[0] == '\n')
    {
      string++;
      if (string >= end)
        {
          end[0] = '\0';
          return end;
        }
    }

  /* Here string is < end. */
  if (end[0] == ' ' || end[0] == '\n')
    {
      end--;
      while (end >= string && (end[0] == ' ' || end[0] == '\n'))
        {
          end--;
        }
      end[1] = '\0';
    }
  return string;
}
