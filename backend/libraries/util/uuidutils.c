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
 * @brief UUID creation.
 */

#include "uuidutils.h"

#include <glib.h>
#include <stdlib.h>
#include <uuid/uuid.h>

/**
 * @brief Make a new universal identifier.
 *
 * @return A newly allocated string holding the identifier, which the
 *         caller must free, or NULL on failure.
 */
char *
gvm_uuid_make (void)
{
  char *id;
  uuid_t uuid;

  /* Generate an UUID. */
  uuid_generate (uuid);
  if (uuid_is_null (uuid) == 1)
    {
      g_warning ("%s: failed to generate UUID", __FUNCTION__);
      return NULL;
    }

  /* Allocate mem for string to hold UUID. */
  id = g_malloc0 (sizeof (char) * 37);
  if (id == NULL)
    {
      g_warning ("%s: Cannot export UUID to text: out of memory", __FUNCTION__);
      return NULL;
    }

  /* Export the UUID to text. */
  uuid_unparse (uuid, id);

  return id;
}
