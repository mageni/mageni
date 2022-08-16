/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2009-2019 Greenbone Networks GmbH
 * SPDX-FileComment: UUID creation.
 * SPDX-FileContributor: Mageni Security LLC
 * 
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
