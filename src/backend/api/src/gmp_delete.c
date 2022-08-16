/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2018 Greenbone Networks GmbH
 * SPDX-FileComment: Base facilities.
 * SPDX-FileContributor: Matthew Mundell <matthew.mundell@greenbone.net>
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */


#include "gmp_delete.h"

#include "gmp_base.h"
#include "manage_sql.h"

#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/**
 * @brief Command data for DELETE command.
 */
typedef struct
{
  char *id;            ///< ID of resource to delete.
  gchar *type;         ///< Type of resource.
  gchar *type_capital; ///< Type of resource, as a capital.
  gchar *command;      ///< Command name.
  int ultimate;        ///< Boolean.  Whether to remove entirely or to trashcan.
} delete_t;

/**
 * @brief Parser callback data for DELETE command.
 */
static delete_t delete;

/**
 * @brief Reset command data.
 */
static void
delete_reset ()
{
  free (delete.id);
  g_free (delete.type);
  g_free (delete.type_capital);
  g_free (delete.command);

  memset (&delete, 0, sizeof (delete_t));
}

/**
 * @brief Handle start element.
 *
 * @param[in]  type              Resource type.
 * @param[in]  type_capital      Resource type, capitalised.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
delete_start (const gchar *type,
              const gchar *type_capital,
              const gchar **attribute_names,
              const gchar **attribute_values)
{
  const gchar *attribute;
  gchar *id_name, *command;

  id_name = g_strdup_printf ("%s_id", type);
  append_attribute (attribute_names, attribute_values, id_name, &delete.id);
  g_free (id_name);

  if (find_attribute (
        attribute_names, attribute_values, "ultimate", &attribute))
    delete.ultimate = strcmp (attribute, "0");
  else
    delete.ultimate = 0;

  delete.type = g_strdup (type);
  delete.type_capital = g_strdup (type_capital);
  command = g_strdup_printf ("DELETE_%s", type);
  delete.command = g_ascii_strup (command, -1);
  g_free (command);
}

/**
 * @brief Handle end element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
void
delete_run (gmp_parser_t *gmp_parser, GError **error)
{
  if (delete.id == NULL)
    {
      SENDF_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("%s", "DELETE command requires an id attribute"),
        delete.command);
      delete_reset ();
      return;
    }

  switch (delete_resource (delete.type, delete.id, delete.ultimate))
    {
    case 0:
      SENDF_TO_CLIENT_OR_FAIL (XML_OK ("%s"), delete.command);
      log_event (delete.type, delete.type_capital, delete.id, "deleted");
      break;
    case 1:
      SENDF_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("%s", "Resource is in use"),
                               delete.command);
      log_event_fail (delete.type, delete.type_capital, delete.id, "deleted");
      break;
    case 2:
      if (send_find_error_to_client (
            delete.command, delete.type, delete.id, gmp_parser))
        {
          error_send_to_client (error);
          return;
        }
      log_event_fail (delete.type, delete.type_capital, delete.id, "deleted");
      break;
    case 3:
      SENDF_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("%s", "Attempt to delete a predefined resource"),
        delete.command);
      break;
    case 99:
      SENDF_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("%s", "Permission denied"),
                               delete.command);
      log_event_fail (delete.type, delete.type_capital, delete.id, "deleted");
      break;
    default:
      SENDF_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("%s"), delete.command);
      log_event_fail (delete.type, delete.type_capital, delete.id, "deleted");
    }
  delete_reset ();
}
