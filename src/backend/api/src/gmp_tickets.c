/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2018 Greenbone Networks GmbH
 * SPDX-FileComment: Base facilities.
 * SPDX-FileContributor: Matthew Mundell <matthew.mundell@greenbone.net>
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#include "gmp_tickets.h"

#include "gmp_base.h"
#include "gmp_get.h"
#include "manage_tickets.h"

#include <glib.h>
#include "../../libraries/util/xmlutils.h"
#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/* GET_TICKETS. */

/**
 * @brief The get_tickets command.
 */
typedef struct
{
  get_data_t get; ///< Get args.
} get_tickets_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static get_tickets_t get_tickets_data;

/**
 * @brief Reset command data.
 */
static void
get_tickets_reset ()
{
  get_data_reset (&get_tickets_data.get);
  memset (&get_tickets_data, 0, sizeof (get_tickets_t));
}

/**
 * @brief Handle command start element.
 *
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
get_tickets_start (const gchar **attribute_names,
                   const gchar **attribute_values)
{
  get_data_parse_attributes (
    &get_tickets_data.get, "ticket", attribute_names, attribute_values);
}

/**
 * @brief Handle end element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
void
get_tickets_run (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t tickets;
  int count, filtered, ret, first;

  count = 0;

  ret = init_get ("get_tickets", &get_tickets_data.get, "Tickets", &first);
  if (ret)
    {
      switch (ret)
        {
        case 99:
          SEND_TO_CLIENT_OR_FAIL (
            XML_ERROR_SYNTAX ("get_tickets", "Permission denied"));
          break;
        default:
          internal_error_send_to_client (error);
          get_tickets_reset ();
          return;
        }
      get_tickets_reset ();
      return;
    }

  /* Setup the iterator. */

  ret = init_ticket_iterator (&tickets, &get_tickets_data.get);
  if (ret)
    {
      switch (ret)
        {
        case 1:
          if (send_find_error_to_client (
                "get_tickets", "ticket", get_tickets_data.get.id, gmp_parser))
            {
              error_send_to_client (error);
              get_tickets_reset ();
              return;
            }
          break;
        case 2:
          if (send_find_error_to_client ("get_tickets",
                                         "filter",
                                         get_tickets_data.get.filt_id,
                                         gmp_parser))
            {
              error_send_to_client (error);
              get_tickets_reset ();
              return;
            }
          break;
        case -1:
          SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_tickets"));
          break;
        }
      get_tickets_reset ();
      return;
    }

  /* Loop through tickets, sending XML. */

  SEND_GET_START ("ticket");
  while (1)
    {
      iterator_t results;
      int orphan;

      ret = get_next (
        &tickets, &get_tickets_data.get, &first, &count, init_ticket_iterator);
      if (ret == 1)
        break;
      if (ret == -1)
        {
          internal_error_send_to_client (error);
          get_tickets_reset ();
          return;
        }

      /* Send generic GET command elements. */

      SEND_GET_COMMON (ticket, &get_tickets_data.get, &tickets);

      /* Send ticket info. */

      SENDF_TO_CLIENT_OR_FAIL ("<assigned_to>"
                               "<user id=\"%s\">"
                               "<name>%s</name>"
                               "</user>"
                               "</assigned_to>"
                               "<severity>%1.1f</severity>"
                               "<host>%s</host>"
                               "<location>%s</location>"
                               "<solution_type>%s</solution_type>"
                               "<status>%s</status>"
                               "<open_time>%s</open_time>"
                               "<open_note>%s</open_note>"
                               "<nvt oid=\"%s\"/>",
                               ticket_iterator_user_id (&tickets),
                               ticket_iterator_user_name (&tickets),
                               ticket_iterator_severity (&tickets),
                               ticket_iterator_host (&tickets),
                               ticket_iterator_location (&tickets),
                               ticket_iterator_solution_type (&tickets),
                               ticket_iterator_status (&tickets),
                               ticket_iterator_open_time (&tickets),
                               ticket_iterator_open_note (&tickets),
                               ticket_iterator_nvt_oid (&tickets));

      if (ticket_iterator_task_id (&tickets))
        SENDF_TO_CLIENT_OR_FAIL (
          "<task id=\"%s\">"
          "<name>%s</name>"
          "<trash>%i</trash>"
          "</task>",
          ticket_iterator_task_id (&tickets),
          ticket_iterator_task_name (&tickets),
          task_in_trash_id (ticket_iterator_task_id (&tickets)));

      if (ticket_iterator_report_id (&tickets))
        {
          gchar *timestamp;

          if (report_timestamp (ticket_iterator_report_id (&tickets),
                                &timestamp))
            g_error ("%s: error getting timestamp of report, aborting",
                     __FUNCTION__);

          SENDF_TO_CLIENT_OR_FAIL ("<report id=\"%s\">"
                                   "<timestamp>%s</timestamp>"
                                   "</report>",
                                   ticket_iterator_report_id (&tickets),
                                   timestamp);
        }

      /* Send timestamps. */

      if (ticket_iterator_fixed_time (&tickets)
          && strlen (ticket_iterator_fixed_time (&tickets)))
        SENDF_TO_CLIENT_OR_FAIL ("<fixed_time>%s</fixed_time>",
                                 ticket_iterator_fixed_time (&tickets));

      if (ticket_iterator_fixed_note (&tickets))
        SENDF_TO_CLIENT_OR_FAIL ("<fixed_note>%s</fixed_note>",
                                 ticket_iterator_fixed_note (&tickets));

      if (ticket_iterator_closed_time (&tickets)
          && strlen (ticket_iterator_closed_time (&tickets)))
        SENDF_TO_CLIENT_OR_FAIL ("<closed_time>%s</closed_time>",
                                 ticket_iterator_closed_time (&tickets));

      if (ticket_iterator_closed_note (&tickets))
        SENDF_TO_CLIENT_OR_FAIL ("<closed_note>%s</closed_note>",
                                 ticket_iterator_closed_note (&tickets));

      if (ticket_iterator_fix_verified_time (&tickets)
          && strlen (ticket_iterator_fix_verified_time (&tickets)))
        {
          SENDF_TO_CLIENT_OR_FAIL (
            "<fix_verified_time>%s</fix_verified_time>",
            ticket_iterator_fix_verified_time (&tickets));
          if (ticket_iterator_fix_verified_report_id (&tickets))
            {
              gchar *timestamp;

              if (report_timestamp (
                    ticket_iterator_fix_verified_report_id (&tickets),
                    &timestamp))
                g_error ("%s: error getting timestamp of verified report,"
                         " aborting",
                         __FUNCTION__);

              SENDF_TO_CLIENT_OR_FAIL (
                "<fix_verified_report>"
                "<report id=\"%s\">"
                "<timestamp>%s</timestamp>"
                "</report>"
                "</fix_verified_report>",
                ticket_iterator_fix_verified_report_id (&tickets),
                timestamp);
            }
        }

      /* Send results that are linked to ticket. */

      if (init_ticket_result_iterator (
            &results, get_iterator_uuid (&tickets), get_tickets_data.get.trash))
        {
          internal_error_send_to_client (error);
          get_tickets_reset ();
          return;
        }
      orphan = 1;
      while (next (&results))
        {
          orphan = 0;
          SENDF_TO_CLIENT_OR_FAIL ("<result id=\"%s\"/>",
                                   ticket_result_iterator_result_id (&results));
        }
      cleanup_iterator (&results);

      SENDF_TO_CLIENT_OR_FAIL ("<orphan>%i</orphan>"
                               "</ticket>",
                               orphan);
      count++;
    }
  cleanup_iterator (&tickets);
  filtered = get_tickets_data.get.id ? 1 : ticket_count (&get_tickets_data.get);
  SEND_GET_END ("ticket", &get_tickets_data.get, count, filtered);

  get_tickets_reset ();
}

/* CREATE_TICKET. */

/**
 * @brief The create_ticket command.
 */
typedef struct
{
  context_data_t *context; ///< XML parser context.
} create_ticket_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static create_ticket_t create_ticket_data;

/**
 * @brief Reset command data.
 */
static void
create_ticket_reset ()
{
  if (create_ticket_data.context->first)
    {
      free_entity (create_ticket_data.context->first->data);
      g_slist_free_1 (create_ticket_data.context->first);
    }
  g_free (create_ticket_data.context);
  memset (&create_ticket_data, 0, sizeof (create_ticket_t));
}

/**
 * @brief Start a command.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
create_ticket_start (gmp_parser_t *gmp_parser,
                     const gchar **attribute_names,
                     const gchar **attribute_values)
{
  memset (&create_ticket_data, 0, sizeof (create_ticket_t));
  create_ticket_data.context = g_malloc0 (sizeof (context_data_t));
  create_ticket_element_start (
    gmp_parser, "create_ticket", attribute_names, attribute_values);
}

/**
 * @brief Start element.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  name              Element name.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
create_ticket_element_start (gmp_parser_t *gmp_parser,
                             const gchar *name,
                             const gchar **attribute_names,
                             const gchar **attribute_values)
{
  xml_handle_start_element (
    create_ticket_data.context, name, attribute_names, attribute_values);
}

/**
 * @brief Execute command.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
void
create_ticket_run (gmp_parser_t *gmp_parser, GError **error)
{
  entity_t entity, copy, comment, result, assigned_to, user, open_note;
  ticket_t new_ticket;
  const char *result_id, *user_id;

  entity = (entity_t) create_ticket_data.context->first->data;

  copy = entity_child (entity, "copy");

  if (copy)
    {
      /* Copy from an existing ticket and exit. */

      comment = entity_child (entity, "comment");
      switch (copy_ticket (
        comment ? entity_text (comment) : "", entity_text (copy), &new_ticket))
        {
        case 0:
          {
            char *uuid;
            uuid = ticket_uuid (new_ticket);
            SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_ticket"), uuid);
            log_event ("ticket", "Ticket", uuid, "created");
            free (uuid);
            break;
          }
        case 1:
          SEND_TO_CLIENT_OR_FAIL (
            XML_ERROR_SYNTAX ("create_ticket", "Ticket exists already"));
          log_event_fail ("ticket", "Ticket", NULL, "created");
          break;
        case 2:
          if (send_find_error_to_client (
                "create_ticket", "ticket", entity_text (copy), gmp_parser))
            {
              error_send_to_client (error);
              return;
            }
          log_event_fail ("ticket", "Ticket", NULL, "created");
          break;
        case 99:
          SEND_TO_CLIENT_OR_FAIL (
            XML_ERROR_SYNTAX ("create_ticket", "Permission denied"));
          log_event_fail ("ticket", "Ticket", NULL, "created");
          break;
        case -1:
        default:
          SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_ticket"));
          log_event_fail ("ticket", "Ticket", NULL, "created");
          break;
        }
      create_ticket_reset ();
      return;
    }

  /* Check given info. */

  comment = entity_child (entity, "comment");

  open_note = entity_child (entity, "open_note");
  if (open_note == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX (
        "create_ticket", "CREATE_TICKET requires an OPEN_NOTE"));
      create_ticket_reset ();
      return;
    }

  result = entity_child (entity, "result");
  if (result == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("create_ticket", "CREATE_TICKET requires a RESULT"));
      create_ticket_reset ();
      return;
    }

  assigned_to = entity_child (entity, "assigned_to");
  if (assigned_to == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX (
        "create_ticket", "CREATE_TICKET requires an ASSIGNED_TO element"));
      create_ticket_reset ();
      return;
    }

  user = entity_child (assigned_to, "user");
  if (user == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX (
        "create_ticket", "CREATE_TICKET requires USER in ASSIGNED_TO"));
      create_ticket_reset ();
      return;
    }

  /* Create ticket from given info. */

  result_id = entity_attribute (result, "id");
  user_id = entity_attribute (user, "id");

  if ((result_id == NULL) || (strlen (result_id) == 0))
    SEND_TO_CLIENT_OR_FAIL (
      XML_ERROR_SYNTAX ("create_ticket",
                        "CREATE_TICKET RESULT must have an id"
                        " attribute"));
  else if ((user_id == NULL) || (strlen (user_id) == 0))
    SEND_TO_CLIENT_OR_FAIL (
      XML_ERROR_SYNTAX ("create_ticket",
                        "CREATE_TICKET USER must have an id"
                        " attribute"));
  else if (strlen (entity_text (open_note)) == 0)
    SEND_TO_CLIENT_OR_FAIL (
      XML_ERROR_SYNTAX ("create_ticket", "CREATE_TICKET OPEN_NOTE is empty"));
  else
    switch (create_ticket (comment ? entity_text (comment) : "",
                           result_id,
                           user_id,
                           entity_text (open_note),
                           &new_ticket))
      {
      case 0:
        {
          char *uuid = ticket_uuid (new_ticket);
          SENDF_TO_CLIENT_OR_FAIL (XML_OK_CREATED_ID ("create_ticket"), uuid);
          log_event ("ticket", "Ticket", uuid, "created");
          free (uuid);
          break;
        }
      case 1:
        log_event_fail ("ticket", "Ticket", NULL, "created");
        if (send_find_error_to_client (
              "create_ticket", "user", user_id, gmp_parser))
          {
            error_send_to_client (error);
            return;
          }
        break;
      case 2:
        log_event_fail ("ticket", "Ticket", NULL, "created");
        if (send_find_error_to_client (
              "create_ticket", "result", result_id, gmp_parser))
          {
            error_send_to_client (error);
            return;
          }
        break;
      case 99:
        SEND_TO_CLIENT_OR_FAIL (
          XML_ERROR_SYNTAX ("create_ticket", "Permission denied"));
        log_event_fail ("ticket", "Ticket", NULL, "created");
        break;
      case -1:
      default:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("create_ticket"));
        log_event_fail ("ticket", "Ticket", NULL, "created");
        break;
      }

  create_ticket_reset ();
}

/**
 * @brief End element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 * @param[in]  name         Element name.
 *
 * @return 0 success, 1 command finished.
 */
int
create_ticket_element_end (gmp_parser_t *gmp_parser,
                           GError **error,
                           const gchar *name)
{
  xml_handle_end_element (create_ticket_data.context, name);
  if (create_ticket_data.context->done)
    {
      create_ticket_run (gmp_parser, error);
      return 1;
    }
  return 0;
}

/**
 * @brief Add text to element.
 *
 * @param[in]  text         Text.
 * @param[in]  text_len     Text length.
 */
void
create_ticket_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (create_ticket_data.context, text, text_len);
}

/* MODIFY_TICKET. */

/**
 * @brief The modify_ticket command.
 */
typedef struct
{
  context_data_t *context; ///< XML parser context.
} modify_ticket_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static modify_ticket_t modify_ticket_data;

/**
 * @brief Reset command data.
 */
static void
modify_ticket_reset ()
{
  if (modify_ticket_data.context->first)
    {
      free_entity (modify_ticket_data.context->first->data);
      g_slist_free_1 (modify_ticket_data.context->first);
    }
  g_free (modify_ticket_data.context);
  memset (&modify_ticket_data, 0, sizeof (modify_ticket_t));
}

/**
 * @brief Start a command.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
modify_ticket_start (gmp_parser_t *gmp_parser,
                     const gchar **attribute_names,
                     const gchar **attribute_values)
{
  memset (&modify_ticket_data, 0, sizeof (modify_ticket_t));
  modify_ticket_data.context = g_malloc0 (sizeof (context_data_t));
  modify_ticket_element_start (
    gmp_parser, "modify_ticket", attribute_names, attribute_values);
}

/**
 * @brief Start element.
 *
 * @param[in]  gmp_parser        GMP parser.
 * @param[in]  name              Element name.
 * @param[in]  attribute_names   All attribute names.
 * @param[in]  attribute_values  All attribute values.
 */
void
modify_ticket_element_start (gmp_parser_t *gmp_parser,
                             const gchar *name,
                             const gchar **attribute_names,
                             const gchar **attribute_values)
{
  xml_handle_start_element (
    modify_ticket_data.context, name, attribute_names, attribute_values);
}

/**
 * @brief Execute command.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 */
void
modify_ticket_run (gmp_parser_t *gmp_parser, GError **error)
{
  entity_t entity, comment, status, open_note, fixed_note, closed_note;
  entity_t assigned_to;
  const char *ticket_id, *user_id;

  entity = (entity_t) modify_ticket_data.context->first->data;

  ticket_id = entity_attribute (entity, "ticket_id");

  /* Check the given info. */

  comment = entity_child (entity, "comment");
  status = entity_child (entity, "status");
  open_note = entity_child (entity, "open_note");
  fixed_note = entity_child (entity, "fixed_note");
  closed_note = entity_child (entity, "closed_note");

  assigned_to = entity_child (entity, "assigned_to");
  if (assigned_to)
    {
      entity_t user;

      user = entity_child (assigned_to, "user");
      if (user == NULL)
        {
          SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX (
            "modify_ticket", "MODIFY_TICKET requires USER in ASSIGNED_TO"));
          modify_ticket_reset ();
          return;
        }

      user_id = entity_attribute (user, "id");
      if ((user_id == NULL) || (strlen (user_id) == 0))
        {
          SEND_TO_CLIENT_OR_FAIL (
            XML_ERROR_SYNTAX ("modify_ticket",
                              "MODIFY_TICKET USER must have an id"
                              " attribute"));
          modify_ticket_reset ();
          return;
        }
    }
  else
    user_id = NULL;

  /* Modify the ticket. */

  if (ticket_id == NULL)
    SEND_TO_CLIENT_OR_FAIL (
      XML_ERROR_SYNTAX ("modify_ticket",
                        "MODIFY_TICKET requires a ticket_id"
                        " attribute"));
  else
    switch (modify_ticket (ticket_id,
                           comment ? entity_text (comment) : NULL,
                           status ? entity_text (status) : NULL,
                           open_note ? entity_text (open_note) : NULL,
                           fixed_note ? entity_text (fixed_note) : NULL,
                           closed_note ? entity_text (closed_note) : NULL,
                           user_id))
      {
      case 0:
        SENDF_TO_CLIENT_OR_FAIL (XML_OK ("modify_ticket"));
        log_event ("ticket", "Ticket", ticket_id, "modified");
        break;
      case 1:
        SEND_TO_CLIENT_OR_FAIL (
          XML_ERROR_SYNTAX ("modify_ticket", "Ticket exists already"));
        log_event_fail ("ticket", "Ticket", ticket_id, "modified");
        break;
      case 2:
        log_event_fail ("ticket", "Ticket", ticket_id, "modified");
        if (send_find_error_to_client (
              "modify_ticket", "ticket", ticket_id, gmp_parser))
          {
            error_send_to_client (error);
            return;
          }
        break;
      case 3:
        log_event_fail ("ticket", "Ticket", ticket_id, "modified");
        if (send_find_error_to_client (
              "modify_ticket", "user", user_id, gmp_parser))
          {
            error_send_to_client (error);
            return;
          }
        break;
      case 4:
        SEND_TO_CLIENT_OR_FAIL (
          XML_ERROR_SYNTAX ("modify_ticket", "Error in status"));
        log_event_fail ("ticket", "Ticket", ticket_id, "modified");
        break;
      case 5:
        SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX (
          "modify_ticket", "Fixed STATUS requires a FIXED_NOTE"));
        log_event_fail ("ticket", "Ticket", ticket_id, "modified");
        break;
      case 6:
        SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX (
          "modify_ticket", "Closed STATUS requires a CLOSED_NOTE"));
        log_event_fail ("ticket", "Ticket", ticket_id, "modified");
        break;
      case 7:
        SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX (
          "modify_ticket", "Open STATUS requires an OPEN_NOTE"));
        log_event_fail ("ticket", "Ticket", ticket_id, "modified");
        break;
      case 99:
        SEND_TO_CLIENT_OR_FAIL (
          XML_ERROR_SYNTAX ("modify_ticket", "Permission denied"));
        log_event_fail ("ticket", "Ticket", ticket_id, "modified");
        break;
      case -1:
      default:
        SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_ticket"));
        log_event_fail ("ticket", "Ticket", ticket_id, "modified");
        break;
      }

  modify_ticket_reset ();
}

/**
 * @brief End element.
 *
 * @param[in]  gmp_parser   GMP parser.
 * @param[in]  error        Error parameter.
 * @param[in]  name         Element name.
 *
 * @return 0 success, 1 command finished.
 */
int
modify_ticket_element_end (gmp_parser_t *gmp_parser,
                           GError **error,
                           const gchar *name)
{
  xml_handle_end_element (modify_ticket_data.context, name);
  if (modify_ticket_data.context->done)
    {
      modify_ticket_run (gmp_parser, error);
      return 1;
    }
  return 0;
}

/**
 * @brief Add text to element.
 *
 * @param[in]  text         Text.
 * @param[in]  text_len     Text length.
 */
void
modify_ticket_element_text (const gchar *text, gsize text_len)
{
  xml_handle_text (modify_ticket_data.context, text, text_len);
}

/* Result ticket support. */

/**
 * @brief Buffer ticket XML for a result.
 *
 * @param[in]  buffer   Buffer.
 * @param[in]  result   Result.
 *
 * @return 0 success, -1 internal error.
 */
int
buffer_result_tickets_xml (GString *buffer, result_t result)
{
  iterator_t tickets;
  int ret;

  ret = init_result_ticket_iterator (&tickets, result);

  if (ret == 0)
    {
      buffer_xml_append_printf (buffer, "<tickets>");
      while (next (&tickets))
        buffer_xml_append_printf (buffer,
                                  "<ticket id=\"%s\"/>",
                                  result_ticket_iterator_ticket_id (&tickets));
      buffer_xml_append_printf (buffer, "</tickets>");
      cleanup_iterator (&tickets);
    }

  return ret;
}
