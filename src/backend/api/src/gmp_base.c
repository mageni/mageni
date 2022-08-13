// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Name: gmp_base.c
 * Brief: Base facilities.
 * 
 * GMP base facilities used by all modules, but not exported for users of the
 * GMP layer (i.e. gmpd.c).
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 * 
 * Copyright:
 * Copyright (C) 2018 Greenbone Networks GmbH
 * Copyright (C) 2022, Mageni Security LLC
 */

#include "gmp_base.h"

#include "manage.h"

#include "../../libraries/base/strings.h"
#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/**
 * @brief Find an attribute in a parser callback list of attributes.
 *
 * @param[in]   attribute_names   List of names.
 * @param[in]   attribute_values  List of values.
 * @param[in]   attribute_name    Name of sought attribute.
 * @param[out]  attribute_value   Attribute value return.
 *
 * @return 1 if found, else 0.
 */
int find_attribute (const gchar **attribute_names,
                const gchar **attribute_values,
                const char *attribute_name,
                const gchar **attribute_value)
{
  while (*attribute_names && *attribute_values)
    if (strcmp (*attribute_names, attribute_name))
      attribute_names++, attribute_values++;
    else
      {
        *attribute_value = *attribute_values;
        return 1;
      }
  return 0;
}

/**
 * @brief Find an attribute in a parser callback list of attributes and append
 * @brief it to a string using gvm_append_string.
 *
 * @param[in]   attribute_names   List of names.
 * @param[in]   attribute_values  List of values.
 * @param[in]   attribute_name    Name of sought attribute.
 * @param[out]  string            String to append attribute value to, if
 *                                found.
 *
 * @return 1 if found and appended, else 0.
 */
int
append_attribute (const gchar **attribute_names,
                  const gchar **attribute_values,
                  const char *attribute_name,
                  gchar **string)
{
  const gchar *attribute;
  if (find_attribute (
        attribute_names, attribute_values, attribute_name, &attribute))
    {
      gvm_append_string (string, attribute);
      return 1;
    }
  return 0;
}

/**
 * @brief Format XML into a buffer.
 *
 * @param[in]  buffer  Buffer.
 * @param[in]  format  Format string for XML.
 * @param[in]  ...     Arguments for format string.
 */
void
buffer_xml_append_printf (GString *buffer, const char *format, ...)
{
  va_list args;
  gchar *msg;
  va_start (args, format);
  msg = g_markup_vprintf_escaped (format, args);
  va_end (args);
  g_string_append (buffer, msg);
  g_free (msg);
}

/* Communication. */

/**
 * @brief Send a response message to the client.
 *
 * @param[in]  msg                       The message, a string.
 * @param[in]  user_send_to_client       Function to send to client.
 * @param[in]  user_send_to_client_data  Argument to \p user_send_to_client.
 *
 * @return TRUE if send to client failed, else FALSE.
 */
gboolean
send_to_client (const char *msg,
                int (*user_send_to_client) (const char *, void *),
                void *user_send_to_client_data)
{
  if (user_send_to_client && msg)
    return user_send_to_client (msg, user_send_to_client_data);
  return FALSE;
}

/**
 * @brief Send an XML element error response message to the client.
 *
 * @param[in]  command  Command name.
 * @param[in]  element  Element name.
 * @param[in]  write_to_client       Function to write to client.
 * @param[in]  write_to_client_data  Argument to \p write_to_client.
 *
 * @return TRUE if out of space in to_client, else FALSE.
 */
gboolean
send_element_error_to_client (const char *command,
                              const char *element,
                              int (*write_to_client) (const char *, void *),
                              void *write_to_client_data)
{
  gchar *msg;
  gboolean ret;

  /** @todo Set gerror so parsing terminates. */
  msg = g_strdup_printf ("<%s_response status=\"" STATUS_ERROR_SYNTAX
                         "\" status_text=\"Bogus element: %s\"/>",
                         command,
                         element);
  ret = send_to_client (msg, write_to_client, write_to_client_data);
  g_free (msg);
  return ret;
}

/**
 * @brief Send an XML find error response message to the client.
 *
 * @param[in]  command      Command name.
 * @param[in]  type         Resource type.
 * @param[in]  id           Resource ID.
 * @param[in]  gmp_parser   GMP Parser.
 *
 * @return TRUE if out of space in to_client, else FALSE.
 */
gboolean
send_find_error_to_client (const char *command,
                           const char *type,
                           const char *id,
                           gmp_parser_t *gmp_parser)
{
  gchar *msg;
  gboolean ret;

  msg = g_strdup_printf ("<%s_response status=\"" STATUS_ERROR_MISSING
                         "\" status_text=\"Failed to find %s '%s'\"/>",
                         command,
                         type,
                         id);
  ret = send_to_client (
    msg, gmp_parser->client_writer, gmp_parser->client_writer_data);
  g_free (msg);
  return ret;
}

/**
 * @brief Set an out of space parse error on a GError.
 *
 * @param [out]  error  The error.
 */
void
error_send_to_client (GError **error)
{
  g_debug ("   send_to_client out of space in to_client");
  g_set_error (error,
               G_MARKUP_ERROR,
               G_MARKUP_ERROR_PARSE,
               "Manager out of space for reply to client.");
}

/**
 * @brief Set an internal error on a GError.
 *
 * @param [out]  error  The error.
 */
void
internal_error_send_to_client (GError **error)
{
  g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_PARSE, "Internal Error.");
}

/**
 * @brief Creates a log event entry for a resource action.
 *
 * @param[in]   type        Resource type.
 * @param[in]   type_name   Resource type name.
 * @param[in]   id          Resource id.
 * @param[in]   action      Action done.
 * @param[in]   fail        Whether it is a fail event.
 */
static void
log_event_internal (const char *type,
                    const char *type_name,
                    const char *id,
                    const char *action,
                    int fail)
{
  gchar *domain;

  domain = g_strdup_printf ("event %s", type);

  if (id)
    {
      char *name;

      if (manage_resource_name (type, id, &name))
        name = NULL;
      else if ((name == NULL) && manage_trash_resource_name (type, id, &name))
        name = NULL;

      if (name)
        g_log (domain,
               G_LOG_LEVEL_MESSAGE,
               "%s %s (%s) %s %s by %s",
               type_name,
               name,
               id,
               fail ? "could not be" : "has been",
               action,
               current_credentials.username);
      else
        g_log (domain,
               G_LOG_LEVEL_MESSAGE,
               "%s %s %s %s by %s",
               type_name,
               id,
               fail ? "could not be" : "has been",
               action,
               current_credentials.username);

      free (name);
    }
  else
    g_log (domain,
           G_LOG_LEVEL_MESSAGE,
           "%s %s %s by %s",
           type_name,
           fail ? "could not be" : "has been",
           action,
           current_credentials.username);

  g_free (domain);
}

/**
 * @brief Creates a log event entry for a resource action.
 *
 * @param[in]   type        Resource type.
 * @param[in]   type_name   Resource type name.
 * @param[in]   id          Resource id.
 * @param[in]   action      Action done.
 */
void
log_event (const char *type,
           const char *type_name,
           const char *id,
           const char *action)
{
  log_event_internal (type, type_name, id, action, 0);
}

/**
 * @brief Creates a log event failure entry for a resource action.
 *
 * @param[in]   type        Resource type.
 * @param[in]   type_name   Resource type name.
 * @param[in]   id          Resource id.
 * @param[in]   action      Action done.
 */
void log_event_fail (const char *type,
                const char *type_name,
                const char *id,
                const char *action)
{
  log_event_internal (type, type_name, id, action, 1);
}
