/* GVM
 * $Id$
 * Description: GVM GMP layer: Headers used internally.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2018 Greenbone Networks GmbH
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

#ifndef _GVMD_GMP_BASE_H
#define _GVMD_GMP_BASE_H

#include <glib.h>

/**
 * @brief A handle on a GMP parser.
 */
typedef struct
{
  int (*client_writer) (const char *, void *); ///< Writes to the client.
  void *client_writer_data;                    ///< Argument to client_writer.
  int importing;             ///< Whether the current op is importing.
  int read_over;             ///< Read over any child elements.
  int parent_state;          ///< Parent state when reading over.
  gchar **disabled_commands; ///< Disabled commands.
} gmp_parser_t;

int
find_attribute (const gchar **, const gchar **, const char *, const gchar **);

int
append_attribute (const gchar **, const gchar **, const char *, gchar **);

void
buffer_xml_append_printf (GString *, const char *, ...);

gboolean
send_to_client (const char *, int (*) (const char *, void *), void *);

gboolean
send_element_error_to_client (const char *,
                              const char *,
                              int (*) (const char *, void *),
                              void *);

gboolean
send_find_error_to_client (const char *,
                           const char *,
                           const char *,
                           gmp_parser_t *);

void
error_send_to_client (GError **);

void
internal_error_send_to_client (GError **);

/**
 * @brief Send response message to client, returning on fail.
 *
 * Queue a message in \ref to_client with \ref send_to_client.  On failure
 * call \ref error_send_to_client on a GError* called "error" and do a return.
 *
 * @param[in]   format    Format string for message.
 * @param[in]   args      Arguments for format string.
 */
#define SENDF_TO_CLIENT_OR_FAIL(format, args...)                             \
  do                                                                         \
    {                                                                        \
      gchar *msg = g_markup_printf_escaped (format, ##args);                 \
      if (send_to_client (                                                   \
            msg, gmp_parser->client_writer, gmp_parser->client_writer_data)) \
        {                                                                    \
          g_free (msg);                                                      \
          error_send_to_client (error);                                      \
          return;                                                            \
        }                                                                    \
      g_free (msg);                                                          \
    }                                                                        \
  while (0)

/**
 * @brief Send response message to client, returning on fail.
 *
 * Queue a message in \ref to_client with \ref send_to_client.  On failure
 * call \ref error_send_to_client on a GError* called "error" and do a return.
 *
 * @param[in]   msg    The message, a string.
 */
#define SEND_TO_CLIENT_OR_FAIL(msg)                                          \
  do                                                                         \
    {                                                                        \
      if (send_to_client (                                                   \
            msg, gmp_parser->client_writer, gmp_parser->client_writer_data)) \
        {                                                                    \
          error_send_to_client (error);                                      \
          return;                                                            \
        }                                                                    \
    }                                                                        \
  while (0)

void
log_event (const char *, const char *, const char *, const char *);

void
log_event_fail (const char *, const char *, const char *, const char *);

/* Status codes. */

/* HTTP status codes used:
 *
 *     200 OK
 *     201 Created
 *     202 Accepted
 *     400 Bad request
 *     401 Must auth
 *     404 Missing
 */

/**
 * @brief Response code for a syntax error.
 */
#define STATUS_ERROR_SYNTAX "400"

/**
 * @brief Response code when authorisation is required.
 */
#define STATUS_ERROR_MUST_AUTH "401"

/**
 * @brief Response code when authorisation is required.
 */
#define STATUS_ERROR_MUST_AUTH_TEXT "Authenticate first"

/**
 * @brief Response code for forbidden access.
 */
#define STATUS_ERROR_ACCESS "403"

/**
 * @brief Response code text for forbidden access.
 */
#define STATUS_ERROR_ACCESS_TEXT "Access to resource forbidden"

/**
 * @brief Response code for a missing resource.
 */
#define STATUS_ERROR_MISSING "404"

/**
 * @brief Response code text for a missing resource.
 */
#define STATUS_ERROR_MISSING_TEXT "Resource missing"

/**
 * @brief Response code for a busy resource.
 */
#define STATUS_ERROR_BUSY "409"

/**
 * @brief Response code text for a busy resource.
 */
#define STATUS_ERROR_BUSY_TEXT "Resource busy"

/**
 * @brief Response code when authorisation failed.
 */
#define STATUS_ERROR_AUTH_FAILED "400"

/**
 * @brief Response code text when authorisation failed.
 */
#define STATUS_ERROR_AUTH_FAILED_TEXT "Authentication failed"

/**
 * @brief Response code on success.
 */
#define STATUS_OK "200"

/**
 * @brief Response code text on success.
 */
#define STATUS_OK_TEXT "OK"

/**
 * @brief Response code on success, when a resource is created.
 */
#define STATUS_OK_CREATED "201"

/**
 * @brief Response code on success, when a resource is created.
 */
#define STATUS_OK_CREATED_TEXT "OK, resource created"

/**
 * @brief Response code on success, when the operation will finish later.
 */
#define STATUS_OK_REQUESTED "202"

/**
 * @brief Response code text on success, when the operation will finish later.
 */
#define STATUS_OK_REQUESTED_TEXT "OK, request submitted"

/**
 * @brief Response code for an internal error.
 */
#define STATUS_INTERNAL_ERROR "500"

/**
 * @brief Response code text for an internal error.
 */
#define STATUS_INTERNAL_ERROR_TEXT "Internal error"

/**
 * @brief Response code when a service is unavailable.
 */
#define STATUS_SERVICE_UNAVAILABLE "503"

/**
 * @brief Response code when a service is down.
 */
#define STATUS_SERVICE_DOWN "503"

/**
 * @brief Response code text when a service is down.
 */
#define STATUS_SERVICE_DOWN_TEXT "Service temporarily down"

/**
 * @brief Expand to XML for a STATUS_ERROR_SYNTAX response.
 *
 * @param  tag   Name of the command generating the response.
 * @param  text  Text for the status_text attribute of the response.
 */
#define XML_ERROR_SYNTAX(tag, text)     \
  "<" tag "_response"                   \
  " status=\"" STATUS_ERROR_SYNTAX "\"" \
  " status_text=\"" text "\"/>"

/**
 * @brief Expand to XML for a STATUS_ERROR_ACCESS response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_ERROR_ACCESS(tag)           \
  "<" tag "_response"                   \
  " status=\"" STATUS_ERROR_ACCESS "\"" \
  " status_text=\"" STATUS_ERROR_ACCESS_TEXT "\"/>"

/**
 * @brief Expand to XML for a STATUS_SERVICE_UNAVAILABLE response.
 *
 * @param  tag   Name of the command generating the response.
 * @param  text  Status text.
 */
#define XML_ERROR_UNAVAILABLE(tag, text)       \
  "<" tag "_response"                          \
  " status=\"" STATUS_SERVICE_UNAVAILABLE "\"" \
  " status_text=\"" text "\"/>"

/**
 * @brief Expand to XML for a STATUS_ERROR_MISSING response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_ERROR_MISSING(tag)           \
  "<" tag "_response"                    \
  " status=\"" STATUS_ERROR_MISSING "\"" \
  " status_text=\"" STATUS_ERROR_MISSING_TEXT "\"/>"

/**
 * @brief Expand to XML for a STATUS_ERROR_AUTH_FAILED response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_ERROR_AUTH_FAILED(tag)           \
  "<" tag "_response"                        \
  " status=\"" STATUS_ERROR_AUTH_FAILED "\"" \
  " status_text=\"" STATUS_ERROR_AUTH_FAILED_TEXT "\"/>"

/**
 * @brief Expand to XML for a STATUS_ERROR_BUSY response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_ERROR_BUSY(tag)           \
  "<" tag "_response"                 \
  " status=\"" STATUS_ERROR_BUSY "\"" \
  " status_text=\"" STATUS_ERROR_BUSY_TEXT "\"/>"

/**
 * @brief Expand to XML for a STATUS_OK response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_OK(tag)           \
  "<" tag "_response"         \
  " status=\"" STATUS_OK "\"" \
  " status_text=\"" STATUS_OK_TEXT "\"/>"

/**
 * @brief Expand to XML for a STATUS_OK_CREATED response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_OK_CREATED(tag)           \
  "<" tag "_response"                 \
  " status=\"" STATUS_OK_CREATED "\"" \
  " status_text=\"" STATUS_OK_CREATED_TEXT "\"/>"

/**
 * @brief Expand to XML for a STATUS_OK_CREATED response with %s for ID.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_OK_CREATED_ID(tag)                  \
  "<" tag "_response"                           \
  " status=\"" STATUS_OK_CREATED "\""           \
  " status_text=\"" STATUS_OK_CREATED_TEXT "\"" \
  " id=\"%s\"/>"

/**
 * @brief Expand to XML for a STATUS_OK_REQUESTED response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_OK_REQUESTED(tag)           \
  "<" tag "_response"                   \
  " status=\"" STATUS_OK_REQUESTED "\"" \
  " status_text=\"" STATUS_OK_REQUESTED_TEXT "\"/>"

/**
 * @brief Expand to XML for a STATUS_INTERNAL_ERROR response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_INTERNAL_ERROR(tag)           \
  "<" tag "_response"                     \
  " status=\"" STATUS_INTERNAL_ERROR "\"" \
  " status_text=\"" STATUS_INTERNAL_ERROR_TEXT "\"/>"

/**
 * @brief Sends XML for a STATUS_SERVICE_DOWN response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define SEND_XML_SERVICE_DOWN(tag)                                             \
  do                                                                           \
    {                                                                          \
      char *str;                                                               \
      if (scanner_current_loading && scanner_total_loading)                    \
        str = g_strdup_printf ("<%s_response status='%s' "                     \
                               "status_text='Scanner loading KBs (%d/%d)'/>", \
                               tag,                                            \
                               STATUS_SERVICE_DOWN,                            \
                               scanner_current_loading,                        \
                               scanner_total_loading);                         \
      else                                                                     \
        str = g_strdup_printf ("<%s_response status='%s' status_text='%s'/>",  \
                               tag,                                            \
                               STATUS_SERVICE_DOWN,                            \
                               STATUS_SERVICE_DOWN_TEXT);                      \
      SEND_TO_CLIENT_OR_FAIL (str);                                            \
      g_free (str);                                                            \
    }                                                                          \
  while (0);

#endif /* not _GVMD_GMP_BASE_H */
