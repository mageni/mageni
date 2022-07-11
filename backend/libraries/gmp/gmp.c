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
 * @brief API for Greenbone Management Protocol communication.
 *
 * This provides higher level, GMP-aware, facilities for working with with
 * the Greenbone Vulnerability Manager.
 *
 * There are examples of using this interface in the gvm tests.
 */

#include "gmp.h"

#include "../util/serverutils.h" /* for gvm_server_sendf, gvm_server_sendf_xml */

#include <errno.h>  /* for ERANGE, errno */
#include <stdlib.h> /* for NULL, strtol, atoi */
#include <string.h> /* for strlen, strdup */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "lib   gmp"

#define GMP_FMT_BOOL_ATTRIB(var, attrib) \
  (var.attrib == 0 ? " " #attrib "=\"0\"" : " " #attrib "=\"1\"")

#define GMP_FMT_STRING_ATTRIB(var, attrib)                                \
  (var.attrib ? " " #attrib "= \"" : ""), (var.attrib ? var.attrib : ""), \
    (var.attrib ? "\"" : "")

/* GMP. */

/**
 * @brief Get the task status from a GMP GET_TASKS response.
 *
 * @param[in]  response   GET_TASKS response.
 *
 * @return The entity_text of the status entity if the entity is found, else
 *         NULL.
 */
const char *
gmp_task_status (entity_t response)
{
  entity_t task = entity_child (response, "task");
  if (task)
    {
      entity_t status = entity_child (task, "status");
      if (status)
        return entity_text (status);
    }
  return NULL;
}

/**
 * @brief Read response and convert status of response to a return value.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  entity   Entity containing response.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_check_response (gnutls_session_t *session, entity_t *entity)
{
  int ret;
  const char *status;

  /* Read the response. */

  *entity = NULL;
  if (read_entity (session, entity))
    return -1;

  /* Check the response. */

  status = entity_attribute (*entity, "status");
  if (status == NULL)
    {
      free_entity (*entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (*entity);
      return -1;
    }
  if (status[0] == '2')
    {
      return 0;
    }
  ret = (int) strtol (status, NULL, 10);
  free_entity (*entity);
  if (errno == ERANGE)
    return -1;
  return ret;
}

/**
 * @brief "Ping" the manager.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  timeout   Server idle time before giving up, in milliseconds.  0
 *                       to wait forever.
 *
 * @return 0 on success, 1 if manager closed connection, 2 on timeout,
 *         -1 on error.
 */
int
gmp_ping (gnutls_session_t *session, int timeout)
{
  entity_t entity;
  const char *status;
  char first;
  int ret;

  /* Send a GET_VERSION request. */

  ret = gvm_server_sendf (session, "<get_version/>");
  if (ret)
    return ret;

  /* Read the response, with a timeout. */

  entity = NULL;
  switch (try_read_entity (session, timeout, &entity))
    {
    case 0:
      break;
    case -4:
      return 2;
    default:
      return -1;
    }

  /* Check the response. */

  status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }
  first = status[0];
  free_entity (entity);
  if (first == '2')
    return 0;
  return -1;
}

/**
 * @brief "Ping" the manager.
 *
 * @param[in]  connection  Pointer to GNUTLS session.
 * @param[in]  timeout  Server idle time before giving up, in milliseconds.  0
 *                      to wait forever.
 * @param[out] version  Return location for freshly allocated version if
 *                      required, else NULL.
 *
 * @return 0 on success, 1 if manager closed connection, 2 on timeout,
 *         -1 on error.
 */
int
gmp_ping_c (gvm_connection_t *connection, int timeout, gchar **version)
{
  entity_t entity;
  const char *status;
  int ret;

  if (version && *version)
    *version = NULL;

  /* Send a GET_VERSION request. */

  ret = gvm_connection_sendf (connection, "<get_version/>");
  if (ret)
    return ret;

  /* Read the response, with a timeout. */

  entity = NULL;
  switch (try_read_entity_c (connection, timeout, &entity))
    {
    case 0:
      break;
    case -4:
      return 2;
    default:
      return -1;
    }

  /* Check the response. */

  status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }
  if (status[0] == '2')
    {
      if (version)
        {
          entity_t omp_version;
          omp_version = entity_child (entity, "version");
          if (omp_version == NULL)
            {
              free_entity (entity);
              return -1;
            }
          *version = strdup (entity_text (omp_version));
        }
      free_entity (entity);
      return 0;
    }
  free_entity (entity);
  return -1;
}

/**
 * @brief Authenticate with the manager.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  username  Username.
 * @param[in]  password  Password.
 *
 * @return 0 on success, 1 if manager closed connection, 2 if auth failed,
 *         -1 on error.
 */
int
gmp_authenticate (gnutls_session_t *session, const char *username,
                  const char *password)
{
  entity_t entity;
  int ret;

  /* Send the auth request. */
  ret = gvm_server_sendf_xml_quiet (session,
                                    "<authenticate><credentials>"
                                    "<username>%s</username>"
                                    "<password>%s</password>"
                                    "</credentials></authenticate>",
                                    username ? username : "",
                                    password ? password : "");
  if (ret)
    return ret;

  /* Read the response. */

  entity = NULL;
  ret = gmp_check_response (session, &entity);
  if (ret == 0)
    {
      free_entity (entity);
      return ret;
    }
  else if (ret == -1)
    return ret;
  return 2;
}

/**
 * @brief Authenticate with the manager.
 *
 * @param[in]  session    Pointer to GNUTLS session.
 * @param[in]  opts       Struct containing the options to apply.
 * @param[out] opts       Additional account information if authentication
 *                        was successful.
 *
 * @return 0 on success, 1 if manager closed connection, 2 if auth failed,
 *         3 on timeout, -1 on error.
 */
int
gmp_authenticate_info_ext (gnutls_session_t *session,
                           gmp_authenticate_info_opts_t opts)
{
  entity_t entity;
  const char *status;
  char first;
  int ret;

  *(opts.timezone) = NULL;

  /* Send the auth request. */

  ret = gvm_server_sendf_xml_quiet (session,
                                    "<authenticate><credentials>"
                                    "<username>%s</username>"
                                    "<password>%s</password>"
                                    "</credentials></authenticate>",
                                    opts.username, opts.password);
  if (ret)
    return ret;

  /* Read the response. */

  entity = NULL;
  switch (try_read_entity (session, opts.timeout, &entity))
    {
    case 0:
      break;
    case -4:
      return 3;
    default:
      return -1;
    }

  /* Check the response. */

  status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }
  first = status[0];
  if (first == '2')
    {
      entity_t timezone_entity, role_entity, severity_entity, pw_warn_entity;
      /* Get the extra info. */
      timezone_entity = entity_child (entity, "timezone");
      if (timezone_entity)
        *opts.timezone = g_strdup (entity_text (timezone_entity));
      role_entity = entity_child (entity, "role");
      if (role_entity)
        *opts.role = g_strdup (entity_text (role_entity));
      severity_entity = entity_child (entity, "severity");
      if (severity_entity)
        *opts.severity = g_strdup (entity_text (severity_entity));
      pw_warn_entity = entity_child (entity, "password_warning");
      if (pw_warn_entity)
        *(opts.pw_warning) = g_strdup (entity_text (pw_warn_entity));
      else
        *(opts.pw_warning) = NULL;

      free_entity (entity);
      return 0;
    }
  free_entity (entity);
  return 2;
}

/**
 * @brief Authenticate with the manager.
 *
 * @param[in]  connection  Connection
 * @param[in]  opts        Struct containing the options to apply.
 *
 * @return 0 on success, 1 if manager closed connection, 2 if auth failed,
 *         3 on timeout, -1 on error.
 */
int
gmp_authenticate_info_ext_c (gvm_connection_t *connection,
                             gmp_authenticate_info_opts_t opts)
{
  entity_t entity;
  const char *status;
  char first;
  int ret;

  if (opts.timezone)
    *(opts.timezone) = NULL;

  /* Send the auth request. */

  ret = gvm_connection_sendf_xml_quiet (connection,
                                        "<authenticate>"
                                        "<credentials>"
                                        "<username>%s</username>"
                                        "<password>%s</password>"
                                        "</credentials>"
                                        "</authenticate>",
                                        opts.username, opts.password);
  if (ret)
    return ret;

  /* Read the response. */

  entity = NULL;
  switch (try_read_entity_c (connection, opts.timeout, &entity))
    {
    case 0:
      break;
    case -4:
      return 3;
    default:
      return -1;
    }

  /* Check the response. */

  status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }
  first = status[0];
  if (first == '2')
    {
      entity_t timezone_entity, role_entity, severity_entity;
      /* Get the extra info. */
      timezone_entity = entity_child (entity, "timezone");
      if (timezone_entity && opts.timezone)
        *opts.timezone = g_strdup (entity_text (timezone_entity));
      role_entity = entity_child (entity, "role");
      if (role_entity && opts.role)
        *opts.role = g_strdup (entity_text (role_entity));
      severity_entity = entity_child (entity, "severity");
      if (severity_entity && opts.severity)
        *opts.severity = g_strdup (entity_text (severity_entity));
      if (opts.pw_warning)
        {
          entity_t pw_warn_entity;
          pw_warn_entity = entity_child (entity, "password_warning");
          if (pw_warn_entity)
            *(opts.pw_warning) = g_strdup (entity_text (pw_warn_entity));
          else
            *(opts.pw_warning) = NULL;
        }

      free_entity (entity);
      return 0;
    }
  free_entity (entity);
  return 2;
}

/**
 * @brief Create a task.
 *
 * FIXME: Using the according opts it should be possible to generate
 * any type of create_task request defined by the spec.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  opts      Struct containing the options to apply.
 * @param[out]  id       Pointer for newly allocated ID of new task, or NULL.
 *                       Only set on successful return.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_create_task_ext (gnutls_session_t *session, gmp_create_task_opts_t opts,
                     gchar **id)
{
  /* Create the GMP request. */

  gchar *prefs, *start, *hosts_ordering, *scanner, *schedule, *slave;
  GString *alerts, *observers;
  int ret;
  if ((opts.config_id == NULL) || (opts.target_id == NULL))
    return -1;

  prefs = NULL;
  start = g_markup_printf_escaped (
    "<create_task>"
    "<config id=\"%s\"/>"
    "<target id=\"%s\"/>"
    "<name>%s</name>"
    "<comment>%s</comment>"
    "<alterable>%d</alterable>",
    opts.config_id, opts.target_id, opts.name ? opts.name : "unnamed",
    opts.comment ? opts.comment : "", opts.alterable ? 1 : 0);

  if (opts.hosts_ordering)
    hosts_ordering = g_strdup_printf ("<hosts_ordering>%s</hosts_ordering>",
                                      opts.hosts_ordering);
  else
    hosts_ordering = NULL;

  if (opts.scanner_id)
    scanner = g_strdup_printf ("<scanner id=\"%s\"/>", opts.scanner_id);
  else
    scanner = NULL;

  if (opts.schedule_id)
    schedule = g_strdup_printf ("<schedule id=\"%s\"/>"
                                "<schedule_periods>%d</schedule_periods>",
                                opts.schedule_id, opts.schedule_periods);
  else
    schedule = NULL;

  if (opts.slave_id)
    slave = g_strdup_printf ("<slave id=\"%s\"/>", opts.slave_id);
  else
    slave = NULL;

  if (opts.max_checks || opts.max_hosts || opts.in_assets || opts.source_iface)
    {
      gchar *in_assets, *checks, *hosts, *source_iface;

      in_assets = checks = hosts = source_iface = NULL;

      if (opts.in_assets)
        in_assets = g_markup_printf_escaped ("<preference>"
                                             "<scanner_name>"
                                             "in_assets"
                                             "</scanner_name>"
                                             "<value>"
                                             "%s"
                                             "</value>"
                                             "</preference>",
                                             opts.in_assets);

      if (opts.max_hosts)
        hosts = g_markup_printf_escaped ("<preference>"
                                         "<scanner_name>"
                                         "max_hosts"
                                         "</scanner_name>"
                                         "<value>"
                                         "%s"
                                         "</value>"
                                         "</preference>",
                                         opts.max_hosts);

      if (opts.max_checks)
        checks = g_markup_printf_escaped ("<preference>"
                                          "<scanner_name>"
                                          "max_checks"
                                          "</scanner_name>"
                                          "<value>"
                                          "%s"
                                          "</value>"
                                          "</preference>",
                                          opts.max_checks);

      if (opts.source_iface)
        source_iface = g_markup_printf_escaped ("<preference>"
                                                "<scanner_name>"
                                                "source_iface"
                                                "</scanner_name>"
                                                "<value>"
                                                "%s"
                                                "</value>"
                                                "</preference>",
                                                opts.source_iface);

      prefs =
        g_strdup_printf ("<preferences>%s%s%s%s</preferences>",
                         in_assets ? in_assets : "", checks ? checks : "",
                         hosts ? hosts : "", source_iface ? source_iface : "");
      g_free (in_assets);
      g_free (checks);
      g_free (hosts);
      g_free (source_iface);
    }

  if (opts.alert_ids)
    {
      unsigned int i;
      alerts = g_string_new ("");
      for (i = 0; i < opts.alert_ids->len; i++)
        {
          char *alert = (char *) g_ptr_array_index (opts.alert_ids, i);
          g_string_append_printf (alerts, "<alert id=\"%s\"/>", alert);
        }
    }
  else
    alerts = g_string_new ("");

  if (opts.observers || opts.observer_groups)
    {
      observers = g_string_new ("<observers>");

      if (opts.observers)
        g_string_append (observers, opts.observers);

      if (opts.observer_groups)
        {
          unsigned int i;
          for (i = 0; i < opts.observer_groups->len; i++)
            {
              char *group =
                (char *) g_ptr_array_index (opts.observer_groups, i);
              g_string_append_printf (observers, "<group id=\"%s\"/>", group);
            }
        }
      g_string_append (observers, "</observers>");
    }
  else
    observers = g_string_new ("");

  /* Send the request. */
  ret = gvm_server_sendf (
    session, "%s%s%s%s%s%s%s%s</create_task>", start, prefs ? prefs : "",
    hosts_ordering ? hosts_ordering : "", scanner ? scanner : "",
    schedule ? schedule : "", slave ? slave : "", alerts ? alerts->str : "",
    observers ? observers->str : "");
  g_free (start);
  g_free (prefs);
  g_free (hosts_ordering);
  g_free (scanner);
  g_free (schedule);
  g_free (slave);
  g_string_free (alerts, TRUE);
  g_string_free (observers, TRUE);

  if (ret)
    return -1;

  /* Read the response. */

  ret = gmp_read_create_response (session, id);
  if (ret == 201)
    return 0;
  return ret;
}

/**
 * @brief Create a task given a config and target.
 *
 * @param[in]   session     Pointer to GNUTLS session.
 * @param[in]   name        Task name.
 * @param[in]   config      Task config name.
 * @param[in]   target      Task target name.
 * @param[in]   comment     Task comment.
 * @param[out]  id          Pointer for newly allocated ID of new task.  Only
 *                          set on successful return.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_create_task (gnutls_session_t *session, const char *name,
                 const char *config, const char *target, const char *comment,
                 gchar **id)
{
  int ret;

  ret = gvm_server_sendf_xml (session,
                              "<create_task>"
                              "<config id=\"%s\"/>"
                              "<target id=\"%s\"/>"
                              "<name>%s</name>"
                              "<comment>%s</comment>"
                              "</create_task>",
                              config, target, name, comment);
  if (ret)
    return -1;

  /* Read the response. */

  ret = gmp_read_create_response (session, id);
  if (ret == 201)
    return 0;
  return ret;
}

/**
 * @brief Start a task and read the manager response.
 *
 * @param[in]   session    Pointer to GNUTLS session.
 * @param[in]   task_id    ID of task.
 * @param[out]  report_id  ID of report.
 *
 * @return 0 on success, 1 on failure, -1 on error.
 */
int
gmp_start_task_report (gnutls_session_t *session, const char *task_id,
                       char **report_id)
{
  int ret;
  entity_t entity;
  if (gvm_server_sendf (session, "<start_task task_id=\"%s\"/>", task_id) == -1)
    return -1;

  /* Read the response. */

  entity = NULL;
  ret = gmp_check_response (session, &entity);

  if (ret == 0)
    {
      if (report_id)
        {
          entity_t report_id_xml = entity_child (entity, "report_id");
          if (report_id_xml)
            *report_id = g_strdup (entity_text (report_id_xml));
          else
            {
              free_entity (entity);
              return -1;
            }
        }
      free_entity (entity);
      return ret;
    }
  else if (ret == -1)
    return ret;

  return 1;
}

/**
 * @brief Start a task and read the manager response.
 *
 * @param[in]   connection  Connection.
 * @param[in]   task_id     ID of task.
 * @param[out]  report_id   ID of report.
 *
 * @return 0 on success, 1 on failure, -1 on error.
 */
int
gmp_start_task_report_c (gvm_connection_t *connection, const char *task_id,
                         char **report_id)
{
  entity_t entity;
  const char *status;
  char first;

  if (gvm_connection_sendf (connection, "<start_task task_id=\"%s\"/>", task_id)
      == -1)
    return -1;

  /* Read the response. */

  entity = NULL;
  if (read_entity_c (connection, &entity))
    return -1;

  /* Check the response. */

  status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }
  first = status[0];
  if (first == '2')
    {
      if (report_id)
        {
          entity_t report_id_xml = entity_child (entity, "report_id");
          if (report_id_xml)
            *report_id = g_strdup (entity_text (report_id_xml));
          else
            {
              free_entity (entity);
              return -1;
            }
        }
      free_entity (entity);
      return 0;
    }
  free_entity (entity);
  return 1;
}

/**
 * @brief Read response and convert status of response to a return value.
 *
 * @param[in]  connection  Connection.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_check_response_c (gvm_connection_t *connection)
{
  int ret;
  const char *status;
  entity_t entity;

  /* Read the response. */

  entity = NULL;
  if (read_entity_c (connection, &entity))
    return -1;

  /* Check the response. */

  status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }
  if (status[0] == '2')
    {
      free_entity (entity);
      return 0;
    }
  ret = (int) strtol (status, NULL, 10);
  free_entity (entity);
  if (errno == ERANGE)
    return -1;
  return ret;
}

/**
 * @brief Read response status and resource UUID.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[out] uuid     Either NULL or address for freshly allocated UUID of
 *                      created response.
 *
 * @return GMP response code on success, -1 on error.
 */
int
gmp_read_create_response (gnutls_session_t *session, gchar **uuid)
{
  int ret;
  const char *status;
  entity_t entity;

  /* Read the response. */

  entity = NULL;
  if (read_entity (session, &entity))
    return -1;

  /* Parse the response. */

  status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }

  if (uuid)
    {
      const char *id;

      id = entity_attribute (entity, "id");
      if (id == NULL)
        {
          free_entity (entity);
          return -1;
        }
      if (strlen (id) == 0)
        {
          free_entity (entity);
          return -1;
        }
      *uuid = g_strdup (id);
    }

  ret = atoi (status);
  free_entity (entity);
  return ret;
}

/**
 * @brief Stop a task and read the manager response.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  id       ID of task.
 *
 * @return 0 on success, GMP response code on failure, -1 on error.
 */
int
gmp_stop_task (gnutls_session_t *session, const char *id)
{
  entity_t entity;
  int ret;

  if (gvm_server_sendf (session, "<stop_task task_id=\"%s\"/>", id) == -1)
    return -1;

  entity = NULL;
  ret = gmp_check_response (session, &entity);
  if (ret == 0)
    free_entity (entity);
  return ret;
}

/**
 * @brief Stop a task and read the manager response.
 *
 * @param[in]  connection  Connection.
 * @param[in]  id       ID of task.
 *
 * @return 0 on success, GMP response code on failure, -1 on error.
 */
int
gmp_stop_task_c (gvm_connection_t *connection, const char *id)
{
  if (gvm_connection_sendf (connection, "<stop_task task_id=\"%s\"/>", id)
      == -1)
    return -1;

  return gmp_check_response_c (connection);
}

/**
 * @brief Resume a task and read the manager response.
 *
 * @param[in]   session    Pointer to GNUTLS session.
 * @param[in]   task_id    ID of task.
 * @param[out]  report_id  ID of report.
 *
 * @return 0 on success, 1 on GMP failure, -1 on error.
 */
int
gmp_resume_task_report (gnutls_session_t *session, const char *task_id,
                        char **report_id)
{
  int ret;
  entity_t entity;
  if (gvm_server_sendf (session, "<resume_task task_id=\"%s\"/>", task_id)
      == -1)
    return -1;

  /* Read the response. */

  entity = NULL;
  ret = gmp_check_response (session, &entity);

  if (ret == 0)
    {
      if (report_id)
        {
          entity_t report_id_xml = entity_child (entity, "report_id");
          if (report_id_xml)
            *report_id = g_strdup (entity_text (report_id_xml));
          else
            {
              free_entity (entity);
              return -1;
            }
        }
      free_entity (entity);
      return 0;
    }
  else if (ret == -1)
    return ret;
  return 1;
}

/**
 * @brief Resume a task and read the manager response.
 *
 * @param[in]   connection  Connection.
 * @param[in]   task_id     ID of task.
 * @param[out]  report_id   ID of report.
 *
 * @return 0 on success, 1 on GMP failure, -1 on error.
 */
int
gmp_resume_task_report_c (gvm_connection_t *connection, const char *task_id,
                          char **report_id)
{
  if (gvm_connection_sendf (connection, "<resume_task task_id=\"%s\"/>",
                            task_id)
      == -1)
    return -1;

  /* Read the response. */

  entity_t entity = NULL;
  if (read_entity_c (connection, &entity))
    return -1;

  /* Check the response. */

  const char *status = entity_attribute (entity, "status");
  if (status == NULL)
    {
      free_entity (entity);
      return -1;
    }
  if (strlen (status) == 0)
    {
      free_entity (entity);
      return -1;
    }
  char first = status[0];
  if (first == '2')
    {
      if (report_id)
        {
          entity_t report_id_xml = entity_child (entity, "report_id");
          if (report_id_xml)
            *report_id = g_strdup (entity_text (report_id_xml));
          else
            {
              free_entity (entity);
              return -1;
            }
        }
      free_entity (entity);
      return 0;
    }
  free_entity (entity);
  return 1;
}

/**
 * @brief Delete a task and read the manager response.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  id        ID of task.
 * @param[in]  opts      Struct containing the options to apply.
 *
 * @return 0 on success, GMP response code on failure, -1 on error.
 */
int
gmp_delete_task_ext (gnutls_session_t *session, const char *id,
                     gmp_delete_opts_t opts)
{
  entity_t entity;
  int ret;

  if (gvm_server_sendf (session,
                        "<delete_task task_id=\"%s\" ultimate=\"%d\"/>", id,
                        opts.ultimate)
      == -1)
    return -1;

  entity = NULL;
  ret = gmp_check_response (session, &entity);
  if (ret == 0)
    free_entity (entity);
  return ret;
}

/**
 * @brief Get the status of a task.
 *
 * @param[in]  session         Pointer to GNUTLS session.
 * @param[in]  id              ID of task or NULL for all tasks.
 * @param[in]  details         Whether to request task details.
 * @param[in]  include_rcfile  Ignored.  Removed since GMP 6.0.
 * @param[out] status          Status return.  On success contains GET_TASKS
 *                             response.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_get_tasks (gnutls_session_t *session, const char *id, int details,
               int include_rcfile, entity_t *status)
{
  (void) include_rcfile;
  if (id == NULL)
    {
      if (gvm_server_sendf (session, "<get_tasks details=\"%i\"/>", details)
          == -1)
        return -1;
    }
  else
    {
      if (gvm_server_sendf (session,
                            "<get_tasks"
                            " task_id=\"%s\""
                            " details=\"%i\"/>",
                            id, details)
          == -1)
        return -1;
    }

  /* Read the response. */
  return gmp_check_response (session, status);
}

/**
 * @brief Get a task (generic version).
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  opts      Struct containing the options to apply.
 * @param[out] response  Task.  On success contains GET_TASKS response.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_get_task_ext (gnutls_session_t *session, gmp_get_task_opts_t opts,
                  entity_t *response)
{
  if ((response == NULL) || (opts.task_id == NULL))
    return -1;

  if (opts.actions)
    {
      if (gvm_server_sendf (session,
                            "<get_tasks"
                            " task_id=\"%s\""
                            " actions=\"%s\""
                            "%s/>",
                            opts.task_id, opts.actions,
                            GMP_FMT_BOOL_ATTRIB (opts, details)))
        return -1;
    }
  else if (gvm_server_sendf (session,
                             "<get_tasks"
                             " task_id=\"%s\""
                             "%s/>",
                             opts.task_id, GMP_FMT_BOOL_ATTRIB (opts, details)))
    return -1;

  return gmp_check_response (session, response);
}

/**
 * @brief Get all tasks (generic version).
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  opts      Struct containing the options to apply.
 * @param[out] response  Tasks.  On success contains GET_TASKS response.
 *
 * @return 0 on success, 2 on timeout, -1 or GMP response code on error.
 */
int
gmp_get_tasks_ext (gnutls_session_t *session, gmp_get_tasks_opts_t opts,
                   entity_t *response)
{
  int ret;
  const char *status_code;
  gchar *cmd;

  if (response == NULL)
    return -1;

  cmd = g_markup_printf_escaped ("<get_tasks"
                                 " filter=\"%s\"",
                                 opts.filter);

  if (gvm_server_sendf (session, "%s%s/>", cmd,
                        GMP_FMT_BOOL_ATTRIB (opts, details)))
    {
      g_free (cmd);
      return -1;
    }
  g_free (cmd);

  *response = NULL;
  switch (try_read_entity (session, opts.timeout, response))
    {
    case 0:
      break;
    case -4:
      return 2;
    default:
      return -1;
    }

  /* Check the response. */

  status_code = entity_attribute (*response, "status");
  if (status_code == NULL)
    {
      free_entity (*response);
      return -1;
    }
  if (strlen (status_code) == 0)
    {
      free_entity (*response);
      return -1;
    }
  if (status_code[0] == '2')
    return 0;
  ret = (int) strtol (status_code, NULL, 10);
  free_entity (*response);
  if (errno == ERANGE)
    return -1;
  return ret;
}

/**
 * @brief Modify a file on a task.
 *
 * @param[in]  session      Pointer to GNUTLS session.
 * @param[in]  id           ID of task.
 * @param[in]  name         Name of file.
 * @param[in]  content      New content.  NULL to remove file.
 * @param[in]  content_len  Length of content.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_modify_task_file (gnutls_session_t *session, const char *id,
                      const char *name, const void *content, gsize content_len)
{
  entity_t entity;
  int ret;

  if (name == NULL)
    return -1;

  if (gvm_server_sendf (session, "<modify_task task_id=\"%s\">", id))
    return -1;

  if (content)
    {
      if (gvm_server_sendf (session, "<file name=\"%s\" action=\"update\">",
                            name))
        return -1;

      if (content_len)
        {
          gchar *base64_content =
            g_base64_encode ((guchar *) content, content_len);
          int ret = gvm_server_sendf (session, "%s", base64_content);
          g_free (base64_content);
          if (ret)
            return -1;
        }

      if (gvm_server_sendf (session, "</file>"))
        return -1;
    }
  else
    {
      if (gvm_server_sendf (session, "<file name=\"%s\" action=\"remove\" />",
                            name))
        return -1;
    }

  if (gvm_server_sendf (session, "</modify_task>"))
    return -1;

  entity = NULL;
  ret = gmp_check_response (session, &entity);
  if (ret == 0)
    free_entity (entity);
  return ret;
}

/**
 * @brief Delete a task and read the manager response.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  id       ID of task.
 *
 * @return 0 on success, GMP response code on failure, -1 on error.
 */
int
gmp_delete_task (gnutls_session_t *session, const char *id)
{
  entity_t entity;
  int ret;

  if (gvm_server_sendf (session, "<delete_task task_id=\"%s\"/>", id) == -1)
    return -1;

  entity = NULL;
  ret = gmp_check_response (session, &entity);
  if (ret == 0)
    free_entity (entity);
  return ret;
}

/**
 * @brief Get a target.
 *
 * @param[in]  session         Pointer to GNUTLS session.
 * @param[in]  id              ID of target or NULL for all targets.
 * @param[in]  tasks           Whether to include tasks that use the target.
 * @param[in]  include_rcfile  Not used.
 * @param[out] target          Target return.  On success contains GET_TARGETS
 *                             response.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_get_targets (gnutls_session_t *session, const char *id, int tasks,
                 int include_rcfile, entity_t *target)
{
  (void) include_rcfile;
  if (id == NULL)
    {
      if (gvm_server_sendf (session, "<get_targets tasks=\"%i\"/>", tasks)
          == -1)
        return -1;
    }
  else
    {
      if (gvm_server_sendf (session,
                            "<get_targets"
                            " target_id=\"%s\""
                            " tasks=\"%i\"/>",
                            id, tasks)
          == -1)
        return -1;
    }

  /* Read the response. */
  return gmp_check_response (session, target);
}

/**
 * @brief Get a report (generic version).
 *
 * FIXME: Using the according opts it should be possible to generate
 * any type of get_reports request defined by the spec.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  opts      Struct containing the options to apply.
 * @param[out] response  Report.  On success contains GET_REPORT response.
 *
 * @return 0 on success, 2 on timeout, -1 or GMP response code on error.
 */
int
gmp_get_report_ext (gnutls_session_t *session, gmp_get_report_opts_t opts,
                    entity_t *response)
{
  int ret;
  const char *status_code;

  if (response == NULL)
    return -1;

  if (gvm_server_sendf (
        session,
        "<get_reports"
        " report_id=\"%s\""
        " format_id=\"%s\""
        " host_first_result=\"%i\""
        " host_max_results=\"%i\""
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s"
        "%s%s%s%s%s%s%s/>",
        opts.report_id, opts.format_id, opts.host_first_result,
        opts.host_max_results, GMP_FMT_STRING_ATTRIB (opts, type),
        GMP_FMT_STRING_ATTRIB (opts, filter),
        GMP_FMT_STRING_ATTRIB (opts, filt_id),
        GMP_FMT_STRING_ATTRIB (opts, host), GMP_FMT_STRING_ATTRIB (opts, pos),
        GMP_FMT_STRING_ATTRIB (opts, timezone),
        GMP_FMT_STRING_ATTRIB (opts, alert_id),
        GMP_FMT_STRING_ATTRIB (opts, delta_report_id),
        GMP_FMT_STRING_ATTRIB (opts, delta_states),
        GMP_FMT_STRING_ATTRIB (opts, host_levels),
        GMP_FMT_STRING_ATTRIB (opts, search_phrase),
        GMP_FMT_STRING_ATTRIB (opts, host_search_phrase),
        GMP_FMT_STRING_ATTRIB (opts, min_cvss_base),
        GMP_FMT_STRING_ATTRIB (opts, min_qod),
        GMP_FMT_BOOL_ATTRIB (opts, notes),
        GMP_FMT_BOOL_ATTRIB (opts, notes_details),
        GMP_FMT_BOOL_ATTRIB (opts, overrides),
        GMP_FMT_BOOL_ATTRIB (opts, override_details),
        GMP_FMT_BOOL_ATTRIB (opts, apply_overrides),
        GMP_FMT_BOOL_ATTRIB (opts, result_hosts_only),
        GMP_FMT_BOOL_ATTRIB (opts, ignore_pagination)))
    return -1;

  *response = NULL;
  switch (try_read_entity (session, opts.timeout, response))
    {
    case 0:
      break;
    case -4:
      return 2;
    default:
      return -1;
    }

  /* Check the response. */

  status_code = entity_attribute (*response, "status");
  if (status_code == NULL)
    {
      free_entity (*response);
      return -1;
    }
  if (strlen (status_code) == 0)
    {
      free_entity (*response);
      return -1;
    }
  if (status_code[0] == '2')
    return 0;
  ret = (int) strtol (status_code, NULL, 10);
  free_entity (*response);
  if (errno == ERANGE)
    return -1;
  return ret;
}

/**
 * @brief Delete a port list.
 *
 * @param[in]   session     Pointer to GNUTLS session.
 * @param[in]   id          UUID of port list.
 * @param[in]   opts        Struct containing the options to apply.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_delete_port_list_ext (gnutls_session_t *session, const char *id,
                          gmp_delete_opts_t opts)
{
  entity_t entity;
  int ret;

  if (gvm_server_sendf (
        session, "<delete_port_list port_list_id=\"%s\" ultimate=\"%d\"/>", id,
        opts.ultimate)
      == -1)
    return -1;

  entity = NULL;
  ret = gmp_check_response (session, &entity);
  if (ret == 0)
    free_entity (entity);
  return ret;
}

/**
 * @brief Remove a report.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  id        ID of report.
 *
 * @return 0 on success, GMP response code on failure, -1 on error.
 */
int
gmp_delete_report (gnutls_session_t *session, const char *id)
{
  entity_t entity;
  int ret;

  if (gvm_server_sendf (session, "<delete_report report_id=\"%s\"/>", id))
    return -1;

  entity = NULL;
  ret = gmp_check_response (session, &entity);
  if (ret == 0)
    free_entity (entity);
  return ret;
}

/**
 * @brief Create a target.
 *
 * FIXME: Using the according opts it should be possible to generate
 * any type of create_target request defined by the spec.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  opts      Struct containing the options to apply.
 * @param[out] id        Pointer for newly allocated ID of new target, or NULL.
 *                       Only set on successful return.
 *
 * @return 0 on success (GMP 201), -2 on connection error, GMP response code on
 *         GMP error, -1 other error.
 */
int
gmp_create_target_ext (gnutls_session_t *session, gmp_create_target_opts_t opts,
                       gchar **id)
{
  gchar *comment, *ssh, *smb, *esxi, *snmp, *port_range, *start;
  gchar *exclude_hosts, *alive_tests;
  int ret;

  /* Create the GMP request. */

  if (opts.hosts == NULL)
    return -1;

  start =
    g_markup_printf_escaped ("<create_target>"
                             "<name>%s</name>"
                             "<hosts>%s</hosts>",
                             opts.name ? opts.name : "unnamed", opts.hosts);

  if (opts.exclude_hosts)
    exclude_hosts = g_markup_printf_escaped ("<exclude_hosts>"
                                             "%s"
                                             "</exclude_hosts>",
                                             opts.exclude_hosts);
  else
    exclude_hosts = NULL;

  if (opts.alive_tests)
    alive_tests = g_markup_printf_escaped ("<alive_tests>"
                                           "%s"
                                           "</alive_tests>",
                                           opts.alive_tests);
  else
    alive_tests = NULL;

  if (opts.comment)
    comment = g_markup_printf_escaped ("<comment>"
                                       "%s"
                                       "</comment>",
                                       opts.comment);
  else
    comment = NULL;

  if (opts.ssh_credential_id)
    {
      if (opts.ssh_credential_port)
        ssh = g_markup_printf_escaped ("<ssh_lsc_credential id=\"%s\">"
                                       "<port>%i</port>"
                                       "</ssh_lsc_credential>",
                                       opts.ssh_credential_id,
                                       opts.ssh_credential_port);
      else
        ssh = g_markup_printf_escaped ("<ssh_lsc_credential id=\"%s\"/>",
                                       opts.ssh_credential_id);
    }
  else
    ssh = NULL;

  if (opts.smb_credential_id)
    smb = g_markup_printf_escaped ("<smb_lsc_credential id=\"%s\"/>",
                                   opts.smb_credential_id);
  else
    smb = NULL;

  if (opts.esxi_credential_id)
    esxi = g_markup_printf_escaped ("<esxi_lsc_credential id=\"%s\"/>",
                                    opts.esxi_credential_id);
  else
    esxi = NULL;

  if (opts.snmp_credential_id)
    snmp = g_markup_printf_escaped ("<snmp_credential id=\"%s\"/>",
                                    opts.snmp_credential_id);
  else
    snmp = NULL;

  if (opts.port_range)
    port_range =
      g_markup_printf_escaped ("<port_range>%s</port_range>", opts.port_range);
  else
    port_range = NULL;

  /* Send the request. */
  ret = gvm_server_sendf (session,
                          "%s%s%s%s%s%s%s%s%s"
                          "<reverse_lookup_only>%d</reverse_lookup_only>"
                          "<reverse_lookup_unify>%d</reverse_lookup_unify>"
                          "</create_target>",
                          start, exclude_hosts ? exclude_hosts : "",
                          alive_tests ? alive_tests : "", ssh ? ssh : "",
                          smb ? smb : "", esxi ? esxi : "", snmp ? snmp : "",
                          port_range ? port_range : "", comment ? comment : "",
                          opts.reverse_lookup_only, opts.reverse_lookup_unify);
  g_free (start);
  g_free (exclude_hosts);
  g_free (alive_tests);
  g_free (ssh);
  g_free (smb);
  g_free (esxi);
  g_free (port_range);
  g_free (comment);
  if (ret)
    return -2;

  /* Read the response. */

  ret = gmp_read_create_response (session, id);
  if (ret == 201)
    return 0;
  return ret;
}

/**
 * @brief Delete a target.
 *
 * @param[in]   session     Pointer to GNUTLS session.
 * @param[in]   id          UUID of target.
 * @param[in]   opts        Struct containing the options to apply.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_delete_target_ext (gnutls_session_t *session, const char *id,
                       gmp_delete_opts_t opts)
{
  entity_t entity;
  int ret;

  if (gvm_server_sendf (session,
                        "<delete_target target_id=\"%s\" ultimate=\"%d\"/>", id,
                        opts.ultimate)
      == -1)
    return -1;

  entity = NULL;
  ret = gmp_check_response (session, &entity);
  if (ret == 0)
    free_entity (entity);
  return ret;
}

/**
 * @brief Delete a config.
 *
 * @param[in]   session     Pointer to GNUTLS session.
 * @param[in]   id          UUID of config.
 * @param[in]   opts        Struct containing the options to apply.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_delete_config_ext (gnutls_session_t *session, const char *id,
                       gmp_delete_opts_t opts)
{
  entity_t entity;
  int ret;

  if (gvm_server_sendf (session,
                        "<delete_config config_id=\"%s\" ultimate=\"%d\"/>", id,
                        opts.ultimate)
      == -1)
    return -1;

  entity = NULL;
  ret = gmp_check_response (session, &entity);
  if (ret == 0)
    free_entity (entity);
  return ret;
}

/**
 * @brief Create an LSC Credential.
 *
 * @param[in]   session   Pointer to GNUTLS session.
 * @param[in]   name      Name of LSC Credential.
 * @param[in]   login     Login associated with name.
 * @param[in]   password  Password, or NULL for autogenerated credentials.
 * @param[in]   comment   LSC Credential comment.
 * @param[out]  uuid      Either NULL or address for UUID of created credential.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_create_lsc_credential (gnutls_session_t *session, const char *name,
                           const char *login, const char *password,
                           const char *comment, gchar **uuid)
{
  int ret;

  if (password)
    {
      if (comment)
        ret = gvm_server_sendf_xml_quiet (session,
                                          "<create_credential>"
                                          "<name>%s</name>"
                                          "<login>%s</login>"
                                          "<password>%s</password>"
                                          "<comment>%s</comment>"
                                          "</create_credential>",
                                          name, login, password, comment);
      else
        ret = gvm_server_sendf_xml_quiet (session,
                                          "<create_credential>"
                                          "<name>%s</name>"
                                          "<login>%s</login>"
                                          "<password>%s</password>"
                                          "</create_credential>",
                                          name, login, password);
    }
  else
    {
      if (comment)
        ret = gvm_server_sendf_xml (session,
                                    "<create_credential>"
                                    "<name>%s</name>"
                                    "<login>%s</login>"
                                    "<comment>%s</comment>"
                                    "</create_credential>",
                                    name, login, comment);
      else
        ret = gvm_server_sendf_xml (session,
                                    "<create_credential>"
                                    "<name>%s</name>"
                                    "<login>%s</login>"
                                    "</create_credential>",
                                    name, login);
    }
  if (ret)
    return -1;

  ret = gmp_read_create_response (session, uuid);
  if (ret == 201)
    return 0;
  return ret;
}

/**
 * @brief Create an LSC Credential with a key.
 *
 * @param[in]   session      Pointer to GNUTLS session.
 * @param[in]   name         Name of LSC Credential.
 * @param[in]   login        Login associated with name.
 * @param[in]   passphrase   Passphrase for private key.
 * @param[in]   private_key  Private key.
 * @param[in]   comment      LSC Credential comment.
 * @param[out]  uuid         Either NULL or address for UUID of created
 *                           credential.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_create_lsc_credential_key (gnutls_session_t *session, const char *name,
                               const char *login, const char *passphrase,
                               const char *private_key, const char *comment,
                               gchar **uuid)
{
  int ret;

  if (comment)
    ret = gvm_server_sendf_xml (session,
                                "<create_credential>"
                                "<name>%s</name>"
                                "<login>%s</login>"
                                "<key>"
                                "<phrase>%s</phrase>"
                                "<private>%s</private>"
                                "</key>"
                                "<comment>%s</comment>"
                                "</create_credential>",
                                name, login, passphrase ? passphrase : "",
                                private_key, comment);
  else
    ret = gvm_server_sendf_xml (session,
                                "<create_credential>"
                                "<name>%s</name>"
                                "<login>%s</login>"
                                "<key>"
                                "<phrase>%s</phrase>"
                                "<private>%s</private>"
                                "</key>"
                                "</create_credential>",
                                name, login, passphrase ? passphrase : "",
                                private_key);

  if (ret)
    return -1;

  ret = gmp_read_create_response (session, uuid);
  if (ret == 201)
    return 0;
  return ret;
}

/**
 * @brief Create an LSC credential.
 *
 * @param[in]  session   Pointer to GNUTLS session.
 * @param[in]  opts      Struct containing the options to apply.
 * @param[out] id        Pointer for newly allocated ID of new LSC credential,
 *                       or NULL.  Only set on successful return.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_create_lsc_credential_ext (gnutls_session_t *session,
                               gmp_create_lsc_credential_opts_t opts,
                               gchar **id)
{
  gchar *comment, *pass, *start, *snmp_elems;
  int ret;

  /* Create the GMP request. */

  if (opts.login == NULL)
    return -1;

  start =
    g_markup_printf_escaped ("<create_credential>"
                             "<name>%s</name>"
                             "<login>%s</login>",
                             opts.name ? opts.name : "unnamed", opts.login);

  if (opts.comment)
    comment = g_markup_printf_escaped ("<comment>"
                                       "%s"
                                       "</comment>",
                                       opts.comment);
  else
    comment = NULL;

  if (opts.private_key)
    pass = g_markup_printf_escaped ("<key>"
                                    "<phrase>%s</phrase>"
                                    "<private>%s</private>"
                                    "</key>",
                                    opts.passphrase ? opts.passphrase : "",
                                    opts.private_key);
  else
    {
      if (opts.passphrase)
        pass = g_markup_printf_escaped ("<password>"
                                        "%s"
                                        "</password>",
                                        opts.passphrase);
      else
        pass = NULL;
    }

  if (opts.community && opts.auth_algorithm && opts.privacy_password
      && opts.privacy_algorithm)
    snmp_elems =
      g_markup_printf_escaped ("<community>"
                               "%s"
                               "</community>"
                               "<auth_algorithm>"
                               "%s"
                               "</auth_algorithm>"
                               "<privacy>"
                               "<password>%s</password>"
                               "<algorithm>%s</algorithm>"
                               "</privacy>",
                               opts.community, opts.auth_algorithm,
                               opts.privacy_password, opts.privacy_algorithm);
  else
    snmp_elems = NULL;

  /* Send the request. */

  ret = gvm_server_sendf (session, "%s%s%s%s</create_credential>", start,
                          comment ? comment : "", pass ? pass : "",
                          snmp_elems ? snmp_elems : "");

  g_free (start);
  g_free (comment);
  g_free (pass);
  if (ret)
    return -1;

  /* Read the response. */

  ret = gmp_read_create_response (session, id);
  if (ret == 201)
    return 0;
  return ret;
}

/**
 * @brief Delete a LSC credential.
 *
 * @param[in]   session     Pointer to GNUTLS session.
 * @param[in]   id          UUID of LSC credential.
 * @param[in]   opts        Struct containing the options to apply.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_delete_lsc_credential_ext (gnutls_session_t *session, const char *id,
                               gmp_delete_opts_t opts)
{
  entity_t entity;
  int ret;

  if (gvm_server_sendf (session,
                        "<delete_credential credential_id=\"%s\""
                        " ultimate=\"%d\"/>",
                        id, opts.ultimate)
      == -1)
    return -1;

  entity = NULL;
  ret = gmp_check_response (session, &entity);
  if (ret == 0)
    free_entity (entity);
  return ret;
}

/**
 * @brief Get system reports.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  name     Name of system report.  NULL for all.
 * @param[in]  brief    Whether to request brief response.
 * @param[out] reports  Reports return.  On success contains GET_SYSTEM_REPORTS
 *                      response.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_get_system_reports (gnutls_session_t *session, const char *name, int brief,
                        entity_t *reports)
{
  if (name)
    {
      if (gvm_server_sendf (session,
                            "<get_system_reports name=\"%s\" brief=\"%i\"/>",
                            name, brief)
          == -1)
        return -1;
    }
  else if (gvm_server_sendf (session, "<get_system_reports brief=\"%i\"/>",
                             brief)
           == -1)
    return -1;

  /* Read and check the response. */
  return gmp_check_response (session, reports);
}

/**
 * @brief Get system reports.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  opts     Struct containing the options to apply.
 * @param[out] reports  Reports return.  On success contains GET_SYSTEM_REPORTS
 *                      response.
 *
 * @return 0 on success, -1 or GMP response code on error.
 */
int
gmp_get_system_reports_ext (gnutls_session_t *session,
                            gmp_get_system_reports_opts_t opts,
                            entity_t *reports)
{
  GString *request;

  request = g_string_new ("<get_system_reports");

  if (opts.slave_id)
    xml_string_append (request, " slave_id=\"%s\"", opts.slave_id);

  if (opts.name)
    xml_string_append (request, " name=\"%s\"", opts.name);

  if (opts.duration)
    xml_string_append (request, " duration=\"%s\"", opts.duration);

  if (opts.start_time)
    xml_string_append (request, " start_time=\"%s\"", opts.start_time);

  if (opts.end_time)
    xml_string_append (request, " end_time=\"%s\"", opts.end_time);

  g_string_append (request, "/>");

  /* Create the GMP request. */

  if (gvm_server_sendf (session, "%s", request->str) == -1)
    {
      g_string_free (request, 1);
      return -1;
    }
  g_string_free (request, 1);

  /* Read and check the response. */
  return gmp_check_response (session, reports);
}
