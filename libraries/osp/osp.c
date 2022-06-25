/* Copyright (C) 2014-2019 Greenbone Networks GmbH
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
 * @brief API for Open Scanner Protocol communication.
 */

#include "osp.h"

#include "../base/hosts.h"       /* for gvm_get_host_type */
#include "../util/serverutils.h" /* for gvm_server_close, gvm_server_open_w... */
#include "../util/xmlutils.h" /* for entity_child, entity_text, free_entity */

#include <assert.h>        /* for assert */
#include <gnutls/gnutls.h> /* for gnutls_session_int, gnutls_session_t */
#include <stdarg.h>        /* for va_list */
#include <stdlib.h>        /* for NULL, atoi */
#include <string.h>        /* for strcmp, strlen, strncpy */
#include <sys/socket.h>    /* for AF_UNIX, connect, socket, SOCK_STREAM */
#include <sys/un.h>        /* for sockaddr_un, sa_family_t */
#include <unistd.h>        /* for close */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "lib  osp"

/**
 * @brief Struct holding options for OSP connection.
 */
struct osp_connection
{
  gnutls_session_t session; /**< Pointer to GNUTLS Session. */
  int socket;               /**< Socket. */
  char *host;               /**< Host. */
  int port;                 /**< Port. */
};

/**
 * @brief Struct holding options for OSP parameters.
 */
struct osp_param
{
  char *id;              /**< Parameter id. */
  char *name;            /**< Parameter name. */
  char *desc;            /**< Parameter description. */
  char *def;             /**< Default value. */
  osp_param_type_t type; /**< Parameter type. */
  int mandatory;         /**< If mandatory or not. */
};

static int
osp_send_command (osp_connection_t *, entity_t *, const char *, ...)
  __attribute__ ((__format__ (__printf__, 3, 4)));

/**
 * @brief Open a new connection to an OSP server.
 *
 * @param[in]   host    Host of OSP server.
 * @param[in]   port    Port of OSP server.
 * @param[in]   cacert  CA public key.
 * @param[in]   cert    Client public key.
 * @param[in]   key     Client private key.
 *
 * @return New osp connection, NULL if error.
 */
osp_connection_t *
osp_connection_new (const char *host, int port, const char *cacert,
                    const char *cert, const char *key)
{
  osp_connection_t *connection;

  if (host && *host == '/')
    {
      struct sockaddr_un addr;
      int len;

      connection = g_malloc0 (sizeof (*connection));
      connection->socket = socket (AF_UNIX, SOCK_STREAM, 0);
      if (connection->socket == -1)
        return NULL;

      addr.sun_family = AF_UNIX;
      strncpy (addr.sun_path, host, sizeof (addr.sun_path) - 1);
      len = strlen (addr.sun_path) + sizeof (addr.sun_family);
      if (connect (connection->socket, (struct sockaddr *) &addr, len) == -1)
        {
          close (connection->socket);
          return NULL;
        }
    }
  else
    {
      if (port <= 0 || port > 65535)
        return NULL;
      if (!host || gvm_get_host_type (host) == -1)
        return NULL;
      if (!cert || !key || !cacert)
        return NULL;

      connection = g_malloc0 (sizeof (*connection));
      connection->socket = gvm_server_open_with_cert (
        &connection->session, host, port, cacert, cert, key);
    }
  if (connection->socket == -1)
    {
      g_free (connection);
      return NULL;
    }

  connection->host = g_strdup (host);
  connection->port = port;
  return connection;
}

/**
 * @brief Send a command to an OSP server.
 *
 * @param[in]   connection  Connection to OSP server.
 * @param[out]  response    Response from OSP server.
 * @param[in]   fmt         OSP Command to send.
 *
 * @return 0 and response, 1 if error.
 */
int
osp_send_command (osp_connection_t *connection, entity_t *response,
                  const char *fmt, ...)
{
  va_list ap;
  int rc = 1;

  va_start (ap, fmt);

  if (!connection || !fmt || !response)
    goto out;

  if (*connection->host == '/')
    {
      if (gvm_socket_vsendf (connection->socket, fmt, ap) == -1)
        goto out;
      if (read_entity_s (connection->socket, response))
        goto out;
    }
  else
    {
      if (gvm_server_vsendf (&connection->session, fmt, ap) == -1)
        goto out;
      if (read_entity (&connection->session, response))
        goto out;
    }

  rc = 0;

out:
  va_end (ap);

  return rc;
}

/**
 * @brief Close a connection to an OSP server.
 *
 * @param[in]   connection  Connection to OSP server to close.
 */
void
osp_connection_close (osp_connection_t *connection)
{
  if (!connection)
    return;

  if (*connection->host == '/')
    close (connection->socket);
  else
    gvm_server_close (connection->socket, connection->session);
  g_free (connection->host);
  g_free (connection);
}

/**
 * @brief Get the scanner version from an OSP server.
 *
 * @param[in]   connection  Connection to an OSP server.
 * @param[out]  s_name      Parsed scanner name.
 * @param[out]  s_version   Parsed scanner version.
 * @param[out]  d_name      Parsed scanner name.
 * @param[out]  d_version   Parsed scanner version.
 * @param[out]  p_name      Parsed scanner name.
 * @param[out]  p_version   Parsed scanner version.
 *
 * @return 0 if success, 1 if error.
 */
int
osp_get_version (osp_connection_t *connection, char **s_name, char **s_version,
                 char **d_name, char **d_version, char **p_name,
                 char **p_version)
{
  entity_t entity, child, gchild;

  if (!connection)
    return 1;

  if (osp_send_command (connection, &entity, "<get_version/>"))
    return 1;

  child = entity_child (entity, "scanner");
  if (!child)
    goto err_get_version;
  gchild = entity_child (child, "name");
  if (!gchild)
    goto err_get_version;
  if (s_name)
    *s_name = g_strdup (entity_text (gchild));
  gchild = entity_child (child, "version");
  if (!gchild)
    goto err_get_version;
  if (s_version)
    *s_version = g_strdup (entity_text (gchild));

  child = entity_child (entity, "daemon");
  if (!child)
    goto err_get_version;
  gchild = entity_child (child, "name");
  if (!gchild)
    goto err_get_version;
  if (d_name)
    *d_name = g_strdup (entity_text (gchild));
  gchild = entity_child (child, "version");
  if (!gchild)
    goto err_get_version;
  if (d_version)
    *d_version = g_strdup (entity_text (gchild));

  child = entity_child (entity, "protocol");
  if (!child)
    goto err_get_version;
  gchild = entity_child (child, "name");
  if (!gchild)
    goto err_get_version;
  if (p_name)
    *p_name = g_strdup (entity_text (gchild));
  gchild = entity_child (child, "version");
  if (!gchild)
    goto err_get_version;
  if (p_version)
    *p_version = g_strdup (entity_text (gchild));

  free_entity (entity);
  return 0;

err_get_version:
  g_warning ("Erroneous OSP <get_version/> response.");
  if (s_name)
    g_free (*s_name);
  if (s_version)
    g_free (*s_version);
  if (d_name)
    g_free (*d_name);
  if (d_version)
    g_free (*d_version);
  if (p_name)
    g_free (*p_name);
  if (p_version)
    g_free (*p_version);
  free_entity (entity);
  return 1;
}

/**
 * @brief Delete a scan from an OSP server.
 *
 * @param[in]   connection  Connection to an OSP server.
 * @param[in]   scan_id     ID of scan to delete.
 *
 * @return 0 if success, 1 if error.
 */
int
osp_delete_scan (osp_connection_t *connection, const char *scan_id)
{
  entity_t entity;
  int ret = 0;
  const char *status;

  if (!connection)
    return 1;

  ret = osp_send_command (connection, &entity, "<delete_scan scan_id='%s'/>",
                          scan_id);
  if (ret)
    return 1;

  /* Check response status. */
  status = entity_attribute (entity, "status");
  assert (status);
  if (strcmp (status, "200"))
    ret = 1;

  free_entity (entity);
  return ret;
}

/**
 * @brief Get a scan from an OSP server.
 *
 * @param[in]   connection  Connection to an OSP server.
 * @param[in]   scan_id     ID of scan to get.
 * @param[out]  report_xml  Scans report.
 * @param[in]   details     0 for no scan details, 1 otherwise.
 * @param[out]  error       Pointer to error, if any.
 *
 * @return Scan progress if success, -1 if error.
 */
int
osp_get_scan (osp_connection_t *connection, const char *scan_id,
              char **report_xml, int details, char **error)
{
  entity_t entity, child;
  int progress;
  int rc;

  assert (connection);
  assert (scan_id);
  rc = osp_send_command (connection, &entity,
                         "<get_scans scan_id='%s' details='%d'/>", scan_id,
                         details ? 1 : 0);
  if (rc)
    {
      if (error)
        *error = g_strdup ("Couldn't send get_scans command to scanner");
      return -1;
    }

  child = entity_child (entity, "scan");
  if (!child)
    {
      const char *text = entity_attribute (entity, "status_text");

      assert (text);
      if (error)
        *error = g_strdup (text);
      free_entity (entity);
      return -1;
    }
  progress = atoi (entity_attribute (child, "progress"));
  if (report_xml)
    {
      GString *string;

      string = g_string_new ("");
      print_entity_to_string (child, string);
      *report_xml = g_string_free (string, FALSE);
    }
  free_entity (entity);
  return progress;
}

/**
 * @brief Stop a scan on an OSP server.
 *
 * @param[in]   connection  Connection to an OSP server.
 * @param[in]   scan_id     ID of scan to delete.
 * @param[out]  error       Pointer to error, if any.
 *
 * @return Scan progress if success, -1 if error.
 */
int
osp_stop_scan (osp_connection_t *connection, const char *scan_id, char **error)
{
  entity_t entity;
  int rc;

  assert (connection);
  assert (scan_id);
  rc = osp_send_command (connection, &entity, "<stop_scan scan_id='%s'/>",
                         scan_id);
  if (rc)
    {
      if (error)
        *error = g_strdup ("Couldn't send stop_scan command to scanner");
      return -1;
    }

  rc = atoi (entity_attribute (entity, "status"));
  if (rc == 200)
    {
      free_entity (entity);
      return 0;
    }
  else
    {
      const char *text = entity_attribute (entity, "status_text");

      assert (text);
      if (error)
        *error = g_strdup (text);
      free_entity (entity);
      return -1;
    }
}

/**
 * @brief Concatenate options as xml.
 *
 * @param[in]     key      Tag name for xml element.
 * @param[in]     value    Text for xml element.
 * @param[in,out] pstr     Parameters as xml concatenated xml elements.
 *
 */
static void
option_concat_as_xml (gpointer key, gpointer value, gpointer pstr)
{
  char *options_str, *tmp, *key_escaped, *value_escaped;

  options_str = *(char **) pstr;

  key_escaped = g_markup_escape_text ((char *) key, -1);
  value_escaped = g_markup_escape_text ((char *) value, -1);
  tmp = g_strdup_printf ("%s<%s>%s</%s>", options_str ? options_str : "",
                         key_escaped, value_escaped, key_escaped);

  g_free (options_str);
  g_free (key_escaped);
  g_free (value_escaped);
  *(char **) pstr = tmp;
}

/**
 * @brief Start an OSP scan against a target.
 *
 * @param[in]   connection  Connection to an OSP server.
 * @param[in]   target      Target host to scan.
 * @param[in]   ports       List of ports to scan.
 * @param[in]   options     Table of scan options.
 * @param[in]   scan_id     uuid to set for scan, null otherwise.
 * @param[out]  error       Pointer to error, if any.
 *
 * @return 0 on success, -1 otherwise.
 */
int
osp_start_scan (osp_connection_t *connection, const char *target,
                const char *ports, GHashTable *options, const char *scan_id,
                char **error)
{
  entity_t entity;
  char *options_str = NULL;
  int status;
  int rc;

  assert (connection);
  assert (target);
  /* Construct options string. */
  if (options)
    g_hash_table_foreach (options, option_concat_as_xml, &options_str);

  rc = osp_send_command (connection, &entity,
                         "<start_scan target='%s' ports='%s' scan_id='%s'>"
                         "<scanner_params>%s</scanner_params></start_scan>",
                         target, ports ? ports : "", scan_id ? scan_id : "",
                         options_str ? options_str : "");
  g_free (options_str);
  if (rc)
    {
      if (error)
        *error = g_strdup ("Couldn't send start_scan command to scanner");
      return -1;
    }

  status = atoi (entity_attribute (entity, "status"));
  if (status == 200)
    {
      free_entity (entity);
      return 0;
    }
  else
    {
      const char *text = entity_attribute (entity, "status_text");

      assert (text);
      if (error)
        *error = g_strdup (text);
      free_entity (entity);
      return -1;
    }
}

/**
 * @brief Get an OSP parameter's type from its string format.
 *
 * @param[in]   str     OSP parameter in string format.
 *
 * @return OSP parameter type.
 */
static osp_param_type_t
osp_param_str_to_type (const char *str)
{
  assert (str);
  if (!strcmp (str, "integer"))
    return OSP_PARAM_TYPE_INT;
  else if (!strcmp (str, "string"))
    return OSP_PARAM_TYPE_STR;
  else if (!strcmp (str, "password"))
    return OSP_PARAM_TYPE_PASSWORD;
  else if (!strcmp (str, "file"))
    return OSP_PARAM_TYPE_FILE;
  else if (!strcmp (str, "boolean"))
    return OSP_PARAM_TYPE_BOOLEAN;
  else if (!strcmp (str, "ovaldef_file"))
    return OSP_PARAM_TYPE_OVALDEF_FILE;
  else if (!strcmp (str, "selection"))
    return OSP_PARAM_TYPE_SELECTION;
  else if (!strcmp (str, "credential_up"))
    return OSP_PARAM_TYPE_CRD_UP;
  assert (0);
  return 0;
}

/**
 * @brief Get an OSP parameter in string format form its type.
 *
 * @param[in]   param     OSP parameter.
 *
 * @return OSP parameter in string format.
 */
const char *
osp_param_type_str (const osp_param_t *param)
{
  osp_param_type_t type;

  assert (param);
  type = param->type;
  if (type == OSP_PARAM_TYPE_INT)
    return "integer";
  else if (type == OSP_PARAM_TYPE_STR)
    return "string";
  else if (type == OSP_PARAM_TYPE_PASSWORD)
    return "password";
  else if (type == OSP_PARAM_TYPE_FILE)
    return "file";
  else if (type == OSP_PARAM_TYPE_BOOLEAN)
    return "boolean";
  else if (type == OSP_PARAM_TYPE_OVALDEF_FILE)
    return "ovaldef_file";
  else if (type == OSP_PARAM_TYPE_SELECTION)
    return "selection";
  else if (type == OSP_PARAM_TYPE_CRD_UP)
    return "credential_up";
  assert (0);
  return NULL;
}

/**
 * @brief Get an OSP scanner's details.
 *
 * @param[in]   connection  Connection to an OSP server.
 * @param[out]  desc        Scanner's description.
 * @param[out]  params      Scanner's parameters.
 *
 * @return 0 if success, 1 if failure.
 */
int
osp_get_scanner_details (osp_connection_t *connection, char **desc,
                         GSList **params)
{
  entity_t entity, child;
  entities_t entities;

  assert (connection);

  if (osp_send_command (connection, &entity, "<get_scanner_details/>"))
    return 1;
  if (params)
    {
      child = entity_child (entity, "scanner_params");
      if (!child)
        {
          free_entity (entity);
          return 1;
        }
      entities = child->entities;
      while (entities)
        {
          osp_param_t *param;

          child = entities->data;
          param = osp_param_new ();
          param->id = g_strdup (entity_attribute (child, "id"));
          param->type =
            osp_param_str_to_type (entity_attribute (child, "type"));
          param->name = g_strdup (entity_text (entity_child (child, "name")));
          param->desc =
            g_strdup (entity_text (entity_child (child, "description")));
          param->def = g_strdup (entity_text (entity_child (child, "default")));
          if (entity_child (child, "mandatory"))
            param->mandatory =
              atoi (entity_text (entity_child (child, "mandatory")));
          *params = g_slist_append (*params, param);
          entities = next_entities (entities);
        }
    }
  if (desc)
    {
      child = entity_child (entity, "description");
      assert (child);
      *desc = g_strdup (entity_text (child));
    }

  free_entity (entity);
  return 0;
}

/**
 * @brief Create a new OSP parameter.
 *
 * @return New OSP parameter.
 */
osp_param_t *
osp_param_new (void)
{
  return g_malloc0 (sizeof (osp_param_t));
}

/**
 * @brief Get an OSP parameter's id.
 *
 * @param[in]   param   OSP parameter.
 *
 * @return ID of OSP parameter.
 */
const char *
osp_param_id (const osp_param_t *param)
{
  assert (param);

  return param->id;
}

/**
 * @brief Get an OSP parameter's name.
 *
 * @param[in]   param   OSP parameter.
 *
 * @return Name of OSP parameter.
 */
const char *
osp_param_name (const osp_param_t *param)
{
  assert (param);

  return param->name;
}

/**
 * @brief Get an OSP parameter's description.
 *
 * @param[in]   param   OSP parameter.
 *
 * @return Description of OSP parameter.
 */
const char *
osp_param_desc (const osp_param_t *param)
{
  assert (param);

  return param->desc;
}

/**
 * @brief Get an OSP parameter's default value.
 *
 * @param[in]   param   OSP parameter.
 *
 * @return Default value of OSP parameter.
 */
const char *
osp_param_default (const osp_param_t *param)
{
  assert (param);

  return param->def;
}

/**
 * @brief Get an OSP parameter's mandatory value.
 *
 * @param[in]   param   OSP parameter.
 *
 * @return Mandatory value of OSP parameter.
 */
int
osp_param_mandatory (const osp_param_t *param)
{
  assert (param);

  return param->mandatory;
}

/**
 * @brief Free an OSP parameter.
 *
 * @param[in] param OSP parameter to destroy.
 */
void
osp_param_free (osp_param_t *param)
{
  if (!param)
    return;
  g_free (param->id);
  g_free (param->name);
  g_free (param->desc);
  g_free (param->def);
  g_free (param);
}
