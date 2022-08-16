/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2018 Greenbone Networks GmbH
 * SPDX-FileComment: Base facilities.
 * SPDX-FileContributor: Matthew Mundell <matthew.mundell@greenbone.net>
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#include "gmp_get.h"

#include "gmp_base.h"
#include "manage_acl.h"

#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/**
 * @brief Parse attributes for a GET command.
 *
 * @param[in]  data              GET operation data.
 * @param[in]  type              Resource type.
 * @param[in]  attribute_names   XML attribute names.
 * @param[in]  attribute_values  XML attribute values.
 *
 * @param[in]  data  Command data.
 */
void
get_data_parse_attributes (get_data_t *data,
                           const gchar *type,
                           const gchar **attribute_names,
                           const gchar **attribute_values)
{
  gchar *name;
  const gchar *attribute;

  data->type = g_strdup (type);

  append_attribute (attribute_names, attribute_values, "filter", &data->filter);

  name = g_strdup_printf ("%s_id", type);
  append_attribute (attribute_names, attribute_values, name, &data->id);
  g_free (name);

  append_attribute (
    attribute_names, attribute_values, "filt_id", &data->filt_id);

  if (find_attribute (attribute_names, attribute_values, "trash", &attribute))
    data->trash = strcmp (attribute, "0");
  else
    data->trash = 0;

  if (find_attribute (attribute_names, attribute_values, "details", &attribute))
    data->details = strcmp (attribute, "0");
  else
    data->details = 0;

  if (find_attribute (
        attribute_names, attribute_values, "ignore_pagination", &attribute))
    data->ignore_pagination = strcmp (attribute, "0");
  else
    data->ignore_pagination = 0;

  append_attribute (
    attribute_names, attribute_values, "filter_replace", &data->filter_replace);
}

/**
 * @brief Init for a GET handler.
 *
 * @param[in]  command       GMP command name.
 * @param[in]  get           GET data.
 * @param[in]  setting_name  Type name for setting.
 * @param[out] first         First result, from filter.
 *
 * @return 0 success, -1 error.
 */
int
init_get (gchar *command,
          get_data_t *get,
          const gchar *setting_name,
          int *first)
{
  gchar *filter, *replacement;

  if (acl_user_may (command) == 0)
    return 99;

  /* Get any replacement out of get->filter, before it changes.  Used to add
   * task_id to the filter for GET_REPORTS. */

  if (get->filter_replace && strlen (get->filter_replace) && get->filter)
    replacement = filter_term_value (get->filter, get->filter_replace);
  else
    replacement = NULL;

  /* Switch to the default filter from the setting, if required. */

  if (get->filt_id && strcmp (get->filt_id, FILT_ID_USER_SETTING) == 0)
    {
      char *user_filter = setting_filter (setting_name);

      if (user_filter && strlen (user_filter))
        {
          get->filt_id = user_filter;
          get->filter = filter_term (user_filter);
        }
      else
        {
          free (user_filter);
          get->filt_id = g_strdup ("0");
        }
    }

  /* Get the actual filter string. */

  if (get->filt_id && strcmp (get->filt_id, FILT_ID_NONE))
    {
      filter = filter_term (get->filt_id);
      if (filter == NULL)
        {
          char *user_filter;

          /* Probably the user deleted the filter, switch to default. */

          g_free (get->filt_id);

          user_filter = setting_filter (setting_name);
          if (user_filter && strlen (user_filter))
            {
              get->filt_id = user_filter;
              get->filter = filter_term (user_filter);
              filter = filter_term (get->filt_id);
            }
          else
            get->filt_id = g_strdup ("0");
        }
    }
  else
    filter = NULL;

  if (replacement)
    {
      const gchar *term;

      /* Replace the term in filter.  Used to add task_id to the filter
       * for GET_REPORTS. */

      term = filter ? filter : get->filter;

      if (term)
        {
          gchar *new_filter, *clean;

          clean = manage_clean_filter_remove (term, get->filter_replace);
          new_filter = g_strdup_printf (
            "%s=%s %s", get->filter_replace, replacement, clean);
          g_free (clean);
          if (get->filter)
            {
              g_free (get->filter);
              get->filter = new_filter;
            }
          else
            {
              g_free (filter);
              filter = new_filter;
            }
          get->filter_replacement = g_strdup (new_filter);
        }

      g_free (replacement);
    }

  /* Get the value of "first" from the filter string.
   *
   * This is used by get_next when the result set is empty, to determine if
   * the query should be rerun with first 1.
   */
  manage_filter_controls (
    filter ? filter : get->filter, first, NULL, NULL, NULL);

  g_free (filter);

  return 0;
}

/**
 * @brief Iterate a GET iterator.
 *
 * If the user requested to start at an offset from the first result, but
 * the result set was empty, then reset the iterator to start from the
 * first result.
 *
 * @param[in]  resources  Resource iterator.
 * @param[in]  get        GET command data.
 * @param[out] first      First.  Number of first item to get.
 * @param[out] count      Count.
 * @param[in]  init       Init function, to reset the iterator.
 *
 * @return What to do next: 0 continue, 1 end, -1 fail.
 */
int
get_next (iterator_t *resources,
          get_data_t *get,
          int *first,
          int *count,
          int (*init) (iterator_t *, const get_data_t *))
{
  if (next (resources) == FALSE)
    {
      gchar *new_filter;

      if (get->filt_id && strcmp (get->filt_id, FILT_ID_NONE))
        /* If filtering by a named filter, then just end, because changing
         * the filter term would probably surprise the user. */
        return 1;

      if (*first == 0)
        return 1;

      if (*first == 1 || *count > 0)
        /* Some results were found or first was 1, so stop iterating. */
        return 1;

      /* Reset the iterator with first 1, and start again. */
      cleanup_iterator (resources);
      new_filter = g_strdup_printf ("first=1 %s", get->filter);
      g_free (get->filter);
      get->filter = new_filter;
      if (init (resources, get))
        return -1;
      *count = 0;
      *first = 1;
      if (next (resources) == FALSE)
        return 1;
    }
  return 0;
}

/**
 * @brief Send start of GET response.
 *
 * @param[in]  type                  Type.
 * @param[in]  write_to_client       Function that sends to clients.
 * @param[in]  write_to_client_data  Data for write_to_client.
 *
 * @return 0 success, 1 send to client failed.
 */
int
send_get_start (const char *type,
                int (*write_to_client) (const char *, void *),
                void *write_to_client_data)
{
  gchar *msg;

  if (strcmp (type, "info"))
    msg = g_markup_printf_escaped ("<get_%ss_response"
                                   " status=\"" STATUS_OK "\""
                                   " status_text=\"" STATUS_OK_TEXT "\">",
                                   type);
  else
    msg = g_markup_printf_escaped ("<get_%s_response"
                                   " status=\"" STATUS_OK "\""
                                   " status_text=\"" STATUS_OK_TEXT "\">",
                                   type);

  if (send_to_client (msg, write_to_client, write_to_client_data))
    {
      g_free (msg);
      return 1;
    }
  g_free (msg);
  return 0;
}

/**
 * @brief Send common part of GET response for a single resource.
 *
 * @param[in]  type                  Type.
 * @param[in]  get                   GET data.
 * @param[in]  iterator              Iterator.
 * @param[in]  write_to_client       Function that sends to clients.
 * @param[in]  write_to_client_data  Data for write_to_client.
 * @param[in]  writable              Whether the resource is writable.
 * @param[in]  in_use                Whether the resource is in use.
 *
 * @return 0 success, 1 send error.
 */
int
send_get_common (const char *type,
                 get_data_t *get,
                 iterator_t *iterator,
                 int (*write_to_client) (const char *, void *),
                 void *write_to_client_data,
                 int writable,
                 int in_use)
{
  GString *buffer;
  const char *tag_type;
  iterator_t tags;
  int tag_count;

  buffer = g_string_new ("");

  buffer_xml_append_printf (
    buffer,
    "<%s id=\"%s\">"
    "<owner><name>%s</name></owner>"
    "<name>%s</name>"
    "<comment>%s</comment>"
    "<creation_time>%s</creation_time>"
    "<modification_time>%s</modification_time>"
    "<writable>%i</writable>"
    "<in_use>%i</in_use>"
    "<permissions>",
    type,
    get_iterator_uuid (iterator) ? get_iterator_uuid (iterator) : "",
    get_iterator_owner_name (iterator) ? get_iterator_owner_name (iterator)
                                       : "",
    get_iterator_name (iterator) ? get_iterator_name (iterator) : "",
    get_iterator_comment (iterator) ? get_iterator_comment (iterator) : "",
    get_iterator_creation_time (iterator)
      ? get_iterator_creation_time (iterator)
      : "",
    get_iterator_modification_time (iterator)
      ? get_iterator_modification_time (iterator)
      : "",
    writable,
    in_use);

  if (/* The user is the owner. */
      (current_credentials.username && get_iterator_owner_name (iterator)
       && (strcmp (get_iterator_owner_name (iterator),
                   current_credentials.username)
           == 0))
      /* Or the user is effectively the owner. */
      || acl_user_has_super (current_credentials.uuid,
                             get_iterator_owner (iterator))
      /* Or the user has Admin rights and the resource is a permission or a
       * report format... */
      || (current_credentials.uuid
          && ((strcmp (type, "permission") == 0)
              && get_iterator_uuid (iterator)
              /* ... but not the special Admin permission. */
              && permission_is_admin (get_iterator_uuid (iterator)))
          && acl_user_can_everything (current_credentials.uuid)))
    {
      buffer_xml_append_printf (buffer,
                                "<permission>"
                                "<name>Everything</name>"
                                "</permission>"
                                "</permissions>");
    }
  else if (current_credentials.uuid && (strcmp (type, "user") == 0)
           && acl_user_can_super_everyone (get_iterator_uuid (iterator))
           && strcmp (get_iterator_uuid (iterator), current_credentials.uuid))
    {
      /* Resource is the Super Admin. */
      buffer_xml_append_printf (
        buffer,
        "<permission><name>get_users</name></permission>"
        "</permissions>");
    }
  else
    {
      iterator_t perms;
      get_data_t perms_get;

      memset (&perms_get, '\0', sizeof (perms_get));
      perms_get.filter = g_strdup_printf ("resource_uuid=%s"
                                          " owner=any"
                                          " permission=any",
                                          get_iterator_uuid (iterator));
      init_permission_iterator (&perms, &perms_get);
      g_free (perms_get.filter);
      while (next (&perms))
        buffer_xml_append_printf (buffer,
                                  "<permission><name>%s</name></permission>",
                                  get_iterator_name (&perms));
      cleanup_iterator (&perms);

      buffer_xml_append_printf (buffer, "</permissions>");
    }

  tag_type = get->subtype ? get->subtype : get->type;
  tag_count =
    resource_tag_count (tag_type, get_iterator_resource (iterator), 1);

  if (tag_count)
    {
      if (get->details || get->id)
        {
          buffer_xml_append_printf (buffer,
                                    "<user_tags>"
                                    "<count>%i</count>",
                                    tag_count);

          init_resource_tag_iterator (
            &tags, tag_type, get_iterator_resource (iterator), 1, NULL, 1);

          while (next (&tags))
            {
              buffer_xml_append_printf (buffer,
                                        "<tag id=\"%s\">"
                                        "<name>%s</name>"
                                        "<value>%s</value>"
                                        "<comment>%s</comment>"
                                        "</tag>",
                                        resource_tag_iterator_uuid (&tags),
                                        resource_tag_iterator_name (&tags),
                                        resource_tag_iterator_value (&tags),
                                        resource_tag_iterator_comment (&tags));
            }

          cleanup_iterator (&tags);

          buffer_xml_append_printf (buffer, "</user_tags>");
        }
      else
        {
          buffer_xml_append_printf (buffer,
                                    "<user_tags>"
                                    "<count>%i</count>"
                                    "</user_tags>",
                                    tag_count);
        }
    }

  if (send_to_client (buffer->str, write_to_client, write_to_client_data))
    {
      g_string_free (buffer, TRUE);
      return 1;
    }
  g_string_free (buffer, TRUE);
  return 0;
}

/**
 * @brief Write data of a GET command filter to a string buffer as XML.
 *
 * @param[in] msg          The string buffer to write to.
 * @param[in] type         The filtered type.
 * @param[in] get          GET data.
 * @param[in] filter_term  Filter term.
 * @param[in] extra_xml    Extra XML to include in the FILTER element.
 *
 * @return Always 0.
 */
int
buffer_get_filter_xml (GString *msg,
                       const char *type,
                       const get_data_t *get,
                       const char *filter_term,
                       const char *extra_xml)
{
  keyword_t **point;
  array_t *split;
  filter_t filter;

  buffer_xml_append_printf (msg,
                            "<filters id=\"%s\">"
                            "<term>%s</term>",
                            get->filt_id ? get->filt_id : "",
                            filter_term);

  if (get->filt_id && strcmp (get->filt_id, "")
      && (find_filter_with_permission (get->filt_id, &filter, "get_filters")
          == 0)
      && filter != 0)
    buffer_xml_append_printf (msg, "<name>%s</name>", filter_name (filter));

  if (extra_xml)
    g_string_append (msg, extra_xml);

  buffer_xml_append_printf (msg, "<keywords>");

  split = split_filter (filter_term);
  point = (keyword_t **) split->pdata;
  while (*point)
    {
      keyword_t *keyword;
      keyword = *point;
      buffer_xml_append_printf (
        msg,
        "<keyword>"
        "<column>%s</column>"
        "<relation>%s</relation>"
        "<value>%s%s%s</value>"
        "</keyword>",
        keyword->column ? keyword->column : "",
        keyword->equal ? "="
                       : (keyword_special (keyword)
                            ? ""
                            : keyword_relation_symbol (keyword->relation)),
        keyword->quoted ? "\"" : "",
        keyword->string ? keyword->string : "",
        keyword->quoted ? "\"" : "");
      point++;
    }
  filter_free (split);

  buffer_xml_append_printf (msg,
                            "</keywords>"
                            "</filters>");
  return 0;
}

/**
 * @brief Send end of GET response.
 *
 * @param[in]  type                  Type.
 * @param[in]  get                   GET data.
 * @param[in]  get_counts            Include counts.
 * @param[in]  count                 Page count.
 * @param[in]  filtered              Filtered count.
 * @param[in]  full                  Full count.
 * @param[in]  write_to_client       Function that sends to clients.
 * @param[in]  write_to_client_data  Data for write_to_client.
 *
 * @return 0 success, 1 sending to client failed, 2 failed to allocate filter
 *         term.
 */
static int
send_get_end_internal (const char *type,
                       get_data_t *get,
                       int get_counts,
                       int count,
                       int filtered,
                       int full,
                       int (*write_to_client) (const char *, void *),
                       void *write_to_client_data)
{
  gchar *sort_field, *filter;
  int first, max, sort_order;
  GString *type_many, *msg;

  if (get->filt_id && strcmp (get->filt_id, FILT_ID_NONE))
    {
      if (get->filter_replacement)
        filter = g_strdup (get->filter_replacement);
      else
        filter = filter_term (get->filt_id);
      if (filter == NULL)
        return 2;
    }
  else
    filter = NULL;

  manage_filter_controls (
    filter ? filter : get->filter, &first, &max, &sort_field, &sort_order);

  if (get->ignore_pagination && (strcmp (type, "task") == 0))
    {
      first = 1;
      max = -1;
    }

  max = manage_max_rows (max);

  if (filter || get->filter)
    {
      gchar *new_filter;
      new_filter = manage_clean_filter (filter ? filter : get->filter);
      g_free (filter);
      if ((strcmp (type, "task") == 0) || (strcmp (type, "report") == 0)
          || (strcmp (type, "result") == 0))
        {
          gchar *value;

          value = filter_term_value (new_filter, "min_qod");
          if (value == NULL)
            {
              filter = new_filter;
              new_filter =
                g_strdup_printf ("min_qod=%i %s", MIN_QOD_DEFAULT, filter);
              g_free (filter);
            }
          g_free (value);

          value = filter_term_value (new_filter, "apply_overrides");
          if (value == NULL)
            {
              filter = new_filter;
              new_filter = g_strdup_printf (
                "apply_overrides=%i %s", APPLY_OVERRIDES_DEFAULT, filter);
              g_free (filter);
            }
          g_free (value);
        }
      filter = new_filter;
    }
  else
    {
      if ((strcmp (type, "task") == 0) || (strcmp (type, "report") == 0)
          || (strcmp (type, "result") == 0))
        filter = manage_clean_filter ("apply_overrides=" G_STRINGIFY (
          APPLY_OVERRIDES_DEFAULT) " min_qod=" G_STRINGIFY (MIN_QOD_DEFAULT));
      else
        filter = manage_clean_filter ("");
    }

  type_many = g_string_new (type);

  if (strcmp (type, "info") != 0)
    g_string_append (type_many, "s");

  msg = g_string_new ("");

  buffer_get_filter_xml (msg, type, get, filter, NULL);

  buffer_xml_append_printf (msg,
                            "<sort>"
                            "<field>%s<order>%s</order></field>"
                            "</sort>"
                            "<%s start=\"%i\" max=\"%i\"/>",
                            sort_field,
                            sort_order ? "ascending" : "descending",
                            type_many->str,
                            first,
                            max);
  if (get_counts)
    buffer_xml_append_printf (msg,
                              "<%s_count>"
                              "%i"
                              "<filtered>%i</filtered>"
                              "<page>%i</page>"
                              "</%s_count>",
                              type,
                              full,
                              filtered,
                              count,
                              type);
  buffer_xml_append_printf (msg, "</get_%s_response>", type_many->str);
  g_string_free (type_many, TRUE);
  g_free (sort_field);
  g_free (filter);

  if (send_to_client (msg->str, write_to_client, write_to_client_data))
    {
      g_string_free (msg, TRUE);
      return 1;
    }
  g_string_free (msg, TRUE);
  return 0;
}

/**
 * @brief Send end of GET response.
 *
 * @param[in]  type                  Type.
 * @param[in]  get                   GET data.
 * @param[in]  count                 Page count.
 * @param[in]  filtered              Filtered count.
 * @param[in]  full                  Full count.
 * @param[in]  write_to_client       Function that sends to clients.
 * @param[in]  write_to_client_data  Data for write_to_client.
 *
 * @return 0 success, 1 sending to client failed, 2 failed to allocate filter
 *         term.
 */
int
send_get_end (const char *type,
              get_data_t *get,
              int count,
              int filtered,
              int full,
              int (*write_to_client) (const char *, void *),
              void *write_to_client_data)
{
  return send_get_end_internal (
    type, get, 1, count, filtered, full, write_to_client, write_to_client_data);
}

/**
 * @brief Send end of GET response, skipping result counts.
 *
 * @param[in]  type                  Type.
 * @param[in]  get                   GET data.
 * @param[in]  write_to_client       Function that sends to clients.
 * @param[in]  write_to_client_data  Data for write_to_client.
 *
 * @return 0 success, 1 sending to client failed, 2 failed to allocate filter
 *         term.
 */
int
send_get_end_no_counts (const char *type,
                        get_data_t *get,
                        int (*write_to_client) (const char *, void *),
                        void *write_to_client_data)
{
  return send_get_end_internal (
    type, get, 0, 0, 0, 0, write_to_client, write_to_client_data);
}
