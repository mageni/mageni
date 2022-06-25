/* Copyright (C) 2013-2018 Greenbone Networks GmbH
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
 * @file  manage_acl.c
 * @brief The Greenbone Vulnerability Manager management library (Access
 * Control Layer).
 *
 * This file isolates the access control portions of the GVM
 * management library.
 */

#include "manage_acl.h"

#include "manage_sql.h"
#include "sql.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Test whether a user may perform an operation.
 *
 * @param[in]  operation  Name of operation.
 *
 * @return 1 if user has permission, else 0.
 */
int
acl_user_may (const char *operation)
{
  int ret;
  gchar *quoted_operation;

  assert (operation);

  if (strlen (current_credentials.uuid) == 0)
    /* Allow the dummy user in init_manage to do anything. */
    return 1;

  if (sql_int ("SELECT user_can_everything ('%s');", current_credentials.uuid))
    return 1;

  quoted_operation = sql_quote (operation);

  ret = sql_int (ACL_USER_MAY ("0"),
                 current_credentials.uuid,
                 current_credentials.uuid,
                 current_credentials.uuid,
                 quoted_operation,
                 quoted_operation,
                 quoted_operation,
                 quoted_operation);

  g_free (quoted_operation);

  return ret;
}

/**
 * @brief Check whether a role has Super Admin capability.
 *
 * @param[in]  role_id  ID of role.
 *
 * @return 1 if role can Super Admin, else 0.
 */
int
acl_role_can_super_everyone (const char *role_id)
{
  gchar *quoted_role_id;
  quoted_role_id = sql_quote (role_id);
  if (sql_int (
        " SELECT EXISTS (SELECT * FROM permissions"
        "                WHERE name = 'Super'"
        /*                    Super on everyone. */
        "                AND (resource = 0)"
        "                AND subject_location"
        "                    = " G_STRINGIFY (
          LOCATION_TABLE) "                AND (subject_type = 'role'"
                          "                     AND subject"
                          "                         = (SELECT id"
                          "                            FROM roles"
                          "                            WHERE uuid = '%s')));",
        role_id))
    {
      g_free (quoted_role_id);
      return 1;
    }
  g_free (quoted_role_id);
  return 0;
}

/**
 * @brief Check whether a user is a Super Admin.
 *
 * @param[in]  uuid  Uuid of user.
 *
 * @return 1 if user is a Super Admin, else 0.
 */
int
acl_user_can_super_everyone (const char *uuid)
{
  gchar *quoted_uuid;

  quoted_uuid = sql_quote (uuid);
  if (
    sql_int (
      " SELECT EXISTS (SELECT * FROM permissions"
      "                WHERE name = 'Super'"
      /*                    Super on everyone. */
      "                AND (resource = 0)"
      "                AND subject_location"
      "                    = " G_STRINGIFY (
        LOCATION_TABLE) "                AND ((subject_type = 'user'"
                        "                      AND subject"
                        "                          = (SELECT id FROM users"
                        "                             WHERE users.uuid = '%s'))"
                        "                     OR (subject_type = 'group'"
                        "                         AND subject"
                        "                             IN (SELECT DISTINCT "
                        "\"group\""
                        "                                 FROM group_users"
                        "                                 WHERE \"user\""
                        "                                       = (SELECT id"
                        "                                          FROM users"
                        "                                          WHERE "
                        "users.uuid"
                        "                                                = "
                        "'%s')))"
                        "                     OR (subject_type = 'role'"
                        "                         AND subject"
                        "                             IN (SELECT DISTINCT role"
                        "                                 FROM role_users"
                        "                                 WHERE \"user\""
                        "                                       = (SELECT id"
                        "                                          FROM users"
                        "                                          WHERE "
                        "users.uuid"
                        "                                                = "
                        "'%s')))));",
      quoted_uuid,
      quoted_uuid,
      quoted_uuid))
    {
      g_free (quoted_uuid);
      return 1;
    }
  g_free (quoted_uuid);
  return 0;
}

/**
 * @brief Test whether a user may perform any operation.
 *
 * @param[in]  user_id  UUID of user.
 *
 * @return 1 if user has permission, else 0.
 */
int
acl_user_can_everything (const char *user_id)
{
  gchar *quoted_user_id;
  int ret;

  quoted_user_id = sql_quote (user_id);
  ret = sql_int (
    "SELECT count(*) > 0 FROM permissions"
    " WHERE resource = 0"
    " AND subject_location"
    "     = " G_STRINGIFY (
      LOCATION_TABLE) " AND ((subject_type = 'user'"
                      "       AND subject"
                      "           = (SELECT id FROM users"
                      "              WHERE users.uuid = '%s'))"
                      "      OR (subject_type = 'group'"
                      "          AND subject"
                      "              IN (SELECT DISTINCT \"group\""
                      "                  FROM group_users"
                      "                  WHERE \"user\" = (SELECT id"
                      "                                    FROM users"
                      "                                    WHERE users.uuid"
                      "                                          = '%s')))"
                      "      OR (subject_type = 'role'"
                      "          AND subject"
                      "              IN (SELECT DISTINCT role"
                      "                  FROM role_users"
                      "                  WHERE \"user\" = (SELECT id"
                      "                                    FROM users"
                      "                                    WHERE users.uuid"
                      "                                          = '%s'))))"
                      " AND name = 'Everything';",
    quoted_user_id,
    quoted_user_id,
    quoted_user_id);
  g_free (quoted_user_id);
  return ret;
}

/**
 * @brief Test whether a user has super permission on another user.
 *
 * @param[in]  super_user_id  UUID of user who may have super permission.
 * @param[in]  other_user     Other user.
 *
 * @return 1 if user has permission, else 0.
 */
int
acl_user_has_super (const char *super_user_id, user_t other_user)
{
  gchar *quoted_super_user_id;

  quoted_super_user_id = sql_quote (super_user_id);
  if (
    sql_int (
      " SELECT EXISTS (SELECT * FROM permissions"
      "                WHERE name = 'Super'"
      /*                    Super on everyone. */
      "                AND ((resource = 0)"
      /*                    Super on other_user. */
      "                     OR ((resource_type = 'user')"
      "                         AND (resource = %llu))"
      /*                    Super on other_user's role. */
      "                     OR ((resource_type = 'role')"
      "                         AND (resource"
      "                              IN (SELECT DISTINCT role"
      "                                  FROM role_users"
      "                                  WHERE \"user\" = %llu)))"
      /*                    Super on other_user's group. */
      "                     OR ((resource_type = 'group')"
      "                         AND (resource"
      "                              IN (SELECT DISTINCT \"group\""
      "                                  FROM group_users"
      "                                  WHERE \"user\" = %llu))))"
      "                AND subject_location"
      "                    = " G_STRINGIFY (
        LOCATION_TABLE) "                AND ((subject_type = 'user'"
                        "                      AND subject"
                        "                          = (SELECT id FROM users"
                        "                             WHERE users.uuid = '%s'))"
                        "                     OR (subject_type = 'group'"
                        "                         AND subject"
                        "                             IN (SELECT DISTINCT "
                        "\"group\""
                        "                                 FROM group_users"
                        "                                 WHERE \"user\""
                        "                                       = (SELECT id"
                        "                                          FROM users"
                        "                                          WHERE "
                        "users.uuid"
                        "                                                = "
                        "'%s')))"
                        "                     OR (subject_type = 'role'"
                        "                         AND subject"
                        "                             IN (SELECT DISTINCT role"
                        "                                 FROM role_users"
                        "                                 WHERE \"user\""
                        "                                       = (SELECT id"
                        "                                          FROM users"
                        "                                          WHERE "
                        "users.uuid"
                        "                                                = "
                        "'%s')))));",
      other_user,
      other_user,
      other_user,
      super_user_id,
      super_user_id,
      super_user_id))
    {
      g_free (quoted_super_user_id);
      return 1;
    }
  g_free (quoted_super_user_id);
  return 0;
}

/**
 * @brief Check whether a user is an Admin.
 *
 * @param[in]  uuid  Uuid of user.
 *
 * @return 1 if user is an Admin, else 0.
 */
int
acl_user_is_admin (const char *uuid)
{
  int ret;
  gchar *quoted_uuid;

  quoted_uuid = sql_quote (uuid);
  ret = sql_int ("SELECT count (*) FROM role_users"
                 " WHERE role = (SELECT id FROM roles"
                 "               WHERE uuid = '" ROLE_UUID_ADMIN "')"
                 " AND \"user\" = (SELECT id FROM users WHERE uuid = '%s');",
                 quoted_uuid);
  g_free (quoted_uuid);
  return ret;
}

/**
 * @brief Check whether a user is an Observer.
 *
 * @param[in]  uuid  Uuid of user.
 *
 * @return 1 if user is an Observer, else 0.
 */
int
acl_user_is_observer (const char *uuid)
{
  int ret;
  gchar *quoted_uuid;

  quoted_uuid = sql_quote (uuid);
  ret = sql_int ("SELECT count (*) FROM role_users"
                 " WHERE role = (SELECT id FROM roles"
                 "               WHERE uuid = '" ROLE_UUID_OBSERVER "')"
                 " AND \"user\" = (SELECT id FROM users WHERE uuid = '%s');",
                 quoted_uuid);
  g_free (quoted_uuid);
  return ret;
}

/**
 * @brief Check whether a user is a Super Admin.
 *
 * @param[in]  uuid  Uuid of user.
 *
 * @return 1 if user is a Super Admin, else 0.
 */
int
acl_user_is_super_admin (const char *uuid)
{
  int ret;
  gchar *quoted_uuid;

  quoted_uuid = sql_quote (uuid);
  ret = sql_int ("SELECT count (*) FROM role_users"
                 " WHERE role = (SELECT id FROM roles"
                 "               WHERE uuid = '" ROLE_UUID_SUPER_ADMIN "')"
                 " AND \"user\" = (SELECT id FROM users WHERE uuid = '%s');",
                 quoted_uuid);
  g_free (quoted_uuid);
  return ret;
}

/**
 * @brief Check whether a user has the User role.
 *
 * @param[in]  uuid  Uuid of user.
 *
 * @return 1 if user has the User role, else 0.
 */
int
acl_user_is_user (const char *uuid)
{
  int ret;
  gchar *quoted_uuid;

  quoted_uuid = sql_quote (uuid);
  ret = sql_int ("SELECT count (*) FROM role_users"
                 " WHERE role = (SELECT id FROM roles"
                 "               WHERE uuid = '" ROLE_UUID_USER "')"
                 " AND \"user\" = (SELECT id FROM users WHERE uuid = '%s');",
                 quoted_uuid);
  g_free (quoted_uuid);
  return ret;
}

/* TODO This is only predicatable for unique fields like "id".  If the field
 *      is "name" then "SELECT ... format" will choose arbitrarily between
 *      the resources that have the same name. */
/**
 * @brief Super clause.
 *
 * @param[in]  format  Value format specifier.
 */
#define ACL_SUPER_CLAUSE(format)                                               \
  "                name = 'Super'" /*                    Super on everyone. */ \
  "                AND ((resource = 0)" /*                    Super on         \
                                           other_user. */                      \
  "                     OR ((resource_type = 'user')"                          \
  "                         AND (resource = (SELECT %ss%s.owner"               \
  "                                          FROM %ss%s"                       \
  "                                          WHERE %s = " format               \
  ")))" /*                    Super on other_user's role. */                   \
  "                     OR ((resource_type = 'role')"                          \
  "                         AND (resource"                                     \
  "                              IN (SELECT DISTINCT role"                     \
  "                                  FROM role_users"                          \
  "                                  WHERE \"user\""                           \
  "                                        = (SELECT %ss%s.owner"              \
  "                                           FROM %ss%s"                      \
  "                                           WHERE %s"                        \
  "                                                 = " format                 \
  "))))" /*                    Super on other_user's group. */                 \
  "                     OR ((resource_type = 'group')"                         \
  "                         AND (resource"                                     \
  "                              IN (SELECT DISTINCT \"group\""                \
  "                                  FROM group_users"                         \
  "                                  WHERE \"user\""                           \
  "                                        = (SELECT %ss%s.owner"              \
  "                                           FROM %ss%s"                      \
  "                                           WHERE %s = " format ")))))"      \
  "                AND subject_location = " G_STRINGIFY (                      \
    LOCATION_TABLE) "                AND ((subject_type = 'user'"              \
                    "                      AND subject"                        \
                    "                          = (SELECT id FROM users"        \
                    "                             WHERE users.uuid = '%s'))"   \
                    "                     OR (subject_type = 'group'"          \
                    "                         AND subject"                     \
                    "                             IN (SELECT DISTINCT "        \
                    "\"group\""                                                \
                    "                                 FROM group_users"        \
                    "                                 WHERE \"user\""          \
                    "                                       = (SELECT id"      \
                    "                                          FROM users"     \
                    "                                          WHERE "         \
                    "users.uuid"                                               \
                    "                                                = "       \
                    "'%s')))"                                                  \
                    "                     OR (subject_type = 'role'"           \
                    "                         AND subject"                     \
                    "                             IN (SELECT DISTINCT role"    \
                    "                                 FROM role_users"         \
                    "                                 WHERE \"user\""          \
                    "                                       = (SELECT id"      \
                    "                                          FROM users"     \
                    "                                          WHERE "         \
                    "users.uuid"                                               \
                    "                                                = "       \
                    "'%s'))))"

/**
 * @brief Super clause arguments.
 *
 * @param[in]  type     Type of resource.
 * @param[in]  field    Field to compare.  Typically "uuid".
 * @param[in]  value    Expected value of field.
 * @param[in]  user_id  UUID of user.
 * @param[in]  trash    Whether to search trash.
 */
#define ACL_SUPER_CLAUSE_ARGS(type, field, value, user_id, trash)           \
  type, trash ? (strcasecmp (type, "task") ? "_trash" : "") : "", type,     \
    trash ? (strcasecmp (type, "task") ? "_trash" : "") : "", field, value, \
    type, trash ? (strcasecmp (type, "task") ? "_trash" : "") : "", type,   \
    trash ? (strcasecmp (type, "task") ? "_trash" : "") : "", field, value, \
    type, trash ? (strcasecmp (type, "task") ? "_trash" : "") : "", type,   \
    trash ? (strcasecmp (type, "task") ? "_trash" : "") : "", field, value, \
    user_id, user_id, user_id

/**
 * @brief Test whether a user has Super permission on a resource.
 *
 * @param[in]  type      Type of resource.
 * @param[in]  field     Field to compare with value.
 * @param[in]  value     Identifier value of resource.
 * @param[in]  trash     Whether resource is in trash.
 *
 * @return 1 if user has Super, else 0.
 */
static int
acl_user_has_super_on (const char *type,
                       const char *field,
                       const char *value,
                       int trash)
{
  gchar *quoted_value;
  quoted_value = sql_quote (value);
  if (sql_int ("SELECT EXISTS (SELECT * FROM permissions"
               "               WHERE " ACL_SUPER_CLAUSE ("'%s'") ");",
               ACL_SUPER_CLAUSE_ARGS (
                 type, field, quoted_value, current_credentials.uuid, trash)))
    {
      g_free (quoted_value);
      return 1;
    }
  g_free (quoted_value);
  return 0;
}

/**
 * @brief Test whether a user has Super permission on a resource.
 *
 * @param[in]  type      Type of resource.
 * @param[in]  field     Field to compare with resource.
 * @param[in]  resource  Resource.
 * @param[in]  trash     Whether resource is in trash.
 *
 * @return 1 if user has Super, else 0.
 */
static int
acl_user_has_super_on_resource (const char *type,
                                const char *field,
                                resource_t resource,
                                int trash)
{
  if (sql_int ("SELECT EXISTS (SELECT * FROM permissions"
               "               WHERE " ACL_SUPER_CLAUSE ("%llu") ");",
               ACL_SUPER_CLAUSE_ARGS (
                 type, field, resource, current_credentials.uuid, trash)))
    return 1;
  return 0;
}

/**
 * @brief Test whether a user is the actual owner of a resource.
 *
 * @param[in]  type   Type of resource, for example "task".
 * @param[in]  uuid   UUID of resource.
 *
 * @return 1 if user actually owns resource, else 0.
 */
int
acl_user_is_owner (const char *type, const char *uuid)
{
  int ret;
  gchar *quoted_uuid;

  assert (uuid && current_credentials.uuid);

  quoted_uuid = g_strdup (uuid);
  ret = sql_int ("SELECT count(*) FROM %ss"
                 " WHERE uuid = '%s'"
                 " AND owner = (SELECT users.id FROM users"
                 "              WHERE users.uuid = '%s');",
                 type,
                 quoted_uuid,
                 current_credentials.uuid);
  g_free (quoted_uuid);

  return ret;
}

/**
 * @brief Test whether a user effectively owns a resource.
 *
 * A Super permissions can give a user effective ownership of another
 * user's resource.
 *
 * @param[in]  type  Type of resource, for example "task".
 * @param[in]  uuid      UUID of resource.
 * @param[in]  trash     Whether the resource is in the trash.
 *
 * @return 1 if user owns resource, else 0.
 */
int
acl_user_owns_uuid (const char *type, const char *uuid, int trash)
{
  int ret;
  gchar *quoted_uuid;

  assert (current_credentials.uuid);

  if ((strcmp (type, "nvt") == 0) || (strcmp (type, "cve") == 0)
      || (strcmp (type, "cpe") == 0) || (strcmp (type, "ovaldef") == 0)
      || (strcmp (type, "cert_bund_adv") == 0)
      || (strcmp (type, "dfn_cert_adv") == 0))
    return 1;

  if (acl_user_has_super_on (type, "uuid", uuid, 0))
    return 1;

  quoted_uuid = sql_quote (uuid);
  if (strcmp (type, "result") == 0)
    ret = sql_int ("SELECT count(*) FROM results, reports"
                   " WHERE results.uuid = '%s'"
                   " AND results.report = reports.id"
                   " AND (reports.owner = (SELECT users.id FROM users"
                   "                       WHERE users.uuid = '%s'));",
                   quoted_uuid,
                   current_credentials.uuid);
  else if (strcmp (type, "report") == 0)
    ret = sql_int ("SELECT count(*) FROM reports"
                   " WHERE uuid = '%s'"
                   " AND (owner = (SELECT users.id FROM users"
                   "               WHERE users.uuid = '%s'));",
                   quoted_uuid,
                   current_credentials.uuid);
  else if (strcmp (type, "permission") == 0)
    ret = sql_int ("SELECT count(*) FROM permissions%s"
                   " WHERE uuid = '%s'"
                   " AND ((owner IS NULL)"
                   "      OR (owner = (SELECT users.id FROM users"
                   "                   WHERE users.uuid = '%s')));",
                   trash ? "_trash" : "",
                   quoted_uuid,
                   current_credentials.uuid);
  else
    ret = sql_int ("SELECT count(*) FROM %ss%s"
                   " WHERE uuid = '%s'"
                   "%s"
                   " AND (owner = (SELECT users.id FROM users"
                   "               WHERE users.uuid = '%s'));",
                   type,
                   (strcmp (type, "task") && trash) ? "_trash" : "",
                   quoted_uuid,
                   (strcmp (type, "task")
                      ? ""
                      : (trash ? " AND hidden = 2" : " AND hidden < 2")),
                   current_credentials.uuid);
  g_free (quoted_uuid);

  return ret;
}

/**
 * @brief Test whether a user effectively owns a resource.
 *
 * A Super permissions can give a user effective ownership of another
 * user's resource.
 *
 * @param[in]  type      Type of resource, for example "task".
 * @param[in]  resource  Resource.
 * @param[in]  trash     Whether the resource is in the trash.
 *
 * @return 1 if user owns resource, else 0.
 */
int
acl_user_owns (const char *type, resource_t resource, int trash)
{
  int ret;

  assert (current_credentials.uuid);

  if ((strcmp (type, "nvt") == 0) || (strcmp (type, "cve") == 0)
      || (strcmp (type, "cpe") == 0) || (strcmp (type, "ovaldef") == 0)
      || (strcmp (type, "cert_bund_adv") == 0)
      || (strcmp (type, "dfn_cert_adv") == 0))
    return 1;

  if (acl_user_has_super_on_resource (type, "id", resource, trash))
    return 1;

  if (strcmp (type, "result") == 0)
    ret = sql_int ("SELECT count(*) FROM results, reports"
                   " WHERE results.id = %llu"
                   " AND results.report = reports.id"
                   " AND (reports.owner = (SELECT users.id FROM users"
                   "                       WHERE users.uuid = '%s'));",
                   resource,
                   current_credentials.uuid);
  else
    ret = sql_int ("SELECT count(*) FROM %ss%s"
                   " WHERE id = %llu"
                   "%s"
                   " AND (owner = (SELECT users.id FROM users"
                   "               WHERE users.uuid = '%s'));",
                   type,
                   (strcmp (type, "task") && trash) ? "_trash" : "",
                   resource,
                   (strcmp (type, "task")
                      ? ""
                      : (trash ? " AND hidden = 2" : " AND hidden < 2")),
                   current_credentials.uuid);

  return ret;
}

/**
 * @brief Test whether a user effectively owns a resource.
 *
 * A Super permissions can give a user effective ownership of another
 * user's resource.
 *
 * @param[in]  type  Type of resource, for example "task".
 * @param[in]  uuid  UUID of resource.
 *
 * @return 1 if user owns resource, else 0.
 */
int
acl_user_owns_trash_uuid (const char *type, const char *uuid)
{
  int ret;
  gchar *quoted_uuid;

  assert (current_credentials.uuid);
  assert (type && strcmp (type, "task"));

  if (acl_user_has_super_on (type, "uuid", uuid, 1))
    return 1;

  quoted_uuid = sql_quote (uuid);
  ret = sql_int ("SELECT count(*) FROM %ss_trash"
                 " WHERE uuid = '%s'"
                 " AND (owner = (SELECT users.id FROM users"
                 "               WHERE users.uuid = '%s'));",
                 type,
                 quoted_uuid,
                 current_credentials.uuid);
  g_free (quoted_uuid);

  return ret;
}

/**
 * @brief Test whether the user may access a resource.
 *
 * @param[in]  type      Type of resource, for example "task".
 * @param[in]  uuid      UUID of resource.
 * @param[in]  permission       Permission.
 * @param[in]  trash            Whether the resource is in the trash.
 *
 * @return 1 if user may access resource, else 0.
 */
int
acl_user_has_access_uuid (const char *type,
                          const char *uuid,
                          const char *permission,
                          int trash)
{
  int ret, get;
  char *uuid_task;
  gchar *quoted_permission, *quoted_uuid;

  assert (current_credentials.uuid);

  if (permission && (valid_gmp_command (permission) == 0))
    return 0;

  if (!strcmp (current_credentials.uuid, ""))
    return 1;

  /* The Super case is checked here. */
  ret = acl_user_owns_uuid (type, uuid, trash);
  if (ret)
    return ret;

  if (trash)
    /* For simplicity, trashcan items are visible only to their owners. */
    return 0;

  quoted_uuid = sql_quote (uuid);
  if (strcasecmp (type, "report") == 0)
    {
      task_t task;
      report_t report;

      switch (sql_int64 (
        &report, "SELECT id FROM reports WHERE uuid = '%s';", quoted_uuid))
        {
        case 0:
          break;
        case 1: /* Too few rows in result of query. */
          g_free (quoted_uuid);
          return 0;
          break;
        default: /* Programming error. */
          assert (0);
        case -1:
          g_free (quoted_uuid);
          return 0;
          break;
        }

      report_task (report, &task);
      if (task == 0)
        {
          g_free (quoted_uuid);
          return 0;
        }
      task_uuid (task, &uuid_task);
    }
  else if (strcasecmp (type, "result") == 0)
    {
      task_t task;

      switch (
        sql_int64 (&task, "SELECT task FROM results WHERE uuid = '%s';", uuid))
        {
        case 0:
          break;
        case 1: /* Too few rows in result of query. */
          g_free (quoted_uuid);
          return 0;
          break;
        default: /* Programming error. */
          assert (0);
        case -1:
          g_free (quoted_uuid);
          return 0;
          break;
        }

      task_uuid (task, &uuid_task);
    }
  else
    uuid_task = NULL;

  if ((strcmp (type, "permission") == 0)
      && ((permission == NULL)
          || (strlen (permission) > 3 && strncmp (permission, "get", 3) == 0)))
    {
      ret = sql_int (
        "SELECT count(*) FROM permissions"
        /* Any permission implies 'get'. */
        " WHERE (resource_uuid = '%s'"
        /* Users may view any permissions that affect them. */
        "        OR uuid = '%s')"
        " AND subject_location = " G_STRINGIFY (
          LOCATION_TABLE) " AND ((subject_type = 'user'"
                          "       AND subject"
                          "           = (SELECT id FROM users"
                          "              WHERE users.uuid = '%s'))"
                          "      OR (subject_type = 'group'"
                          "          AND subject"
                          "              IN (SELECT DISTINCT \"group\""
                          "                  FROM group_users"
                          "                  WHERE \"user\" = (SELECT id"
                          "                                    FROM users"
                          "                                    WHERE users.uuid"
                          "                                          = '%s')))"
                          "      OR (subject_type = 'role'"
                          "          AND subject"
                          "              IN (SELECT DISTINCT role"
                          "                  FROM role_users"
                          "                  WHERE \"user\" = (SELECT id"
                          "                                    FROM users"
                          "                                    WHERE users.uuid"
                          "                                          = "
                          "'%s'))));",
        uuid_task ? uuid_task : quoted_uuid,
        uuid_task ? uuid_task : quoted_uuid,
        current_credentials.uuid,
        current_credentials.uuid,
        current_credentials.uuid);
      free (uuid_task);
      g_free (quoted_uuid);
      return ret;
    }
  else if (strcmp (type, "permission") == 0)
    {
      /* There are no "permissions on permissions", so if a user does not
       * effectively own a permission, there's no way for the user to access
       * the permission. */
      free (uuid_task);
      g_free (quoted_uuid);
      return 0;
    }

  get = (permission == NULL
         || (strlen (permission) > 3 && strncmp (permission, "get", 3) == 0));
  quoted_permission = sql_quote (permission ? permission : "");

  ret = sql_int (
    "SELECT count(*) FROM permissions"
    " WHERE resource_uuid = '%s'"
    " AND subject_location = " G_STRINGIFY (
      LOCATION_TABLE) " AND ((subject_type = 'user'"
                      "       AND subject"
                      "           = (SELECT id FROM users"
                      "              WHERE users.uuid = '%s'))"
                      "      OR (subject_type = 'group'"
                      "          AND subject"
                      "              IN (SELECT DISTINCT \"group\""
                      "                  FROM group_users"
                      "                  WHERE \"user\" = (SELECT id"
                      "                                    FROM users"
                      "                                    WHERE users.uuid"
                      "                                          = '%s')))"
                      "      OR (subject_type = 'role'"
                      "          AND subject"
                      "              IN (SELECT DISTINCT role"
                      "                  FROM role_users"
                      "                  WHERE \"user\" = (SELECT id"
                      "                                    FROM users"
                      "                                    WHERE users.uuid"
                      "                                          = '%s'))))"
                      " %s%s%s;",
    uuid_task ? uuid_task : quoted_uuid,
    current_credentials.uuid,
    current_credentials.uuid,
    current_credentials.uuid,
    (get ? "" : "AND name = '"),
    (get ? "" : quoted_permission),
    (get ? "" : "'"));

  free (uuid_task);
  g_free (quoted_permission);
  g_free (quoted_uuid);
  return ret;
}

/**
 * @brief Generate the ownership part of an SQL WHERE clause for a given user.
 *
 * @param[in]  user_id         UUID of user.  "" can be used to rely on
 *                             user_sql alone, except when type is "permission".
 * @param[in]  user_sql        SQL to get user.
 * @param[in]  type            Type of resource.
 * @param[in]  get             GET data.
 * @param[in]  owned           Only get items accessible by the given user.
 * @param[in]  owner_filter    Owner filter keyword.
 * @param[in]  resource        Resource.
 * @param[in]  permissions     Permissions.
 * @param[out] with            Address for WITH clause if allowed, else NULL.
 *
 * @return Newly allocated owned clause.
 */
static gchar *
acl_where_owned_user (const char *user_id,
                      const char *user_sql,
                      const char *type,
                      const get_data_t *get,
                      int owned,
                      const gchar *owner_filter,
                      resource_t resource,
                      array_t *permissions,
                      gchar **with)
{
  gchar *owned_clause, *filter_owned_clause;
  GString *permission_or;
  int table_trash;
  guint index;

  if (with)
    *with = NULL;

  if (owned == 0)
    return g_strdup (" t ()");

  permission_or = g_string_new ("");
  index = 0;
  if (permissions == NULL || permissions->len == 0)
    {
      /* Treat filters with no permissions keyword as "any". */
      permission_or = g_string_new ("t ()");
      index = 1;
    }
  else if (permissions)
    for (; index < permissions->len; index++)
      {
        gchar *permission, *quoted;
        permission = (gchar *) g_ptr_array_index (permissions, index);
        if (strcasecmp (permission, "any") == 0)
          {
            g_string_free (permission_or, TRUE);
            permission_or = g_string_new ("t ()");
            index = 1;
            break;
          }
        quoted = sql_quote (permission);
        if (index == 0)
          g_string_append_printf (permission_or, "name = '%s'", quoted);
        else
          g_string_append_printf (permission_or, " OR name = '%s'", quoted);
        g_free (quoted);
      }

  table_trash = get->trash && strcasecmp (type, "task");
  if (resource || (user_id == NULL))
    owned_clause = g_strdup (" (t ())");
  else if (with)
    {
      gchar *permission_clause;

      /* Caller supports WITH clause. */

      *with = g_strdup_printf (
        "WITH permissions_subject"
        "     AS (SELECT * FROM permissions"
        "         WHERE subject_location"
        "               = " G_STRINGIFY (
          LOCATION_TABLE) "         AND ((subject_type = 'user'"
                          "               AND subject"
                          "                   = (%s))"
                          "              OR (subject_type = 'group'"
                          "                  AND subject"
                          "                      IN (SELECT DISTINCT \"group\""
                          "                          FROM group_users"
                          "                          WHERE \"user\""
                          "                                = (%s)))"
                          "              OR (subject_type = 'role'"
                          "                  AND subject"
                          "                      IN (SELECT DISTINCT role"
                          "                          FROM role_users"
                          "                          WHERE \"user\""
                          "                                = (%s))))),"
                          "     super_on_users"
                          "     AS (SELECT DISTINCT *"
                          "         FROM (SELECT resource FROM "
                          "permissions_subject"
                          "               WHERE name = 'Super'"
                          "               AND resource_type = 'user'"
                          "               UNION"
                          "               SELECT \"user\" FROM role_users"
                          "               WHERE role"
                          "                     IN (SELECT resource"
                          "                         FROM permissions_subject"
                          "                         WHERE name = 'Super'"
                          "                         AND resource_type = 'role')"
                          "               UNION"
                          "               SELECT \"user\" FROM group_users"
                          "               WHERE \"group\""
                          "                     IN (SELECT resource"
                          "                         FROM permissions_subject"
                          "                         WHERE name = 'Super'"
                          "                         AND resource_type = "
                          "'group'))"
                          "              AS all_users)",
        user_sql,
        user_sql,
        user_sql);

      permission_clause = NULL;
      if (user_id && index)
        {
          gchar *clause;
          clause = g_strdup_printf (
            "OR EXISTS"
            " (SELECT id FROM permissions_subject"
            "  WHERE resource = %ss%s.id"
            "  AND resource_type = '%s'"
            "  AND resource_location = %i"
            "  AND (%s))",
            type,
            get->trash && strcmp (type, "task") ? "_trash" : "",
            type,
            get->trash ? LOCATION_TRASH : LOCATION_TABLE,
            permission_or->str);

          if (strcmp (type, "report") == 0)
            permission_clause =
              g_strdup_printf ("%s"
                               " OR EXISTS"
                               " (SELECT id FROM permissions_subject"
                               "  WHERE resource = reports%s.task"
                               "  AND resource_type = 'task'"
                               "  AND (%s))",
                               clause,
                               get->trash ? "_trash" : "",
                               permission_or->str);
          else if (strcmp (type, "result") == 0)
            permission_clause =
              g_strdup_printf ("%s"
                               " OR EXISTS"
                               " (SELECT id FROM permissions_subject"
                               "  WHERE resource = results%s.task"
                               "  AND resource_type = 'task'"
                               "  AND (%s))",
                               clause,
                               get->trash ? "_trash" : "",
                               permission_or->str);

          if ((strcmp (type, "report") == 0) || (strcmp (type, "result") == 0))
            g_free (clause);
          else
            permission_clause = clause;
        }

      if (strcmp (type, "permission") == 0)
        {
          int admin;
          assert (strcmp (user_id, ""));
          admin = acl_user_can_everything (user_id);
          /* A user sees permissions that involve the user.  Admin users also
           * see all higher level permissions. */
          owned_clause =
            g_strdup_printf (/* Either the user is the owner. */
                             " ((permissions%s.owner = (%s))"
                             /* Or, for admins, it's a global permission. */
                             "  %s"
                             /* Or the permission applies to the user. */
                             "  OR (%i = 0" /* Skip for trash. */
                             "      AND (permissions%s.subject_type = 'user'"
                             "           AND permissions%s.subject_location"
                             "               = " G_STRINGIFY (
                               LOCATION_TABLE) "           AND "
                                               "permissions%s.subject"
                                               "               = (%s)))"
                                               /* Or the permission applies to
                                                  the user's group. */
                                               "  OR (%i = 0" /* Skip for trash.
                                                               */
                                               "      AND "
                                               "(permissions%s.subject_type = "
                                               "'group'"
                                               "           AND "
                                               "permissions%s.subject_location"
                                               "               = " G_STRINGIFY (
                                                 LOCATION_TABLE) "           "
                                                                 "AND "
                                                                 "permissions%"
                                                                 "s.subject"
                                                                 "             "
                                                                 "  IN (SELECT "
                                                                 "DISTINCT "
                                                                 "\"group\""
                                                                 "             "
                                                                 "      FROM "
                                                                 "group_users"
                                                                 "             "
                                                                 "      WHERE "
                                                                 "\"user\" = "
                                                                 "(%s))))"
                                                                 /* Or the
                                                                    permission
                                                                    applies to
                                                                    the user's
                                                                    role. */
                                                                 "  OR (%i = 0" /* Skip for trash. */
                                                                 "      AND "
                                                                 "(permissions%"
                                                                 "s.subject_"
                                                                 "type = 'role'"
                                                                 "           "
                                                                 "AND "
                                                                 "permissions%"
                                                                 "s.subject_"
                                                                 "location"
                                                                 "             "
                                                                 "  "
                                                                 "="
                                                                 " " G_STRINGIFY (
                                                                   LOCATION_TABLE) "           AND permissions%s.subject"
                                                                                   "               IN (SELECT DISTINCT role"
                                                                                   "                   FROM role_users"
                                                                                   "                   WHERE \"user\" = (%s))))"
                                                                                   /* Or the user has super permission on all. */
                                                                                   "  OR EXISTS (SELECT * FROM permissions_subject"
                                                                                   "             WHERE name = 'Super'"
                                                                                   "             AND (resource = 0))"
                                                                                   /* Or the user has super permission on the owner,
                                                                                    * (directly, via the role, or via the group). */
                                                                                   "  OR permissions%s.owner IN (SELECT *"
                                                                                   "                            FROM super_on_users)"
                                                                                   "  %s)",
                             get->trash ? "_trash" : "",
                             user_sql,
                             admin ? (get->trash
                                        ? "OR (permissions_trash.owner IS NULL)"
                                        : "OR (permissions.owner IS NULL)")
                                   : "",
                             get->trash,
                             table_trash ? "_trash" : "",
                             table_trash ? "_trash" : "",
                             table_trash ? "_trash" : "",
                             user_sql,
                             get->trash,
                             table_trash ? "_trash" : "",
                             table_trash ? "_trash" : "",
                             table_trash ? "_trash" : "",
                             user_sql,
                             get->trash,
                             table_trash ? "_trash" : "",
                             table_trash ? "_trash" : "",
                             table_trash ? "_trash" : "",
                             user_sql,
                             table_trash ? "_trash" : "",
                             permission_clause ? permission_clause : "");
        }
      else
        /* Any resource type other than Permissions. */
        owned_clause =
          g_strdup_printf (/* Either the user is the owner. */
                           " ((%ss%s.owner"
                           "   = (%s))"
                           /* Or the user has super permission on all. */
                           "  OR EXISTS (SELECT * FROM permissions_subject"
                           "             WHERE name = 'Super'"
                           "             AND (resource = 0))"
                           /* Or the user has super permission on the owner,
                            * (directly, via the role, or via the group). */
                           "  OR %ss%s.owner IN (SELECT *"
                           "                     FROM super_on_users)"
                           "  %s)",
                           type,
                           table_trash ? "_trash" : "",
                           user_sql,
                           type,
                           table_trash ? "_trash" : "",
                           permission_clause ? permission_clause : "");

      g_free (permission_clause);
    }
  else
    {
      gchar *permission_clause;

      /* Caller does not support WITH.
       *
       * The result_overrides view is the last caller that requires this case,
       * because it cannot support this WITH mechanism. */

      permission_clause = NULL;

      /* Check on index is because default is owner and global, for backward
       * compatibility. */
      if (user_id && index)
        {
          gchar *clause;
          clause = g_strdup_printf (
            "OR EXISTS"
            " (SELECT id FROM permissions"
            "  WHERE resource = %ss%s.id"
            "  AND resource_type = '%s'"
            "  AND resource_location = %i"
            "  AND subject_location"
            "      = " G_STRINGIFY (
              LOCATION_TABLE) "  AND ((subject_type = 'user'"
                              "        AND subject"
                              "            = (%s))"
                              "       OR (subject_type = 'group'"
                              "           AND subject"
                              "               IN (SELECT DISTINCT \"group\""
                              "                   FROM group_users"
                              "                   WHERE \"user\""
                              "                         = (%s)))"
                              "       OR (subject_type = 'role'"
                              "           AND subject"
                              "               IN (SELECT DISTINCT role"
                              "                   FROM role_users"
                              "                   WHERE \"user\""
                              "                         = (%s))))"
                              "  AND (%s))",
            type,
            get->trash && strcmp (type, "task") ? "_trash" : "",
            type,
            get->trash ? LOCATION_TRASH : LOCATION_TABLE,
            user_sql,
            user_sql,
            user_sql,
            permission_or->str);

          if (strcmp (type, "report") == 0)
            permission_clause = g_strdup_printf (
              "%s"
              " OR EXISTS"
              " (SELECT id FROM permissions"
              "  WHERE resource = reports%s.task"
              "  AND resource_type = 'task'"
              "  AND subject_location"
              "      = " G_STRINGIFY (
                LOCATION_TABLE) "  AND ((subject_type = 'user'"
                                "        AND subject"
                                "            = (%s))"
                                "       OR (subject_type = 'group'"
                                "           AND subject"
                                "               IN (SELECT DISTINCT \"group\""
                                "                   FROM group_users"
                                "                   WHERE \"user\""
                                "                         = (%s)))"
                                "       OR (subject_type = 'role'"
                                "           AND subject"
                                "               IN (SELECT DISTINCT role"
                                "                   FROM role_users"
                                "                   WHERE \"user\""
                                "                         = (%s))))"
                                "  AND (%s))",
              clause,
              get->trash ? "_trash" : "",
              user_sql,
              user_sql,
              user_sql,
              permission_or->str);
          else if (strcmp (type, "result") == 0)
            permission_clause = g_strdup_printf (
              "%s"
              " OR EXISTS"
              " (SELECT id FROM permissions"
              "  WHERE resource = results%s.task"
              "  AND resource_type = 'task'"
              "  AND subject_location"
              "      = " G_STRINGIFY (
                LOCATION_TABLE) "  AND ((subject_type = 'user'"
                                "        AND subject"
                                "            = (%s))"
                                "       OR (subject_type = 'group'"
                                "           AND subject"
                                "               IN (SELECT DISTINCT \"group\""
                                "                   FROM group_users"
                                "                   WHERE \"user\""
                                "                         = (%s)))"
                                "       OR (subject_type = 'role'"
                                "           AND subject"
                                "               IN (SELECT DISTINCT role"
                                "                   FROM role_users"
                                "                   WHERE \"user\""
                                "                         = (%s))))"
                                "  AND (%s))",
              clause,
              get->trash ? "_trash" : "",
              user_sql,
              user_sql,
              user_sql,
              permission_or->str);

          if ((strcmp (type, "report") == 0) || (strcmp (type, "result") == 0))
            g_free (clause);
          else
            permission_clause = clause;
        }

      owned_clause =
        g_strdup_printf (/* Either the user is the owner. */
                         " ((%ss%s.owner"
                         "   = (%s))"
                         /* Or the user has super permission. */
                         "  OR EXISTS (SELECT * FROM permissions"
                         "             WHERE name = 'Super'"
                         /*                 Super on everyone. */
                         "             AND ((resource = 0)"
                         /*                 Super on other_user. */
                         "                  OR ((resource_type = 'user')"
                         "                      AND (resource = %ss%s.owner))"
                         /*                 Super on other_user's role. */
                         "                  OR ((resource_type = 'role')"
                         "                      AND (resource"
                         "                           IN (SELECT DISTINCT role"
                         "                               FROM role_users"
                         "                               WHERE \"user\""
                         "                                     = %ss%s.owner)))"
                         /*                 Super on other_user's group. */
                         "                  OR ((resource_type = 'group')"
                         "                      AND (resource"
                         "                           IN (SELECT DISTINCT "
                         "\"group\""
                         "                               FROM group_users"
                         "                               WHERE \"user\""
                         "                                     = "
                         "%ss%s.owner))))"
                         "             AND subject_location"
                         "                 = " G_STRINGIFY (
                           LOCATION_TABLE) "             AND ((subject_type = "
                                           "'user'"
                                           "                   AND subject"
                                           "                       = (%s))"
                                           "                  OR (subject_type "
                                           "= 'group'"
                                           "                      AND subject"
                                           "                          IN "
                                           "(SELECT DISTINCT \"group\""
                                           "                              FROM "
                                           "group_users"
                                           "                              "
                                           "WHERE \"user\""
                                           "                                   "
                                           " = (%s)))"
                                           "                  OR (subject_type "
                                           "= 'role'"
                                           "                      AND subject"
                                           "                          IN "
                                           "(SELECT DISTINCT role"
                                           "                              FROM "
                                           "role_users"
                                           "                              "
                                           "WHERE \"user\""
                                           "                                   "
                                           " = (%s)))))"
                                           "  %s)",
                         type,
                         table_trash ? "_trash" : "",
                         user_sql,
                         type,
                         table_trash ? "_trash" : "",
                         type,
                         table_trash ? "_trash" : "",
                         type,
                         table_trash ? "_trash" : "",
                         user_sql,
                         user_sql,
                         user_sql,
                         permission_clause ? permission_clause : "");

      g_free (permission_clause);
    }

  g_string_free (permission_or, TRUE);

  if (get->trash && (strcasecmp (type, "task") == 0))
    {
      gchar *new;
      new = g_strdup_printf (" (%ss.hidden = 2"
                             "  AND %s)",
                             type,
                             owned_clause);
      g_free (owned_clause);
      owned_clause = new;
    }

  if (owner_filter == NULL
      || (owner_filter && (strcmp (owner_filter, "any") == 0)))
    filter_owned_clause = g_strdup (owned_clause);
  else if (owner_filter && strcmp (owner_filter, ""))
    {
      gchar *quoted;
      quoted = sql_quote (owner_filter);
      filter_owned_clause = g_strdup_printf ("(owner = (SELECT id"
                                             "          FROM users"
                                             "          WHERE name = '%s')"
                                             " AND %s)",
                                             quoted,
                                             owned_clause);
      g_free (quoted);
    }
  else
    filter_owned_clause = g_strdup_printf ("((owner = (%s))"
                                           " AND %s)",
                                           user_sql,
                                           owned_clause);

  g_free (owned_clause);

  return filter_owned_clause;
}

/**
 * @brief Generate the ownership part of an SQL WHERE clause.
 *
 * @param[in]  type            Type of resource.
 * @param[in]  get             GET data.
 * @param[in]  owned           Only get items owned by the current user.
 * @param[in]  owner_filter    Owner filter keyword.
 * @param[in]  resource        Resource.
 * @param[in]  permissions     Permissions.
 * @param[out] with            Address for WITH clause if allowed, else NULL.
 *
 * @return Newly allocated owned clause.
 */
gchar *
acl_where_owned (const char *type,
                 const get_data_t *get,
                 int owned,
                 const gchar *owner_filter,
                 resource_t resource,
                 array_t *permissions,
                 gchar **with)
{
  gchar *ret, *user_sql;
  if (current_credentials.uuid)
    user_sql = g_strdup_printf ("SELECT id FROM users WHERE users.uuid = '%s'",
                                current_credentials.uuid);
  else
    user_sql = NULL;
  ret = acl_where_owned_user (current_credentials.uuid,
                              user_sql,
                              type,
                              get,
                              owned,
                              owner_filter,
                              resource,
                              permissions,
                              with);
  g_free (user_sql);
  return ret;
}

/**
 * @brief Generate ownership part of WHERE, for getting a type of resource.
 *
 * @param[in]  type      Type of resource.
 * @param[in]  user_sql  SQL for getting user.  If NULL SQL will be for current
 *                       user.
 * @param[out] with      Return location for WITH preselection clause if
 *                       desired, else NULL.
 *
 * @return Newly allocated owned clause.
 */
gchar *
acl_where_owned_for_get (const char *type, const char *user_sql, gchar **with)
{
  gchar *owned_clause;
  get_data_t get;
  array_t *permissions;
  gchar *user_sql_new;

  if (user_sql)
    user_sql_new = g_strdup (user_sql);
  else if (current_credentials.uuid)
    user_sql_new = g_strdup_printf (
      "SELECT id FROM users WHERE users.uuid = '%s'", current_credentials.uuid);
  else
    user_sql_new = NULL;

  get.trash = 0;
  permissions = make_array ();
  array_add (permissions, g_strdup_printf ("get_%ss", type));
  owned_clause =
    acl_where_owned_user (current_credentials.uuid ? current_credentials.uuid
                                                   /* Use user_sql_new. */
                                                   : "",
                          user_sql_new,
                          type,
                          &get,
                          1, /* Do owner checks. */
                          "any",
                          0, /* Resource. */
                          permissions,
                          with);
  array_free (permissions);
  g_free (user_sql_new);

  return owned_clause;
}

/**
 * @brief Get an SQL values expression of users that can get a resource
 *
 * @param[in]  type         The resource type.
 * @param[in]  resource_id  The UUID of the resource.
 * @param[in]  users_where  Optional clause to limit users.
 *
 * @return  Newly allocated SQL string or NULL if no users have access.
 */

gchar *
acl_users_with_access_sql (const char *type,
                           const char *resource_id,
                           const char *users_where)
{
  GString *users_string;
  int users_count = 0;
  gchar *old_user_id, *command;
  iterator_t users;

  old_user_id = current_credentials.uuid;
  init_iterator (&users,
                 "SELECT id, uuid FROM users WHERE %s;",
                 users_where ? users_where : "t()");

  users_string = g_string_new ("(VALUES ");

  command = g_strdup_printf ("get_%ss", type);

  while (next (&users))
    {
      current_credentials.uuid = g_strdup (iterator_string (&users, 1));
      manage_session_init (current_credentials.uuid);
      if (acl_user_has_access_uuid (type, resource_id, command, 0))
        {
          if (users_count)
            g_string_append (users_string, ", ");

          g_string_append_printf (
            users_string, "(%llu)", iterator_int64 (&users, 0));
          users_count++;
        }
      g_free (current_credentials.uuid);
    }
  g_string_append (users_string, ")");
  cleanup_iterator (&users);

  current_credentials.uuid = old_user_id;
  manage_session_init (old_user_id);

  g_free (command);

  if (users_count == 0)
    {
      g_string_free (users_string, TRUE);
      return NULL;
    }

  return g_string_free (users_string, FALSE);
}

/**
 * @brief Get a static SQL condition selecting users that can get a resource
 *
 * @param[in]  type         The resource type.
 * @param[in]  resource_id  The UUID of the resource.
 * @param[in]  users_where  Optional clause to limit users.
 * @param[in]  user_expr    Expression for the user, e.g. the column name.
 *
 * @return  Newly allocated SQL string or NULL if no users have access.
 */

gchar *
acl_users_with_access_where (const char *type,
                             const char *resource_id,
                             const char *users_where,
                             const char *user_expr)
{
  gchar *values, *ret;
  assert (user_expr);
  values = acl_users_with_access_sql (type, resource_id, users_where);
  if (values)
    ret = g_strdup_printf ("%s IN %s", user_expr, values);
  else
    ret = g_strdup ("NOT t()");
  g_free (values);
  return ret;
}
