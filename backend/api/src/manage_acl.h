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
 * @file manage_acl.h
 * @brief Headers for Greenbone Vulnerability Manager: the Manage library.
 */

#ifndef _GVMD_MANAGE_ACL_H
#define _GVMD_MANAGE_ACL_H

#include "manage_sql.h"

#include <glib.h>

/**
 * @brief Generate SQL for user permission check.
 *
 * @param[in]  resource  Resource.
 */
#define ACL_USER_MAY(resource)                                                                               \
  "SELECT count(*) > 0 FROM permissions"                                                                     \
  " WHERE resource = " resource " AND subject_location = " G_STRINGIFY (                                     \
    LOCATION_TABLE) " AND ((subject_type = 'user'"                                                           \
                    "       AND subject"                                                                     \
                    "           = (SELECT id FROM users"                                                     \
                    "              WHERE users.uuid = '%s'))"                                                \
                    "      OR (subject_type = 'group'"                                                       \
                    "          AND subject"                                                                  \
                    "              IN (SELECT DISTINCT \"group\""                                            \
                    "                  FROM group_users"                                                     \
                    "                  WHERE \"user\" = (SELECT id"                                          \
                    "                                FROM users"                                             \
                    "                                WHERE users.uuid"                                       \
                    "                                      = '%s')))"                                        \
                    "      OR (subject_type = 'role'"                                                        \
                    "          AND subject"                                                                  \
                    "              IN (SELECT DISTINCT role"                                                 \
                    "                  FROM role_users"                                                      \
                    "                  WHERE \"user\" = (SELECT id"                                          \
                    "                                    FROM users"                                         \
                    "                                    WHERE users.uuid"                                   \
                    "                                          = '%s'))))" /* Any permission implies GET. */ \
                    " AND ((lower (substr ('%s', 1, 3)) = 'get'"                                             \
                    "       AND name LIKE '%%'"                                                              \
                    "                     || lower (substr ('%s',"                                           \
                    "                                       5,"                                              \
                    "                                       length ('%s') - "                                \
                    "5)))"                                                                                   \
                    "      OR name = lower ('%s'))"

/**
 * @brief Generate SQL for global check.
 *
 * This is the SQL clause for selecting global resources.
 */
#define ACL_IS_GLOBAL() "owner IS NULL"

/**
 * @brief Generate SQL for user ownership check.
 *
 * This is the SQL clause for selecting global resources and resources owned
 * directly by the user.
 *
 * Caller must organise the single argument, the user's UUID, as a string.
 */
#define ACL_USER_OWNS()                   \
  " (owner = (SELECT users.id FROM users" \
  "           WHERE users.uuid = '%s'))"

/**
 * @brief Generate SQL for user ownership check.
 *
 * This is the SQL clause for selecting global resources and resources owned
 * directly by the user.
 *
 * Caller must organise the single argument, the user's UUID, as a string.
 */
#define ACL_GLOBAL_OR_USER_OWNS()                                    \
  " ((" ACL_IS_GLOBAL () ")"                                         \
                         "  OR (owner = (SELECT users.id FROM users" \
                         "               WHERE users.uuid = '%s')))"

int
acl_user_may (const char *);

int
acl_user_can_everything (const char *);

int
acl_role_can_super_everyone (const char *);

int
acl_user_can_super_everyone (const char *);

int
acl_user_has_super (const char *, user_t);

int
acl_user_is_admin (const char *);

int
acl_user_is_user (const char *);

int
acl_user_is_super_admin (const char *);

int
acl_user_is_observer (const char *);

int
acl_user_owns (const char *, resource_t, int);

int
acl_user_is_owner (const char *, const char *);

int
acl_user_owns_uuid (const char *, const char *, int);

int
acl_user_owns_trash_uuid (const char *resource, const char *uuid);

int
acl_user_has_access_uuid (const char *, const char *, const char *, int);

gchar *
acl_where_owned (const char *,
                 const get_data_t *,
                 int,
                 const gchar *,
                 resource_t,
                 array_t *,
                 gchar **);

gchar *
acl_where_owned_for_get (const char *, const char *, gchar **);

gchar *
acl_users_with_access_sql (const char *, const char *, const char *);

gchar *
acl_users_with_access_where (const char *,
                             const char *,
                             const char *,
                             const char *);

#endif /* not _GVMD_MANAGE_ACL_H */
