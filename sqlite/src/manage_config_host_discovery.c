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
 * @file  manage_config_host_discovery.c
 * @brief GVM management layer: Predefined config: Host Discovery
 *
 * This file contains the creation of the predefined config Host Discovery.
 */

#include "manage.h"
#include "manage_sql.h"
#include "sql.h"

#include <assert.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md   main"

/**
 * @brief Make Host Discovery Scan Config.
 *
 * Caller must lock the db.
 *
 * @param[in]  uuid           UUID for new scan config.
 * @param[in]  selector_name  Name of NVT selector to use.
 */
void
make_config_host_discovery (char *const uuid, char *const selector_name)
{
  config_t config;

  /* Create the Host Discovery config. */

  sql ("INSERT into configs (uuid, name, owner, nvt_selector, comment,"
       " family_count, nvt_count, nvts_growing, families_growing,"
       " type, creation_time, modification_time)"
       " VALUES ('%s', 'Host Discovery', NULL,"
       "         '%s', 'Network Host Discovery scan configuration.',"
       "         0, 0, 0, 0, 0, m_now (), m_now ());",
       uuid,
       selector_name);

  config = sql_last_insert_id ();

  /* Add the Ping Host NVT to the config. */

  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.100315', "
                                "'Port scanners');",
       selector_name);

  /* Update number of families and nvts. */

  sql ("UPDATE configs"
       " SET family_count = %i, nvt_count = %i,"
       "     modification_time = m_now ()"
       " WHERE id = %llu;",
       nvt_selector_family_count (selector_name, 0),
       nvt_selector_nvt_count (selector_name, NULL, 0),
       config);

  /* Add preferences for "ping host" nvt. */

  sql ("INSERT INTO config_preferences (config, type, name, value)"
       " VALUES (%llu,"
       "         'PLUGINS_PREFS',"
       "         'Ping Host[checkbox]:Mark unrechable Hosts as dead (not "
       "scanning)',"
       "         'yes');",
       config);

  sql ("INSERT INTO config_preferences (config, type, name, value)"
       " VALUES (%llu,"
       "         'PLUGINS_PREFS',"
       "         'Ping Host[checkbox]:Report about reachable Hosts',"
       "         'yes');",
       config);

  sql ("INSERT INTO config_preferences (config, type, name, value)"
       " VALUES (%llu,"
       "         'PLUGINS_PREFS',"
       "         'Ping Host[checkbox]:Report about unrechable Hosts',"
       "         'no');",
       config);
}

/**
 * @brief Preference name.
 */
#define NAME "Global variable settings[checkbox]:Strictly unauthenticated"

/**
 * @brief Ensure the Host Discovery config is up to date.
 *
 * @param[in]  uuid  UUID of config.
 *
 * @return 0 success, -1 error.
 */
int
check_config_host_discovery (const char *uuid)
{
  int update;

  update = 0;

  /* Check new preference. */

  if (sql_int ("SELECT count (*) FROM config_preferences"
               " WHERE config = (SELECT id FROM configs WHERE uuid = '%s')"
               "       AND type = 'PLUGINS_PREFS'"
               "       AND name = '" NAME "';",
               uuid)
      == 0)
    {
      sql ("INSERT INTO config_preferences (config, type, name, value)"
           " VALUES ((SELECT id FROM configs WHERE uuid = '%s'),"
           "         'PLUGINS_PREFS',"
           "         '" NAME "',"
           "         'yes');",
           uuid);
      update = 1;
    }

  /* Check new NVT. */

  if (sql_int ("SELECT count (*) FROM nvt_selectors"
               " WHERE name = (SELECT nvt_selector FROM configs"
               "               WHERE uuid = '%s')"
               "       AND family_or_nvt = '1.3.6.1.4.1.25623.1.0.12288';",
               uuid)
      == 0)
    {
      sql (
        "INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
        " VALUES ((SELECT nvt_selector FROM configs WHERE uuid = '%s'), 0,"
        "         " G_STRINGIFY (
          NVT_SELECTOR_TYPE_NVT) ","
                                 "         '1.3.6.1.4.1.25623.1.0.12288', "
                                 "'Settings');",
        uuid);
      update = 1;
    }

  if (update)
    update_config_cache_init (uuid);

  /* Check preferences. */

  update_config_preference (uuid,
                            "PLUGINS_PREFS",
                            "Ping Host[checkbox]:Mark unrechable Hosts as dead"
                            " (not scanning)",
                            "yes",
                            TRUE);

  return 0;
}
