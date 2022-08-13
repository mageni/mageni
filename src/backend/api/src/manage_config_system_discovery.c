// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Name: manage_config_system_discovery.c
 * Brief: GVM management layer: Predefined config: System Discovery
 * 
 * This file contains the creation of the predefined config System Discovery.
 * 
 * Copyright:
 * Copyright (C) 2013-2018 Greenbone Networks GmbH
 * Copyright (C) 2022, Mageni Security LLC
 *
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
 * @brief Make System Discovery Scan Config.
 *
 * Caller must lock the db.
 *
 * @param[in]  uuid           UUID for new scan config.
 * @param[in]  selector_name  Name of NVT selector to use.
 */
void
make_config_system_discovery (char *const uuid, char *const selector_name)
{
  config_t config;

  /* Create the System Discovery config. */

  sql ("INSERT into configs (uuid, name, owner, nvt_selector, comment,"
       " family_count, nvt_count, nvts_growing, families_growing,"
       " type, creation_time, modification_time)"
       " VALUES ('%s', 'System Discovery', NULL,"
       "         '%s', 'Network System Discovery scan configuration.',"
       "         0, 0, 0, 0, 0, m_now (), m_now ());",
       uuid,
       selector_name);

  config = sql_last_insert_id ();

  /* Add NVTs to the config. */

  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.100315', "
                                "'Port scanners');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.14259', 'Port "
                                "scanners');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.50282', "
                                "'General');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.51662', "
                                "'General');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.96207', "
                                "'Windows');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.103621', "
                                "'Windows');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.103220', "
                                "'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.102002', "
                                "'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.103633', "
                                "'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.103804', "
                                "'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.96200', "
                                "'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.103675', "
                                "'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.103817', "
                                "'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.103628', "
                                "'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.803719', "
                                "'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.103799', "
                                "'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.103685', "
                                "'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.103809', "
                                "'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.103707', "
                                "'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.103418', "
                                "'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.10267', "
                                "'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.103417', "
                                "'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.103648', "
                                "'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.103779', "
                                "'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.105937', "
                                "'Product detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.103997', "
                                "'Service detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.10884', "
                                "'Service detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.102011', "
                                "'Service detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.101013', "
                                "'Service detection');",
       selector_name);
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_NVT) ","
                                "         '1.3.6.1.4.1.25623.1.0.103416', "
                                "'SNMP');",
       selector_name);

  /* Update number of families and nvts. */

  sql ("UPDATE configs"
       " SET family_count = %i, nvt_count = %i,"
       "     modification_time = m_now ()"
       " WHERE id = %llu;",
       nvt_selector_family_count (selector_name, 0),
       nvt_selector_nvt_count (selector_name, NULL, 0),
       config);
}

/**
 * @brief Ensure the Discovery config is up to date.
 *
 * @param[in]  uuid  UUID of config.
 *
 * @return 0 success, -1 error.
 */
int
check_config_system_discovery (const char *uuid)
{
  int update;

  update = 0;

  /* Check new NVT. */

  if (sql_int ("SELECT count (*) FROM nvt_selectors"
               " WHERE name = (SELECT nvt_selector FROM configs"
               "               WHERE uuid = '%s')"
               "       AND family_or_nvt = '1.3.6.1.4.1.25623.1.0.51662';",
               uuid)
      == 0)
    {
      sql (
        "INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
        " VALUES ((SELECT nvt_selector FROM configs WHERE uuid = '%s'), 0,"
        "         " G_STRINGIFY (
          NVT_SELECTOR_TYPE_NVT) ","
                                 "         '1.3.6.1.4.1.25623.1.0.51662', "
                                 "'General');",
        uuid);
      update = 1;
    }

  if (sql_int ("SELECT count (*) FROM nvt_selectors"
               " WHERE name = (SELECT nvt_selector FROM configs"
               "               WHERE uuid = '%s')"
               "       AND family_or_nvt = '1.3.6.1.4.1.25623.1.0.105937';",
               uuid)
      == 0)
    {
      sql (
        "INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
        " VALUES ((SELECT nvt_selector FROM configs WHERE uuid = '%s'), 0,"
        "         " G_STRINGIFY (
          NVT_SELECTOR_TYPE_NVT) ","
                                 "         '1.3.6.1.4.1.25623.1.0.105937', "
                                 "'Product detection');",
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
