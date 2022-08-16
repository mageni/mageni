/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2014-2018 Greenbone Networks GmbH
 * SPDX-FileComment: SQLite Backend
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#define _XOPEN_SOURCE

#include "manage.h"
#include "manage_acl.h"
#include "manage_utils.h"
#include "sql.h"

#include <assert.h>
#include <errno.h>
#include "../../libraries/base/hosts.h"
#include "../../libraries/util/uuidutils.h"
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Location of SCAP db.
 */
#define SCAP_DB_DIR MAGENI_STATE_DIR "/scap/"

/**
 * @brief Location of SCAP db.
 */
#define SCAP_DB_FILE SCAP_DB_DIR "scap.db"

/**
 * @brief Location of CERT db.
 */
#define CERT_DB_DIR MAGENI_STATE_DIR "/cert/"

/**
 * @brief Location of CERT db.
 */
#define CERT_DB_FILE CERT_DB_DIR "cert.db"

/* Variables */

extern sqlite3 *gvmd_db;

/* Headers of manage_sql.c functions also used here. */

gchar *
clean_hosts (const char *, int *);

char *
iso_time (time_t *);

int
days_from_now (time_t *);

int
resource_name (const char *, const char *, int, char **);

int
resource_exists (const char *, resource_t, int);

/* Session. */

/**
 * @brief WHERE clause for view vulns.
 */
#define VULNS_RESULTS_WHERE     \
  " WHERE uuid IN"              \
  "   (SELECT nvt FROM results" \
  "     WHERE (results.severity != " G_STRINGIFY (SEVERITY_ERROR) "))"

/**
 * @brief Setup session.
 *
 * @param[in]  uuid  User UUID.
 */
void
manage_session_init (const char *uuid)
{
  sql ("CREATE TEMPORARY TABLE IF NOT EXISTS current_credentials"
       " (id INTEGER PRIMARY KEY,"
       "  uuid text UNIQUE NOT NULL,"
       "  tz_override text);");
  sql ("DELETE FROM current_credentials;");
  if (uuid)
    sql ("INSERT INTO current_credentials (uuid) VALUES ('%s');", uuid);

  /* Vulnerabilities view must be created as temporary to allow using
   * tables from SCAP database */

  sql ("DROP VIEW IF EXISTS vulns;");
  sql ("CREATE TEMPORARY VIEW vulns AS"
         " SELECT id, uuid, name, creation_time, modification_time,"
         "        cast (cvss_base AS double precision) AS severity, qod,"
         "        'nvt' AS type"
         " FROM nvts" VULNS_RESULTS_WHERE);

#undef VULNS_RESULTS_WHERE
}

/**
 * @brief Setup session timezone.
 *
 * @param[in]  zone  Timezone.
 */
void
manage_session_set_timezone (const char *zone)
{
  return;
}

/* Helpers. */

/**
 * @brief Check whether database is empty.
 *
 * @return 1 if empty, else 0;
 */
int
manage_db_empty ()
{
  return sql_int ("SELECT count (*) FROM main.sqlite_master"
                  " WHERE type = 'table'"
                  " AND name = 'meta';")
         == 0;
}

/* SQL functions. */

/**
 * @brief Return 1.
 *
 * This is a callback for a scalar SQL function of zero arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_t (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  assert (argc == 0);

  sqlite3_result_int (context, 1);
}

/**
 * @brief Get position of a substring like the strpos function in PostgreSQL.
 *
 * This is a callback for a scalar SQL function of two arguments.
 * The SQLite function instr could be used as replacement, but is only
 *  available in versions >= 3.7.15.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_strpos (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const unsigned char *str, *substr, *substr_in_str;

  assert (argc == 2);

  str = sqlite3_value_text (argv[0]);
  substr = sqlite3_value_text (argv[1]);

  if (str == NULL)
    {
      sqlite3_result_error (context, "Failed to get string argument", -1);
      return;
    }

  if (substr == NULL)
    {
      sqlite3_result_error (context, "Failed to get substring argument", -1);
      return;
    }

  substr_in_str = (const unsigned char *) g_strrstr ((const gchar *) str,
                                                     (const gchar *) substr);

  sqlite3_result_int (context, substr_in_str ? substr_in_str - str + 1 : 0);
}

/**
 * @brief Convert an IP address into a sortable form.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_order_inet (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const char *ip;
  unsigned int one, two, three, four;
  one = two = three = four = 0;
  gchar *ip_expanded;

  assert (argc == 1);

  ip = (const char *) sqlite3_value_text (argv[0]);
  if (ip == NULL)
    sqlite3_result_int (context, 0);
  else
    {
      if (g_regex_match_simple ("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$", ip, 0, 0)
          && sscanf (ip, "%u.%u.%u.%u", &one, &two, &three, &four) == 4)
        {
          ip_expanded =
            g_strdup_printf ("%03u.%03u.%03u.%03u", one, two, three, four);
          sqlite3_result_text (context, ip_expanded, -1, SQLITE_TRANSIENT);
          g_free (ip_expanded);
        }
      else
        sqlite3_result_text (context, ip, -1, SQLITE_TRANSIENT);
    }
}

/**
 * @brief Convert a message type into an integer for sorting.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_order_message_type (sqlite3_context *context,
                        int argc,
                        sqlite3_value **argv)
{
  const char *type;

  assert (argc == 1);

  type = (const char *) sqlite3_value_text (argv[0]);
  if (type == NULL)
    sqlite3_result_int (context, 8);
  else if (strcmp (type, "Security Hole") == 0)
    sqlite3_result_int (context, 1);
  else if (strcmp (type, "Security Warning") == 0)
    sqlite3_result_int (context, 2);
  else if (strcmp (type, "Security Note") == 0)
    sqlite3_result_int (context, 3);
  else if (strcmp (type, "Log Message") == 0)
    sqlite3_result_int (context, 4);
  else if (strcmp (type, "Debug Message") == 0)
    sqlite3_result_int (context, 5);
  else if (strcmp (type, "Error Message") == 0)
    sqlite3_result_int (context, 6);
  else
    sqlite3_result_int (context, 7);
}

/**
 * @brief Convert a port into an integer for sorting.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_order_port (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const char *port;
  int port_num;

  assert (argc == 1);

  port = (const char *) sqlite3_value_text (argv[0]);

  port_num = atoi (port);
  if (port_num > 0)
    sqlite3_result_int (context, port_num);
  else if (sscanf (port, "%*s (%i/%*s)", &port_num) == 1)
    sqlite3_result_int (context, port_num);
  else
    sqlite3_result_int (context, 0);
}

/**
 * @brief Convert a role for sorting.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_order_role (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const char *name;

  assert (argc == 1);

  name = (const char *) sqlite3_value_text (argv[0]);
  if (name == NULL)
    sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
  else if (strcmp (name, "Admin") == 0)
    sqlite3_result_text (context, " !", -1, SQLITE_TRANSIENT);
  else
    sqlite3_result_text (context, name, -1, SQLITE_TRANSIENT);
}

/**
 * @brief Convert a threat into an integer for sorting.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_order_threat (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const char *type;

  assert (argc == 1);

  type = (const char *) sqlite3_value_text (argv[0]);
  if (type == NULL)
    sqlite3_result_int (context, 9);
  else if (strcmp (type, "High") == 0)
    sqlite3_result_int (context, 1);
  else if (strcmp (type, "Medium") == 0)
    sqlite3_result_int (context, 2);
  else if (strcmp (type, "Low") == 0)
    sqlite3_result_int (context, 3);
  else if (strcmp (type, "Log") == 0)
    sqlite3_result_int (context, 4);
  else if (strcmp (type, "Debug") == 0)
    sqlite3_result_int (context, 5);
  else if (strcmp (type, "False Positive") == 0)
    sqlite3_result_int (context, 6);
  else if (strcmp (type, "None") == 0)
    sqlite3_result_int (context, 7);
  else
    sqlite3_result_int (context, 8);
}

/**
 * @brief Make a UUID.
 *
 * This is a callback for a scalar SQL function of zero arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_make_uuid (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  char *uuid;

  assert (argc == 0);

  uuid = gvm_uuid_make ();
  if (uuid == NULL)
    {
      sqlite3_result_error (context, "Failed to create UUID", -1);
      return;
    }

  sqlite3_result_text (context, uuid, -1, free);
}

/**
 * @brief Check if a host list contains a host
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_hosts_contains (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const char *hosts, *host;
  int max_hosts;

  assert (argc == 2);

  hosts = (const char *) sqlite3_value_text (argv[0]);
  if (hosts == NULL)
    {
      sqlite3_result_error (context, "Failed to get hosts argument", -1);
      return;
    }

  host = (const char *) sqlite3_value_text (argv[1]);
  if (host == NULL)
    {
      sqlite3_result_error (context, "Failed to get host argument", -1);
      return;
    }

  max_hosts = sql_int ("SELECT coalesce ((SELECT value FROM meta"
                       "                  WHERE name = 'max_hosts'),"
                       "                 '4095');");

  sqlite3_result_int (context, hosts_str_contains (hosts, host, max_hosts));
}

/**
 * @brief Clean a host list.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_clean_hosts (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const unsigned char *hosts;
  gchar *clean;

  assert (argc == 1);

  hosts = sqlite3_value_text (argv[0]);
  if (hosts == NULL)
    {
      sqlite3_result_error (context, "Failed to get hosts argument", -1);
      return;
    }

  clean = clean_hosts ((gchar *) hosts, NULL);
  sqlite3_result_text (context, clean, -1, SQLITE_TRANSIENT);
  g_free (clean);
}

/**
 * @brief Insert or replace a DFN-Cert Advisory.
 *
 * This is a callback for a scalar SQL function of six argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_merge_dfn_cert_adv (sqlite3_context *context,
                        int argc,
                        sqlite3_value **argv)
{
  const unsigned char *refnum, *title, *summary;
  time_t published, updated;
  gchar *quoted_refnum, *quoted_title, *quoted_summary;
  int cve_refs;

  assert (argc == 6);

  refnum = sqlite3_value_text (argv[0]);
  if (refnum == NULL)
    {
      sqlite3_result_error (context, "Failed to get refnum argument", -1);
      return;
    }

  published = sqlite3_value_int (argv[1]);
  updated = sqlite3_value_int (argv[2]);

  title = sqlite3_value_text (argv[3]);
  if (title == NULL)
    {
      sqlite3_result_error (context, "Failed to get title argument", -1);
      return;
    }

  summary = sqlite3_value_text (argv[4]);
  if (summary == NULL)
    {
      sqlite3_result_error (context, "Failed to get summary argument", -1);
      return;
    }

  cve_refs = sqlite3_value_int (argv[5]);

  quoted_refnum = sql_quote ((const char *) refnum);
  quoted_title = sql_quote ((const char *) title);
  quoted_summary = sql_quote ((const char *) summary);

  sql ("INSERT OR REPLACE INTO dfn_cert_advs"
       " (uuid, name, comment, creation_time, modification_time,"
       "  title, summary, cve_refs)"
       " VALUES"
       " ('%s', '%s', '', %i, %i, '%s', '%s', %i);",
       quoted_refnum,
       quoted_refnum,
       published,
       updated,
       quoted_title,
       quoted_summary,
       cve_refs);

  g_free (quoted_refnum);
  g_free (quoted_title);
  g_free (quoted_summary);
}

/**
 * @brief Insert or replace a CERT-Bund Advisory.
 *
 * This is a callback for a scalar SQL function of six argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_merge_bund_adv (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const unsigned char *refnum, *title, *summary;
  time_t published, updated;
  gchar *quoted_refnum, *quoted_title, *quoted_summary;
  int cve_refs;

  assert (argc == 6);

  refnum = sqlite3_value_text (argv[0]);
  if (refnum == NULL)
    {
      sqlite3_result_error (context, "Failed to get refnum argument", -1);
      return;
    }

  published = sqlite3_value_int (argv[1]);
  updated = sqlite3_value_int (argv[2]);

  title = sqlite3_value_text (argv[3]);
  if (title == NULL)
    {
      sqlite3_result_error (context, "Failed to get title argument", -1);
      return;
    }

  summary = sqlite3_value_text (argv[4]);
  if (summary == NULL)
    {
      sqlite3_result_error (context, "Failed to get summary argument", -1);
      return;
    }

  cve_refs = sqlite3_value_int (argv[5]);

  quoted_refnum = sql_quote ((const char *) refnum);
  quoted_title = sql_quote ((const char *) title);
  quoted_summary = sql_quote ((const char *) summary);

  sql ("INSERT OR REPLACE INTO cert_bund_advs"
       " (uuid, name, comment, creation_time, modification_time,"
       "  title, summary, cve_refs)"
       " VALUES"
       " ('%s', '%s', '', %i, %i, '%s', '%s', %i);",
       quoted_refnum,
       quoted_refnum,
       published,
       updated,
       quoted_title,
       quoted_summary,
       cve_refs);

  g_free (quoted_refnum);
  g_free (quoted_title);
  g_free (quoted_summary);
}

/**
 * @brief Insert or replace a CPE.
 *
 * This is a callback for a scalar SQL function of eight argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_merge_cpe (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const unsigned char *name, *title, *status, *nvd_id;
  gchar *quoted_name, *quoted_title, *quoted_status, *quoted_nvd_id;
  int created, modified, deprecated_by_id;

  assert (argc == 7);

  name = sqlite3_value_text (argv[0]);
  if (name == NULL)
    {
      sqlite3_result_error (context, "Failed to get name argument", -1);
      return;
    }

  title = sqlite3_value_text (argv[1]);
  if (title == NULL)
    {
      sqlite3_result_error (context, "Failed to get title argument", -1);
      return;
    }

  created = sqlite3_value_int (argv[2]);
  modified = sqlite3_value_int (argv[3]);

  status = sqlite3_value_text (argv[4]);
  if (status == NULL)
    {
      sqlite3_result_error (context, "Failed to get status argument", -1);
      return;
    }

  deprecated_by_id = sqlite3_value_int (argv[5]);

  nvd_id = sqlite3_value_text (argv[6]);
  if (nvd_id == NULL)
    {
      sqlite3_result_error (context, "Failed to get nvd_id argument", -1);
      return;
    }

  quoted_name = sql_quote ((const char *) name);
  quoted_title = sql_quote ((const char *) title);
  quoted_status = sql_quote ((const char *) status);
  quoted_nvd_id = sql_quote ((const char *) nvd_id);

  sql ("INSERT OR REPLACE INTO cpes"
       " (uuid, name, title, creation_time, modification_time, status,"
       "  deprecated_by_id, nvd_id)"
       " VALUES"
       " ('%s', '%s', '%s', %i, %i, '%s', %i, '%s');",
       quoted_name,
       quoted_name,
       quoted_title,
       created,
       modified,
       quoted_status,
       deprecated_by_id,
       quoted_nvd_id);

  g_free (quoted_name);
  g_free (quoted_title);
  g_free (quoted_status);
  g_free (quoted_nvd_id);
}

/**
 * @brief Insert or replace a CVE.
 *
 * This is a callback for a scalar SQL function of 13 arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_merge_cve (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const unsigned char *uuid, *name, *cvss, *description, *vector, *complexity;
  const unsigned char *authentication, *confidentiality, *integrity;
  const unsigned char *availability, *products;
  gchar *quoted_uuid, *quoted_name, *quoted_description;
  gchar *quoted_vector, *quoted_complexity, *quoted_authentication;
  gchar *quoted_confidentiality, *quoted_integrity, *quoted_availability;
  gchar *quoted_products;
  int created, modified;

  assert (argc == 13);

  uuid = sqlite3_value_text (argv[0]);
  if (uuid == NULL)
    {
      sqlite3_result_error (context, "Failed to get uuid argument", -1);
      return;
    }

  name = sqlite3_value_text (argv[1]);
  if (name == NULL)
    {
      sqlite3_result_error (context, "Failed to get name argument", -1);
      return;
    }

  created = sqlite3_value_int (argv[2]);
  modified = sqlite3_value_int (argv[3]);

  if (sqlite3_value_type (argv[4]) == SQLITE_NULL)
    cvss = (unsigned char *) "NULL";
  else
    {
      cvss = sqlite3_value_text (argv[4]);
      if (cvss == NULL)
        {
          sqlite3_result_error (context, "Failed to get cvss argument", -1);
          return;
        }
      if (g_regex_match_simple ("^1?[0-9][.][0-9]$", (gchar *) cvss, 0, 0) == 0)
        {
          gchar *msg;
          msg = g_strdup_printf ("CVSS format not recognised: %s", cvss);
          sqlite3_result_error (context, msg, -1);
          g_free (msg);
          return;
        }
    }

  description = sqlite3_value_text (argv[5]);
  if (description == NULL)
    {
      sqlite3_result_error (context, "Failed to get description argument", -1);
      return;
    }

  vector = sqlite3_value_text (argv[6]);
  if (vector == NULL)
    {
      sqlite3_result_error (context, "Failed to get vector argument", -1);
      return;
    }

  complexity = sqlite3_value_text (argv[7]);
  if (complexity == NULL)
    {
      sqlite3_result_error (context, "Failed to get complexity argument", -1);
      return;
    }

  authentication = sqlite3_value_text (argv[8]);
  if (authentication == NULL)
    {
      sqlite3_result_error (
        context, "Failed to get authentication argument", -1);
      return;
    }

  confidentiality = sqlite3_value_text (argv[9]);
  if (confidentiality == NULL)
    {
      sqlite3_result_error (
        context, "Failed to get confidentiality_impact argument", -1);
      return;
    }

  integrity = sqlite3_value_text (argv[10]);
  if (integrity == NULL)
    {
      sqlite3_result_error (context, "Failed to get integrity argument", -1);
      return;
    }

  availability = sqlite3_value_text (argv[11]);
  if (availability == NULL)
    {
      sqlite3_result_error (context, "Failed to get availability argument", -1);
      return;
    }

  products = sqlite3_value_text (argv[12]);
  if (products == NULL)
    {
      sqlite3_result_error (context, "Failed to get products argument", -1);
      return;
    }

  quoted_uuid = sql_quote ((const char *) uuid);
  quoted_name = sql_quote ((const char *) name);
  quoted_description = sql_quote ((const char *) description);
  quoted_vector = sql_quote ((const char *) vector);
  quoted_complexity = sql_quote ((const char *) complexity);
  quoted_authentication = sql_quote ((const char *) authentication);
  quoted_confidentiality = sql_quote ((const char *) confidentiality);
  quoted_integrity = sql_quote ((const char *) integrity);
  quoted_availability = sql_quote ((const char *) availability);
  quoted_products = sql_quote ((const char *) products);

  sql ("INSERT OR REPLACE INTO cves"
       " (uuid, name, creation_time, modification_time, cvss, description,"
       "  vector, complexity, authentication, confidentiality_impact,"
       "  integrity_impact, availability_impact, products)"
       " VALUES"
       " ('%s', '%s', %i, %i, %s, '%s', '%s', '%s', '%s', '%s', '%s', '%s',"
       "  '%s');",
       quoted_uuid,
       quoted_name,
       created,
       modified,
       cvss,
       quoted_description,
       quoted_vector,
       quoted_complexity,
       quoted_authentication,
       quoted_confidentiality,
       quoted_integrity,
       quoted_availability,
       quoted_products);

  g_free (quoted_uuid);
  g_free (quoted_name);
  g_free (quoted_description);
  g_free (quoted_vector);
  g_free (quoted_complexity);
  g_free (quoted_authentication);
  g_free (quoted_confidentiality);
  g_free (quoted_integrity);
  g_free (quoted_availability);
  g_free (quoted_products);
}

/**
 * @brief Insert or replace a CPE.
 *
 * This is a callback for a scalar SQL function of 4 arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_merge_cpe_name (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const unsigned char *uuid, *name;
  gchar *quoted_uuid, *quoted_name;
  int creation_time, modification_time;

  assert (argc == 4);

  uuid = sqlite3_value_text (argv[0]);
  if (uuid == NULL)
    {
      sqlite3_result_error (context, "Failed to get uuid argument", -1);
      return;
    }

  name = sqlite3_value_text (argv[1]);
  if (name == NULL)
    {
      sqlite3_result_error (context, "Failed to get name argument", -1);
      return;
    }

  creation_time = sqlite3_value_int (argv[2]);
  modification_time = sqlite3_value_int (argv[3]);

  quoted_uuid = sql_quote ((const char *) uuid);
  quoted_name = sql_quote ((const char *) name);

  sql ("INSERT OR IGNORE INTO cpes"
       " (uuid, name, creation_time, modification_time)"
       " VALUES"
       " ('%s', '%s', %i, %i);",
       quoted_uuid,
       quoted_name,
       creation_time,
       modification_time);

  g_free (quoted_uuid);
  g_free (quoted_name);
}

/**
 * @brief Insert or replace an affected product.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_merge_affected_product (sqlite3_context *context,
                            int argc,
                            sqlite3_value **argv)
{
  int cve, cpe;

  assert (argc == 2);

  cve = sqlite3_value_int (argv[0]);
  cpe = sqlite3_value_int (argv[1]);

  sql ("INSERT OR REPLACE INTO affected_products"
       " (cve, cpe)"
       " VALUES"
       " (%i, %i);",
       cve,
       cpe);
}

/**
 * @brief Insert or replace an OVAL def.
 *
 * This is a callback for a scalar SQL function of 13 arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_merge_ovaldef (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const unsigned char *uuid, *name, *comment, *def_class, *title, *description;
  const unsigned char *xml_file, *status;
  int created, modified, version, deprecated;
  gchar *quoted_uuid, *quoted_name, *quoted_comment, *quoted_def_class;
  gchar *quoted_title, *quoted_description, *quoted_xml_file;
  gchar *quoted_status;
  int cve_refs;

  assert (argc == 13);

  uuid = sqlite3_value_text (argv[0]);
  if (uuid == NULL)
    {
      sqlite3_result_error (context, "Failed to get uuid argument", -1);
      return;
    }

  name = sqlite3_value_text (argv[1]);
  if (name == NULL)
    {
      sqlite3_result_error (context, "Failed to get name argument", -1);
      return;
    }

  comment = sqlite3_value_text (argv[2]);
  if (name == NULL)
    {
      sqlite3_result_error (context, "Failed to get comment argument", -1);
      return;
    }

  created = sqlite3_value_int (argv[3]);
  modified = sqlite3_value_int (argv[4]);
  version = sqlite3_value_int (argv[5]);
  deprecated = sqlite3_value_int (argv[6]);

  def_class = sqlite3_value_text (argv[7]);
  if (def_class == NULL)
    {
      sqlite3_result_error (context, "Failed to get def_class argument", -1);
      return;
    }

  title = sqlite3_value_text (argv[8]);
  if (title == NULL)
    {
      sqlite3_result_error (context, "Failed to get title argument", -1);
      return;
    }

  description = sqlite3_value_text (argv[9]);
  if (description == NULL)
    {
      sqlite3_result_error (context, "Failed to get description argument", -1);
      return;
    }

  xml_file = sqlite3_value_text (argv[10]);
  if (xml_file == NULL)
    {
      sqlite3_result_error (context, "Failed to get xml_file argument", -1);
      return;
    }

  status = sqlite3_value_text (argv[11]);
  if (status == NULL)
    {
      sqlite3_result_error (context, "Failed to get status argument", -1);
      return;
    }

  cve_refs = sqlite3_value_int (argv[12]);

  quoted_uuid = sql_quote ((const char *) uuid);
  quoted_name = sql_quote ((const char *) name);
  quoted_comment = sql_quote ((const char *) comment);
  quoted_def_class = sql_quote ((const char *) def_class);
  quoted_title = sql_quote ((const char *) title);
  quoted_description = sql_quote ((const char *) description);
  quoted_xml_file = sql_quote ((const char *) xml_file);
  quoted_status = sql_quote ((const char *) status);

  sql ("INSERT OR REPLACE INTO ovaldefs"
       " (uuid, name, comment, creation_time, modification_time, version,"
       "  deprecated, def_class, title, description, xml_file, status,"
       "  max_cvss, cve_refs)"
       " VALUES"
       " ('%s', '%s', '%s', %i, %i, %i, %i, '%s', '%s', '%s', '%s', '%s',"
       "  0.0, %i);",
       quoted_uuid,
       quoted_name,
       quoted_comment,
       created,
       modified,
       version,
       deprecated,
       quoted_def_class,
       quoted_title,
       quoted_description,
       quoted_xml_file,
       quoted_status,
       cve_refs);

  g_free (quoted_uuid);
  g_free (quoted_name);
  g_free (quoted_comment);
  g_free (quoted_def_class);
  g_free (quoted_title);
  g_free (quoted_description);
  g_free (quoted_xml_file);
  g_free (quoted_status);
}

/**
 * @brief Make a name unique.
 *
 * This is a callback for a scalar SQL function of four argument.
 *
 * It's up to the caller to ensure there is a read-only transaction.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_uniquify (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const unsigned char *proposed_name, *type, *suffix;
  gchar *candidate_name, *quoted_candidate_name;
  unsigned int number;
  sqlite3_int64 owner;

  assert (argc == 4);

  type = sqlite3_value_text (argv[0]);
  if (type == NULL)
    {
      sqlite3_result_error (context, "Failed to get type argument", -1);
      return;
    }

  proposed_name = sqlite3_value_text (argv[1]);
  if (proposed_name == NULL)
    {
      sqlite3_result_error (
        context, "Failed to get proposed name argument", -1);
      return;
    }

  owner = sqlite3_value_int64 (argv[2]);

  suffix = sqlite3_value_text (argv[3]);
  if (suffix == NULL)
    {
      sqlite3_result_error (context, "Failed to get suffix argument", -1);
      return;
    }

  number = 0;
  candidate_name = g_strdup_printf ("%s%s%c%i",
                                    proposed_name,
                                    suffix,
                                    strcmp ((char *) type, "user") ? ' ' : '_',
                                    ++number);
  quoted_candidate_name = sql_quote (candidate_name);

  while (sql_int ("SELECT COUNT (*) FROM %ss WHERE name = '%s'"
                  " AND ((owner IS NULL) OR (owner = %llu));",
                  type,
                  quoted_candidate_name,
                  owner))
    {
      g_free (candidate_name);
      g_free (quoted_candidate_name);
      candidate_name =
        g_strdup_printf ("%s%s%c%u",
                         proposed_name,
                         suffix,
                         strcmp ((char *) type, "user") ? ' ' : '_',
                         ++number);
      quoted_candidate_name = sql_quote (candidate_name);
    }

  g_free (quoted_candidate_name);

  sqlite3_result_text (context, candidate_name, -1, SQLITE_TRANSIENT);
  g_free (candidate_name);
}

/**
 * @brief Convert an epoch time into a string in ISO format.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_iso_time (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  time_t epoch_time;

  assert (argc == 1);

  epoch_time = sqlite3_value_int (argv[0]);
  if (epoch_time == 0)
    sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
  else
    {
      const char *iso;

      iso = iso_time (&epoch_time);
      if (iso)
        sqlite3_result_text (context, iso, -1, SQLITE_TRANSIENT);
      else
        sqlite3_result_error (context, "Failed to format time", -1);
    }
}

/**
 * @brief Calculate difference between now and epoch time in days
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_days_from_now (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  time_t epoch_time;

  assert (argc == 1);

  epoch_time = sqlite3_value_int (argv[0]);
  if (epoch_time == 0)
    sqlite3_result_int (context, -2);
  else
    {
      int days;

      days = days_from_now (&epoch_time);
      sqlite3_result_int (context, days);
    }
}

/**
 * @brief Try convert an OTP NVT tag time string into epoch time.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * This is only used by the SQLite backend, in the SQL of some older migrators.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_parse_time (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const gchar *string;
  int epoch_time;

  assert (argc == 1);

  string = (const gchar *) sqlite3_value_text (argv[0]);

  switch (parse_time (string, &epoch_time))
    {
    case -1:
      g_debug ("%s: Failed to parse time: %s", __FUNCTION__, string);
      sqlite3_result_int (context, 0);
      break;
    case -2:
      g_debug ("%s: Failed to make time: %s", __FUNCTION__, string);
      sqlite3_result_int (context, 0);
      break;
    case -3:
      g_debug (
        "%s: Failed to parse timezone offset: %s", __FUNCTION__, string);
      sqlite3_result_int (context, 0);
      break;
    default:
      sqlite3_result_int (context, epoch_time);
    }
}

/**
 * @brief Calculate the next time from now given a start time and a period.
 *
 * This is a callback for a scalar SQL function of four to six arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_next_time (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  time_t first;
  time_t period;
  int period_months, byday, periods_offset;
  const char *zone;

  assert (argc == 4 || argc == 5 || argc == 6);

  first = sqlite3_value_int (argv[0]);
  period = sqlite3_value_int (argv[1]);
  period_months = sqlite3_value_int (argv[2]);
  byday = sqlite3_value_int (argv[3]);
  if (argc < 5 || sqlite3_value_type (argv[4]) == SQLITE_NULL)
    zone = NULL;
  else
    zone = (char *) sqlite3_value_text (argv[4]);

  if (argc < 6 || sqlite3_value_type (argv[5]) == SQLITE_NULL)
    periods_offset = 0;
  else
    periods_offset = sqlite3_value_int (argv[5]);

  sqlite3_result_int (
    context,
    next_time (first, period, period_months, byday, zone, periods_offset));
}

/**
 * @brief Calculate the next time from now based on an iCalendar string.
 *
 * This is a callback for a scalar SQL function of two to three arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_next_time_ical (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  int periods_offset;
  const char *icalendar, *zone;

  assert (argc == 2 || argc == 3);

  if (argc < 1 || sqlite3_value_type (argv[0]) == SQLITE_NULL)
    icalendar = NULL;
  else
    icalendar = (char *) sqlite3_value_text (argv[0]);

  if (argc < 2 || sqlite3_value_type (argv[1]) == SQLITE_NULL)
    zone = NULL;
  else
    zone = (char *) sqlite3_value_text (argv[1]);

  if (argc < 3 || sqlite3_value_type (argv[2]) == SQLITE_NULL)
    periods_offset = 0;
  else
    periods_offset = sqlite3_value_int (argv[2]);

  sqlite3_result_int (
    context, icalendar_next_time_from_string (icalendar, zone, periods_offset));
}

/**
 * @brief Get the current time as an epoch integer.
 *
 * This is a callback for a scalar SQL function of zero arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_now (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  assert (argc == 0);
  sqlite3_result_int (context, time (NULL));
}

/**
 * @brief Extract a tag from an OTP tag list.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_tag (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const char *tags, *tag;
  gchar *value;

  assert (argc == 2);

  tags = (char *) sqlite3_value_text (argv[0]);
  if (tags == NULL)
    {
      sqlite3_result_error (context, "Failed to get tags argument", -1);
      return;
    }

  tag = (char *) sqlite3_value_text (argv[1]);
  if (tag == NULL)
    {
      sqlite3_result_error (context, "Failed to get tag argument", -1);
      return;
    }

  value = tag_value (tags, tag);
  sqlite3_result_text (context, value, -1, SQLITE_TRANSIENT);
  g_free (value);

  return;
}

/**
 * @brief Return number of hosts.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_max_hosts (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const unsigned char *hosts, *exclude_hosts;
  gchar *max;

  assert (argc == 2);

  hosts = sqlite3_value_text (argv[0]);
  if (hosts == NULL)
    {
      /* Seems this happens when the query result is empty. */
      sqlite3_result_text (context, "0", -1, SQLITE_TRANSIENT);
      return;
    }
  exclude_hosts = sqlite3_value_text (argv[1]);

  max = g_strdup_printf (
    "%i", manage_count_hosts ((gchar *) hosts, (gchar *) exclude_hosts));
  sqlite3_result_text (context, max, -1, SQLITE_TRANSIENT);
  g_free (max);
}

/**
 * @brief Move data from a table to a new table, heeding column rename.
 *
 * @param[in]  old_table  Existing table.
 * @param[in]  new_table  New empty table with renamed column.
 * @param[in]  old_name   Name of column in old table.
 * @param[in]  new_name   Name of column in new table.
 */
void
sql_rename_column (const char *old_table,
                   const char *new_table,
                   const char *old_name,
                   const char *new_name)
{
  iterator_t rows;

  /* Get a row with all columns. */

  init_iterator (&rows, "SELECT * FROM %s LIMIT 1;", old_table);
  if (next (&rows))
    {
      GString *one, *two;
      int end, column, first;

      /* Build the INSERT query from the column names in the row. */

      one = g_string_new ("");
      g_string_append_printf (one, "INSERT INTO %s (", new_table);

      two = g_string_new (") SELECT ");

      end = iterator_column_count (&rows);
      first = 1;
      for (column = 0; column < end; column++)
        {
          const char *name;
          name = iterator_column_name (&rows, column);
          g_string_append_printf (
            one,
            "%s%s",
            (first ? "" : ", "),
            (strcmp (name, old_name) == 0 ? new_name : name));
          if (first)
            first = 0;
          else
            g_string_append (two, ", ");
          g_string_append (two, name);
        }
      cleanup_iterator (&rows);

      g_string_append_printf (one, "%s FROM %s;", two->str, old_table);

      /* Run the INSERT query. */

      sql (one->str);

      g_string_free (one, TRUE);
      g_string_free (two, TRUE);
    }
  else
    cleanup_iterator (&rows);
}

/**
 * @brief Check if two CVE lists contain a common CVE.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_common_cve (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  gchar **split_1, **split_2, **point_1, **point_2;
  const unsigned char *cve1, *cve2;

  assert (argc == 2);

  g_debug ("   %s: top", __FUNCTION__);

  cve1 = sqlite3_value_text (argv[0]);
  if (cve1 == NULL)
    {
      sqlite3_result_error (context, "Failed to get first CVE argument", -1);
      return;
    }

  cve2 = sqlite3_value_text (argv[1]);
  if (cve2 == NULL)
    {
      sqlite3_result_error (context, "Failed to get second CVE argument", -1);
      return;
    }

  split_1 = g_strsplit ((gchar *) cve1, ",", 0);
  split_2 = g_strsplit ((gchar *) cve2, ",", 0);
  point_1 = split_1;
  point_2 = split_2;
  while (*point_1)
    {
      while (*point_2)
        {
          g_debug ("   %s: %s vs %s",
                   __FUNCTION__,
                   g_strstrip (*point_1),
                   g_strstrip (*point_2));
          if (strcmp (g_strstrip (*point_1), g_strstrip (*point_2)) == 0)
            {
              g_strfreev (split_1);
              g_strfreev (split_2);
              sqlite3_result_int (context, 1);
              return;
            }
          point_2++;
        }
      point_1++;
    }
  g_strfreev (split_1);
  g_strfreev (split_2);

  sqlite3_result_int (context, 0);
}

/**
 * @brief Check if two CVE lists contain a common CVE.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_cpe_title (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const unsigned char *cpe_id;
  gchar *quoted_cpe_id;
  char *cpe_title;

  assert (argc == 1);

  cpe_id = sqlite3_value_text (argv[0]);

  if (manage_scap_loaded () && sqlite3_value_type (argv[0]) != SQLITE_NULL)
    {
      quoted_cpe_id = sql_quote ((gchar *) cpe_id);
      cpe_title = sql_string ("SELECT title FROM scap.cpes"
                              " WHERE uuid = '%s';",
                              quoted_cpe_id);
      g_free (quoted_cpe_id);

      if (cpe_title)
        {
          sqlite3_result_text (context, cpe_title, -1, SQLITE_TRANSIENT);
          g_free (cpe_title);
        }
      else
        {
          sqlite3_result_null (context);
        }
    }
  else
    {
      sqlite3_result_null (context);
    }
}

/**
 * @brief Get a value from the data of a credential.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_credential_value (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  credential_t credential;
  int trash;
  const unsigned char *type;
  gchar *quoted_type, *result;

  assert (argc == 3);

  credential = sqlite3_value_int64 (argv[0]);
  trash = sqlite3_value_int (argv[1]);
  type = sqlite3_value_text (argv[2]);

  quoted_type = sql_quote ((const char *) type);
  if (trash)
    {
      result = sql_string ("SELECT value FROM credentials_trash_data"
                           " WHERE credential = %llu AND type = '%s';",
                           credential,
                           quoted_type);
    }
  else
    {
      result = sql_string ("SELECT value FROM credentials_data"
                           " WHERE credential = %llu AND type = '%s';",
                           credential,
                           quoted_type);
    }

  if (result)
    sqlite3_result_text (context, result, -1, SQLITE_TRANSIENT);
  else
    sqlite3_result_null (context);

  g_free (result);
}

/**
 * @brief Get the offset from UTC of the current time for a timezone.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_current_offset (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  assert (argc == 1);
  sqlite3_result_int (
    context,
    (int) current_offset ((const char *) sqlite3_value_text (argv[0])));
}

/**
 * @brief Calculate the trend of a task.
 *
 * This is a callback for a scalar SQL function of two argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_task_trend (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  unsigned int overrides;
  int min_qod;
  task_t task;

  assert (argc == 3);

  task = sqlite3_value_int64 (argv[0]);
  if (task == 0)
    {
      sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
      return;
    }

  overrides = sqlite3_value_int (argv[1]);

  if (sqlite3_value_type (argv[2]) == SQLITE_NULL)
    min_qod = MIN_QOD_DEFAULT;
  else
    min_qod = sqlite3_value_int (argv[2]);

  sqlite3_result_text (
    context, task_trend (task, overrides, min_qod), -1, SQLITE_TRANSIENT);
}

/**
 * @brief Severity.
 */
typedef struct
{
  task_t task;               ///< Task.
  gchar *severity;           ///< Severity.
  task_t overrides_task;     ///< Task.
  gchar *overrides_severity; ///< Severity.
  int min_qod;               ///< Minimum QoD.
} sql_severity_t;

/**
 * @brief Get task severity, looking in cache.
 *
 * @param[in]  cache_arg  Cache.
 */
static void
clear_cache (void *cache_arg)
{
  sql_severity_t *cache;

  cache = (sql_severity_t *) cache_arg;
  g_debug (
    "   %s: %llu, %llu", __FUNCTION__, cache->task, cache->overrides_task);
  cache->task = 0;
  cache->overrides_task = 0;
  free (cache->severity);
  cache->severity = NULL;
  free (cache->overrides_severity);
  cache->overrides_severity = NULL;
  cache->min_qod = -1;
}

/**
 * @brief Get task severity, looking in cache.
 *
 * Cache a single severity value because task_threat and task_severity both
 * do the same expensive severity calculation for each row in the task
 * iterator.  Use auxdata on the overrides arg to pass the cache between
 * calls with a single statement.
 *
 * @param[in]  context    SQL context.
 * @param[in]  task       Task.
 * @param[in]  overrides  Overrides flag.
 * @param[in]  min_qod    Minimum QoD of report results to count.
 *
 * @return Severity.
 */
static char *
cached_task_severity (sqlite3_context *context,
                      task_t task,
                      int overrides,
                      int min_qod)
{
  static sql_severity_t static_cache = {.task = 0,
                                        .severity = NULL,
                                        .min_qod = MIN_QOD_DEFAULT,
                                        .overrides_task = 0,
                                        .overrides_severity = NULL};
  sql_severity_t *cache;
  char *severity;

  cache = sqlite3_get_auxdata (context, 1);
  if (cache)
    {
      if (overrides)
        {
          if (cache->overrides_task == task && cache->min_qod == min_qod)
            return cache->overrides_severity;
          /* Replace the cached severity. */
          cache->overrides_task = task;
          free (cache->overrides_severity);
          cache->overrides_severity = task_severity (task, 1, min_qod, 0);
          return cache->overrides_severity;
        }
      else
        {
          if (cache->task == task && cache->min_qod == min_qod)
            return cache->severity;
          /* Replace the cached severity. */
          cache->task = task;
          free (cache->severity);
          cache->severity = task_severity (task, 0, min_qod, 0);
          return cache->severity;
        }
    }
  severity = task_severity (task, overrides, min_qod, 0);
  /* Setup the cached severity. */
  cache = &static_cache;
  if (overrides)
    {
      cache->overrides_task = task;
      cache->overrides_severity = severity;
    }
  else
    {
      cache->task = task;
      cache->severity = severity;
    }
  sqlite3_set_auxdata (context, 1, cache, clear_cache);
  return severity;
}

/**
 * @brief Calculate the threat level of a task.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_task_threat_level (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  task_t task;
  report_t last_report;
  const char *threat;
  unsigned int overrides;
  int min_qod;
  char *severity;
  double severity_dbl;

  assert (argc == 3);

  task = sqlite3_value_int64 (argv[0]);
  if (task == 0)
    {
      sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
      return;
    }

  overrides = sqlite3_value_int (argv[1]);

  if (sqlite3_value_type (argv[2]) == SQLITE_NULL)
    min_qod = MIN_QOD_DEFAULT;
  else
    min_qod = sqlite3_value_int (argv[2]);

  severity = cached_task_severity (context, task, overrides, min_qod);

  if (severity == NULL || sscanf (severity, "%lf", &severity_dbl) != 1)
    threat = NULL;
  else
    threat = severity_to_level (severity_dbl, 0);

  g_debug ("   %s: %llu: %s", __FUNCTION__, task, threat);
  if (threat)
    {
      sqlite3_result_text (context, threat, -1, SQLITE_TRANSIENT);
      return;
    }

  task_last_report (task, &last_report);
  if (last_report == 0)
    {
      sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
      return;
    }

  sqlite3_result_text (context, "None", -1, SQLITE_TRANSIENT);
  return;
}

/**
 * @brief Calculate the progress of a report.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_report_progress (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  report_t report;
  task_t task;

  assert (argc == 1);

  report = sqlite3_value_int64 (argv[0]);
  if (report == 0)
    {
      sqlite3_result_int (context, -1);
      return;
    }

  if (report_task (report, &task))
    {
      sqlite3_result_int (context, -1);
      return;
    }

  sqlite3_result_int (context, report_progress (report, task, NULL));
  return;
}

/**
 * @brief Calculate the severity of a report.
 *
 * This is a callback for a scalar SQL function of three arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_report_severity (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  report_t report;
  double severity;
  unsigned int overrides;
  int min_qod;

  assert (argc == 3);

  report = sqlite3_value_int64 (argv[0]);
  if (report == 0)
    {
      sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
      return;
    }

  overrides = sqlite3_value_int (argv[1]);

  if (sqlite3_value_type (argv[2]) == SQLITE_NULL)
    min_qod = MIN_QOD_DEFAULT;
  else
    min_qod = sqlite3_value_int (argv[2]);

  severity = report_severity (report, overrides, min_qod);

  sqlite3_result_double (context, severity);
  return;
}

/**
 * @brief Get the number of results of a given severity level in a report.
 *
 * @param[in] report     The report to count the results of.
 * @param[in] overrides  Whether to apply overrides.
 * @param[in] min_qod    Minimum QoD of results to count.
 * @param[in] level      Severity level of which to count results.
 *
 * @return    The number of results.
 */
static int
report_severity_count (report_t report, int overrides, int min_qod, char *level)
{
  int debugs, false_positives, logs, lows, mediums, highs;
  get_data_t *get;

  if (current_credentials.uuid == NULL
      || strcmp (current_credentials.uuid, "") == 0)
    return 0;
  get = report_results_get_data (1 /* first */,
                                 -1, /* rows */
                                 overrides,
                                 0, /* autofp */
                                 min_qod);
  report_counts_id (report,
                    &debugs,
                    &highs,
                    &lows,
                    &logs,
                    &mediums,
                    &false_positives,
                    NULL,
                    get,
                    NULL);
  get_data_reset (get);
  g_free (get);

  if (strcasecmp (level, "Debug") == 0)
    return debugs;
  if (strcasecmp (level, "False Positive") == 0)
    return false_positives;
  else if (strcasecmp (level, "Log") == 0)
    return logs;
  else if (strcasecmp (level, "Low") == 0)
    return lows;
  else if (strcasecmp (level, "Medium") == 0)
    return mediums;
  else if (strcasecmp (level, "High") == 0)
    return highs;
  else
    return 0;
}

/**
 * @brief Get the number of results of a given severity level in a report.
 *
 * This is a callback for a scalar SQL function of four arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_report_severity_count (sqlite3_context *context,
                           int argc,
                           sqlite3_value **argv)
{
  report_t report;
  unsigned int overrides;
  int min_qod;
  char *level;
  int count;

  assert (argc == 4);

  report = sqlite3_value_int64 (argv[0]);
  if (report == 0)
    {
      sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
      return;
    }

  overrides = sqlite3_value_int (argv[1]);

  if (sqlite3_value_type (argv[2]) == SQLITE_NULL)
    min_qod = MIN_QOD_DEFAULT;
  else
    min_qod = sqlite3_value_int (argv[2]);

  level = (char *) sqlite3_value_text (argv[3]);
  if (level == 0)
    {
      sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
      return;
    }

  count = report_severity_count (report, overrides, min_qod, level);

  sqlite3_result_int (context, count);
  return;
}

/**
 * @brief Count the number of hosts of a report.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_report_host_count (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  report_t report;
  int host_count;

  assert (argc == 1);

  report = sqlite3_value_int64 (argv[0]);
  if (report == 0)
    {
      sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
      return;
    }

  host_count = report_host_count (report);

  sqlite3_result_int (context, host_count);
  return;
}

/**
 * @brief Count the number of hosts of a report with results.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_report_result_host_count (sqlite3_context *context,
                              int argc,
                              sqlite3_value **argv)
{
  report_t report;
  int min_qod;
  int host_count;

  assert (argc == 2);

  report = sqlite3_value_int64 (argv[0]);
  if (report == 0)
    {
      sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
      return;
    }

  if (sqlite3_value_type (argv[1]) == SQLITE_NULL)
    min_qod = MIN_QOD_DEFAULT;
  else
    min_qod = sqlite3_value_int (argv[1]);

  host_count = report_result_host_count (report, min_qod);

  sqlite3_result_int (context, host_count);
  return;
}

/**
 * @brief Calculate the severity of a task.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_task_severity (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  task_t task;
  report_t last_report;
  char *severity;
  double severity_double;
  unsigned int overrides;
  int min_qod;

  assert (argc == 3);

  task = sqlite3_value_int64 (argv[0]);
  if (task == 0)
    {
      sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);
      return;
    }

  overrides = sqlite3_value_int (argv[1]);

  if (sqlite3_value_type (argv[2]) == SQLITE_NULL)
    min_qod = MIN_QOD_DEFAULT;
  else
    min_qod = sqlite3_value_int (argv[2]);

  severity = cached_task_severity (context, task, overrides, min_qod);
  severity_double = severity ? g_strtod (severity, 0) : 0.0;
  g_debug ("   %s: %llu: %s", __FUNCTION__, task, severity);
  if (severity)
    {
      sqlite3_result_double (context, severity_double);
      return;
    }

  task_last_report (task, &last_report);
  if (last_report == 0)
    {
      sqlite3_result_null (context);
      return;
    }

  sqlite3_result_null (context);
  return;
}

/**
 * @brief Get the last report of a task.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_task_last_report (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  task_t task;
  report_t report;

  task = sqlite3_value_int64 (argv[0]);
  if (task == 0)
    sqlite3_result_int64 (context, 0);
  else if (task_last_report (task, &report))
    sqlite3_result_int64 (context, 0);
  else
    sqlite3_result_int64 (context, report);
}

/**
 * @brief Test if a severity score matches an override's severity.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_severity_matches_ov (sqlite3_context *context,
                         int argc,
                         sqlite3_value **argv)
{
  double severity, ov_severity;

  assert (argc == 2);

  if (sqlite3_value_type (argv[0]) == SQLITE_NULL)
    {
      sqlite3_result_int (context, 0);
      return;
    }

  if (sqlite3_value_type (argv[1]) == SQLITE_NULL
      || strcmp ((const char *) (sqlite3_value_text (argv[1])), "") == 0)
    {
      sqlite3_result_int (context, 1);
      return;
    }
  else
    {
      severity = sqlite3_value_double (argv[0]);
      ov_severity = sqlite3_value_double (argv[1]);

      sqlite3_result_int (context, severity_matches_ov (severity, ov_severity));
      return;
    }
}

/**
 * @brief Get the threat level matching a severity score.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_severity_to_level (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  double severity;
  int mode;

  assert (argc == 2);

  if (sqlite3_value_type (argv[0]) == SQLITE_NULL
      || strcmp ((const char *) (sqlite3_value_text (argv[0])), "") == 0)
    {
      sqlite3_result_null (context);
      return;
    }

  mode = sqlite3_value_int (argv[1]);

  severity = sqlite3_value_double (argv[0]);

  sqlite3_result_text (
    context, severity_to_level (severity, mode), -1, SQLITE_TRANSIENT);
  return;
}

/**
 * @brief Get the message type matching a severity score.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_severity_to_type (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  double severity;

  assert (argc == 1);

  if (sqlite3_value_type (argv[0]) == SQLITE_NULL
      || strcmp ((const char *) (sqlite3_value_text (argv[0])), "") == 0)
    {
      sqlite3_result_null (context);
      return;
    }

  severity = sqlite3_value_double (argv[0]);

  sqlite3_result_text (
    context, severity_to_type (severity), -1, SQLITE_TRANSIENT);
  return;
}

/**
 * @brief Do a regexp match.  Implements SQL REGEXP.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_regexp (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const unsigned char *string, *regexp;

  assert (argc == 2);

  regexp = sqlite3_value_text (argv[0]);
  if (regexp == NULL)
    {
      /* Seems this happens when the query result is empty. */
      sqlite3_result_int (context, 0);
      return;
    }

  string = sqlite3_value_text (argv[1]);
  if (string == NULL)
    {
      /* Seems this happens when the query result is empty. */
      sqlite3_result_int (context, 0);
      return;
    }

  if (g_regex_match_simple ((gchar *) regexp, (gchar *) string, 0, 0))
    {
      sqlite3_result_int (context, 1);
      return;
    }
  sqlite3_result_int (context, 0);
}

/**
 * @brief Get the name of a task run status.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_run_status_name (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const char *name;
  int status;

  assert (argc == 1);

  status = sqlite3_value_int (argv[0]);

  name = run_status_name (status);
  sqlite3_result_text (context, name ? name : "", -1, SQLITE_TRANSIENT);
  return;
}

/**
 * @brief Get if a resource exists by its type and ID.
 *
 * This is a callback for a scalar SQL function of three arguments.
 *
 * Used by migrate_119_to_120 to check if a permission refers to a resource
 * that has been removed.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_resource_exists (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const char *type;
  resource_t resource;
  int location, exists;

  assert (argc == 3);

  type = (char *) sqlite3_value_text (argv[0]);
  if (type == NULL)
    {
      sqlite3_result_int (context, 0);
      return;
    }
  if (valid_db_resource_type ((char *) type) == 0)
    {
      sqlite3_result_error (context, "Invalid resource type argument", -1);
      return;
    }

  resource = sqlite3_value_int64 (argv[1]);
  if (resource == 0)
    {
      sqlite3_result_int (context, 0);
      return;
    }

  location = sqlite3_value_int (argv[2]);

  exists = resource_exists (type, resource, location);
  if (exists == -1)
    {
      gchar *msg;
      msg = g_strdup_printf ("Invalid resource type argument: %s", type);
      sqlite3_result_error (context, msg, -1);
      g_free (msg);
      return;
    }
  sqlite3_result_int (context, exists);
  return;
}

/**
 * @brief Get the name of a resource by its type and ID.
 *
 * This is a callback for a scalar SQL function of three arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_resource_name (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const char *type, *id;
  int location;
  char *name;

  assert (argc == 3);

  type = (char *) sqlite3_value_text (argv[0]);
  if (type == NULL)
    {
      sqlite3_result_null (context);
      return;
    }

  id = (char *) sqlite3_value_text (argv[1]);
  if (id == NULL)
    {
      sqlite3_result_null (context);
      return;
    }

  location = sqlite3_value_int (argv[2]);

  if (resource_name (type, id, location, &name))
    {
      gchar *msg;
      msg = g_strdup_printf ("Invalid resource type argument: %s", type);
      sqlite3_result_error (context, msg, -1);
      g_free (msg);
      return;
    }

  if (name)
    sqlite3_result_text (context, name, -1, SQLITE_TRANSIENT);
  else
    sqlite3_result_text (context, "", -1, SQLITE_TRANSIENT);

  free (name);

  return;
}

/**
 * @brief Check whether a severity falls within a threat level.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_severity_in_level (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  double severity;
  const char *threat;

  assert (argc == 2);

  severity = sqlite3_value_double (argv[0]);

  threat = (char *) sqlite3_value_text (argv[1]);
  if (threat == NULL)
    {
      sqlite3_result_null (context);
      return;
    }

  sqlite3_result_int (context, severity_in_level (severity, threat));

  return;
}

/**
 * @brief Get a target credential.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_target_credential (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  target_t target;
  int trash;
  const char *type;

  assert (argc == 3);

  target = sqlite3_value_int64 (argv[0]);
  trash = sqlite3_value_int (argv[1]);
  type = (char *) sqlite3_value_text (argv[2]);

  if (type == NULL)
    {
      sqlite3_result_null (context);
      return;
    }

  if (trash)
    sqlite3_result_int64 (context, trash_target_credential (target, type));
  else
    sqlite3_result_int64 (context, target_credential (target, type));

  return;
}

/**
 * @brief Get the location of a trash target credential.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_trash_target_credential_location (sqlite3_context *context,
                                      int argc,
                                      sqlite3_value **argv)
{
  target_t target;
  const char *type;

  assert (argc == 2);

  target = sqlite3_value_int64 (argv[0]);
  type = (char *) sqlite3_value_text (argv[1]);

  if (type == NULL)
    {
      sqlite3_result_null (context);
      return;
    }

  sqlite3_result_int (context, trash_target_credential_location (target, type));

  return;
}

/**
 * @brief Get a target port.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_target_login_port (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  target_t target;
  int trash;
  const char *type;

  assert (argc == 3);

  target = sqlite3_value_int64 (argv[0]);
  trash = sqlite3_value_int (argv[1]);
  type = (char *) sqlite3_value_text (argv[2]);

  if (type == NULL)
    {
      sqlite3_result_null (context);
      return;
    }

  if (trash)
    sqlite3_result_int64 (context, trash_target_login_port (target, type));
  else
    sqlite3_result_int64 (context, target_login_port (target, type));

  return;
}

/**
 * @brief Check if a user can do anything.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_user_can_everything (sqlite3_context *context,
                         int argc,
                         sqlite3_value **argv)
{
  const unsigned char *uuid;

  assert (argc == 1);

  uuid = sqlite3_value_text (argv[0]);
  if (uuid == NULL)
    {
      sqlite3_result_error (context, "Failed to get uuid argument", -1);
      return;
    }

  sqlite3_result_int (context, acl_user_can_everything ((char *) uuid));
}

/**
 * @brief Check if a user has a given permission for a resource.
 *
 * This is a callback for a scalar SQL function of four arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_user_has_access_uuid (sqlite3_context *context,
                          int argc,
                          sqlite3_value **argv)
{
  const unsigned char *type, *uuid, *permission;
  int trash;
  int ret;

  assert (argc == 4);

  type = sqlite3_value_text (argv[0]);
  if (type == NULL)
    {
      sqlite3_result_error (context, "Failed to get type argument", -1);
      return;
    }

  uuid = sqlite3_value_text (argv[1]);
  if (type == NULL)
    {
      sqlite3_result_error (context, "Failed to get uuid argument", -1);
      return;
    }

  permission = sqlite3_value_text (argv[2]);
  if (type == NULL)
    {
      sqlite3_result_error (context, "Failed to get permission argument", -1);
      return;
    }

  trash = sqlite3_value_int (argv[3]);

  ret = acl_user_has_access_uuid (
    (char *) type, (char *) uuid, (char *) permission, trash);

  sqlite3_result_int (context, ret);
}

/**
 * @brief Check if a user owns or effectively owns a resource.
 *
 * This is a callback for a scalar SQL function of two arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_user_owns (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const unsigned char *type;
  resource_t resource;

  assert (argc == 2);

  type = sqlite3_value_text (argv[0]);
  if (type == NULL)
    {
      sqlite3_result_error (context, "Failed to get type argument", -1);
      return;
    }

  resource = sqlite3_value_int64 (argv[1]);
  if (resource == 0)
    {
      sqlite3_result_int (context, 0);
      return;
    }

  sqlite3_result_int (context, acl_user_owns ((char *) type, resource, 0));
}

/**
 * @brief Gets the number of results for a Vulnerability.
 *
 * This is a callback for a scalar SQL function of four arguments.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
sql_vuln_results (sqlite3_context *context, int argc, sqlite3_value **argv)
{
  const unsigned char *nvt_oid, *host;
  gchar *nvt_oid_quoted, *host_quoted;
  long long int task, report;
  int task_null, report_null;
  int ret;

  assert (argc == 4);

  nvt_oid = sqlite3_value_text (argv[0]);
  if (nvt_oid == NULL)
    {
      sqlite3_result_error (context, "Failed to get nvt_oid argument", -1);
      return;
    }
  nvt_oid_quoted = sql_quote ((char *) nvt_oid);

  task = sqlite3_value_int64 (argv[1]);
  task_null = sqlite3_value_type (argv[1]) == SQLITE_NULL;

  report = sqlite3_value_int64 (argv[2]);
  report_null = sqlite3_value_type (argv[2]) == SQLITE_NULL;

  host = sqlite3_value_text (argv[3]);
  if (host)
    host_quoted = sql_quote ((char *) host);
  else
    host_quoted = NULL;

  ret = sql_int (
    "SELECT count(*) FROM results"
    " WHERE results.nvt = '%s'"
    "   AND (%d OR results.report = %llu)"
    "   AND (%d OR results.task = %llu)"
    "   AND (%d OR results.host = '%s')"
    "   AND (results.severity != " G_STRINGIFY (
      SEVERITY_ERROR) ")"
                      "   AND (SELECT has_permission FROM permissions_get_tasks"
                      "         WHERE \"user\" = (SELECT id FROM users"
                      "                           WHERE uuid ="
                      "                             (SELECT uuid"
                      "                              FROM current_credentials))"
                      "           AND task = results.task)",
    nvt_oid_quoted,
    report_null,
    report,
    task_null,
    task,
    host == NULL,
    host ? (char *) host : "");

  g_free (nvt_oid_quoted);
  g_free (host_quoted);

  sqlite3_result_int (context, ret);
}

/**
 * @brief Create functions.
 *
 * @return 0 success, -1 error.
 */
int
manage_create_sql_functions ()
{
  if (sqlite3_create_function (gvmd_db,
                               "t",
                               0, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_t,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to t", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "strpos",
                               2, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_strpos,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create strpos", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "order_inet",
                               1, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_order_inet,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create order_inet", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "order_message_type",
                               1, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_order_message_type,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create order_message_type", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "order_port",
                               1, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_order_port,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create order_port", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "order_role",
                               1, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_order_role,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create order_role", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "order_threat",
                               1, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_order_threat,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create order_threat", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "make_uuid",
                               0, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_make_uuid,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create make_uuid", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "hosts_contains",
                               2, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_hosts_contains,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create hosts_contains", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "clean_hosts",
                               1, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_clean_hosts,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create clean_hosts", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "iso_time",
                               1, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_iso_time,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create iso_time", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "days_from_now",
                               1, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_days_from_now,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create days_from_now", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "parse_time",
                               1, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_parse_time,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create parse_time", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "tag",
                               2, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_tag,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create tag", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "uniquify",
                               4, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_uniquify,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create uniquify", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "next_time",
                               4, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_next_time,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create next_time", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "next_time",
                               5, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_next_time,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create next_time", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "next_time",
                               6, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_next_time,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create next_time", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "next_time_ical",
                               2, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_next_time_ical,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create next_time_ical", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "next_time_ical",
                               3, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_next_time_ical,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create next_time_ical", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "m_now",
                               0, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_now,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create m_now", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "max_hosts",
                               2, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_max_hosts,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create max_hosts", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "common_cve",
                               2, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_common_cve,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create common_cve", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "cpe_title",
                               1, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_cpe_title,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create cpe_title", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "credential_value",
                               3, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_credential_value,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create credential_value", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "current_offset",
                               1, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_current_offset,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create current_offset", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "task_trend",
                               3, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_task_trend,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create task_trend", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "task_threat_level",
                               3, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_task_threat_level,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create task_threat_level", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "report_progress",
                               1, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_report_progress,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create report_progress", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "report_severity",
                               3, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_report_severity,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create report_severity", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "report_severity_count",
                               4, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_report_severity_count,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create report_severity_count", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "report_host_count",
                               1, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_report_host_count,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create report_result_host_count", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "report_result_host_count",
                               2, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_report_result_host_count,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create report_result_host_count", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "task_severity",
                               3, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_task_severity,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create task_severity", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "task_last_report",
                               1, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_task_last_report,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create task_last_report", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "severity_matches_ov",
                               2, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_severity_matches_ov,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create severity_matches_ov", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "severity_to_level",
                               1, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_severity_to_level,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create severity_to_level", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "severity_to_level",
                               2, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_severity_to_level,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create severity_to_level", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "severity_to_type",
                               1, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_severity_to_type,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create severity_to_type", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "run_status_name",
                               1, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_run_status_name,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create run_status_name", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "resource_exists",
                               3, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_resource_exists,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create resource_exists", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "regexp",
                               2, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_regexp,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create regexp", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "resource_name",
                               3, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_resource_name,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create resource_name", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "severity_in_level",
                               2, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_severity_in_level,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create severity_in_level", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "target_credential",
                               3, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_target_credential,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create target_login_data", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "trash_target_credential_location",
                               2, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_trash_target_credential_location,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create target_login_data", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "target_login_port",
                               3, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_target_login_port,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create target_login_data", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "user_can_everything",
                               1, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_user_can_everything,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create user_can_everything", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "user_has_access_uuid",
                               4, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_user_has_access_uuid,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create user_has_access_uuid", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "user_owns",
                               2, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_user_owns,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create user_owns", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "vuln_results",
                               4, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_vuln_results,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create user_has_access_uuid", __FUNCTION__);
      return -1;
    }

  return 0;
}

/* Creation. */

/**
 * @brief Create result indexes.
 */
void
manage_create_result_indexes ()
{
  sql ("CREATE INDEX IF NOT EXISTS results_by_uuid"
       " ON results (uuid);");
  sql ("CREATE INDEX IF NOT EXISTS results_by_host"
       " ON results (host);");
  sql ("CREATE INDEX IF NOT EXISTS results_by_host_and_qod"
       " ON results (host, qod);");
  sql ("CREATE INDEX IF NOT EXISTS results_by_nvt"
       " ON results (nvt);");
  sql ("CREATE INDEX IF NOT EXISTS results_by_report"
       " ON results (report);");
  sql ("CREATE INDEX IF NOT EXISTS results_by_report_host"
       " ON results (report, host);");
  sql ("CREATE INDEX IF NOT EXISTS results_by_task"
       " ON results (task);");
  sql ("CREATE INDEX IF NOT EXISTS results_by_task_qod_severity"
       " ON results (task, qod, severity);");
  sql ("CREATE INDEX IF NOT EXISTS results_by_type"
       " ON results (type);");
}

/**
 * @brief Create all tables.
 */
void
create_tables ()
{
  gchar *owned_clause;

  sql ("CREATE TABLE IF NOT EXISTS agents"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  installer TEXT, installer_64 TEXT, installer_filename,"
       "  installer_signature_64 TEXT, installer_trust INTEGER,"
       "  installer_trust_time, howto_install TEXT, howto_use TEXT,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS agents_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  installer TEXT, installer_64 TEXT, installer_filename,"
       "  installer_signature_64 TEXT, installer_trust INTEGER,"
       "  installer_trust_time, howto_install TEXT, howto_use TEXT,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS config_preferences"
       " (id INTEGER PRIMARY KEY, config INTEGER, type, name, value,"
       "  default_value, hr_name TEXT);");
  sql ("CREATE TABLE IF NOT EXISTS config_preferences_trash"
       " (id INTEGER PRIMARY KEY, config INTEGER, type, name, value,"
       "  default_value, hr_name TEXT);");
  sql ("CREATE TABLE IF NOT EXISTS configs"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name,"
       "  nvt_selector, comment, family_count INTEGER, nvt_count INTEGER,"
       "  families_growing INTEGER, nvts_growing INTEGER, type, scanner,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS configs_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name,"
       "  nvt_selector, comment, family_count INTEGER, nvt_count INTEGER,"
       "  families_growing INTEGER, nvts_growing INTEGER, type, scanner,"
       "  creation_time, modification_time, scanner_location INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS alert_condition_data"
       " (id INTEGER PRIMARY KEY, alert INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS alert_condition_data_trash"
       " (id INTEGER PRIMARY KEY, alert INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS alert_event_data"
       " (id INTEGER PRIMARY KEY, alert INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS alert_event_data_trash"
       " (id INTEGER PRIMARY KEY, alert INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS alert_method_data"
       " (id INTEGER PRIMARY KEY, alert INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS alert_method_data_trash"
       " (id INTEGER PRIMARY KEY, alert INTEGER, name, data);");
  sql ("CREATE TABLE IF NOT EXISTS alerts"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  event INTEGER, condition INTEGER, method INTEGER, filter INTEGER,"
       "  active INTEGER, creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS alerts_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  event INTEGER, condition INTEGER, method INTEGER, filter INTEGER,"
       "  filter_location INTEGER, active INTEGER, creation_time,"
       "  modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS credentials"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time, type TEXT,"
       "  allow_insecure integer);");
  sql ("CREATE TABLE IF NOT EXISTS credentials_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time, type TEXT,"
       "  allow_insecure integer);");
  sql ("CREATE TABLE IF NOT EXISTS credentials_data"
       " (id INTEGER PRIMARY KEY, credential INTEGER, type TEXT, value TEXT);");
  sql ("CREATE TABLE IF NOT EXISTS credentials_trash_data"
       " (id INTEGER PRIMARY KEY, credential INTEGER, type TEXT, value TEXT);");
  sql ("CREATE TABLE IF NOT EXISTS filters"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  type, term, creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS filters_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  type, term, creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS groups"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS groups_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  type, term, creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS group_users"
       " (id INTEGER PRIMARY KEY, `group` INTEGER, user INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS group_users_trash"
       " (id INTEGER PRIMARY KEY, `group` INTEGER, user INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS hosts"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time);");
  sql (
    "CREATE TABLE IF NOT EXISTS host_identifiers"
    " (id INTEGER PRIMARY KEY, uuid UNIQUE, host INTEGER, owner INTEGER, name,"
    "  comment, value, source_type, source_id, source_data, creation_time,"
    "  modification_time);");
  sql ("CREATE INDEX IF NOT EXISTS host_identifiers_by_host"
       " ON host_identifiers (host);");
  sql ("CREATE INDEX IF NOT EXISTS host_identifiers_by_value"
       " ON host_identifiers (value);");
  sql ("CREATE TABLE IF NOT EXISTS oss"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS host_oss"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, host INTEGER, owner INTEGER,"
       "  name, comment, os INTEGER, source_type, source_id, source_data,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS host_max_severities"
       " (id INTEGER PRIMARY KEY, host INTEGER, severity REAL, source_type,"
       "  source_id, creation_time);");
  sql ("CREATE TABLE IF NOT EXISTS host_details"
       " (id INTEGER PRIMARY KEY, host INTEGER,"
       /* The report that the host detail came from. */
       "  source_type,"
       "  source_id,"
       /* The original source of the host detail, from the scanner. */
       "  detail_source_type,"
       "  detail_source_name,"
       "  detail_source_description,"
       "  name,"
       "  value);");
  sql ("CREATE INDEX IF NOT EXISTS host_details_by_host"
       " ON host_details (host);");
  sql ("CREATE TABLE IF NOT EXISTS auth_cache"
       " (id INTEGER PRIMARY KEY, username, hash, method, creation_time);");
  sql ("CREATE TABLE IF NOT EXISTS meta"
       " (id INTEGER PRIMARY KEY, name UNIQUE, value);");
  sql ("CREATE TABLE IF NOT EXISTS notes"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, nvt,"
       "  creation_time, modification_time, text, hosts, port, severity,"
       "  task INTEGER, result INTEGER, end_time);");
  sql ("CREATE TABLE IF NOT EXISTS notes_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, nvt,"
       "  creation_time, modification_time, text, hosts, port, severity,"
       "  task INTEGER, result INTEGER, end_time);");
  sql ("CREATE TABLE IF NOT EXISTS nvt_preferences"
       " (id INTEGER PRIMARY KEY, name, value);");
  /* nvt_selectors types: 0 all, 1 family, 2 NVT
   * (NVT_SELECTOR_TYPE_* in manage.h). */
  sql ("CREATE TABLE IF NOT EXISTS nvt_selectors"
       " (id INTEGER PRIMARY KEY, name, exclude INTEGER, type INTEGER,"
       "  family_or_nvt, family);");
  sql ("CREATE INDEX IF NOT EXISTS nvt_selectors_by_name"
       " ON nvt_selectors (name);");
  sql ("CREATE INDEX IF NOT EXISTS nvt_selectors_by_family_or_nvt"
       " ON nvt_selectors (type, family_or_nvt);");
  sql ("CREATE TABLE IF NOT EXISTS nvts"
       " (id INTEGER PRIMARY KEY, "
       "  uuid TEXT, oid TEXT, name TEXT, comment TEXT,"
       "  cve TEXT, bid TEXT, xref TEXT, tag TEXT, category INTEGER, family TEXT, cvss_base REAL,"
       "  creation_time INTEGER, modification_time INTEGER, solution_type TEXT, qod INTEGER,"
       "  qod_type TEXT, cvssv2_base_vector TEXT, cvssv2_base_score REAL, cvssv2_base_score_overall REAL,"
       "  cvssv2_base_impact REAL, cvssv2_base_exploit REAL, cvssv2_em_access_vector TEXT,"
       "  cvssv2_em_access_complex TEXT, cvssv2_em_authentication TEXT, cvssv2_impact_ci TEXT,"
       "  cvssv2_impact_ii TEXT, cvssv2_impact_ai TEXT, cvssv3_base_vector TEXT, cvssv3_base_score REAL,"
       "  cvssv3_base_score_overall REAL, cvssv3_base_impact TEXT, cvssv3_base_exploit TEXT, cvssv3_em_attack_vector TEXT,"
       "  cvssv3_em_attack_complex TEXT, cvssv3_em_priv_required TEXT, cvssv3_em_user_interact TEXT, cvssv3_scope TEXT,"
       "  cvssv3_impact_ci TEXT, cvssv3_impact_ii TEXT, cvssv3_impact_ai TEXT, cwe_id TEXT, cpe TEXT, pci_dss TEXT, url_ref TEXT,"
       "  cve_date TEXT, patch_date TEXT, summary TEXT, impact TEXT, insight TEXT, vuldetect TEXT, affected TEXT, solution TEXT, intezer TEXT, "
       "  virustotal TEXT, cve_vt TEXT, apt TEXT, country_apt TEXT, mitre TEXT, cisa_exploited TEXT, cisa_alert TEXT, ransomware TEXT);");
  sql ("CREATE INDEX IF NOT EXISTS nvts_by_oid"
       " ON nvts (oid);");
  sql ("CREATE INDEX IF NOT EXISTS nvts_by_name"
       " ON nvts (name);");
  sql ("CREATE INDEX IF NOT EXISTS nvts_by_family"
       " ON nvts (family);");
  sql ("CREATE TABLE IF NOT EXISTS nvt_cves"
       " (nvt, oid, cve_name)");
  sql ("CREATE INDEX IF NOT EXISTS nvts_by_creation_time"
       " ON nvts (creation_time);");
  sql ("CREATE INDEX IF NOT EXISTS nvts_by_modification_time"
       " ON nvts (modification_time);");
  sql ("CREATE INDEX IF NOT EXISTS nvts_by_cvss_base"
       " ON nvts (cvss_base);");
  sql ("CREATE INDEX IF NOT EXISTS nvts_by_solution_type"
       " ON nvts (solution_type);");
  sql ("CREATE INDEX IF NOT EXISTS nvt_cves_by_oid"
       " ON nvt_cves (oid);");
  sql ("CREATE TABLE IF NOT EXISTS overrides"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, nvt, result_nvt,"
       "  creation_time, modification_time, text, hosts, port, severity,"
       "  new_severity, task INTEGER, result INTEGER, end_time);");
  sql ("CREATE TABLE IF NOT EXISTS overrides_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, nvt, result_nvt,"
       "  creation_time, modification_time, text, hosts, port, severity,"
       "  new_severity, task INTEGER, result INTEGER, end_time);");
  sql ("CREATE TABLE IF NOT EXISTS permissions"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner, name, comment,"
       "  resource_type, resource, resource_uuid, resource_location,"
       "  subject_type, subject, subject_location,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS permissions_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner, name, comment,"
       "  resource_type, resource, resource_uuid, resource_location,"
       "  subject_type, subject, subject_location,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS permissions_get_tasks"
       " (\"user\" integer, task integer, has_permission boolean,"
       "  UNIQUE (\"user\", task));");
  /* Overlapping port ranges will cause problems, at least for the port
   * counting.  GMP CREATE_PORT_LIST and CREATE_PORT_RANGE check for this,
   * but whoever creates a predefined port list must check this manually. */
  sql ("CREATE TABLE IF NOT EXISTS port_lists"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS port_lists_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS port_names"
       " (id INTEGER PRIMARY KEY, number INTEGER, protocol, name,"
       "  UNIQUE (number, protocol) ON CONFLICT REPLACE);");
  sql ("CREATE TABLE IF NOT EXISTS port_ranges"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, port_list INTEGER, type, start,"
       "  end, comment, exclude);");
  sql ("CREATE TABLE IF NOT EXISTS port_ranges_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, port_list INTEGER, type, start,"
       "  end, comment, exclude);");
  sql (
    "CREATE TABLE IF NOT EXISTS report_host_details"
    " (id INTEGER PRIMARY KEY, report_host INTEGER, source_type, source_name,"
    "  source_description, name, value);");
  sql ("CREATE INDEX IF NOT EXISTS"
       " report_host_details_by_report_host_and_name_and_value"
       " ON report_host_details (report_host, name, value);");
  sql ("CREATE TABLE IF NOT EXISTS report_hosts"
       " (id INTEGER PRIMARY KEY, report INTEGER, host, start_time, end_time,"
       "  current_port, max_port);");
  sql ("CREATE INDEX IF NOT EXISTS report_hosts_by_host"
       " ON report_hosts (host);");
  sql ("CREATE INDEX IF NOT EXISTS report_hosts_by_report"
       " ON report_hosts (report);");
  sql ("CREATE TABLE IF NOT EXISTS report_format_param_options"
       " (id INTEGER PRIMARY KEY, report_format_param, value);");
  sql ("CREATE TABLE IF NOT EXISTS report_format_param_options_trash"
       " (id INTEGER PRIMARY KEY, report_format_param, value);");
  sql ("CREATE TABLE IF NOT EXISTS report_format_params"
       " (id INTEGER PRIMARY KEY, report_format, name, type INTEGER, value,"
       "  type_min, type_max, type_regex, fallback);");
  sql ("CREATE TABLE IF NOT EXISTS report_format_params_trash"
       " (id INTEGER PRIMARY KEY, report_format, name, type INTEGER, value,"
       "  type_min, type_max, type_regex, fallback);");
  sql ("CREATE TABLE IF NOT EXISTS report_formats"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, extension,"
       "  content_type, summary, description, signature, trust INTEGER,"
       "  trust_time, flags INTEGER, creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS report_formats_trash"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, extension,"
       "  content_type, summary, description, signature, trust INTEGER,"
       "  trust_time, flags INTEGER, original_uuid, creation_time,"
       "  modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS reports"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER,"
       "  task INTEGER, date INTEGER, start_time, end_time, nbefile, comment,"
       "  scan_run_status INTEGER, slave_progress, slave_task_uuid,"
       "  slave_uuid, slave_name, slave_host, slave_port, source_iface,"
       "  flags INTEGER);");
  sql ("CREATE INDEX IF NOT EXISTS reports_by_task"
       " ON reports (task);");
  sql ("CREATE TABLE IF NOT EXISTS report_counts"
       " (id INTEGER PRIMARY KEY, report INTEGER, user INTEGER,"
       "  severity, count, override, end_time INTEGER, min_qod INTEGER);");
  sql ("CREATE INDEX IF NOT EXISTS report_counts_by_report_and_override"
       " ON report_counts (report, override);");
  sql ("CREATE TABLE IF NOT EXISTS resources_predefined"
       " (id INTEGER PRIMARY KEY, resource_type, resource INTEGER)");
  sql ("CREATE TABLE IF NOT EXISTS results"
       " (id INTEGER PRIMARY KEY, uuid, task INTEGER, host TEXT, port TEXT, nvt,"
       "  result_nvt, type, description, report, nvt_version, severity REAL,"
       "  qod INTEGER, qod_type TEXT, owner INTEGER, date INTEGER,"
       "  hostname TEXT)");
  sql ("CREATE TABLE IF NOT EXISTS results_trash"
       " (id INTEGER PRIMARY KEY, uuid, task INTEGER, host, port, nvt,"
       "  result_nvt, type, description, report, nvt_version, severity REAL,"
       "  qod INTEGER, qod_type TEXT, owner INTEGER, date INTEGER,"
       "  hostname TEXT)");
  manage_create_result_indexes ();
  sql ("CREATE TABLE IF NOT EXISTS result_nvts"
       " (id SERIAL PRIMARY KEY, nvt text UNIQUE NOT NULL);");
  sql ("CREATE TABLE IF NOT EXISTS result_nvt_reports"
       " (result_nvt INTEGER, report INTEGER);");
  sql ("CREATE INDEX IF NOT EXISTS result_nvt_reports_by_report"
       " ON result_nvt_reports (report);");
  sql ("CREATE TABLE IF NOT EXISTS roles"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS roles_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS role_users"
       " (id INTEGER PRIMARY KEY, role INTEGER, user INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS role_users_trash"
       " (id INTEGER PRIMARY KEY, role INTEGER, user INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS tickets"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name,"
       "  comment, nvt, task, report, severity, host, location,"
       "  solution_type, assigned_to, status, open_time, open_note,"
       "  fixed_time, fixed_note, fix_verified_time, fix_verified_report,"
       "  closed_time, closed_note, creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS ticket_results"
       " (id INTEGER PRIMARY KEY, ticket, result, result_location,"
       "  result_uuid, report);");
  sql ("CREATE TABLE IF NOT EXISTS tickets_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name,"
       "  comment, nvt, task, report, severity, host, location,"
       "  solution_type, assigned_to, status, open_time, open_note,"
       "  fixed_time, fixed_note, fix_verified_time, fix_verified_report,"
       "  closed_time, closed_note, creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS ticket_results_trash"
       " (id INTEGER PRIMARY KEY, ticket, result, result_location,"
       "  result_uuid, report);");
  sql ("CREATE TABLE IF NOT EXISTS scanners"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment,"
       "  host, port, type, ca_pub, credential INTEGER,"
       "  creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS scanners_trash"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment,"
       "  host, port, type, ca_pub, credential INTEGER,"
       "  credential_location INTEGER, creation_time, modification_time);");
  sql ("CREATE TABLE IF NOT EXISTS schedules"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment,"
       "  first_time, period, period_months, byday, duration, timezone,"
       "  initial_offset, creation_time, modification_time, icalendar);");
  sql ("CREATE TABLE IF NOT EXISTS schedules_trash"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment,"
       "  first_time, period, period_months, byday, duration, timezone,"
       "  initial_offset, creation_time, modification_time, icalendar);");
  sql ("CREATE TABLE IF NOT EXISTS settings"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, comment, value);");
  sql ("CREATE TABLE IF NOT EXISTS tags"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner, name, comment,"
       "  creation_time, modification_time, resource_type,"
       "  active, value);");
  sql ("CREATE INDEX IF NOT EXISTS tags_by_name"
       " ON tags (name);");
  sql ("CREATE UNIQUE INDEX IF NOT EXISTS tags_by_uuid"
       " ON tags (uuid);");
  sql ("CREATE TABLE IF NOT EXISTS tag_resources"
       " (tag INTEGER, resource_type text, resource INTEGER,"
       "  resource_uuid TEXT, resource_location INTEGER);");
  sql ("CREATE INDEX IF NOT EXISTS tag_resources_by_resource"
       " ON tag_resources (resource_type, resource, resource_location);");
  sql ("CREATE INDEX IF NOT EXISTS tag_resources_by_resource_uuid"
       " ON tag_resources (resource_type, resource_uuid);");
  sql ("CREATE INDEX IF NOT EXISTS tag_resources_by_tag"
       " ON tag_resources (tag);");
  sql ("CREATE TABLE IF NOT EXISTS tags_trash"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner, name, comment,"
       "  creation_time, modification_time, resource_type,"
       "  active, value);");
  sql ("CREATE TABLE IF NOT EXISTS tag_resources_trash"
       " (tag INTEGER, resource_type text, resource INTEGER,"
       "  resource_uuid TEXT, resource_location INTEGER);");
  sql ("CREATE INDEX IF NOT EXISTS tag_resources_trash_by_tag"
       " ON tag_resources_trash (tag);");
  sql ("CREATE TABLE IF NOT EXISTS targets"
       " (id INTEGER PRIMARY KEY, uuid text UNIQUE NOT NULL,"
       "  owner integer, name text NOT NULL,"
       "  hosts text, exclude_hosts text,"
       "  reverse_lookup_only integer, reverse_lookup_unify integer,"
       "  comment text, port_list integer, alive_test integer,"
       "  creation_time integer, modification_time integer);");
  sql ("CREATE TABLE IF NOT EXISTS targets_trash"
       " (id INTEGER PRIMARY KEY, uuid text UNIQUE NOT NULL,"
       "  owner integer, name text NOT NULL,"
       "  hosts text, exclude_hosts text,"
       "  reverse_lookup_only integer, reverse_lookup_unify integer,"
       "  comment text, port_list integer, port_list_location integer,"
       "  alive_test integer,"
       "  creation_time integer, modification_time integer);");
  sql ("CREATE TABLE IF NOT EXISTS targets_login_data"
       " (id INTEGER PRIMARY KEY, target INTEGER, type TEXT,"
       "  credential INTEGER, port INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS targets_trash_login_data"
       " (id INTEGER PRIMARY KEY, target INTEGER, type TEXT,"
       "  credential INTEGER, port INTEGER, credential_location INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS task_files"
       " (id INTEGER PRIMARY KEY, task INTEGER, name, content);");
  sql ("CREATE TABLE IF NOT EXISTS task_alerts"
       " (id INTEGER PRIMARY KEY, task INTEGER, alert INTEGER,"
       "  alert_location INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS task_preferences"
       " (id INTEGER PRIMARY KEY, task INTEGER, name, value);");
  sql ("CREATE TABLE IF NOT EXISTS tasks"
       " (id INTEGER PRIMARY KEY, uuid, owner INTEGER, name, hidden INTEGER,"
       "  comment, run_status INTEGER, start_time, end_time,"
       "  config INTEGER, target INTEGER, schedule INTEGER, schedule_next_time,"
       "  schedule_periods INTEGER, config_location INTEGER,"
       "  target_location INTEGER, schedule_location INTEGER,"
       "  scanner_location INTEGER, upload_result_count INTEGER,"
       "  hosts_ordering, scanner, alterable, creation_time,"
       "  modification_time);");
  /* Field password contains the hash. */
  /* Field hosts_allow: 0 deny, 1 allow. */
  /* Field ifaces_allow: 0 deny, 1 allow. */
  sql ("CREATE TABLE IF NOT EXISTS users"
       " (id INTEGER PRIMARY KEY, uuid UNIQUE, owner INTEGER, name, comment,"
       "  password, timezone, hosts, hosts_allow, ifaces, ifaces_allow,"
       "  method, creation_time, modification_time);");

  /* Result views */

  owned_clause = acl_where_owned_for_get ("override", "users.id", NULL);

  sql ("DROP VIEW IF EXISTS result_overrides;");
  sql ("CREATE VIEW result_overrides AS"
       " SELECT users.id AS user,"
       "        results.id as result,"
       "        overrides.id AS override,"
       "        overrides.severity AS ov_old_severity,"
       "        overrides.new_severity AS ov_new_severity"
       " FROM users, results, overrides"
       " WHERE overrides.nvt = results.nvt"
       "   AND (overrides.result = 0 OR overrides.result = results.id)"
       "   AND %s"
       " AND ((overrides.end_time = 0)"
       "      OR (overrides.end_time >= m_now ()))"
       " AND (overrides.task ="
       "      (SELECT reports.task FROM reports"
       "       WHERE results.report = reports.id)"
       "      OR overrides.task = 0)"
       " AND (overrides.result = results.id"
       "      OR overrides.result = 0)"
       " AND (overrides.hosts is NULL"
       "      OR overrides.hosts = ''"
       "      OR hosts_contains (overrides.hosts, results.host))"
       " AND (overrides.port is NULL"
       "      OR overrides.port = ''"
       "      OR overrides.port = results.port)"
       " ORDER BY overrides.result DESC, overrides.task DESC,"
       " overrides.port DESC, overrides.severity ASC,"
       " overrides.creation_time DESC",
       owned_clause);

  g_free (owned_clause);

  sql ("DROP VIEW IF EXISTS result_new_severities;");
  sql (
    "CREATE VIEW result_new_severities AS"
    "  SELECT results.id as result, users.id as user, dynamic, override,"
    "    CASE WHEN dynamic THEN"
    "      CASE WHEN override THEN"
    "        coalesce ((SELECT ov_new_severity FROM result_overrides"
    "                   WHERE result = results.id"
    "                     AND result_overrides.user = users.id"
    "                     AND severity_matches_ov"
    "                           (coalesce ((CASE WHEN results.severity"
    "                                                 > " G_STRINGIFY (
      SEVERITY_LOG) "                                       THEN (SELECT "
                    "cvss_base"
                    "                                             FROM nvts"
                    "                                             WHERE "
                    "nvts.oid = results.nvt)"
                    "                                       ELSE "
                    "results.severity"
                    "                                       END),"
                    "                                      results.severity),"
                    "                            ov_old_severity)),"
                    "                  coalesce ((CASE WHEN results.severity"
                    "                                       > " G_STRINGIFY (
                      SEVERITY_LOG) "                             THEN (SELECT "
                                    "cvss_base"
                                    "                                   FROM "
                                    "nvts"
                                    "                                   WHERE "
                                    "nvts.oid = results.nvt)"
                                    "                             ELSE "
                                    "results.severity"
                                    "                             END),"
                                    "                            "
                                    "results.severity))"
                                    "      ELSE"
                                    "        coalesce ((CASE WHEN "
                                    "results.severity"
                                    "                             "
                                    "> " G_STRINGIFY (
                                      SEVERITY_LOG) "                   THEN "
                                                    "(SELECT cvss_base"
                                                    "                         "
                                                    "FROM nvts"
                                                    "                         "
                                                    "WHERE nvts.oid = "
                                                    "results.nvt)"
                                                    "                   ELSE "
                                                    "results.severity"
                                                    "                   END),"
                                                    "                  "
                                                    "results.severity)"
                                                    "      END"
                                                    "    ELSE"
                                                    "      CASE WHEN override "
                                                    "THEN"
                                                    "        coalesce ((SELECT "
                                                    "ov_new_severity FROM "
                                                    "result_overrides"
                                                    "                   WHERE "
                                                    "result = results.id"
                                                    "                     AND "
                                                    "result_overrides.user = "
                                                    "users.id"
                                                    "                     AND "
                                                    "severity_matches_ov"
                                                    "                          "
                                                    " (results.severity,"
                                                    "                          "
                                                    "  ov_old_severity)),"
                                                    "                   "
                                                    "results.severity)"
                                                    "      ELSE"
                                                    "        results.severity"
                                                    "      END"
                                                    "    END AS new_severity"
                                                    "  FROM results, users"
                                                    "  JOIN (SELECT 0 AS "
                                                    "override UNION SELECT 1 "
                                                    "AS override_opts)"
                                                    "  JOIN (SELECT 0 AS "
                                                    "dynamic UNION SELECT 1 AS "
                                                    "dynamic_opts);");

  sql ("DROP VIEW IF EXISTS results_autofp;");
  sql (
    "CREATE VIEW results_autofp AS"
    " SELECT results.id as result, autofp_selection,"
    "        (CASE autofp_selection"
    "         WHEN 1 THEN"
    "          (CASE WHEN"
    "           (((SELECT family FROM nvts WHERE oid = results.nvt)"
    "              IN (" LSC_FAMILY_LIST "))"
    "            OR results.nvt = '0'" /* Open ports previously had 0 NVT. */
    "            OR EXISTS"
    "              (SELECT id FROM nvts"
    "               WHERE oid = results.nvt"
    "               AND"
    "               (cve = 'NOCVE'"
    "                 OR cve NOT IN (SELECT cve FROM nvts"
    "                                WHERE oid IN (SELECT source_name"
    "                                    FROM report_host_details"
    "                                    WHERE report_host"
    "                                    = (SELECT id"
    "                                       FROM report_hosts"
    "                                       WHERE report = %llu"
    "                                       AND host = results.host)"
    "                                    AND name = 'EXIT_CODE'"
    "                                    AND value = 'EXIT_NOTVULN')"
    "                                AND family IN (" LSC_FAMILY_LIST ")))))"
    "           THEN NULL"
    "           WHEN severity = " G_STRINGIFY (
      SEVERITY_ERROR) " THEN NULL"
                      "           ELSE 1 END)"
                      "         WHEN 2 THEN"
                      "          (CASE WHEN"
                      "            (((SELECT family FROM nvts WHERE oid = "
                      "results.nvt)"
                      "              IN (" LSC_FAMILY_LIST "))"
                      "             OR results.nvt = '0'" /* Open ports
                                                             previously had 0
                                                             NVT.*/
                      "             OR EXISTS"
                      "             (SELECT id FROM nvts AS outer_nvts"
                      "              WHERE oid = results.nvt"
                      "              AND"
                      "              (cve = 'NOCVE'"
                      "               OR NOT EXISTS"
                      "                  (SELECT cve FROM nvts"
                      "                   WHERE oid IN (SELECT source_name"
                      "                                 FROM "
                      "report_host_details"
                      "                                 WHERE report_host"
                      "                                 = (SELECT id"
                      "                                    FROM report_hosts"
                      "                                    WHERE report = "
                      "results.report"
                      "                                    AND host = "
                      "results.host)"
                      "                                 AND name = 'EXIT_CODE'"
                      "                                 AND value = "
                      "'EXIT_NOTVULN')"
                      "                   AND family IN (" LSC_FAMILY_LIST ")"
                      /* The CVE of the result NVT is outer_nvts.cve.  The CVE
                       * of the NVT that has registered the "closed" host detail
                       * is nvts.cve. Either can be a list of CVEs. */
                      "                   AND common_cve (nvts.cve, "
                      "outer_nvts.cve)))))"
                      "           THEN NULL"
                      "           WHEN severity = " G_STRINGIFY (
                        SEVERITY_ERROR) " THEN NULL"
                                        "           ELSE 1 END)"
                                        "         ELSE 0 END) AS autofp"
                                        " FROM results,"
                                        "  (SELECT 0 AS autofp_selection"
                                        "   UNION SELECT 1 AS autofp_selection"
                                        "   UNION SELECT 2 AS "
                                        "autofp_selection) AS autofp_opts;");

  /* Vulnerabilities view is created in manage_session_init because
     it must be temporary to allow using the attached SCAP database */
}

/**
 * @brief Ensure sequences for automatic ids are in a consistent state.
 */
void
check_db_sequences ()
{
  // Do nothing because this is only relevant for PostgreSQL.
}

/* SecInfo. */

/**
 * @brief Attach external databases.
 */
void
manage_attach_databases ()
{
  /* Attach the SCAP database. */

  if (access (SCAP_DB_FILE, R_OK))
    switch (errno)
      {
      case ENOENT:
        break;
      default:
        g_warning ("%s: failed to stat SCAP database: %s",
                   __FUNCTION__,
                   strerror (errno));
        break;
      }
  else
    sql_error ("ATTACH DATABASE '" SCAP_DB_FILE "'"
               " AS scap;");

  /* Attach the CERT database. */

  if (access (CERT_DB_FILE, R_OK))
    switch (errno)
      {
      case ENOENT:
        break;
      default:
        g_warning ("%s: failed to stat CERT database: %s",
                   __FUNCTION__,
                   strerror (errno));
        break;
      }
  else
    sql_error ("ATTACH DATABASE '" CERT_DB_FILE "'"
               " AS cert;");
}

/**
 * @brief Remove external database.
 *
 * @param[in]  name  Database name.
 */
void
manage_db_remove (const gchar *name)
{
  if (strcasecmp (name, "cert") == 0)
    {
      sql ("DETACH DATABASE cert;");
      unlink (CERT_DB_FILE);
    }
  else if (strcasecmp (name, "scap") == 0)
    {
      sql ("DETACH DATABASE scap;");
      unlink (SCAP_DB_FILE);
    }
  else
    assert (0);
}

/**
 * @brief Init external database.
 */
int
manage_db_init (const gchar *name)
{
  if (strcasecmp (name, "cert") == 0)
    {
      if (access (CERT_DB_FILE, R_OK) && errno != ENOENT)
        {
          g_warning ("%s: failed to stat CERT database: %s",
                     __FUNCTION__,
                     strerror (errno));
          return -1;
        }
      else
        {
          /* Ensure the parent directory exists. */

          if (g_mkdir_with_parents (CERT_DB_DIR, 0755 /* "rwxr-xr-x" */) == -1)
            {
              g_warning ("%s: failed to create CERT directory: %s",
                         __FUNCTION__,
                         strerror (errno));
              abort ();
            }

          sql ("ATTACH DATABASE '" CERT_DB_FILE "'"
               " AS cert;");
        }

      sql ("PRAGMA cert.journal_mode=WAL;");

      /* Drop existing tables. */

      sql ("DROP TABLE IF EXISTS cert.meta;");
      sql ("DROP TABLE IF EXISTS cert.cert_bund_advs;");
      sql ("DROP TABLE IF EXISTS cert.cert_bund_cves;");
      sql ("DROP TABLE IF EXISTS cert.dfn_cert_advs;");
      sql ("DROP TABLE IF EXISTS cert.dfn_cert_cves;");

      /* Create tables and indexes. */

      sql ("CREATE TABLE cert.meta"
           " (id INTEGER PRIMARY KEY AUTOINCREMENT,"
           "  name UNIQUE,"
           "  value);");

      sql ("CREATE TABLE cert.cert_bund_advs"
           " (id INTEGER PRIMARY KEY AUTOINCREMENT,"
           "  uuid UNIQUE,"
           "  name UNIQUE,"
           "  comment TEXT,"
           "  creation_time DATE,"
           "  modification_time DATE,"
           "  title TEXT,"
           "  summary TEXT,"
           "  cve_refs INTEGER,"
           "  max_cvss FLOAT);");
      sql ("CREATE UNIQUE INDEX cert.cert_bund_advs_idx"
           " ON cert_bund_advs (name);");

      sql ("CREATE TABLE cert.cert_bund_cves"
           " (adv_id INTEGER,"
           "  cve_name VARCHAR(20));");
      sql ("CREATE INDEX cert.cert_bund_cves_adv_idx"
           " ON cert_bund_cves (adv_id);");
      sql ("CREATE INDEX cert.cert_bund_cves_cve_idx"
           " ON cert_bund_cves (cve_name);");

      sql ("CREATE TABLE cert.dfn_cert_advs"
           " (id INTEGER PRIMARY KEY AUTOINCREMENT,"
           "  uuid UNIQUE,"
           "  name UNIQUE,"
           "  comment TEXT,"
           "  creation_time DATE,"
           "  modification_time DATE,"
           "  title TEXT,"
           "  summary TEXT,"
           "  cve_refs INTEGER,"
           "  max_cvss FLOAT);");
      sql ("CREATE UNIQUE INDEX cert.dfn_cert_advs_idx"
           " ON dfn_cert_advs (name);");

      sql ("CREATE TABLE cert.dfn_cert_cves"
           " (adv_id INTEGER,"
           "  cve_name VARCHAR(20));");
      sql ("CREATE INDEX cert.dfn_cert_cves_adv_idx"
           " ON dfn_cert_cves (adv_id);");
      sql ("CREATE INDEX cert.dfn_cert_cves_cve_idx"
           " ON dfn_cert_cves (cve_name);");

      /* Create deletion triggers. */

      sql ("CREATE TRIGGER cert.cert_bund_adv_delete AFTER DELETE"
           " ON cert_bund_advs"
           " BEGIN"
           "   DELETE FROM cert_bund_cves where adv_id = old.id;"
           " END;");

      sql ("CREATE TRIGGER cert.dfn_cert_adv_delete AFTER DELETE"
           " ON dfn_cert_advs"
           " BEGIN"
           "   DELETE FROM dfn_cert_cves where adv_id = old.id;"
           " END;");

      /* Init tables. */

      sql ("INSERT INTO cert.meta (name, value)"
           " VALUES ('database_version', '1100');");
      sql ("INSERT INTO cert.meta (name, value)"
           " VALUES ('last_update', '0');");
    }
  else if (strcasecmp (name, "scap") == 0)
    {
      if (access (SCAP_DB_FILE, R_OK) && errno != ENOENT)
        {
          g_warning ("%s: failed to stat SCAP database: %s",
                     __FUNCTION__,
                     strerror (errno));
          return -1;
        }
      else
        {
          /* Ensure the parent directory exists. */

          if (g_mkdir_with_parents (SCAP_DB_DIR, 0755 /* "rwxr-xr-x" */) == -1)
            {
              g_warning ("%s: failed to create SCAP directory: %s",
                         __FUNCTION__,
                         strerror (errno));
              abort ();
            }

          sql ("ATTACH DATABASE '" SCAP_DB_FILE "' AS scap;");
        }

      sql ("PRAGMA scap.journal_mode=WAL;");

      /* Drop existing tables. */

      sql ("DROP TABLE IF EXISTS scap.meta;");
      sql ("DROP TABLE IF EXISTS scap.cves;");
      sql ("DROP TABLE IF EXISTS scap.cpes;");
      sql ("DROP TABLE IF EXISTS scap.affected_products;");
      sql ("DROP TABLE IF EXISTS scap.oval_def;");
      sql ("DROP TABLE IF EXISTS scap.ovaldefs;");
      sql ("DROP TABLE IF EXISTS scap.ovalfiles;");
      sql ("DROP TABLE IF EXISTS scap.affected_ovaldefs;");

      /* Create tables and indexes. */

      sql ("CREATE TABLE scap.meta"
           " (id INTEGER PRIMARY KEY AUTOINCREMENT,"
           "  name UNIQUE,"
           "  value);");

      sql ("CREATE TABLE scap.cves"
           " (id INTEGER PRIMARY KEY AUTOINCREMENT,"
           "  uuid UNIQUE,"
           "  name,"
           "  comment,"
           "  description,"
           "  creation_time DATE,"
           "  modification_time DATE,"
           "  vector,"
           "  complexity,"
           "  authentication,"
           "  confidentiality_impact,"
           "  integrity_impact,"
           "  availability_impact,"
           "  products,"
           "  cvss FLOAT DEFAULT 0);");
      sql ("CREATE UNIQUE INDEX scap.cve_idx"
           " ON cves (name);");
      sql ("CREATE INDEX scap.cves_by_creation_time_idx"
           " ON cves (creation_time);");
      sql ("CREATE INDEX scap.cves_by_modification_time_idx"
           " ON cves (modification_time);");
      sql ("CREATE INDEX scap.cves_by_cvss"
           " ON cves (cvss);");

      sql ("CREATE TABLE scap.cpes"
           " (id INTEGER PRIMARY KEY AUTOINCREMENT,"
           "  uuid UNIQUE,"
           "  name,"
           "  comment,"
           "  creation_time DATE,"
           "  modification_time DATE,"
           "  title,"
           "  status,"
           "  deprecated_by_id INTEGER,"
           "  max_cvss FLOAT DEFAULT 0,"
           "  cve_refs INTEGER DEFAULT 0,"
           "  nvd_id);");
      sql ("CREATE UNIQUE INDEX scap.cpe_idx"
           " ON cpes (name);");
      sql ("CREATE INDEX scap.cpes_by_creation_time_idx"
           " ON cpes (creation_time);");
      sql ("CREATE INDEX scap.cpes_by_modification_time_idx"
           " ON cpes (modification_time);");
      sql ("CREATE INDEX scap.cpes_by_cvss"
           " ON cpes (max_cvss);");

      sql ("CREATE TABLE scap.affected_products"
           " (cve INTEGER NOT NULL,"
           "  cpe INTEGER NOT NULL,"
           "  FOREIGN KEY(cve) REFERENCES cves(id),"
           "  FOREIGN KEY(cpe) REFERENCES cpes(id));");
      sql ("CREATE INDEX scap.afp_cpe_idx"
           " ON affected_products (cpe);");
      sql ("CREATE INDEX scap.afp_cve_idx"
           " ON affected_products (cve);");

      sql ("CREATE TABLE scap.ovaldefs"
           " (id INTEGER PRIMARY KEY AUTOINCREMENT,"
           "  uuid UNIQUE,"
           "  name," /* OVAL identifier. */
           "  comment,"
           "  creation_time DATE,"
           "  modification_time DATE,"
           "  version INTEGER,"
           "  deprecated BOOLEAN,"
           "  def_class TEXT," /* enum */
           "  title TEXT,"
           "  description TEXT,"
           "  xml_file TEXT,"
           "  status TEXT,"
           "  max_cvss FLOAT,"
           "  cve_refs INTEGER);");
      sql ("CREATE INDEX scap.ovaldefs_idx"
           " ON ovaldefs (name);");

      sql ("CREATE TABLE scap.ovalfiles"
           " (id INTEGER PRIMARY KEY AUTOINCREMENT,"
           "  xml_file TEXT UNIQUE);");
      sql ("CREATE INDEX scap.ovalfiles_idx"
           " ON ovalfiles (xml_file);");

      sql ("CREATE TABLE scap.affected_ovaldefs"
           " (cve INTEGER NOT NULL,"
           "  ovaldef INTEGER NOT NULL,"
           "  FOREIGN KEY(cve) REFERENCES cves(id),"
           "  FOREIGN KEY(ovaldef) REFERENCES ovaldefs(id));");
      sql ("CREATE INDEX scap.aff_ovaldefs_def_idx"
           " ON affected_ovaldefs (ovaldef);");
      sql ("CREATE INDEX scap.aff_ovaldefs_cve_idx"
           " ON affected_ovaldefs (cve);");

      /* Create deletion triggers. */

      sql ("CREATE TRIGGER scap.cves_delete AFTER DELETE"
           " ON cves"
           " BEGIN"
           "   DELETE FROM affected_products WHERE cve = old.id;"
           "   DELETE FROM affected_ovaldefs WHERE cve = old.id;"
           " END;");

      sql ("CREATE TRIGGER scap.affected_delete AFTER DELETE"
           " ON affected_products"
           " BEGIN"
           "   UPDATE cpes SET max_cvss = 0.0 WHERE id = old.cpe;"
           "   UPDATE cpes SET cve_refs = cve_refs -1 WHERE id = old.cpe;"
           " END;");

      sql ("CREATE TRIGGER scap.ovalfiles_delete AFTER DELETE"
           " ON ovalfiles"
           " BEGIN"
           "   DELETE FROM ovaldefs WHERE ovaldefs.xml_file = old.xml_file;"
           " END;");

      sql ("CREATE TRIGGER scap.affected_ovaldefs_delete AFTER DELETE"
           " ON affected_ovaldefs"
           " BEGIN"
           "   UPDATE ovaldefs SET max_cvss = 0.0 WHERE id = old.ovaldef;"
           " END;");

      /* Init tables. */

      sql ("INSERT INTO scap.meta (name, value)"
           " VALUES ('database_version', '1100');");
      sql ("INSERT INTO scap.meta (name, value)"
           " VALUES ('last_update', '0');");
    }
  else
    {
      assert (0);
      return -1;
    }

  return 0;
}

/**
 * @brief Ensure db is in WAL mode.
 *
 * @param[in]  name  Name, like "cert" or "scap".
 */
void
manage_db_check_mode (const gchar *name)
{
  if (strcasecmp (name, "cert") == 0)
    sql ("PRAGMA cert.journal_mode=WAL;");
  else if (strcasecmp (name, "scap") == 0)
    sql ("PRAGMA scap.journal_mode=WAL;");
}

/**
 * @brief Check integrity of db.
 *
 * @param[in]  name  Name, like "cert" or "scap".
 *
 * @return 0 fine, 1 broken, -1 error.
 */
int
manage_db_check (const gchar *name)
{
  if (strcasecmp (name, "cert") == 0)
    {
      char *ok;
      int ret;

      if (access (CERT_DB_FILE, R_OK))
        {
          if (errno == ENOENT)
            return 0;

          g_warning ("%s: failed to stat CERT database: %s",
                     __FUNCTION__,
                     strerror (errno));
          return -1;
        }

      ok = sql_string ("PRAGMA cert.integrity_check;");
      if (ok == NULL)
        return -1;
      ret = (strcmp (ok, "ok") ? 1 : 0);
      g_free (ok);
      return ret;
    }
  else if (strcasecmp (name, "scap") == 0)
    {
      char *ok;
      int ret;

      if (access (SCAP_DB_FILE, R_OK))
        {
          if (errno == ENOENT)
            return 0;

          g_warning ("%s: failed to stat SCAP database: %s",
                     __FUNCTION__,
                     strerror (errno));
          return -1;
        }

      ok = sql_string ("PRAGMA scap.integrity_check;");
      if (ok == NULL)
        return -1;
      ret = (strcmp (ok, "ok") ? 1 : 0);
      g_free (ok);
      return ret;
    }
  return 0;
}

/**
 * @brief Check whether CERT is available.
 *
 * @return 1 if CERT database is loaded, else 0.
 */
int
manage_cert_loaded ()
{
  static int loaded = 0;

  if (loaded)
    return 1;

  if (access (CERT_DB_FILE, R_OK))
    switch (errno)
      {
      case ENOENT:
        return 0;
        break;
      default:
        g_warning ("%s: failed to stat CERT database: %s",
                   __FUNCTION__,
                   strerror (errno));
        return 0;
      }

  if (sql_error ("SELECT count(*) FROM cert.sqlite_master"
                 " WHERE type = 'table' AND name = 'dfn_cert_advs';"))
    /* There was an error, so probably the initial ATTACH failed. */
    return 0;

  loaded = !!sql_int ("SELECT count(*) FROM cert.sqlite_master"
                      " WHERE type = 'table' AND name = 'dfn_cert_advs';");
  return loaded;
}

/**
 * @brief Check whether SCAP is available.
 *
 * @return 1 if SCAP database is loaded, else 0.
 */
int
manage_scap_loaded ()
{
  static int loaded = 0;

  if (loaded)
    return 1;

  if (access (SCAP_DB_FILE, R_OK))
    switch (errno)
      {
      case ENOENT:
        return 0;
        break;
      default:
        g_warning ("%s: failed to stat SCAP database: %s",
                   __FUNCTION__,
                   strerror (errno));
        return 0;
      }

  if (sql_error ("SELECT count(*) FROM scap.sqlite_master"
                 " WHERE type = 'table' AND name = 'cves';"))
    /* There was an error, so probably the initial ATTACH failed. */
    return 0;

  loaded = !!sql_int ("SELECT count(*) FROM scap.sqlite_master"
                      " WHERE type = 'table' AND name = 'cves';");
  return loaded;
}

/**
 * @brief Check if CERT db exists.
 *
 * @return 1 if exists, else 0.
 */
int
manage_cert_db_exists ()
{
  if (access (CERT_DB_FILE, R_OK))
    switch (errno)
      {
      case ENOENT:
        return 0;
        break;
      default:
        g_warning ("%s: failed to stat CERT database: %s",
                   __FUNCTION__,
                   strerror (errno));
        return 1;
      }
  return 1;
}

/**
 * @brief Check if SCAP db exists.
 *
 * @return 1 if exists, else 0.
 */
int
manage_scap_db_exists ()
{
  if (access (SCAP_DB_FILE, R_OK))
    switch (errno)
      {
      case ENOENT:
        return 0;
        break;
      default:
        g_warning ("%s: failed to stat SCAP database: %s",
                   __FUNCTION__,
                   strerror (errno));
        return 1;
      }
  return 1;
}

/**
 * @brief Database specific setup for CERT update.
 *
 * @return 0 success, -1 error.
 */
int
manage_update_cert_db_init ()
{
  if (sqlite3_create_function (gvmd_db,
                               "merge_dfn_cert_adv",
                               6, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_merge_dfn_cert_adv,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create merge_dfn_cert_adv", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "merge_bund_adv",
                               6, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_merge_bund_adv,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create merge_bund_adv", __FUNCTION__);
      return -1;
    }

  return 0;
}

/**
 * @brief Database specific cleanup after CERT update.
 *
 * @return 1 if empty, else 0.
 */
void
manage_update_cert_db_cleanup ()
{
  if (sqlite3_create_function (gvmd_db,
                               "merge_dfn_cert_adv",
                               6, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               NULL,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    g_warning ("%s: failed to remove merge_dfn_cert_adv", __FUNCTION__);

  if (sqlite3_create_function (gvmd_db,
                               "merge_bund_adv",
                               6, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               NULL,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    g_warning ("%s: failed to remove merge_bund_adv", __FUNCTION__);
}

/**
 * @brief Database specific setup for SCAP update.
 *
 * @return 0 success, -1 error.
 */
int
manage_update_scap_db_init ()
{
  if (sqlite3_create_function (gvmd_db,
                               "merge_cpe",
                               7, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_merge_cpe,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create merge_cpe", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "merge_cve",
                               13, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_merge_cve,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create merge_cpe", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "merge_cpe_name",
                               4, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_merge_cpe_name,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create merge_cpe_name", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "merge_affected_product",
                               2, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_merge_affected_product,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create merge_affected_product", __FUNCTION__);
      return -1;
    }

  if (sqlite3_create_function (gvmd_db,
                               "merge_ovaldef",
                               13, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               sql_merge_ovaldef,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create merge_ovaldef", __FUNCTION__);
      return -1;
    }

  return 0;
}

/**
 * @brief Database specific cleanup after SCAP update.
 *
 * @return 1 if empty, else 0.
 */
void
manage_update_scap_db_cleanup ()
{
  if (sqlite3_create_function (gvmd_db,
                               "merge_cpe",
                               8, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               NULL,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    g_warning ("%s: failed to remove merge_cpe", __FUNCTION__);

  if (sqlite3_create_function (gvmd_db,
                               "merge_cve",
                               13, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               NULL,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    g_warning ("%s: failed to remove merge_cve", __FUNCTION__);

  if (sqlite3_create_function (gvmd_db,
                               "merge_cpe_name",
                               4, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               NULL,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    g_warning ("%s: failed to remove merge_cpe_name", __FUNCTION__);

  if (sqlite3_create_function (gvmd_db,
                               "merge_affected_product",
                               2, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               NULL,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    g_warning ("%s: failed to remove merge_affected_product", __FUNCTION__);

  if (sqlite3_create_function (gvmd_db,
                               "merge_ovaldef",
                               14, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               NULL,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    g_warning ("%s: failed to remove merge_ovaldef", __FUNCTION__);
}

/* Backup. */

/**
 * @brief Backup the database to a file.
 *
 * @param[in]   database         Database to backup.
 * @param[out]  backup_file_arg  Location for freshly allocated name of backup
 *                               file, or NULL.  Only set on success.
 *
 * @return 0 success, -1 error.
 */
static int
backup_db (const gchar *database, gchar **backup_file_arg)
{
  gchar *backup_file;
  sqlite3 *backup_db, *actual_gvmd_db;
  sqlite3_backup *backup;

  backup_file = g_strdup_printf ("%s.bak", database);

  if (sqlite3_open (backup_file, &backup_db) != SQLITE_OK)
    {
      g_warning (
        "%s: sqlite3_open failed: %s", __FUNCTION__, sqlite3_errmsg (gvmd_db));
      goto fail;
    }

  /* Turn off WAL for the backup db. */
  actual_gvmd_db = gvmd_db;
  gvmd_db = backup_db;
  sql ("PRAGMA journal_mode=DELETE;");
  gvmd_db = actual_gvmd_db;

  backup = sqlite3_backup_init (backup_db, "main", gvmd_db, "main");
  if (backup == NULL)
    {
      g_warning ("%s: sqlite3_backup_init failed: %s",
                 __FUNCTION__,
                 sqlite3_errmsg (backup_db));
      goto fail;
    }

  while (1)
    {
      int ret;

      ret = sqlite3_backup_step (backup, 20 /* pages */);
      if (ret == SQLITE_DONE)
        break;
      if (ret == SQLITE_OK)
        continue;
      if (ret == SQLITE_BUSY || ret == SQLITE_LOCKED)
        {
          sqlite3_sleep (250);
          continue;
        }
      g_warning ("%s: sqlite3_backup_step failed: %s",
                 __FUNCTION__,
                 sqlite3_errmsg (backup_db));
      sqlite3_backup_finish (backup);
      goto fail;
    }
  sqlite3_backup_finish (backup);
  sqlite3_close (backup_db);

  if (backup_file_arg)
    *backup_file_arg = backup_file;
  else
    g_free (backup_file);
  return 0;

fail:
  sqlite3_close (backup_db);
  g_free (backup_file);
  return -1;
}

/**
 * @brief Backup the database to a file.
 *
 * @param[in]  database  Location of manage database.
 *
 * @return 0 success, -1 error.
 */
int
manage_backup_db (const gchar *database)
{
  int ret;
  const gchar *db = database ? database : sql_default_database ();

  init_manage_process (0, db);

  ret = backup_db (db, NULL);

  cleanup_manage_process (TRUE);

  return ret;
}

/* Migrator helper. */

/**
 * @brief Convert a UTC text time to an integer time since the Epoch.
 *
 * This is a callback for a scalar SQL function of one argument.
 *
 * @param[in]  context  SQL context.
 * @param[in]  argc     Number of arguments.
 * @param[in]  argv     Argument array.
 */
void
migrate_51_to_52_sql_convert (sqlite3_context *context,
                              int argc,
                              sqlite3_value **argv)
{
  const unsigned char *text_time;
  int epoch_time;
  struct tm tm;

  assert (argc == 1);

  text_time = sqlite3_value_text (argv[0]);
  if (text_time)
    {
      /* Scanner uses ctime: "Wed Jun 30 21:49:08 1993".
       *
       * The dates being converted are in the timezone that the Scanner was
       * using.
       *
       * As a special case for this migrator, gvmd.c uses the timezone
       * from the environment, instead of forcing UTC.  This allows the user
       * to set the timezone to be the same as the Scanner timezone, so
       * that these dates are converted from the Scanner timezone.  Even if
       * the user just leaves the timezone as is, it is likely to be the same
       * timezone she/he is running the Scanner under.
       */
      if (text_time && (strlen ((char *) text_time) > 0))
        {
          memset (&tm, 0, sizeof (struct tm));
          if (strptime ((char *) text_time, "%a %b %d %H:%M:%S %Y", &tm)
              == NULL)
            {
              sqlite3_result_error (context, "Failed to parse time", -1);
              return;
            }
          epoch_time = mktime (&tm);
          if (epoch_time == -1)
            {
              sqlite3_result_error (context, "Failed to make time", -1);
              return;
            }
        }
      else
        epoch_time = 0;
    }
  else
    epoch_time = 0;
  sqlite3_result_int (context, epoch_time);
}

/**
 * @brief Setup SQL function for migrate_51_to_52.
 *
 * @return 0 success, -1 error.
 */
int
manage_create_migrate_51_to_52_convert ()
{
  if (sqlite3_create_function (gvmd_db,
                               "convert",
                               1, /* Number of args. */
                               SQLITE_UTF8,
                               NULL, /* Callback data. */
                               migrate_51_to_52_sql_convert,
                               NULL, /* xStep. */
                               NULL) /* xFinal. */
      != SQLITE_OK)
    {
      g_warning ("%s: failed to create convert", __FUNCTION__);
      return -1;
    }
  return 0;
}
