// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Name: manage_sql_nvts.c
 * Brief: The NVT parts of the GVM management layer.
 * 
 * Copyright:
 * Copyright (C) 2009-2018 Greenbone Networks GmbH
 * Copyright (C) 2022, Mageni Security LLC
 *
 */

/**
 * @brief Enable extra GNU functions.
 */
#define _GNU_SOURCE

#include "manage_sql_nvts.h"

#include "manage_sql.h"
#include "sql.h"
#include "utils.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/* Static headers. */

static void
refresh_nvt_cves ();

/* NVT's. */

/**
 * @brief Ensures the sanity of nvts cache in DB.
 */
void
check_db_nvts ()
{
  /* Ensure the nvti cache update flag exists and is clear. */
  if (sql_int ("SELECT count(*) FROM %s.meta"
               " WHERE name = 'update_nvti_cache';",
               sql_schema ()))
    sql ("UPDATE %s.meta SET value = 0 WHERE name = 'update_nvti_cache';",
         sql_schema ());
  else
    sql ("INSERT INTO %s.meta (name, value)"
         " VALUES ('update_nvti_cache', 0);",
         sql_schema ());

  /* Ensure the NVT CVE table is filled. */
  if (sql_int ("SELECT count (*) FROM nvt_cves;") == 0)
    refresh_nvt_cves ();
}

/**
 * @brief Get the name of an NVT.
 *
 * @param[in]  nvt  NVT.
 *
 * @return Freshly allocated name of NVT if possible, else NULL.
 */
char *
manage_nvt_name (nvt_t nvt)
{
  return sql_string ("SELECT name FROM nvts WHERE id = %llu;", nvt);
}

/**
 * @brief Guess the OID of an NVT given a name.
 *
 * @param[in]  name  Name of NVT.
 *
 * @return OID of NVT if possible, else NULL.
 */
char *
nvt_oid (const char *name)
{
  gchar *quoted_name = sql_quote (name);
  char *ret =
    sql_string ("SELECT oid FROM nvts WHERE name = '%s' LIMIT 1;", quoted_name);
  g_free (quoted_name);
  return ret;
}

/**
 * @brief Return feed version of the plugins in the plugin cache.
 *
 * @return Feed version of plugins if the plugins are cached, else NULL.
 */
char *
nvts_feed_version ()
{
  return sql_string ("SELECT value FROM %s.meta"
                     " WHERE name = 'nvts_feed_version';",
                     sql_schema ());
}

/**
 * @brief Set the feed version of the plugins in the plugin cache.
 *
 * @param[in]  feed_version  New feed version.
 *
 * Also queue an update to the nvti cache.
 */
void
set_nvts_feed_version (const char *feed_version)
{
  gchar *quoted = sql_quote (feed_version);
  sql ("DELETE FROM %s.meta WHERE name = 'nvts_feed_version';", sql_schema ());
  sql ("INSERT INTO %s.meta (name, value)"
       " VALUES ('nvts_feed_version', '%s');",
       sql_schema (),
       quoted);
  g_free (quoted);
}

/**
 * @brief Find an NVT given an identifier.
 *
 * @param[in]   oid  An NVT identifier.
 * @param[out]  nvt  NVT return, 0 if successfully failed to find task.
 *
 * @return FALSE on success (including if failed to find NVT), TRUE on error.
 */
gboolean
find_nvt (const char *oid, nvt_t *nvt)
{
  switch (sql_int64 (nvt, "SELECT id FROM nvts WHERE oid = '%s';", oid))
    {
    case 0:
      break;
    case 1: /* Too few rows in result of query. */
      *nvt = 0;
      break;
    default: /* Programming error. */
      assert (0);
    case -1:
      return TRUE;
      break;
    }

  return FALSE;
}

/**
 * @brief Counter for chunking in insert_nvts_list.
 */
static int chunk_count = 0;

/**
 * @brief Size of chunk for insert_nvts_list.
 */
#define CHUNK_SIZE 100

/**
 * @brief Make an nvt from an nvti.
 *
 * @param[in]  nvti    NVTI.
 *
 * @return An NVT.
 */
static nvt_t
make_nvt_from_nvti (const nvti_t *nvti)
{
    gchar *qod_str, *qod_type;
    gchar *quoted_name;
    gchar *quoted_cve, *quoted_bid, *quoted_xref, *quoted_tag;
    gchar *quoted_cvss_base, *quoted_qod_type, *quoted_family, *value;
    gchar *quoted_solution_type;
    gchar *quoted_cvssv2_base_vector;
    gchar *quoted_cvssv2_base_score;
    gchar *quoted_cvssv2_base_score_overall;
    gchar *quoted_cvssv2_base_impact;
    gchar *quoted_cvssv2_base_exploit;
    gchar *quoted_cvssv2_em_access_vector;
    gchar *quoted_cvssv2_em_access_complex;
    gchar *quoted_cvssv2_em_authentication;
    gchar *quoted_cvssv2_impact_ci;
    gchar *quoted_cvssv2_impact_ii;
    gchar *quoted_cvssv2_impact_ai;
    gchar *quoted_cvssv3_base_vector;
    gchar *quoted_cvssv3_base_score;
    gchar *quoted_cvssv3_base_score_overall;
    gchar *quoted_cvssv3_base_impact;
    gchar *quoted_cvssv3_base_exploit;
    gchar *quoted_cvssv3_em_attack_vector;
    gchar *quoted_cvssv3_em_attack_complex;
    gchar *quoted_cvssv3_em_priv_required;
    gchar *quoted_cvssv3_em_user_interact;
    gchar *quoted_cvssv3_scope;
    gchar *quoted_cvssv3_impact_ci;
    gchar *quoted_cvssv3_impact_ii;
    gchar *quoted_cvssv3_impact_ai;
    gchar *quoted_cwe_id;
    gchar *quoted_cpe;
    gchar *quoted_pci_dss;
    gchar *quoted_url_ref;
    gchar *quoted_cve_date;
    gchar *quoted_patch_date;
    gchar *quoted_summary;
    gchar *quoted_impact;
    gchar *quoted_insight;
    gchar *quoted_vuldetect;
    gchar *quoted_affected;
    gchar *quoted_solution;
    gchar *quoted_virustotal;
    gchar *quoted_intezer;
    gchar *quoted_cvssv_base_vector;
    gchar *quoted_cve_vt;
    gchar *quoted_apt;
    gchar *quoted_country_apt;
    gchar *quoted_mitre;
    gchar *quoted_cisa_exploited;
    gchar *quoted_cisa_alert;
    gchar *quoted_ransomware;

  int creation_time, modification_time, qod;

  if (chunk_count == 0)
    {
      chunk_count++;
    }
  else if (chunk_count == CHUNK_SIZE)
    chunk_count = 0;
  else
    chunk_count++;

  quoted_name = sql_quote (nvti_name (nvti) ? nvti_name (nvti) : "");
  quoted_cve = sql_quote (nvti_cve (nvti) ? nvti_cve (nvti) : "");
  quoted_bid = sql_quote (nvti_bid (nvti) ? nvti_bid (nvti) : "");
  quoted_xref = sql_quote (nvti_xref (nvti) ? nvti_xref (nvti) : "");
  if (nvti_tag (nvti))
    {
      const char *tags;
      gchar **split, **point;
      GString *tag;

      tags = nvti_tag (nvti);

      split = g_strsplit (tags, "|", 0);
      point = split;

      while (*point)
        {
          if (((strlen (*point) > strlen ("creation_date"))
               && (strncmp (*point, "creation_date", strlen ("creation_date"))
                   == 0)
               && ((*point)[strlen ("creation_date")] == '='))
              || ((strlen (*point) > strlen ("last_modification"))
                  && (strncmp (*point,
                               "last_modification",
                               strlen ("last_modification"))
                      == 0)
                  && ((*point)[strlen ("last_modification")] == '=')))
            {
              gchar **move;
              move = point;
              g_free (*point);
              while (*move)
                {
                  move[0] = move[1];
                  move++;
                }
            }
          else
            point++;
        }

      point = split;
      tag = g_string_new ("");
      while (*point)
        {
          if (point[1])
            g_string_append_printf (tag, "%s|", *point);
          else
            g_string_append_printf (tag, "%s", *point);
          point++;
        }
      g_strfreev (split);

      quoted_tag = sql_quote (tag->str);
      g_string_free (tag, TRUE);
    }
  else
    quoted_tag = g_strdup ("");
  quoted_cvss_base =
    sql_quote (nvti_cvss_base (nvti) ? nvti_cvss_base (nvti) : "");

  qod_str = tag_value (nvti_tag (nvti), "qod");
  qod_type = tag_value (nvti_tag (nvti), "qod_type");

  if (qod_str == NULL || sscanf (qod_str, "%d", &qod) != 1)
    qod = qod_from_type (qod_type);

  quoted_qod_type = sql_quote (qod_type ? qod_type : "");

  g_free (qod_str);
  g_free (qod_type);

  quoted_family = sql_quote (nvti_family (nvti) ? nvti_family (nvti) : "");

  value = tag_value (nvti_tag (nvti), "creation_date");
  switch (parse_time (value, &creation_time))
    {
    case -1:
      g_debug ("%s: Failed to parse creation time of %s: %s",
                 __FUNCTION__,
                 nvti_oid (nvti),
                 value);
      creation_time = 0;
      break;
    case -2:
      g_debug ("%s: Failed to make time: %s", __FUNCTION__, value);
      creation_time = 0;
      break;
    case -3:
      g_debug (
        "%s: Failed to parse timezone offset: %s", __FUNCTION__, value);
      creation_time = 0;
      break;
    }
  g_free (value);

  value = tag_value (nvti_tag (nvti), "last_modification");
  switch (parse_time (value, &modification_time))
    {
    case -1:
      g_warning ("%s: Failed to parse last_modification time of %s: %s",
                 __FUNCTION__,
                 nvti_oid (nvti),
                 value);
      modification_time = 0;
      break;
    case -2:
      g_warning ("%s: Failed to make time: %s", __FUNCTION__, value);
      modification_time = 0;
      break;
    case -3:
      g_warning (
        "%s: Failed to parse timezone offset: %s", __FUNCTION__, value);
      modification_time = 0;
      break;
    }
  g_free (value);

  value = tag_value (nvti_tag (nvti), "solution_type");
  if (value)
    {
      quoted_solution_type = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_solution_type = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv2_base_vector");
  if (value)
    {
      quoted_cvssv2_base_vector = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv2_base_vector = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv2_base_score");
  if (value)
    {
      quoted_cvssv2_base_score = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv2_base_score = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv2_base_score_overall");
  if (value)
    {
      quoted_cvssv2_base_score_overall = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv2_base_score_overall = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv2_base_impact");
  if (value)
    {
      quoted_cvssv2_base_impact = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv2_base_impact = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv2_base_exploit");
  if (value)
    {
      quoted_cvssv2_base_exploit = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv2_base_exploit = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv2_em_access_vector");
  if (value)
    {
      quoted_cvssv2_em_access_vector = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv2_em_access_vector = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv2_em_access_complex");
  if (value)
    {
      quoted_cvssv2_em_access_complex = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv2_em_access_complex = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv2_em_authentication");
  if (value)
    {
      quoted_cvssv2_em_authentication = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv2_em_authentication = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv2_impact_ci");
  if (value)
    {
      quoted_cvssv2_impact_ci = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv2_impact_ci = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv2_impact_ii");
  if (value)
    {
      quoted_cvssv2_impact_ii = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv2_impact_ii = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv2_impact_ai");
  if (value)
    {
      quoted_cvssv2_impact_ai = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv2_impact_ai = g_strdup ("");
  }

 value = tag_value (nvti_tag (nvti), "cvssv3_base_vector");
  if (value)
    {
      quoted_cvssv3_base_vector = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv3_base_vector = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv3_base_score");
  if (value)
    {
      quoted_cvssv3_base_score = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv3_base_score = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv3_base_score_overall");
  if (value)
    {
      quoted_cvssv3_base_score_overall = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv3_base_score_overall = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv3_base_impact");
  if (value)
    {
      quoted_cvssv3_base_impact = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv3_base_impact = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv3_base_exploit");
  if (value)
    {
      quoted_cvssv3_base_exploit = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv3_base_exploit = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv3_em_attack_vector");
  if (value)
    {
      quoted_cvssv3_em_attack_vector = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv3_em_attack_vector = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv3_em_attack_complex");
  if (value)
    {
      quoted_cvssv3_em_attack_complex = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv3_em_attack_complex = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv3_em_priv_required");
  if (value)
    {
      quoted_cvssv3_em_priv_required = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv3_em_priv_required = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv3_em_user_interact");
  if (value)
    {
      quoted_cvssv3_em_user_interact = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv3_em_user_interact = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv3_scope");
  if (value)
    {
      quoted_cvssv3_scope = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv3_scope = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv3_impact_ci");
  if (value)
    {
      quoted_cvssv3_impact_ci = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv3_impact_ci = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv3_impact_ii");
  if (value)
    {
      quoted_cvssv3_impact_ii = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv3_impact_ii = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvssv3_impact_ai");
  if (value)
    {
      quoted_cvssv3_impact_ai = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cvssv3_impact_ai = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cwe_id");
  if (value)
    {
      quoted_cwe_id = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cwe_id = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cpe");
  if (value)
    {
      quoted_cpe = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_cpe = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "pci_dss");
  if (value)
    {
      quoted_pci_dss = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_pci_dss = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "url_ref");
  if (value)
    {
      quoted_url_ref = sql_quote (value);
      g_free (value);
    }
  else {
      quoted_url_ref = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cve_date");
  if (value)
  {
    quoted_cve_date = sql_quote (value);
    g_free (value);
  }
  else {
    quoted_cve_date = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "patch_date");
  if (value)
  {
    quoted_patch_date = sql_quote (value);
    g_free (value);
  }
  else {
    quoted_patch_date = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "summary");
  if (value)
  {
    quoted_summary = sql_quote (value);
    g_free (value);
  }
  else {
    quoted_summary = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "impact");
  if (value)
  {
    quoted_impact = sql_quote (value);
    g_free (value);
  }
  else {
    quoted_impact = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "insight");
  if (value)
  {
    quoted_insight = sql_quote (value);
    g_free (value);
  }
  else {
    quoted_insight = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "vuldetect");
  if (value)
  {
    quoted_vuldetect = sql_quote (value);
    g_free (value);
  }
  else {
    quoted_vuldetect = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "affected");
  if (value)
  {
    quoted_affected = sql_quote (value);
    g_free (value);
  }
  else {
    quoted_affected = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "solution");
  if (value)
  {
    quoted_solution = sql_quote (value);
    g_free (value);
  }
  else {
    quoted_solution = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "intezer");
  if (value)
  {
    quoted_intezer = sql_quote (value);
    g_free (value);
  }
  else {
    quoted_intezer = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "virustotal");
  if (value)
  {
    quoted_virustotal = sql_quote (value);
    g_free (value);
  }
  else {
    quoted_virustotal = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cvss_base_vector");
  if (value)
  {
    quoted_cvssv_base_vector = sql_quote (value);
    g_free (value);
  }
  else {
    quoted_cvssv_base_vector = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cve_vt");
  if (value)
  {
    quoted_cve_vt = sql_quote (value);
    g_free (value);
  }
  else {
    quoted_cve_vt = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "apt");
  if (value)
  {
    quoted_apt = sql_quote (value);
    g_free (value);
  }
  else {
    quoted_apt = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "country_apt");
  if (value)
  {
    quoted_country_apt = sql_quote (value);
    g_free (value);
  }
  else {
    quoted_country_apt = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "mitre");
  if (value)
  {
    quoted_mitre = sql_quote (value);
    g_free (value);
  }
  else {
    quoted_mitre = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cisa_exploited");
  if (value)
  {
    quoted_cisa_exploited = sql_quote (value);
    g_free (value);
  }
  else {
    quoted_cisa_exploited = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "cisa_alert");
  if (value)
  {
    quoted_cisa_alert = sql_quote (value);
    g_free (value);
  }
  else {
    quoted_cisa_alert = g_strdup ("");
  }

  value = tag_value (nvti_tag (nvti), "ransomware");
  if (value)
  {
    quoted_ransomware = sql_quote (value);
    g_free (value);
  }
  else {
    quoted_ransomware = g_strdup ("");
  }

  if (sql_int ("SELECT EXISTS (SELECT * FROM nvts WHERE oid = '%s');", nvti_oid (nvti)))
  {
      g_warning ("%s: KB with OID %s exists already, ignoring", __FUNCTION__, nvti_oid (nvti));
  } else {
      sql ("INSERT into nvts ("
           "  oid, "
           "  name,"
           "  cve, "
           "  bid, "
           "  xref, "
           "  tag, "
           "  category, "
           "  family, "
           "  cvss_base,"
           "  creation_time, "
           "  modification_time, "
           "  uuid, "
           "  solution_type, "
           "  qod, "
           "  qod_type, "
           "  cvssv2_base_vector, "
           "  cvssv2_base_score, "
           "  cvssv2_base_score_overall, "
           "  cvssv2_base_impact, "
           "  cvssv2_base_exploit, "
           "  cvssv2_em_access_vector, "
           "  cvssv2_em_access_complex, "
           "  cvssv2_em_authentication, "
           "  cvssv2_impact_ci, "
           "  cvssv2_impact_ii, "
           "  cvssv2_impact_ai, "
           "  cvssv3_base_vector, "
           "  cvssv3_base_score, "
           "  cvssv3_base_score_overall, "
           "  cvssv3_base_impact, "
           "  cvssv3_base_exploit, "
           "  cvssv3_em_attack_vector, "
           "  cvssv3_em_attack_complex, "
           "  cvssv3_em_priv_required, "
           "  cvssv3_em_user_interact, "
           "  cvssv3_scope, "
           "  cvssv3_impact_ci, "
           "  cvssv3_impact_ii, "
           "  cvssv3_impact_ai, "
           "  cwe_id, "
           "  cpe, "
           "  pci_dss, "
           "  url_ref, "
           "  cve_date, "
           "  patch_date, "
           "  summary, "
           "  impact, "
           "  insight, "
           "  vuldetect, "
           "  affected, "
           "  solution, "
           "  intezer, "
           "  virustotal, "
           "  cve_vt, "
           "  apt, "
           "  country_apt, "
           "  mitre, "
           "  cisa_exploited, "
           "  cisa_alert, "
           "  ransomware)"
           "  VALUES ("
           "  '%s', " // oid
           "  '%s', " // name
           "  '%s', " // cve
           "  '%s', " // bid
           "  '%s', " // xref
           "  '%s', " // tag
           "  '%i', " // category
           "  '%s', " // family
           "  '%s', " // cvss_base
           "  '%i', " // creation_time
           "  '%i', " // modification_time
           "  '%s', " // uuid
           "  '%s', " // solution_type
           "  '%d', " // qod
           "  '%s', " // qod_type
           "  '%s', " // cvssv2_base_vector
           "  '%s', " // cvssv2_base_score
           "  '%s', " // cvssv2_base_score_overall
           "  '%s', " // cvssv2_base_impact
           "  '%s', " // cvssv2_base_exploit
           "  '%s', " // cvssv2_em_access_vector
           "  '%s', " // cvssv2_em_access_complex
           "  '%s', " // cvssv2_em_authentication
           "  '%s', " // cvssv2_impact_ci
           "  '%s', " // cvssv2_impact_ii
           "  '%s', " // cvssv2_impact_ai
           "  '%s', " // cvssv3_base_vector
           "  '%s', " // cvssv3_base_score
           "  '%s', " // cvssv3_base_score_overall
           "  '%s', " // cvssv3_base_impact
           "  '%s', " // cvssv3_base_exploit
           "  '%s', " // cvssv3_em_attack_vector
           "  '%s', " // cvssv3_em_attack_complex
           "  '%s', " // cvssv3_em_priv_required
           "  '%s', " // cvssv3_em_user_interact
           "  '%s', " // cvssv3_scope
           "  '%s', " // cvssv3_impact_ci
           "  '%s', " // cvssv3_impact_ii
           "  '%s', " // cvssv3_impact_ai
           "  '%s', " // cwe_id
           "  '%s', " // cpe
           "  '%s', " // pci_dss
           "  '%s', " // url_ref
           "  '%s', " // cve_date
           "  '%s', " // patch_date
           "  '%s', " // summary
           "  '%s', " // impact
           "  '%s', " // insight
           "  '%s', " // vuldetect
           "  '%s', " // affected
           "  '%s', " // solution
           "  '%s', " // intezer
           "  '%s', " // virustotal
           "  '%s', " // cve_vt
           "  '%s', " // apt
           "  '%s', " // country_apt
           "  '%s', " // mitre
           "  '%s', " // cisa_exploited
           "  '%s', " // cisa_alert
           "  '%s'  " // ransomware
           ");",
           nvti_oid (nvti),                     // oid
           quoted_name,                         // name
           quoted_cve,                          // cve
           quoted_bid,                          // bid
           quoted_xref,                         // xref
           quoted_tag,                          // tag
           nvti_category (nvti),                // category
           quoted_family,                       // family
           quoted_cvss_base,                    // cvss_base
           creation_time,                       // creation_time
           modification_time,                   // modification_time
           nvti_oid (nvti),                     // uuid
           quoted_solution_type,                // solution_type
           qod,                                 // qod
           quoted_qod_type,                     // qod_type
           quoted_cvssv_base_vector,            // cvssv2_base_vector
           quoted_cvssv2_base_score,            // cvssv2_base_score
           quoted_cvssv2_base_score_overall,    // cvssv2_base_score_overall
           quoted_cvssv2_base_impact,           // cvssv2_base_impact
           quoted_cvssv2_base_exploit,          // cvssv2_base_exploit
           quoted_cvssv2_em_access_vector,      // cvssv2_em_access_vector
           quoted_cvssv2_em_access_complex,     // cvssv2_em_access_complex
           quoted_cvssv2_em_authentication,     // cvssv2_em_authentication
           quoted_cvssv2_impact_ci,             // cvssv2_impact_ci
           quoted_cvssv2_impact_ii,             // cvssv2_impact_ii
           quoted_cvssv2_impact_ai,             // cvssv2_impact_ai
           quoted_cvssv3_base_vector,           // cvssv3_base_vector
           quoted_cvssv3_base_score,            // cvssv3_base_score
           quoted_cvssv3_base_score_overall,    // cvssv3_base_score_overall
           quoted_cvssv3_base_impact,           // cvssv3_base_impact
           quoted_cvssv3_base_exploit,          // cvssv3_base_exploit
           quoted_cvssv3_em_attack_vector,      // cvssv3_em_attack_vector
           quoted_cvssv3_em_attack_complex,     // cvssv3_em_attack_complex
           quoted_cvssv3_em_priv_required,      // cvssv3_em_priv_required
           quoted_cvssv3_em_user_interact,      // cvssv3_em_user_interact
           quoted_cvssv3_scope,                 // cvssv3_scope
           quoted_cvssv3_impact_ci,             // cvssv3_impact_ci,
           quoted_cvssv3_impact_ii,             // cvssv3_impact_ii
           quoted_cvssv3_impact_ai,             // cvssv3_impact_ai
           quoted_cwe_id,                       // cwe_id
           quoted_cpe,                          // cpe
           quoted_pci_dss,                      // pci_dss
           quoted_url_ref,                      // url_ref
           quoted_cve_date,                     // cve_date
           quoted_patch_date,                   // patch_date
           quoted_summary,                      // summary
           quoted_impact,                       // impact
           quoted_insight,                      // insight
           quoted_vuldetect,                    // impact
           quoted_affected,                     // affected
           quoted_solution,                     // solution
           quoted_intezer,                      // intezer
           quoted_virustotal,                   // virustotal
           quoted_cve_vt,                       // cve_vt
           quoted_apt,                          // apt
           quoted_country_apt,                  // country_apt
           quoted_mitre,                        // mitre
           quoted_cisa_exploited,               // cisa_exploited
           quoted_cisa_alert,                   // cisa_alert
           quoted_ransomware                    // ransomware
           );
  }

  g_free (quoted_name);
  g_free (quoted_cve);
  g_free (quoted_bid);
  g_free (quoted_xref);
  g_free (quoted_tag);
  g_free (quoted_cvss_base);
  g_free (quoted_family);
  g_free (quoted_solution_type);
  g_free (quoted_qod_type);
  g_free (quoted_cvssv2_base_vector);
  g_free (quoted_cvssv_base_vector);
  g_free (quoted_cvssv2_base_score);
  g_free (quoted_cvssv2_base_score_overall);
  g_free (quoted_cvssv2_base_impact);
  g_free (quoted_cvssv2_base_exploit);
  g_free (quoted_cvssv2_em_access_vector);
  g_free (quoted_cvssv2_em_access_complex);
  g_free (quoted_cvssv2_em_authentication);
  g_free (quoted_cvssv2_impact_ci);
  g_free (quoted_cvssv2_impact_ii);
  g_free (quoted_cvssv2_impact_ai);
  g_free (quoted_cvssv3_base_vector);
  g_free (quoted_cvssv3_base_score);
  g_free (quoted_cvssv3_base_score_overall);
  g_free (quoted_cvssv3_base_impact);
  g_free (quoted_cvssv3_base_exploit);
  g_free (quoted_cvssv3_em_attack_vector);
  g_free (quoted_cvssv3_em_attack_complex);
  g_free (quoted_cvssv3_em_priv_required);
  g_free (quoted_cvssv3_em_user_interact);
  g_free (quoted_cvssv3_scope);
  g_free (quoted_cvssv3_impact_ci);
  g_free (quoted_cvssv3_impact_ii);
  g_free (quoted_cvssv3_impact_ai);
  g_free (quoted_cwe_id);
  g_free (quoted_cpe);
  g_free (quoted_pci_dss);
  g_free (quoted_url_ref);
  g_free (quoted_cve_date);
  g_free (quoted_patch_date);
  g_free (quoted_summary);
  g_free (quoted_impact);
  g_free (quoted_insight);
  g_free (quoted_vuldetect);
  g_free (quoted_affected);
  g_free (quoted_solution);
  g_free (quoted_intezer);
  g_free (quoted_virustotal);
  g_free (quoted_cve_vt);
  g_free (quoted_apt);
  g_free (quoted_country_apt);
  g_free (quoted_mitre);
  g_free (quoted_cisa_exploited);
  g_free (quoted_cisa_alert);
  g_free (quoted_ransomware);

  return sql_last_insert_id ();
}

/**
 * @brief Initialise an NVT iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 * @param[in]  name        Name of the info
 *
 * @return 0 success, 1 failed to find NVT, 2 failed to find filter,
 *         -1 error.
 */
int
init_nvt_info_iterator (iterator_t *iterator, get_data_t *get, const char *name)
{
  static const char *filter_columns[] = NVT_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = NVT_ITERATOR_COLUMNS;
  gchar *clause = NULL;
  int ret;

  if (get->id)
    {
      // FIX what for anyway?
      gchar *quoted = sql_quote (get->id);
      clause = g_strdup_printf (" AND uuid = '%s'", quoted);
      g_free (quoted);
    }
  else if (name)
    {
      gchar *quoted = sql_quote (name);
      clause = g_strdup_printf (" AND name = '%s'", quoted);
      g_free (quoted);
      /* The entry is specified by name, so filtering just gets in the way. */
      g_free (get->filter);
      get->filter = NULL;
    }

  ret = init_get_iterator (iterator,
                           "nvt",
                           get,
                           /* Columns. */
                           columns,
                           /* Columns for trashcan. */
                           NULL,
                           filter_columns,
                           0,
                           NULL,
                           clause,
                           0);

  g_free (clause);
  return ret;
}

/**
 * @brief Get NVT iterator SELECT columns.
 *
 * @return SELECT columns
 */
static gchar *
nvt_iterator_columns ()
{
  static column_t select_columns[] = NVT_ITERATOR_COLUMNS;
  static gchar *columns = NULL;
  if (columns == NULL)
    columns = columns_build_select (select_columns);
  return columns;
}

/**
 * @brief Get NVT iterator SELECT columns.
 *
 * @return SELECT columns
 */
static gchar *
nvt_iterator_columns_nvts ()
{
  static column_t select_columns[] = NVT_ITERATOR_COLUMNS_NVTS;
  static gchar *columns = NULL;
  if (columns == NULL)
    columns = columns_build_select (select_columns);
  return columns;
}

/**
 * @brief Count number of nvt.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of cpes in filtered set.
 */
int
nvt_info_count (const get_data_t *get)
{
  static const char *extra_columns[] = NVT_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = NVT_ITERATOR_COLUMNS;
  return count ("nvt", get, columns, NULL, extra_columns, 0, 0, 0, FALSE);
}

/**
 * @brief Return SQL for selecting NVT's of a config from one family.
 *
 * @param[in]  config      Config.
 * @param[in]  family      Family to limit selection to.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "nvts.id".
 *
 * @return Freshly allocated SELECT statement on success, or NULL on error.
 */
static gchar *
select_config_nvts (const config_t config,
                    const char *family,
                    int ascending,
                    const char *sort_field)
{
  gchar *quoted_selector, *quoted_family, *sql;
  char *selector;

  selector = config_nvt_selector (config);
  if (selector == NULL)
    /* The config should always have a selector. */
    return NULL;

  quoted_selector = sql_quote (selector);
  free (selector);

  quoted_family = sql_quote (family);

  if (config_nvts_growing (config))
    {
      int constraining;

      /* The number of NVT's can increase. */

      constraining = config_families_growing (config);

      if (constraining)
        {
          /* Constraining the universe. */

          if (sql_int ("SELECT COUNT(*) FROM nvt_selectors WHERE name = '%s';",
                       quoted_selector)
              == 1)
            /* There is one selector, it should be the all selector. */
            sql = g_strdup_printf ("SELECT %s"
                                   " FROM nvts WHERE family = '%s'"
                                   " ORDER BY %s %s;",
                                   nvt_iterator_columns (),
                                   quoted_family,
                                   sort_field ? sort_field : "name",
                                   ascending ? "ASC" : "DESC");
          else
            {
              /* There are multiple selectors. */

              if (sql_int (
                    "SELECT COUNT(*) FROM nvt_selectors"
                    " WHERE name = '%s' AND exclude = 1"
                    " AND type = " G_STRINGIFY (
                      NVT_SELECTOR_TYPE_FAMILY) " AND family_or_nvt = '%s'"
                                                ";",
                    quoted_selector,
                    quoted_family))
                /* The family is excluded, just iterate the NVT includes. */
                sql = g_strdup_printf (
                  "SELECT %s"
                  " FROM nvts, nvt_selectors"
                  " WHERE"
                  " nvts.family = '%s'"
                  " AND nvt_selectors.name = '%s'"
                  " AND nvt_selectors.family = '%s'"
                  " AND nvt_selectors.type = " G_STRINGIFY (
                    NVT_SELECTOR_TYPE_NVT) " AND nvt_selectors.exclude = 0"
                                           " AND nvts.oid = "
                                           "nvt_selectors.family_or_nvt"
                                           " ORDER BY %s %s;",
                  nvt_iterator_columns_nvts (),
                  quoted_family,
                  quoted_selector,
                  quoted_family,
                  sort_field ? sort_field : "nvts.name",
                  ascending ? "ASC" : "DESC");
              else
                /* The family is included.
                 *
                 * Iterate all NVT's minus excluded NVT's. */
                sql = g_strdup_printf (
                  "SELECT %s"
                  " FROM nvts"
                  " WHERE family = '%s'"
                  " EXCEPT"
                  " SELECT %s"
                  " FROM nvt_selectors, nvts"
                  " WHERE"
                  " nvts.family = '%s'"
                  " AND nvt_selectors.name = '%s'"
                  " AND nvt_selectors.family = '%s'"
                  " AND nvt_selectors.type = " G_STRINGIFY (
                    NVT_SELECTOR_TYPE_NVT) " AND nvt_selectors.exclude = 1"
                                           " AND nvts.oid = "
                                           "nvt_selectors.family_or_nvt"
                                           " ORDER BY %s %s;",
                  nvt_iterator_columns (),
                  quoted_family,
                  nvt_iterator_columns_nvts (),
                  quoted_family,
                  quoted_selector,
                  quoted_family,
                  // FIX PG "ERROR: missing FROM-clause" using nvts.name.
                  sort_field && strcmp (sort_field, "nvts.name")
                    ? sort_field
                    : "3", /* 3 is nvts.name. */
                  ascending ? "ASC" : "DESC");
            }
        }
      else
        {
          int all;

          /* Generating from empty. */

          all =
            sql_int ("SELECT COUNT(*) FROM nvt_selectors"
                     " WHERE name = '%s' AND exclude = 0"
                     " AND type = " G_STRINGIFY (
                       NVT_SELECTOR_TYPE_FAMILY) " AND family_or_nvt = '%s';",
                     quoted_selector,
                     quoted_family);

          if (all)
            /* There is a family include for this family. */
            sql = g_strdup_printf (
              "SELECT %s"
              " FROM nvts"
              " WHERE family = '%s'"
              " EXCEPT"
              " SELECT %s"
              " FROM nvt_selectors, nvts"
              " WHERE"
              " nvts.family = '%s'"
              " AND nvt_selectors.name = '%s'"
              " AND nvt_selectors.family = '%s'"
              " AND nvt_selectors.type = " G_STRINGIFY (
                NVT_SELECTOR_TYPE_NVT) " AND nvt_selectors.exclude = 1"
                                       " AND nvts.oid = "
                                       "nvt_selectors.family_or_nvt"
                                       " ORDER BY %s %s;",
              nvt_iterator_columns (),
              quoted_family,
              nvt_iterator_columns_nvts (),
              quoted_family,
              quoted_selector,
              quoted_family,
              // FIX PG "ERROR: missing FROM-clause" using nvts.name.
              sort_field && strcmp (sort_field, "nvts.name")
                ? sort_field
                : "3", /* 3 is nvts.name. */
              ascending ? "ASC" : "DESC");
          else
            sql = g_strdup_printf (
              " SELECT %s"
              " FROM nvt_selectors, nvts"
              " WHERE"
              " nvts.family = '%s'"
              " AND nvt_selectors.name = '%s'"
              " AND nvt_selectors.family = '%s'"
              " AND nvt_selectors.type = " G_STRINGIFY (
                NVT_SELECTOR_TYPE_NVT) " AND nvt_selectors.exclude = 0"
                                       " AND nvts.oid = "
                                       "nvt_selectors.family_or_nvt"
                                       " ORDER BY %s %s;",
              nvt_iterator_columns_nvts (),
              quoted_family,
              quoted_selector,
              quoted_family,
              sort_field ? sort_field : "nvts.name",
              ascending ? "ASC" : "DESC");
        }
    }
  else
    {
      /* The number of NVT's is static.  Assume a simple list of NVT
       * includes. */

      sql = g_strdup_printf (
        "SELECT %s"
        " FROM nvt_selectors, nvts"
        " WHERE nvts.family = '%s'"
        " AND nvt_selectors.exclude = 0"
        " AND nvt_selectors.type = " G_STRINGIFY (
          NVT_SELECTOR_TYPE_NVT) " AND nvt_selectors.name = '%s'"
                                 " AND nvts.oid = nvt_selectors.family_or_nvt"
                                 " ORDER BY %s %s;",
        nvt_iterator_columns_nvts (),
        quoted_family,
        quoted_selector,
        sort_field ? sort_field : "nvts.id",
        ascending ? "ASC" : "DESC");
    }

  g_free (quoted_selector);
  g_free (quoted_family);

  return sql;
}

/**
 * @brief Initialise an NVT iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  nvt         NVT to iterate over, all if 0.
 * @param[in]  config      Config to limit selection to.  NULL for all NVTs.
 *                         Overridden by \arg nvt.
 * @param[in]  family      Family to limit selection to.  NULL for all NVTs.
 *                         Overridden by \arg config.
 * @param[in]  category    Category to limit selection to.  NULL for all.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "id".
 */
void
init_nvt_iterator (iterator_t *iterator,
                   nvt_t nvt,
                   config_t config,
                   const char *family,
                   const char *category,
                   int ascending,
                   const char *sort_field)
{
  assert ((nvt && family) == 0);

  if (nvt)
    {
      gchar *sql;
      sql = g_strdup_printf ("SELECT %s"
                             " FROM nvts WHERE id = %llu;",
                             nvt_iterator_columns (),
                             nvt);
      init_iterator (iterator, sql);
      g_free (sql);
    }
  else if (config)
    {
      gchar *sql;
      if (family == NULL)
        abort ();
      sql = select_config_nvts (config, family, ascending, sort_field);
      if (sql)
        {
          init_iterator (iterator, sql);
          g_free (sql);
        }
      else
        init_iterator (iterator,
                       "SELECT %s"
                       " FROM nvts LIMIT 0;",
                       nvt_iterator_columns ());
    }
  else if (family)
    {
      gchar *quoted_family = sql_quote (family);
      init_iterator (iterator,
                     "SELECT %s"
                     " FROM nvts"
                     " WHERE family = '%s'"
                     " ORDER BY %s %s;",
                     nvt_iterator_columns (),
                     quoted_family,
                     sort_field ? sort_field : "name",
                     ascending ? "ASC" : "DESC");
      g_free (quoted_family);
    }
  else if (category)
    {
      gchar *quoted_category;
      quoted_category = sql_quote (category);
      init_iterator (iterator,
                     "SELECT %s"
                     " FROM nvts"
                     " WHERE category = '%s'"
                     " ORDER BY %s %s;",
                     nvt_iterator_columns (),
                     quoted_category,
                     sort_field ? sort_field : "name",
                     ascending ? "ASC" : "DESC");
      g_free (quoted_category);
    }
  else
    init_iterator (iterator,
                   "SELECT %s"
                   " FROM nvts"
                   " ORDER BY %s %s;",
                   nvt_iterator_columns (),
                   sort_field ? sort_field : "name",
                   ascending ? "ASC" : "DESC");
}

/**
 * @brief Initialise an NVT iterator, for NVTs of a certain CVE.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  cve         CVE name.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "id".
 */
void
init_cve_nvt_iterator (iterator_t *iterator,
                       const char *cve,
                       int ascending,
                       const char *sort_field)
{
  init_iterator (iterator,
                 "SELECT %s"
                 " FROM nvts"
                 " WHERE cve %s '%%%s%%'"
                 " ORDER BY %s %s;",
                 nvt_iterator_columns (),
                 sql_ilike_op (),
                 cve ? cve : "",
                 sort_field ? sort_field : "name",
                 ascending ? "ASC" : "DESC");
}

/**
 * @brief Get the OID from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return OID, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_oid, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the name from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_name, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the cve from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Cve, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_cve, GET_ITERATOR_COLUMN_COUNT + 3);

/**
 * @brief Get the bid from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Bid, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_bid, GET_ITERATOR_COLUMN_COUNT + 4);

/**
 * @brief Get the xref from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Xref, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_xref, GET_ITERATOR_COLUMN_COUNT + 5);

/**
 * @brief Get the tag from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Tag, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_tag, GET_ITERATOR_COLUMN_COUNT + 6);

/**
 * @brief Get the category from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Category.
 */
int
nvt_iterator_category (iterator_t *iterator)
{
  int ret;
  if (iterator->done)
    return -1;
  ret = iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 7);
  return ret;
}

/**
 * @brief Get the family from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Family, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_family, GET_ITERATOR_COLUMN_COUNT + 8);

/**
 * @brief Get the cvss_base from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Cvss_base, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_cvss_base, GET_ITERATOR_COLUMN_COUNT + 9);

/**
 * @brief Get the qod from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return QoD, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_qod, GET_ITERATOR_COLUMN_COUNT + 12);

/**
 * @brief Get the qod_type from an NVT iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return QoD type, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (nvt_iterator_qod_type, GET_ITERATOR_COLUMN_COUNT + 13);

/**
 * @brief Get the default timeout of an NVT.
 *
 * @param[in]  oid  The OID of the NVT to get the timeout of.
 *
 * @return  Newly allocated string of the timeout in seconds or NULL.
 */
char *
nvt_default_timeout (const char *oid)
{
  return sql_string ("SELECT value FROM nvt_preferences"
                     " WHERE name = (SELECT name FROM nvts"
                     "               WHERE oid = '%s')"
                     "              || '[entry]:Timeout'",
                     oid);
}

/**
 * @brief Get the number of NVTs in one or all families.
 *
 * @param[in]  family  Family name.  NULL for all families.
 *
 * @return Number of NVTs in family, or total number of nvts.
 */
int
family_nvt_count (const char *family)
{
  gchar *quoted_family;

  if (family == NULL)
    {
      static int nvt_count = -1;
      if (nvt_count == -1)
        nvt_count = sql_int ("SELECT COUNT(*) FROM nvts"
                             " WHERE family != 'Credentials';");
      return nvt_count;
    }

  quoted_family = sql_quote (family);
  int ret =
    sql_int ("SELECT COUNT(*) FROM nvts WHERE family = '%s';", quoted_family);
  g_free (quoted_family);
  return ret;
}

/**
 * @brief Get the number of families.
 *
 * @return Total number of families.
 */
int
family_count ()
{
  return sql_int ("SELECT COUNT(distinct family) FROM nvts"
                  " WHERE family != 'Credentials';");
}

/**
 * @brief Insert an NVT from an nvti structure.
 *
 * @param[in] nvti   nvti_t to insert in nvts table.
 * @param[in] dummy  Dummy arg for g_list_foreach.
 */
static void
insert_nvt_from_nvti (gpointer nvti, gpointer dummy)
{
  if (nvti == NULL)
    return;

  make_nvt_from_nvti (nvti);
}

/**
 * @brief Insert a NVT preferences.
 *
 * @param[in] nvt_preference  Preference.
 * @param[in] dummy           Dummy arg for g_list_foreach.
 *
 */
static void
insert_nvt_preference (gpointer nvt_preference, gpointer dummy)
{
  preference_t *preference;

  if (nvt_preference == NULL)
    return;

  preference = (preference_t *) nvt_preference;
  manage_nvt_preference_add (preference->name, preference->value);
}

/**
 * @brief Inserts NVTs in DB from a list of nvti_t structures.
 *
 * @param[in]  nvts_list     List of nvts to be inserted.
 */
static void
insert_nvts_list (GList *nvts_list)
{
  chunk_count = 0;
  g_list_foreach (nvts_list, insert_nvt_from_nvti, NULL);
  if (chunk_count > 0)
    g_debug ("SQLite autocommit will commit this query.");
    // sql_commit ();
}

/**
 * @brief Inserts NVT preferences in DB from a list of nvt_preference_t
 * structures.
 *
 * @param[in]  nvt_preferences_list     List of nvts to be inserted.
 */
static void
insert_nvt_preferences_list (GList *nvt_preferences_list)
{
  g_list_foreach (nvt_preferences_list, insert_nvt_preference, NULL);
}

/**
 * @brief Check for new NVTs after an update.
 */
static void
check_for_new_nvts ()
{
  if (sql_int ("SELECT EXISTS"
               " (SELECT * FROM nvts"
               "  WHERE oid NOT IN (SELECT oid FROM old_nvts));"))
    event (EVENT_NEW_SECINFO, "nvt", 0, 0);
}

/**
 * @brief Check for updated NVTS after an update.
 */
static void
check_for_updated_nvts ()
{
  if (sql_int ("SELECT EXISTS"
               " (SELECT * FROM nvts"
               "  WHERE modification_time > (SELECT modification_time"
               "                             FROM old_nvts"
               "                             WHERE old_nvts.oid = nvts.oid));"))
    event (EVENT_UPDATED_SECINFO, "nvt", 0, 0);
}

/**
 * @brief Refresh nvt_cves table.
 *
 * Caller must organise transaction.
 */
static void
refresh_nvt_cves ()
{
  iterator_t nvts;

  sql ("DELETE FROM nvt_cves;");

  init_iterator (&nvts, "SELECT id, oid, cve FROM nvts;");
  while (next (&nvts))
    {
      gchar **split, **point;

      split = g_strsplit_set (iterator_string (&nvts, 2), " ,", 0);

      point = split;
      while (*point)
        {
          g_strstrip (*point);
          if (strlen (*point))
            {
              gchar *quoted_cve, *quoted_oid;

              quoted_cve = sql_insert (*point);
              quoted_oid = sql_insert (iterator_string (&nvts, 1));
              sql ("INSERT INTO nvt_cves (nvt, oid, cve_name)"
                   " VALUES (%llu, %s, %s);",
                   iterator_int64 (&nvts, 0),
                   quoted_oid,
                   quoted_cve);
              g_free (quoted_cve);
              g_free (quoted_oid);
            }
          point++;
        }
      g_strfreev (split);
    }
  cleanup_iterator (&nvts);

  sql ("REINDEX nvt_cves_by_oid;");
}

/**
 * @brief Complete an update of the NVT cache.
 *
 * @param[in]  nvts_list             List of nvti_t to insert.
 * @param[in]  nvt_preferences_list  List of preference_t to insert.
 */
void
manage_complete_nvt_cache_update (GList *nvts_list, GList *nvt_preferences_list)
{
  iterator_t configs;
  int count;

  sql ("DELETE FROM nvt_cves;");
  sql ("DELETE FROM nvts;");
  sql ("DELETE FROM nvt_preferences;");

  /* NVTs and preferences are buffered, insert them into DB. */
  insert_nvts_list (nvts_list);
  insert_nvt_preferences_list (nvt_preferences_list);

  /* Remove preferences from configs where the preference has vanished from the associated NVT. */
  init_iterator (&configs, "SELECT id FROM configs;");
  while (next (&configs))
    sql ("DELETE FROM config_preferences"
         " WHERE config = %llu"
         " AND type = 'PLUGINS_PREFS'"
         " AND name NOT IN (SELECT nvt_preferences.name FROM nvt_preferences);",
         get_iterator_resource (&configs));
  cleanup_iterator (&configs);

  if (check_config_families ())
  {
      g_warning ("%s: Error: One or more configs refer to an outdated category of a KB", __FUNCTION__);
  }

  update_all_config_caches ();
  refresh_nvt_cves ();

  if (sql_int ("SELECT NOT EXISTS (SELECT * FROM meta WHERE name = 'nvts_check_time')"))
  {
      sql ("INSERT INTO meta (name, value) VALUES ('nvts_check_time', m_now ());");
  }
  else if (sql_int ("SELECT value = '0' FROM meta WHERE name = 'nvts_check_time';"))
  {
      sql ("UPDATE meta SET value = m_now () WHERE name = 'nvts_check_time';");
  }
  else
  {
      check_for_new_nvts ();
      check_for_updated_nvts ();
      sql ("UPDATE meta SET value = m_now () WHERE name = 'nvts_check_time';");
  }

  /* Tell the main process to update its NVTi cache. */
  sql ("UPDATE %s.meta SET value = 1 WHERE name = 'update_nvti_cache';", sql_schema ());

  count = sql_int ("SELECT count (*) FROM nvts;");
  g_info ("Knowledge Base Update Completed with %i KBs", count);
}

/**
 * @brief Sync NVTs if newer NVTs are available.
 *
 * @param[in]  fork_update_nvt_cache  Function to do the update.
 */
void
manage_sync_nvts (int (*fork_update_nvt_cache) ())
{
  fork_update_nvt_cache ();
}
