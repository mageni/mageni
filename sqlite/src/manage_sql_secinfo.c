/* Copyright (C) 2009-2018 Greenbone Networks GmbH
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
 * @file manage_sql_secinfo.c
 * @brief GVM management layer: SecInfo
 *
 * The SecInfo parts of the GVM management layer.
 */

/**
 * @brief Enable extra GNU functions.
 */
#define _GNU_SOURCE

#include "manage_sql_secinfo.h"

#include "manage_sql.h"
#include "sql.h"
#include "utils.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <ftw.h>
#include <glib/gstdio.h>
#include "../../libraries/base/proctitle.h"
#include "../../libraries/util/fileutils.h"
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/* Static variables. */

/**
 * @brief Commit size for updates.
 */
static int secinfo_commit_size = SECINFO_COMMIT_SIZE_DEFAULT;

/* Headers. */

void
manage_db_remove (const gchar *);

int
manage_db_init (const gchar *);

/* Helpers. */

/**
 * @brief Replace text in a string.
 *
 * @param[in]  string  String to replace in.
 * @param[in]  to      Replacement text.
 *
 * @return Freshly allocated string with replacements.
 */
static gchar *
string_replace (const gchar *string, const gchar *to, ...)
{
  va_list ap;
  const gchar *from;
  gchar *ret;

  ret = g_strdup (string);
  va_start (ap, to);
  while ((from = va_arg (ap, const gchar *)))
    {
      gchar **split;
      split = g_strsplit (ret, from, 0);
      g_free (ret);
      ret = g_strjoinv ("~", split);
      g_strfreev (split);
    }
  va_end (ap);
  return ret;
}

/**
 * @brief Increment transaction size, commit and reset at secinfo_commit_size.
 *
 * @param[in,out] current_size Pointer to current size to increment and compare.
 */
inline static void
increment_transaction_size (int *current_size)
{
  if (secinfo_commit_size && (++(*current_size) > secinfo_commit_size))
    {
      *current_size = 0;
      // sql_commit ();
      // sql_begin_immediate ();
    }
}

/* CPE data. */

/**
 * @brief Count number of cpe.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of cpes in filtered set.
 */
int
cpe_info_count (const get_data_t *get)
{
  static const char *filter_columns[] = CPE_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = CPE_INFO_ITERATOR_COLUMNS;
  return count ("cpe", get, columns, NULL, filter_columns, 0, 0, 0, FALSE);
}

/**
 * @brief Initialise a info iterator.
 *
 * @param[in]  iterator        Iterator.
 * @param[in]  get             GET data.
 * @param[in]  name            Name of the info
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_cpe_info_iterator (iterator_t *iterator, get_data_t *get, const char *name)
{
  static const char *filter_columns[] = CPE_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = CPE_INFO_ITERATOR_COLUMNS;
  gchar *clause = NULL;
  int ret;

  if (get->id)
    {
      gchar *quoted = sql_quote (get->id);
      clause = g_strdup_printf (" AND uuid = '%s'", quoted);
      g_free (quoted);
      /* The entry is specified by ID, so filtering just gets in the way. */
      g_free (get->filter);
      get->filter = NULL;
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
                           "cpe",
                           get,
                           columns,
                           NULL,
                           filter_columns,
                           0,
                           NULL,
                           clause,
                           FALSE);
  g_free (clause);
  return ret;
}

/**
 * @brief Get the title from a CPE iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The Title of the CPE, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (cpe_info_iterator_title, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the status from a CPE iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The Status of the CPE, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (cpe_info_iterator_status, GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the Highest CVSS Score of all CVE's referencing this cpe.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The Highest CVSS of the CPE, or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (cpe_info_iterator_max_cvss, GET_ITERATOR_COLUMN_COUNT + 3);

/**
 * @brief Get the Number of CVE's referencing this cpe from a CPE iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The Number of references to the CPE, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cpe_info_iterator_cve_refs, GET_ITERATOR_COLUMN_COUNT + 4);

/**
 * @brief Get the NVD ID for this CPE.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The NVD ID of this CPE, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cpe_info_iterator_nvd_id, GET_ITERATOR_COLUMN_COUNT + 5);

/* CVE data. */

/**
 * @brief Initialise an CVE iterator, for CVEs reported for a certain CPE.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  cve         CVE.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "id".
 */
void
init_cpe_cve_iterator (iterator_t *iterator,
                       const char *cve,
                       int ascending,
                       const char *sort_field)
{
  gchar *quoted_cpe;
  assert (cve);
  quoted_cpe = sql_quote (cve);
  init_iterator (iterator,
                 "SELECT id, name, cvss FROM cves WHERE id IN"
                 " (SELECT cve FROM affected_products"
                 "  WHERE cpe ="
                 "  (SELECT id FROM cpes WHERE name = '%s'))"
                 " ORDER BY %s %s;",
                 quoted_cpe,
                 sort_field ? sort_field : "cvss DESC, name",
                 ascending ? "ASC" : "DESC");
  g_free (quoted_cpe);
}

/**
 * @brief Get the name from a CVE iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the CVE, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (cve_iterator_name, 1);

/**
 * @brief Get the CVSS from a CVE iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The CVSS of the CVE, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (cve_iterator_cvss, 2);

/**
 * @brief Get the short file name for an OVALDEF.
 *
 * @param[in]  cve  Full OVAL identifier with file suffix.
 *
 * @return The file name of the OVAL definition relative to the SCAP directory,
 *         Freed by g_free.
 */
gchar *
cve_cvss_base (const gchar *cve)
{
  gchar *quoted_cve, *ret;
  quoted_cve = sql_quote (cve);
  ret = sql_string ("SELECT cvss FROM cves WHERE name = '%s'", quoted_cve);
  g_free (quoted_cve);
  return ret;
}

/**
 * @brief Count number of cve.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of cpes in filtered set.
 */
int
cve_info_count (const get_data_t *get)
{
  static const char *filter_columns[] = CVE_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = CVE_INFO_ITERATOR_COLUMNS;
  return count ("cve", get, columns, NULL, filter_columns, 0, 0, 0, FALSE);
}

/**
 * @brief Initialise a info iterator.
 *
 * @param[in]  iterator        Iterator.
 * @param[in]  get             GET data.
 * @param[in]  name            Name of the info
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_cve_info_iterator (iterator_t *iterator, get_data_t *get, const char *name)
{
  static const char *filter_columns[] = CVE_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = CVE_INFO_ITERATOR_COLUMNS;
  gchar *clause = NULL;
  int ret;

  if (get->id)
    {
      gchar *quoted = sql_quote (get->id);
      clause = g_strdup_printf (" AND uuid = '%s'", quoted);
      g_free (quoted);
      /* The entry is specified by ID, so filtering just gets in the way. */
      g_free (get->filter);
      get->filter = NULL;
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
                           "cve",
                           get,
                           columns,
                           NULL,
                           filter_columns,
                           0,
                           NULL,
                           clause,
                           FALSE);
  g_free (clause);
  return ret;
}

/**
 * @brief Get the CVSS attack vector for this CVE.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The CVSS attack vector of this CVE, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cve_info_iterator_vector, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the CVSS attack complexity for this CVE.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The CVSS attack complexity of this CVE, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cve_info_iterator_complexity, GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the CVSS attack authentication for this CVE.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The CVSS attack authentication of this CVE, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cve_info_iterator_authentication, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the CVSS confidentiality impact for this CVE.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The CVSS confidentiality impact of this CVE, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cve_info_iterator_confidentiality_impact,
            GET_ITERATOR_COLUMN_COUNT + 3);

/**
 * @brief Get the CVSS integrity impact for this CVE.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The CVSS integrity impact of this CVE, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cve_info_iterator_integrity_impact, GET_ITERATOR_COLUMN_COUNT + 4);

/**
 * @brief Get the CVSS availability impact for this CVE.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The CVSS availability impact of this CVE, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cve_info_iterator_availability_impact,
            GET_ITERATOR_COLUMN_COUNT + 5);

/**
 * @brief Get a space separated list of CPEs affected by this CVE.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return A space separated list of CPEs or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cve_info_iterator_products, GET_ITERATOR_COLUMN_COUNT + 6);

/**
 * @brief Get the CVSS base score for this CVE.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The CVSS base score of this CVE, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cve_info_iterator_cvss, GET_ITERATOR_COLUMN_COUNT + 7);

/**
 * @brief Get the Summary for this CVE.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The Summary of this CVE, or NULL if iteration is
 *         complete. Freed by cleanup_iterator.
 */
DEF_ACCESS (cve_info_iterator_description, GET_ITERATOR_COLUMN_COUNT + 8);

/* OVAL data. */

/**
 * @brief Initialise an OVAL definition (ovaldef) info iterator.
 *
 * @param[in]  iterator        Iterator.
 * @param[in]  get             GET data.
 * @param[in]  name            Name of the info
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_ovaldef_info_iterator (iterator_t *iterator,
                            get_data_t *get,
                            const char *name)
{
  static const char *filter_columns[] = OVALDEF_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = OVALDEF_INFO_ITERATOR_COLUMNS;
  gchar *clause = NULL;
  int ret;

  if (get->id)
    {
      gchar *quoted = sql_quote (get->id);
      clause = g_strdup_printf (" AND uuid = '%s'", quoted);
      g_free (quoted);
      /* The entry is specified by ID, so filtering just gets in the way. */
      g_free (get->filter);
      get->filter = NULL;
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
                           "ovaldef",
                           get,
                           columns,
                           NULL,
                           filter_columns,
                           0,
                           NULL,
                           clause,
                           FALSE);
  g_free (clause);
  return ret;
}

/**
 * @brief Count number of ovaldef.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of OVAL definitions in filtered set.
 */
int
ovaldef_info_count (const get_data_t *get)
{
  static const char *filter_columns[] = OVALDEF_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = OVALDEF_INFO_ITERATOR_COLUMNS;
  return count ("ovaldef", get, columns, NULL, filter_columns, 0, 0, 0, FALSE);
}

/**
 * @brief Get the version number from an OVALDEF iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The version number of the OVAL definition,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (ovaldef_info_iterator_version, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the deprecation status from an OVALDEF iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return True if the OVAL definition is deprecated, false if not,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (ovaldef_info_iterator_deprecated, GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the definition class from an OVALDEF iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The definition class (e.g. 'patch' or 'vulnerability') of the OVAL
 *         definition, or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (ovaldef_info_iterator_class, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the title from an OVALDEF iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The title / short description of the OVAL definition,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (ovaldef_info_iterator_title, GET_ITERATOR_COLUMN_COUNT + 3);

/**
 * @brief Get the description from an OVALDEF iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The long description of the OVAL definition,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (ovaldef_info_iterator_description, GET_ITERATOR_COLUMN_COUNT + 4);

/**
 * @brief Get the source xml file from an OVALDEF iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The short xml source file name of the OVAL definition,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (ovaldef_info_iterator_file, GET_ITERATOR_COLUMN_COUNT + 5);

/**
 * @brief Get the repository entry status from an OVALDEF iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The repository entry status of the OVAL definition,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (ovaldef_info_iterator_status, GET_ITERATOR_COLUMN_COUNT + 6);

/**
 * @brief Get maximum CVSS score from an OVALDEF iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The maximum CVSS score of the OVAL definition,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (ovaldef_info_iterator_max_cvss, GET_ITERATOR_COLUMN_COUNT + 7);

/**
 * @brief Get number of referenced CVEs from an OVALDEF iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The maximum CVSS score of the OVAL definition,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (ovaldef_info_iterator_cve_refs, GET_ITERATOR_COLUMN_COUNT + 8);

/**
 * @brief Get the short file name for an OVALDEF.
 *
 * @param[in]  item_id  Full OVAL identifier with file suffix.
 *
 * @return The file name of the OVAL definition relative to the SCAP directory,
 *         Freed by g_free.
 */
gchar *
get_ovaldef_short_filename (char *item_id)
{
  return sql_string ("SELECT xml_file FROM ovaldefs WHERE uuid = '%s';",
                     item_id);
}

/**
 * @brief Get the uuid for an OVALDEF from a name and file name.
 *
 * @param[in]  name     Oval definition name.
 * @param[in]  fname    Oval definition file name.
 *
 * @return The OVAL definition uuid from the SCAP directory. Freed by g_free.
 */
char *
ovaldef_uuid (const char *name, const char *fname)
{
  char *quoted_name, *quoted_fname, *ret;

  assert (name);
  assert (fname);
  quoted_name = sql_quote (name);
  quoted_fname = sql_quote (fname);
  ret = sql_string ("SELECT uuid FROM ovaldefs WHERE name = '%s'"
                    " AND xml_file = '%s';",
                    name,
                    fname);
  g_free (quoted_name);
  g_free (quoted_fname);
  return ret;
}

/**
 * @brief Get the severity of an OVALDEF using an ID.
 *
 * @param[in]  id  Oval definition ID.
 *
 * @return The severity of the OVAL definition from the SCAP directory.
 *         Freed by g_free.
 */
char *
ovaldef_severity (const char *id)
{
  char *quoted_id, *ret;

  assert (id);
  quoted_id = sql_quote (id);
  ret =
    sql_string ("SELECT max_cvss FROM ovaldefs WHERE uuid = '%s';", quoted_id);
  g_free (quoted_id);
  return ret;
}

/**
 * @brief Get the version of an OVALDEF using an ID.
 *
 * @param[in]  id  Oval definition ID.
 *
 * @return The version of the OVAL definition from the SCAP directory.
 *         Freed by g_free.
 */
char *
ovaldef_version (const char *id)
{
  char *quoted_id, *ret;

  assert (id);
  quoted_id = sql_quote (id);
  ret =
    sql_string ("SELECT version FROM ovaldefs WHERE uuid = '%s';", quoted_id);
  g_free (quoted_id);
  return ret;
}

/**
 * @brief Get the CVE names of an OVALDEF as ", " separated str.
 *
 * @param[in]  id  Oval definition ID.
 *
 * @return String of CVEs affecting of the OVAL definition, NULL otherwise.
 *         Freed by g_free.
 */
char *
ovaldef_cves (const char *id)
{
  char *quoted_id, *ret = NULL;
  iterator_t iterator;

  assert (id);
  quoted_id = sql_quote (id);
  init_iterator (&iterator,
                 "SELECT DISTINCT cves.name FROM cves, ovaldefs,"
                 " affected_ovaldefs WHERE ovaldefs.uuid = '%s'"
                 " AND cves.id = affected_ovaldefs.cve"
                 " AND ovaldefs.id = affected_ovaldefs.ovaldef;",
                 quoted_id);
  g_free (quoted_id);
  while (next (&iterator))
    {
      char *tmp = ret;
      ret = g_strdup_printf (
        "%s%s%s", ret ?: "", ret ? ", " : "", iterator_string (&iterator, 0));
      g_free (tmp);
    }
  cleanup_iterator (&iterator);
  return ret;
}

/* CERT-Bund data. */

/**
 * @brief Initialise an CERT-Bund advisory (cert_bund_adv) info iterator.
 *
 * @param[in]  iterator        Iterator.
 * @param[in]  get             GET data.
 * @param[in]  name            Name of the info
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_cert_bund_adv_info_iterator (iterator_t *iterator,
                                  get_data_t *get,
                                  const char *name)
{
  static const char *filter_columns[] =
    CERT_BUND_ADV_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = CERT_BUND_ADV_INFO_ITERATOR_COLUMNS;
  gchar *clause = NULL;
  int ret;

  if (get->id)
    {
      gchar *quoted = sql_quote (get->id);
      clause = g_strdup_printf (" AND uuid = '%s'", quoted);
      g_free (quoted);
      /* The entry is specified by ID, so filtering just gets in the way. */
      g_free (get->filter);
      get->filter = NULL;
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
                           "cert_bund_adv",
                           get,
                           columns,
                           NULL,
                           filter_columns,
                           0,
                           NULL,
                           clause,
                           FALSE);
  g_free (clause);
  return ret;
}

/**
 * @brief Count number of cert_bund_adv.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of CERT-Bund advisories in filtered set.
 */
int
cert_bund_adv_info_count (const get_data_t *get)
{
  static const char *filter_columns[] =
    CERT_BUND_ADV_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = CERT_BUND_ADV_INFO_ITERATOR_COLUMNS;
  return count (
    "cert_bund_adv", get, columns, NULL, filter_columns, 0, 0, 0, FALSE);
}

/**
 * @brief Get the title from an CERT_BUND_ADV iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The title of the CERT-Bund advisory,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (cert_bund_adv_info_iterator_title, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the summary from an CERT_BUND_ADV iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The summary of the CERT-Bund advisory,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (cert_bund_adv_info_iterator_summary, GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the number of cves from an CERT_BUND_ADV iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The number of CVEs referenced in the CERT-Bund advisory,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (cert_bund_adv_info_iterator_cve_refs,
            GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the maximum CVSS from an CERT_BUND_ADV iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The maximum CVSS of the CVEs referenced in the CERT-Bund advisory,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (cert_bund_adv_info_iterator_max_cvss,
            GET_ITERATOR_COLUMN_COUNT + 3);

/**
 * @brief Initialise CVE iterator, for CVEs referenced by a CERT-Bund advisory.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  cve         Name of the CVE.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "id".
 */
void
init_cve_cert_bund_adv_iterator (iterator_t *iterator,
                                 const char *cve,
                                 int ascending,
                                 const char *sort_field)
{
  static column_t select_columns[] = CERT_BUND_ADV_INFO_ITERATOR_COLUMNS;
  gchar *columns;

  assert (cve);

  columns = columns_build_select (select_columns);
  init_iterator (iterator,
                 "SELECT %s"
                 " FROM cert_bund_advs"
                 " WHERE id IN (SELECT adv_id FROM cert_bund_cves"
                 "              WHERE cve_name = '%s')"
                 " ORDER BY %s %s;",
                 columns,
                 cve,
                 sort_field ? sort_field : "name",
                 ascending ? "ASC" : "DESC");
  g_free (columns);
}

/**
 * @brief Initialise an CERT-Bund iterator, for advisories relevant to a NVT.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  oid         OID of the NVT.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "id".
 */
void
init_nvt_cert_bund_adv_iterator (iterator_t *iterator,
                                 const char *oid,
                                 int ascending,
                                 const char *sort_field)
{
  static column_t select_columns[] = DFN_CERT_ADV_INFO_ITERATOR_COLUMNS;
  gchar *columns;

  assert (oid);

  columns = columns_build_select (select_columns);
  init_iterator (iterator,
                 "SELECT %s"
                 " FROM cert_bund_advs"
                 " WHERE id IN (SELECT adv_id FROM cert_bund_cves"
                 "              WHERE cve_name IN (SELECT cve_name"
                 "                                 FROM nvt_cves"
                 "                                 WHERE oid = '%s'))"
                 " ORDER BY %s %s;",
                 columns,
                 oid,
                 sort_field ? sort_field : "name",
                 ascending ? "ASC" : "DESC");
  g_free (columns);
}

/* DFN-CERT data. */

/**
 * @brief Initialise an DFN-CERT advisory (dfn_cert_adv) info iterator.
 *
 * @param[in]  iterator        Iterator.
 * @param[in]  get             GET data.
 * @param[in]  name            Name of the info
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_dfn_cert_adv_info_iterator (iterator_t *iterator,
                                 get_data_t *get,
                                 const char *name)
{
  static const char *filter_columns[] =
    DFN_CERT_ADV_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = DFN_CERT_ADV_INFO_ITERATOR_COLUMNS;
  gchar *clause = NULL;
  int ret;

  if (get->id)
    {
      gchar *quoted = sql_quote (get->id);
      clause = g_strdup_printf (" AND uuid = '%s'", quoted);
      g_free (quoted);
      /* The entry is specified by ID, so filtering just gets in the way. */
      g_free (get->filter);
      get->filter = NULL;
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
                           "dfn_cert_adv",
                           get,
                           columns,
                           NULL,
                           filter_columns,
                           0,
                           NULL,
                           clause,
                           FALSE);
  g_free (clause);
  return ret;
}

/**
 * @brief Count number of dfn_cert_adv.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of DFN-CERT advisories in filtered set.
 */
int
dfn_cert_adv_info_count (const get_data_t *get)
{
  static const char *filter_columns[] =
    DFN_CERT_ADV_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = DFN_CERT_ADV_INFO_ITERATOR_COLUMNS;
  return count (
    "dfn_cert_adv", get, columns, NULL, filter_columns, 0, 0, 0, FALSE);
}

/**
 * @brief Get the title from an DFN_CERT_ADV iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The title of the DFN-CERT advisory,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (dfn_cert_adv_info_iterator_title, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the summary from an DFN_CERT_ADV iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The summary of the DFN-CERT advisory,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (dfn_cert_adv_info_iterator_summary, GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the number of cves from an DFN_CERT_ADV iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The number of CVEs referenced in the DFN-CERT advisory,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (dfn_cert_adv_info_iterator_cve_refs, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the maximum CVSS from an DFN_CERT_ADV iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The maximum CVSS of the CVEs referenced in the DFN-CERT advisory,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (dfn_cert_adv_info_iterator_max_cvss, GET_ITERATOR_COLUMN_COUNT + 3);

/**
 * @brief Initialise CVE iterator, for CVEs referenced by a DFN-CERT advisory.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  cve         Name of the CVE.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "id".
 */
void
init_cve_dfn_cert_adv_iterator (iterator_t *iterator,
                                const char *cve,
                                int ascending,
                                const char *sort_field)
{
  static column_t select_columns[] = DFN_CERT_ADV_INFO_ITERATOR_COLUMNS;
  gchar *columns;

  assert (cve);

  columns = columns_build_select (select_columns);
  init_iterator (iterator,
                 "SELECT %s"
                 " FROM dfn_cert_advs"
                 " WHERE id IN (SELECT adv_id FROM dfn_cert_cves"
                 "              WHERE cve_name = '%s')"
                 " ORDER BY %s %s;",
                 columns,
                 cve,
                 sort_field ? sort_field : "name",
                 ascending ? "ASC" : "DESC");
  g_free (columns);
}

/**
 * @brief Initialise an DFN-CERT iterator, for advisories relevant to a NVT.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  oid         OID of the NVT.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for "id".
 */
void
init_nvt_dfn_cert_adv_iterator (iterator_t *iterator,
                                const char *oid,
                                int ascending,
                                const char *sort_field)
{
  static column_t select_columns[] = DFN_CERT_ADV_INFO_ITERATOR_COLUMNS;
  gchar *columns;

  assert (oid);

  columns = columns_build_select (select_columns);
  init_iterator (iterator,
                 "SELECT %s"
                 " FROM dfn_cert_advs"
                 " WHERE id IN (SELECT adv_id FROM dfn_cert_cves"
                 "              WHERE cve_name IN (SELECT cve_name"
                 "                                 FROM nvt_cves"
                 "                                 WHERE oid = '%s'))"
                 " ORDER BY %s %s;",
                 columns,
                 oid,
                 sort_field ? sort_field : "name",
                 ascending ? "ASC" : "DESC");
  g_free (columns);
}

/* All SecInfo data. */

/**
 * @brief Count number of SecInfo entries.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of SecInfo entries in filtered set.
 */
int
all_info_count (const get_data_t *get)
{
  return total_info_count (get, 1);
}

/**
 * @brief Count number of all SecInfo entries.
 *
 * @param[in]   get  GET params.
 * @param[in]   filtered Whether to count entries in filtered set only.
 *
 * @return Total number of SecInfo entries.
 */
int
total_info_count (const get_data_t *get, int filtered)
{
  gchar *clause;

  if (filtered)
    {
      static const char *filter_columns[] = ALL_INFO_ITERATOR_FILTER_COLUMNS;
      static column_t select_columns[] = ALL_INFO_ITERATOR_COLUMNS;
      gchar *filter;

      if (get->filt_id && strcmp (get->filt_id, FILT_ID_NONE))
        {
          filter = filter_term (get->filt_id);
          if (filter == NULL)
            return -1;
        }
      else
        filter = NULL;

      clause = filter_clause ("allinfo",
                              filter ? filter : get->filter,
                              filter_columns,
                              select_columns,
                              NULL,
                              get->trash,
                              NULL,
                              NULL,
                              NULL,
                              NULL,
                              NULL);
      if (clause)
        return sql_int (
          "SELECT count (id) FROM" ALL_INFO_UNION_COLUMNS " WHERE %s;", clause);
    }

  return sql_int ("SELECT (SELECT count (*) FROM cves)"
                  " + (SELECT count (*) FROM cpes)"
                  " + (SELECT count (*) FROM nvts)"
                  " + (SELECT count (*) FROM cert_bund_advs)"
                  " + (SELECT count (*) FROM dfn_cert_advs)"
                  " + (SELECT count (*) FROM ovaldefs);");
}

/**
 * @brief Initialise an info iterator.
 *
 * @param[in]  iterator        Iterator.
 * @param[in]  get             GET data.
 * @param[in]  name            Name of the info
 *
 *
 * @return 0 success, 1 failed to find info, 2 failed to find filter,
 *         -1 error.
 */
int
init_all_info_iterator (iterator_t *iterator, get_data_t *get, const char *name)
{
  static const char *filter_columns[] = ALL_INFO_ITERATOR_FILTER_COLUMNS;
  static column_t select_columns[] = ALL_INFO_ITERATOR_COLUMNS;
  static column_t cve_select_columns[] = ALL_INFO_ITERATOR_COLUMNS_ARGS (
    "CAST ('cve' AS text)", "description", "cvss");
  static column_t cpe_select_columns[] = ALL_INFO_ITERATOR_COLUMNS_ARGS (
    "CAST ('cpe' AS text)", "title", "max_cvss");
  static column_t nvt_select_columns[] =
    ALL_INFO_ITERATOR_COLUMNS_ARGS ("CAST ('nvt' AS text)", "tag", "cvss_base");
  static column_t cert_select_columns[] = ALL_INFO_ITERATOR_COLUMNS_ARGS (
    "CAST ('cert_bund_adv' AS text)", "title", "max_cvss");
  static column_t dfn_select_columns[] = ALL_INFO_ITERATOR_COLUMNS_ARGS (
    "CAST ('dfn_cert_adv' AS text)", "title", "max_cvss");
  static column_t ovaldef_select_columns[] = ALL_INFO_ITERATOR_COLUMNS_ARGS (
    "CAST ('ovaldef' AS text)", "title", "max_cvss");
  int first, max;
  gchar *columns, *clause, *filter, *order, *limit_clause;
  gchar *subselect_limit_clause, *cve_clause, *cpe_clause, *nvt_clause;
  gchar *cert_clause, *dfn_clause, *ovaldef_clause, *cve_order;
  gchar *cpe_order, *nvt_order, *cert_order, *dfn_order, *ovaldef_order;

  if (get->filt_id && strcmp (get->filt_id, FILT_ID_NONE))
    {
      filter = filter_term (get->filt_id);
      if (filter == NULL)
        return 2;
    }
  else
    filter = NULL;

  clause = filter_clause ("allinfo",
                          filter ? filter : get->filter,
                          filter_columns,
                          select_columns,
                          NULL,
                          get->trash,
                          &order,
                          &first,
                          &max,
                          NULL,
                          NULL);
  columns = columns_build_select (select_columns);

  subselect_limit_clause =
    g_strdup_printf ("LIMIT %s", sql_select_limit (max + first));

  limit_clause =
    g_strdup_printf ("LIMIT %s OFFSET %i", sql_select_limit (max), first);

  cve_clause = filter_clause ("cve",
                              filter ? filter : get->filter,
                              filter_columns,
                              cve_select_columns,
                              NULL,
                              get->trash,
                              &cve_order,
                              NULL,
                              NULL,
                              NULL,
                              NULL);
  cpe_clause = filter_clause ("cpe",
                              filter ? filter : get->filter,
                              filter_columns,
                              cpe_select_columns,
                              NULL,
                              get->trash,
                              &cpe_order,
                              NULL,
                              NULL,
                              NULL,
                              NULL);
  nvt_clause = filter_clause ("nvt",
                              filter ? filter : get->filter,
                              filter_columns,
                              nvt_select_columns,
                              NULL,
                              get->trash,
                              &nvt_order,
                              NULL,
                              NULL,
                              NULL,
                              NULL);
  cert_clause = filter_clause ("cert_bund_adv",
                               filter ? filter : get->filter,
                               filter_columns,
                               cert_select_columns,
                               NULL,
                               get->trash,
                               &cert_order,
                               NULL,
                               NULL,
                               NULL,
                               NULL);
  dfn_clause = filter_clause ("dfn_cert_adv",
                              filter ? filter : get->filter,
                              filter_columns,
                              dfn_select_columns,
                              NULL,
                              get->trash,
                              &dfn_order,
                              NULL,
                              NULL,
                              NULL,
                              NULL);
  ovaldef_clause = filter_clause ("ovaldef",
                                  filter ? filter : get->filter,
                                  filter_columns,
                                  ovaldef_select_columns,
                                  NULL,
                                  get->trash,
                                  &ovaldef_order,
                                  NULL,
                                  NULL,
                                  NULL,
                                  NULL);

  init_iterator (iterator,
                 "SELECT %s"
                 " FROM " ALL_INFO_UNION_COLUMNS_LIMIT " %s%s"
                 " %s"
                 " %s;",
                 /* For the outer SELECT. */
                 columns,
                 /* For the inner SELECTs. */
                 cve_clause ? "WHERE " : "",
                 cve_clause ? cve_clause : "",
                 cve_order,
                 subselect_limit_clause,
                 cpe_clause ? "WHERE " : "",
                 cpe_clause ? cpe_clause : "",
                 cpe_order,
                 subselect_limit_clause,
                 nvt_clause ? "WHERE " : "",
                 nvt_clause ? nvt_clause : "",
                 nvt_order,
                 subselect_limit_clause,
                 cert_clause ? "WHERE " : "",
                 cert_clause ? cert_clause : "",
                 cert_order,
                 subselect_limit_clause,
                 dfn_clause ? "WHERE " : "",
                 dfn_clause ? dfn_clause : "",
                 dfn_order,
                 subselect_limit_clause,
                 ovaldef_clause ? "WHERE " : "",
                 ovaldef_clause ? ovaldef_clause : "",
                 ovaldef_order,
                 subselect_limit_clause,
                 /* For the outer SELECT. */
                 clause ? "WHERE " : "",
                 clause ? clause : "",
                 order,
                 limit_clause);

  g_free (subselect_limit_clause);
  g_free (limit_clause);
  g_free (order);
  g_free (filter);
  g_free (columns);
  g_free (clause);
  g_free (cve_clause);
  g_free (cpe_clause);
  g_free (nvt_clause);
  g_free (cert_clause);
  g_free (dfn_clause);
  g_free (ovaldef_clause);
  g_free (cve_order);
  g_free (cpe_order);
  g_free (nvt_order);
  g_free (cert_order);
  g_free (dfn_order);
  g_free (ovaldef_order);
  return 0;
}

/**
 * @brief Get the secinfo type from an all info iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The type of a secinfo entry,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (all_info_iterator_type, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the secinfo extra information from an all info iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return extra info secinfo entry,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (all_info_iterator_extra, GET_ITERATOR_COLUMN_COUNT + 1);

/**
 * @brief Get the severity from an all info iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return extra info secinfo entry,
 *         or NULL if iteration is complete.
 *         Freed by cleanup_iterator.
 */
DEF_ACCESS (all_info_iterator_severity, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Initialise an ovaldi file iterator.
 *
 * @param[in]  iterator        Iterator.
 */
void
init_ovaldi_file_iterator (iterator_t *iterator)
{
  init_iterator (iterator, "SELECT DISTINCT xml_file FROM ovaldefs;");
}

/**
 * @brief Get the name from an ovaldi file iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the file, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (ovaldi_file_iterator_name, 0);

/* CERT update: DFN-CERT. */

/**
 * @brief Update DFN-CERT info from a single XML feed file.
 *
 * @param[in]  xml_path          XML path.
 * @param[in]  last_cert_update  Time of last CERT update.
 * @param[in]  last_dfn_update   Time of last update to a DFN.
 *
 * @return 0 nothing to do, 1 updated, -1 error.
 */
static int
update_dfn_xml (const gchar *xml_path,
                int last_cert_update,
                int last_dfn_update)
{
  GError *error;
  entity_t entity, child;
  entities_t children;
  gchar *xml, *full_path;
  gsize xml_len;
  GStatBuf state;
  int updated_dfn_cert;
  int transaction_size = 0;

  updated_dfn_cert = 0;
  g_info ("%s: %s", __FUNCTION__, xml_path);

  full_path = g_build_filename (GVM_CERT_DATA_DIR, xml_path, NULL);

  if (g_stat (full_path, &state))
    {
      g_warning (
        "%s: Failed to stat CERT file: %s", __FUNCTION__, strerror (errno));
      return -1;
    }

  if ((state.st_mtime - (state.st_mtime % 60)) <= last_cert_update)
    {
      g_info ("Skipping %s, file is older than last revision", full_path);
      g_free (full_path);
      return 0;
    }

  g_info ("Updating %s", full_path);

  error = NULL;
  g_file_get_contents (full_path, &xml, &xml_len, &error);
  if (error)
    {
      g_warning (
        "%s: Failed to get contents: %s", __FUNCTION__, error->message);
      g_error_free (error);
      g_free (full_path);
      return -1;
    }

  if (parse_entity (xml, &entity))
    {
      g_free (xml);
      g_warning ("%s: Failed to parse entity", __FUNCTION__);
      g_free (full_path);
      return -1;
    }
  g_free (xml);

  // sql_begin_immediate ();
  children = entity->entities;
  while ((child = first_entity (children)))
    {
      if (strcmp (entity_name (child), "entry") == 0)
        {
          entity_t updated;

          updated = entity_child (child, "updated");
          if (updated == NULL)
            {
              g_warning ("%s: UPDATED missing", __FUNCTION__);
              free_entity (entity);
              goto fail;
            }

          if (parse_iso_time (entity_text (updated)) > last_dfn_update)
            {
              entity_t refnum, published, summary, title, cve;
              entities_t cves;
              gchar *quoted_refnum, *quoted_title, *quoted_summary;
              int cve_refs;

              refnum = entity_child (child, "dfncert:refnum");
              if (refnum == NULL)
                {
                  GString *string;

                  string = g_string_new ("");
                  g_warning ("%s: REFNUM missing", __FUNCTION__);
                  print_entity_to_string (child, string);
                  g_debug ("child:%s", string->str);
                  g_string_free (string, TRUE);
                  free_entity (entity);
                  goto fail;
                }

              published = entity_child (child, "published");
              if (published == NULL)
                {
                  g_warning ("%s: PUBLISHED missing", __FUNCTION__);
                  free_entity (entity);
                  goto fail;
                }

              title = entity_child (child, "title");
              if (title == NULL)
                {
                  g_warning ("%s: TITLE missing", __FUNCTION__);
                  free_entity (entity);
                  goto fail;
                }

              summary = entity_child (child, "summary");
              if (summary == NULL)
                {
                  g_warning ("%s: SUMMARY missing", __FUNCTION__);
                  free_entity (entity);
                  goto fail;
                }

              cve_refs = 0;
              cves = child->entities;
              while ((cve = first_entity (cves)))
                {
                  if (strcmp (entity_name (cve), "dfncert:cve") == 0)
                    cve_refs++;
                  cves = next_entities (cves);
                }

              quoted_refnum = sql_quote (entity_text (refnum));
              quoted_title = sql_quote (entity_text (title));
              quoted_summary = sql_quote (entity_text (summary));
              sql ("SELECT merge_dfn_cert_adv"
                   "        ('%s', %i, %i, '%s', '%s', %i);",
                   quoted_refnum,
                   parse_iso_time (entity_text (published)),
                   parse_iso_time (entity_text (updated)),
                   quoted_title,
                   quoted_summary,
                   cve_refs);
              increment_transaction_size (&transaction_size);
              g_free (quoted_title);
              g_free (quoted_summary);

              cves = child->entities;
              while ((cve = first_entity (cves)))
                {
                  if (strcmp (entity_name (cve), "dfncert:cve") == 0)
                    {
                      gchar **split, **point;
                      gchar *text, *start;

                      text = g_strdup (entity_text (cve));
                      start = text;
                      while ((start = strstr (start, "CVE ")))
                        start[3] = '-';

                      split = g_strsplit (text, " ", 0);
                      g_free (text);
                      point = split;
                      while (*point)
                        {
                          if (g_str_has_prefix (*point, "CVE-")
                              && (strlen (*point) >= 13)
                              && atoi (*point + 4) > 0)
                            {
                              gchar *quoted_point;

                              quoted_point = sql_quote (*point);
                              /* There's no primary key, so just INSERT, even
                               * for Postgres. */
                              sql ("INSERT INTO dfn_cert_cves"
                                   " (adv_id, cve_name)"
                                   " VALUES"
                                   " ((SELECT id FROM dfn_cert_advs"
                                   "   WHERE name = '%s'),"
                                   "  '%s')",
                                   quoted_refnum,
                                   quoted_point);
                              increment_transaction_size (&transaction_size);
                              g_free (quoted_point);
                            }
                          point++;
                        }
                      g_strfreev (split);
                    }

                  cves = next_entities (cves);
                }

              updated_dfn_cert = 1;
              g_free (quoted_refnum);
            }
        }
      children = next_entities (children);
    }

  free_entity (entity);
  g_free (full_path);
  // sql_commit ();
  return updated_dfn_cert;

fail:
  g_warning ("Update of DFN-CERT Advisories failed at file '%s'", full_path);
  g_free (full_path);
  // sql_commit ();
  return -1;
}

/**
 * @brief Update DFN-CERTs.
 *
 * Assume that the databases are attached.
 *
 * @param[in]  last_cert_update  Time of last CERT update from meta.
 *
 * @return 0 nothing to do, 1 updated, -1 error.
 */
static int
update_dfn_cert_advisories (int last_cert_update)
{
  GError *error;
  int count, last_dfn_update, updated_dfn_cert;
  GDir *dir;
  const gchar *xml_path;

  error = NULL;
  dir = g_dir_open (GVM_CERT_DATA_DIR, 0, &error);
  if (dir == NULL)
    {
      g_warning ("%s: Failed to open directory '%s': %s",
                 __FUNCTION__,
                 GVM_CERT_DATA_DIR,
                 error->message);
      g_error_free (error);
      return -1;
    }

  last_dfn_update = sql_int ("SELECT max (modification_time)"
                             " FROM cert.dfn_cert_advs;");

  g_debug ("%s: VS: " GVM_CERT_DATA_DIR "/dfn-cert-*.xml", __FUNCTION__);
  count = 0;
  updated_dfn_cert = 0;
  while ((xml_path = g_dir_read_name (dir)))
    if (fnmatch ("dfn-cert-*.xml", xml_path, 0) == 0)
      {
        switch (update_dfn_xml (xml_path, last_cert_update, last_dfn_update))
          {
          case 0:
            break;
          case 1:
            updated_dfn_cert = 1;
            break;
          default:
            g_dir_close (dir);
            return -1;
          }
        count++;
      }

  if (count == 0)
    g_warning ("No DFN-CERT advisories found in %s", GVM_CERT_DATA_DIR);

  g_dir_close (dir);
  return updated_dfn_cert;
}

/* CERT update: CERT-BUND. */

/**
 * @brief Update CERT-Bund info from a single XML feed file.
 *
 * @param[in]  xml_path          XML path.
 * @param[in]  last_cert_update  Time of last CERT update.
 * @param[in]  last_bund_update   Time of last update to a DFN.
 *
 * @return 0 nothing to do, 1 updated, -1 error.
 */
static int
update_bund_xml (const gchar *xml_path,
                 int last_cert_update,
                 int last_bund_update)
{
  GError *error;
  entity_t entity, child;
  entities_t children;
  gchar *xml, *full_path;
  gsize xml_len;
  GStatBuf state;
  int updated_cert_bund;
  int transaction_size = 0;

  updated_cert_bund = 0;
  full_path = g_build_filename (GVM_CERT_DATA_DIR, xml_path, NULL);

  if (g_stat (full_path, &state))
    {
      g_warning (
        "%s: Failed to stat CERT file: %s", __FUNCTION__, strerror (errno));
      return -1;
    }

  if ((state.st_mtime - (state.st_mtime % 60)) <= last_cert_update)
    {
      g_info ("Skipping %s, file is older than last revision", full_path);
      g_free (full_path);
      return 0;
    }

  g_info ("Updating %s", full_path);

  error = NULL;
  g_file_get_contents (full_path, &xml, &xml_len, &error);
  if (error)
    {
      g_warning (
        "%s: Failed to get contents: %s", __FUNCTION__, error->message);
      g_error_free (error);
      g_free (full_path);
      return -1;
    }

  if (parse_entity (xml, &entity))
    {
      g_free (xml);
      g_warning ("%s: Failed to parse entity", __FUNCTION__);
      g_free (full_path);
      return -1;
    }
  g_free (xml);

  // sql_begin_immediate ();
  children = entity->entities;
  while ((child = first_entity (children)))
    {
      if (strcmp (entity_name (child), "Advisory") == 0)
        {
          entity_t date;

          date = entity_child (child, "Date");
          if (date == NULL)
            {
              g_warning ("%s: Date missing", __FUNCTION__);
              free_entity (entity);
              goto fail;
            }

          if (parse_iso_time (entity_text (date)) > last_bund_update)
            {
              entity_t refnum, description, title, cve, cve_list;
              gchar *quoted_refnum, *quoted_title, *quoted_summary;
              int cve_refs;
              GString *summary;

              refnum = entity_child (child, "Ref_Num");
              if (refnum == NULL)
                {
                  GString *string;

                  string = g_string_new ("");
                  g_warning ("%s: Ref_Num missing", __FUNCTION__);
                  print_entity_to_string (child, string);
                  g_debug ("child:%s", string->str);
                  g_string_free (string, TRUE);
                  free_entity (entity);
                  goto fail;
                }

              title = entity_child (child, "Title");
              if (title == NULL)
                {
                  g_warning ("%s: Title missing", __FUNCTION__);
                  free_entity (entity);
                  goto fail;
                }

              summary = g_string_new ("");
              description = entity_child (child, "Description");
              if (description)
                {
                  entities_t elements;
                  entity_t element;

                  elements = description->entities;
                  while ((element = first_entity (elements)))
                    {
                      if (strcmp (entity_name (element), "Element") == 0)
                        {
                          entity_t text_block;
                          text_block = entity_child (element, "TextBlock");
                          if (text_block)
                            g_string_append (summary, entity_text (text_block));
                        }
                      elements = next_entities (elements);
                    }
                }

              cve_refs = 0;
              cve_list = entity_child (child, "CVEList");
              if (cve_list)
                {
                  entities_t cves;
                  cves = cve_list->entities;
                  while ((cve = first_entity (cves)))
                    {
                      if (strcmp (entity_name (cve), "CVE") == 0)
                        cve_refs++;
                      cves = next_entities (cves);
                    }
                }

              quoted_refnum = sql_quote (entity_text (refnum));
              quoted_title = sql_quote (entity_text (title));
              quoted_summary = sql_quote (summary->str);
              g_string_free (summary, TRUE);
              sql ("SELECT merge_bund_adv"
                   "        ('%s', %i, %i, '%s', '%s', %i);",
                   quoted_refnum,
                   parse_iso_time (entity_text (date)),
                   parse_iso_time (entity_text (date)),
                   quoted_title,
                   quoted_summary,
                   cve_refs);
              increment_transaction_size (&transaction_size);
              g_free (quoted_title);
              g_free (quoted_summary);

              cve_list = entity_child (child, "CVEList");
              if (cve_list)
                {
                  entities_t cves;
                  cves = cve_list->entities;
                  while ((cve = first_entity (cves)))
                    {
                      if ((strcmp (entity_name (cve), "CVE") == 0)
                          && strlen (entity_text (cve)))
                        {
                          gchar *quoted_cve;
                          quoted_cve = sql_quote (entity_text (cve));
                          /* There's no primary key, so just INSERT, even
                           * for Postgres. */
                          sql ("INSERT INTO cert_bund_cves"
                               " (adv_id, cve_name)"
                               " VALUES"
                               " ((SELECT id FROM cert_bund_advs"
                               "   WHERE name = '%s'),"
                               "  '%s')",
                               quoted_refnum,
                               quoted_cve);
                          increment_transaction_size (&transaction_size);
                          g_free (quoted_cve);
                        }

                      cves = next_entities (cves);
                    }
                }

              updated_cert_bund = 1;
              g_free (quoted_refnum);
            }
        }
      children = next_entities (children);
    }

  free_entity (entity);
  g_free (full_path);
  // sql_commit ();
  return updated_cert_bund;

fail:
  g_warning ("Update of CERT-Bund Advisories failed at file '%s'", full_path);
  g_free (full_path);
  // sql_commit ();
  return -1;
}

/**
 * @brief Update CERT-Bunds.
 *
 * Assume that the databases are attached.
 *
 * @param[in]  last_cert_update  Time of last CERT update from meta.
 *
 * @return 0 nothing to do, 1 updated, -1 error.
 */
static int
update_cert_bund_advisories (int last_cert_update)
{
  GError *error;
  int count, last_bund_update, updated_cert_bund;
  GDir *dir;
  const gchar *xml_path;

  error = NULL;
  dir = g_dir_open (GVM_CERT_DATA_DIR, 0, &error);
  if (dir == NULL)
    {
      g_warning ("%s: Failed to open directory '%s': %s",
                 __FUNCTION__,
                 GVM_CERT_DATA_DIR,
                 error->message);
      g_error_free (error);
      return -1;
    }

  last_bund_update = sql_int ("SELECT max (modification_time)"
                              " FROM cert.cert_bund_advs;");

  count = 0;
  updated_cert_bund = 0;
  while ((xml_path = g_dir_read_name (dir)))
    if (fnmatch ("CB-K*.xml", xml_path, 0) == 0)
      {
        switch (update_bund_xml (xml_path, last_cert_update, last_bund_update))
          {
          case 0:
            break;
          case 1:
            updated_cert_bund = 1;
            break;
          default:
            g_dir_close (dir);
            return -1;
          }
        count++;
      }

  if (count == 0)
    g_warning ("No CERT-Bund advisories found in %s", GVM_CERT_DATA_DIR);

  g_dir_close (dir);
  return updated_cert_bund;
}

/* SCAP update: CPEs. */

/**
 * @brief Update SCAP CPEs.
 *
 * @param[in]  last_scap_update  Time of last SCAP update.
 *
 * @return 0 nothing to do, 1 updated, -1 error.
 */
static int
update_scap_cpes (int last_scap_update)
{
  GError *error;
  entity_t entity, cpe_list, cpe_item;
  entities_t children;
  gchar *xml, *full_path;
  gsize xml_len;
  GStatBuf state;
  int updated_scap_cpes, last_cve_update;
  int transaction_size = 0;

  updated_scap_cpes = 0;
  full_path = g_build_filename (
    GVM_SCAP_DATA_DIR, "official-cpe-dictionary_v2.2.xml", NULL);

  if (g_stat (full_path, &state))
    {
      g_warning (
        "%s: No CPE dictionary found at %s", __FUNCTION__, strerror (errno));
      return -1;
    }

  if ((state.st_mtime - (state.st_mtime % 60)) <= last_scap_update)
    {
      g_info ("Skipping CPEs, file is older than last revision"
              " (this is not an error)");
      g_free (full_path);
      return 0;
    }

  g_info ("Updating CPEs");

  /* This will be zero for an empty db, so everything will be added. */
  last_cve_update = sql_int ("SELECT max (modification_time)"
                             " FROM scap.cves;");

  g_debug ("%s: parsing %s", __FUNCTION__, full_path);

  error = NULL;
  g_file_get_contents (full_path, &xml, &xml_len, &error);
  g_free (full_path);
  if (error)
    {
      g_warning (
        "%s: Failed to get contents: %s", __FUNCTION__, error->message);
      g_error_free (error);
      return -1;
    }

  if (parse_entity (xml, &entity))
    {
      g_free (xml);
      g_warning ("%s: Failed to parse entity", __FUNCTION__);
      return -1;
    }
  g_free (xml);

  cpe_list = entity;
  if (strcmp (entity_name (cpe_list), "cpe-list"))
    {
      free_entity (entity);
      g_warning ("%s: CPE dictionary missing CPE-LIST", __FUNCTION__);
      return -1;
    }

  // sql_begin_immediate ();

  children = cpe_list->entities;
  while ((cpe_item = first_entity (children)))
    {
      if (strcmp (entity_name (cpe_item), "cpe-item") == 0)
        {
          const char *modification_date;
          entity_t item_metadata;

          item_metadata = entity_child (cpe_item, "meta:item-metadata");
          if (item_metadata == NULL)
            {
              g_warning ("%s: item-metadata missing", __FUNCTION__);

              free_entity (entity);
              goto fail;
            }

          modification_date =
            entity_attribute (item_metadata, "modification-date");
          if (modification_date == NULL)
            {
              g_warning ("%s: modification-date missing", __FUNCTION__);
              free_entity (entity);
              goto fail;
            }

          if (parse_iso_time (modification_date) > last_cve_update)
            {
              const char *name, *status, *deprecated, *nvd_id;
              gchar *quoted_name, *quoted_title, *quoted_status, *quoted_nvd_id;
              gchar *name_decoded, *name_tilde;
              entities_t titles;
              entity_t title;

              name = entity_attribute (cpe_item, "name");
              if (name == NULL)
                {
                  g_warning ("%s: name missing", __FUNCTION__);
                  free_entity (entity);
                  goto fail;
                }

              status = entity_attribute (item_metadata, "status");
              if (status == NULL)
                {
                  g_warning ("%s: status missing", __FUNCTION__);
                  free_entity (entity);
                  goto fail;
                }

              deprecated =
                entity_attribute (item_metadata, "deprecated-by-nvd-id");
              if (deprecated
                  && (g_regex_match_simple (
                        "^[0-9]+$", (gchar *) deprecated, 0, 0)
                      == 0))
                {
                  g_warning ("%s: invalid deprecated-by-nvd-id: %s",
                             __FUNCTION__,
                             deprecated);
                  free_entity (entity);
                  goto fail;
                }

              nvd_id = entity_attribute (item_metadata, "nvd-id");
              if (nvd_id == NULL)
                {
                  g_warning ("%s: nvd_id missing", __FUNCTION__);
                  free_entity (entity);
                  goto fail;
                }

              titles = cpe_item->entities;
              quoted_title = g_strdup ("");
              while ((title = first_entity (titles)))
                {
                  if (strcmp (entity_name (title), "title") == 0
                      && entity_attribute (title, "xml:lang")
                      && strcmp (entity_attribute (title, "xml:lang"), "en-US")
                           == 0)
                    {
                      g_free (quoted_title);
                      quoted_title = sql_quote (entity_text (title));
                      break;
                    }
                  titles = next_entities (titles);
                }

              name_decoded = g_uri_unescape_string (name, NULL);
              name_tilde =
                string_replace (name_decoded, "~", "%7E", "%7e", NULL);
              g_free (name_decoded);
              quoted_name = sql_quote (name_tilde);
              g_free (name_tilde);
              quoted_status = sql_quote (status);
              quoted_nvd_id = sql_quote (nvd_id);
              sql ("SELECT merge_cpe"
                   "        ('%s', '%s', %i, %i, '%s', %s, '%s');",
                   quoted_name,
                   quoted_title,
                   parse_iso_time (modification_date),
                   parse_iso_time (modification_date),
                   quoted_status,
                   deprecated ? deprecated : "NULL",
                   quoted_nvd_id);
              increment_transaction_size (&transaction_size);
              g_free (quoted_title);
              g_free (quoted_name);
              g_free (quoted_status);
              g_free (quoted_nvd_id);

              updated_scap_cpes = 1;
            }
        }
      children = next_entities (children);
    }

  free_entity (entity);
  // sql_commit ();
  return updated_scap_cpes;

fail:
  g_warning ("Update of CPEs failed");
  // sql_commit ();
  return -1;
}

/* SCAP update: CVEs. */

/**
 * @brief Update CVE info from a single XML feed file.
 *
 * @param[in]  xml_path          XML path.
 * @param[in]  last_scap_update  Time of last SCAP update.
 * @param[in]  last_cve_update   Time of last update to a DFN.
 *
 * @return 0 nothing to do, 1 updated, -1 error.
 */
static int
update_cve_xml (const gchar *xml_path,
                int last_scap_update,
                int last_cve_update)
{
  GError *error;
  entity_t entity, entry;
  entities_t children;
  gchar *xml, *full_path;
  gsize xml_len;
  GStatBuf state;
  int updated_scap_bund;
  int transaction_size = 0;

  updated_scap_bund = 0;
  full_path = g_build_filename (GVM_SCAP_DATA_DIR, xml_path, NULL);

  if (g_stat (full_path, &state))
    {
      g_warning (
        "%s: Failed to stat SCAP file: %s", __FUNCTION__, strerror (errno));
      return -1;
    }

  if ((state.st_mtime - (state.st_mtime % 60)) <= last_scap_update)
    {
      g_info ("Skipping %s, file is older than last revision"
              " (this is not an error)",
              full_path);
      g_free (full_path);
      return 0;
    }

  g_info ("Updating %s", full_path);

  error = NULL;
  g_file_get_contents (full_path, &xml, &xml_len, &error);
  if (error)
    {
      g_warning (
        "%s: Failed to get contents: %s", __FUNCTION__, error->message);
      g_error_free (error);
      g_free (full_path);
      return -1;
    }

  if (parse_entity (xml, &entity))
    {
      g_free (xml);
      g_warning ("%s: Failed to parse entity", __FUNCTION__);
      g_free (full_path);
      return -1;
    }
  g_free (xml);

  // sql_begin_immediate ();
  children = entity->entities;
  while ((entry = first_entity (children)))
    {
      if (strcmp (entity_name (entry), "entry") == 0)
        {
          entity_t last_modified;

          last_modified = entity_child (entry, "vuln:last-modified-datetime");
          if (last_modified == NULL)
            {
              g_warning ("%s: vuln:last-modified-datetime missing",
                         __FUNCTION__);
              free_entity (entity);
              goto fail;
            }

          if (parse_iso_time (entity_text (last_modified)) > last_cve_update)
            {
              entity_t published, summary, cvss, score, base_metrics;
              entity_t access_vector, access_complexity, authentication;
              entity_t confidentiality_impact, integrity_impact;
              entity_t availability_impact, list;
              gchar *quoted_id, *quoted_summary;
              gchar *quoted_access_vector, *quoted_access_complexity;
              gchar *quoted_authentication, *quoted_confidentiality_impact;
              gchar *quoted_integrity_impact, *quoted_availability_impact;
              gchar *quoted_software;
              const char *id;
              GString *software;
              gchar *software_unescaped, *software_tilde;
              int time_modified, time_published;

              id = entity_attribute (entry, "id");
              if (id == NULL)
                {
                  g_warning ("%s: id missing", __FUNCTION__);
                  free_entity (entity);
                  goto fail;
                }

              published = entity_child (entry, "vuln:published-datetime");
              if (published == NULL)
                {
                  g_warning ("%s: vuln:published-datetime missing",
                             __FUNCTION__);
                  free_entity (entity);
                  goto fail;
                }

              cvss = entity_child (entry, "vuln:cvss");
              if (cvss == NULL)
                base_metrics = NULL;
              else
                base_metrics = entity_child (cvss, "cvss:base_metrics");
              if (base_metrics == NULL)
                {
                  score = NULL;
                  access_vector = NULL;
                  access_complexity = NULL;
                  authentication = NULL;
                  confidentiality_impact = NULL;
                  integrity_impact = NULL;
                  availability_impact = NULL;
                }
              else
                {
                  score = entity_child (base_metrics, "cvss:score");
                  if (score == NULL)
                    {
                      g_warning ("%s: cvss:score missing", __FUNCTION__);
                      free_entity (entity);
                      goto fail;
                    }

                  access_vector =
                    entity_child (base_metrics, "cvss:access-vector");
                  if (access_vector == NULL)
                    {
                      g_warning ("%s: cvss:access-vector missing",
                                 __FUNCTION__);
                      free_entity (entity);
                      goto fail;
                    }

                  access_complexity =
                    entity_child (base_metrics, "cvss:access-complexity");
                  if (access_complexity == NULL)
                    {
                      g_warning ("%s: cvss:access-complexity missing",
                                 __FUNCTION__);
                      free_entity (entity);
                      goto fail;
                    }

                  authentication =
                    entity_child (base_metrics, "cvss:authentication");
                  if (authentication == NULL)
                    {
                      g_warning ("%s: cvss:authentication missing",
                                 __FUNCTION__);
                      free_entity (entity);
                      goto fail;
                    }

                  confidentiality_impact =
                    entity_child (base_metrics, "cvss:confidentiality-impact");
                  if (confidentiality_impact == NULL)
                    {
                      g_warning ("%s: cvss:confidentiality-impact missing",
                                 __FUNCTION__);
                      free_entity (entity);
                      goto fail;
                    }

                  integrity_impact =
                    entity_child (base_metrics, "cvss:integrity-impact");
                  if (integrity_impact == NULL)
                    {
                      g_warning ("%s: cvss:integrity-impact missing",
                                 __FUNCTION__);
                      free_entity (entity);
                      goto fail;
                    }

                  availability_impact =
                    entity_child (base_metrics, "cvss:availability-impact");
                  if (availability_impact == NULL)
                    {
                      g_warning ("%s: cvss:availability-impact missing",
                                 __FUNCTION__);
                      free_entity (entity);
                      goto fail;
                    }
                }

              summary = entity_child (entry, "vuln:summary");
              if (summary == NULL)
                {
                  g_warning ("%s: vuln:summary missing", __FUNCTION__);
                  free_entity (entity);
                  goto fail;
                }

              software = g_string_new ("");
              list = entity_child (entry, "vuln:vulnerable-software-list");
              if (list)
                {
                  entity_t product;
                  entities_t products;
                  products = list->entities;
                  while ((product = first_entity (products)))
                    {
                      if (strcmp (entity_name (product), "vuln:product") == 0)
                        g_string_append_printf (
                          software, "%s ", entity_text (product));
                      products = next_entities (products);
                    }
                }

              quoted_id = sql_quote (id);
              quoted_summary = sql_quote (summary ? entity_text (summary) : "");
              quoted_access_vector =
                sql_quote (access_vector ? entity_text (access_vector) : "");
              quoted_access_complexity = sql_quote (
                access_complexity ? entity_text (access_complexity) : "");
              quoted_authentication =
                sql_quote (authentication ? entity_text (authentication) : "");
              quoted_confidentiality_impact = sql_quote (
                confidentiality_impact ? entity_text (confidentiality_impact)
                                       : "");
              quoted_integrity_impact = sql_quote (
                integrity_impact ? entity_text (integrity_impact) : "");
              quoted_availability_impact = sql_quote (
                availability_impact ? entity_text (availability_impact) : "");
              software_unescaped = g_uri_unescape_string (software->str, NULL);
              g_string_free (software, TRUE);
              software_tilde =
                string_replace (software_unescaped, "~", "%7E", "%7e", NULL);
              g_free (software_unescaped);
              quoted_software = sql_quote (software_tilde);
              g_free (software_tilde);
              time_modified = parse_iso_time (entity_text (last_modified));
              time_published = parse_iso_time (entity_text (published));
              sql ("SELECT merge_cve"
                   "        ('%s', '%s', %i, %i, %s, '%s', '%s', '%s', '%s',"
                   "         '%s', '%s', '%s', '%s');",
                   quoted_id,
                   quoted_id,
                   time_published,
                   time_modified,
                   score ? entity_text (score) : "NULL",
                   quoted_summary,
                   quoted_access_vector,
                   quoted_access_complexity,
                   quoted_authentication,
                   quoted_confidentiality_impact,
                   quoted_integrity_impact,
                   quoted_availability_impact,
                   quoted_software);
              increment_transaction_size (&transaction_size);
              g_free (quoted_summary);
              g_free (quoted_access_vector);
              g_free (quoted_access_complexity);
              g_free (quoted_authentication);
              g_free (quoted_confidentiality_impact);
              g_free (quoted_integrity_impact);
              g_free (quoted_availability_impact);

              if (list)
                {
                  entity_t product;
                  entities_t products;
                  resource_t cve_rowid;

                  products = list->entities;

                  if (first_entity (products))
                    {
                      sql_int64 (&cve_rowid,
                                 "SELECT id FROM cves WHERE uuid='%s';",
                                 quoted_id);

                      while ((product = first_entity (products)))
                        {
                          if ((strcmp (entity_name (product), "vuln:product")
                               == 0)
                              && strlen (entity_text (product)))
                            {
                              gchar *quoted_product, *product_decoded;
                              gchar *product_tilde;

                              product_decoded = g_uri_unescape_string (
                                entity_text (product), NULL);
                              product_tilde = string_replace (
                                product_decoded, "~", "%7E", "%7e", NULL);
                              g_free (product_decoded);
                              quoted_product = sql_quote (product_tilde);
                              g_free (product_tilde);

                              sql ("SELECT merge_cpe_name ('%s', '%s', %i, %i)",
                                   quoted_product,
                                   quoted_product,
                                   time_published,
                                   time_modified);
                              sql ("SELECT merge_affected_product"
                                   "        (%llu,"
                                   "         (SELECT id FROM cpes"
                                   "          WHERE name='%s'))",
                                   cve_rowid,
                                   quoted_product);
                              transaction_size++;
                              increment_transaction_size (&transaction_size);
                              g_free (quoted_product);
                            }

                          products = next_entities (products);
                        }
                    }
                }

              updated_scap_bund = 1;
              g_free (quoted_id);
            }
        }
      children = next_entities (children);
    }

  free_entity (entity);
  g_free (full_path);
  // sql_commit ();
  return updated_scap_bund;

fail:
  g_warning ("Update of CVEs failed at file '%s'", full_path);
  g_free (full_path);
  // sql_commit ();
  return -1;
}

/**
 * @brief Update SCAP CVEs.
 *
 * Assume that the databases are attached.
 *
 * @param[in]  last_scap_update  Time of last SCAP update from meta.
 *
 * @return 0 nothing to do, 1 updated, -1 error.
 */
static int
update_scap_cves (int last_scap_update)
{
  GError *error;
  int count, last_cve_update, updated_scap_cves;
  GDir *dir;
  const gchar *xml_path;

  error = NULL;
  dir = g_dir_open (GVM_SCAP_DATA_DIR, 0, &error);
  if (dir == NULL)
    {
      g_warning ("%s: Failed to open directory '%s': %s",
                 __FUNCTION__,
                 GVM_SCAP_DATA_DIR,
                 error->message);
      g_error_free (error);
      return -1;
    }

  last_cve_update = sql_int ("SELECT max (modification_time)"
                             " FROM scap.cves;");

  count = 0;
  updated_scap_cves = 0;
  while ((xml_path = g_dir_read_name (dir)))
    if (fnmatch ("nvdcve-2.0-*.xml", xml_path, 0) == 0)
      {
        switch (update_cve_xml (xml_path, last_scap_update, last_cve_update))
          {
          case 0:
            break;
          case 1:
            updated_scap_cves = 1;
            break;
          default:
            g_dir_close (dir);
            return -1;
          }
        count++;
      }

  if (count == 0)
    g_warning ("No CVEs found in %s", GVM_SCAP_DATA_DIR);

  g_dir_close (dir);
  return updated_scap_cves;
}

/* SCAP update: OVAL. */

/**
 * @brief Get last date from definition entity.
 *
 * @param[in]  definition              Definition.
 * @param[out] definition_date_newest  Newest date.
 * @param[out] definition_date_oldest  Oldest date.
 */
static void
oval_definition_dates (entity_t definition,
                       int *definition_date_newest,
                       int *definition_date_oldest)
{
  entity_t metadata, oval_repository, date, dates;
  entities_t children;
  int first;
  const char *oldest, *newest;

  assert (definition_date_newest);
  assert (definition_date_oldest);

  *definition_date_newest = 0;
  *definition_date_oldest = 0;

  metadata = entity_child (definition, "metadata");
  if (metadata == NULL)
    {
      g_warning ("%s: metadata missing", __FUNCTION__);
      return;
    }

  oval_repository = entity_child (metadata, "oval_repository");
  if (oval_repository == NULL)
    {
      g_warning ("%s: oval_repository missing", __FUNCTION__);
      return;
    }

  dates = entity_child (oval_repository, "dates");
  if (dates == NULL)
    {
      g_warning ("%s: dates missing", __FUNCTION__);
      return;
    }

  newest = NULL;
  oldest = NULL;
  first = 1;
  children = dates->entities;
  while ((date = first_entity (children)))
    {
      if ((strcmp (entity_name (date), "submitted") == 0)
          || (strcmp (entity_name (date), "status_change") == 0)
          || (strcmp (entity_name (date), "modified") == 0))
        {
          if (first)
            {
              newest = entity_attribute (date, "date");
              first = 0;
            }
          oldest = entity_attribute (date, "date");
        }
      children = next_entities (children);
    }

  if (newest)
    *definition_date_newest = parse_iso_time (newest);
  if (oldest)
    *definition_date_oldest = parse_iso_time (oldest);
}

/**
 * @brief Get generator/timestamp from main oval_definitions entity.
 *
 * @param[in]  entity          Entity.
 * @param[out] file_timestamp  Timestamp.
 */
static void
oval_oval_definitions_date (entity_t entity, int *file_timestamp)
{
  entity_t generator, timestamp;

  assert (file_timestamp);

  *file_timestamp = 0;

  generator = entity_child (entity, "generator");
  if (generator == NULL)
    {
      g_warning ("%s: generator missing", __FUNCTION__);
      return;
    }

  timestamp = entity_child (generator, "oval:timestamp");
  if (timestamp == NULL)
    {
      g_warning ("%s: oval:timestamp missing", __FUNCTION__);
      return;
    }

  *file_timestamp = parse_iso_time (entity_text (timestamp));
}

/**
 * @brief Verify a OVAL definitions file.
 *
 * @param[in]  full_path  Full path to the OVAL definitions file to verify.
 *
 * @return 0 if valid, else -1.
 */
static int
verify_oval_file (const gchar *full_path)
{
  GError *error;
  gchar *xml;
  gsize xml_len;
  entity_t entity;

  error = NULL;
  g_file_get_contents (full_path, &xml, &xml_len, &error);
  if (error)
    {
      g_warning (
        "%s: Failed to get contents: %s", __FUNCTION__, error->message);
      g_error_free (error);
      return -1;
    }

  if (parse_entity (xml, &entity))
    {
      g_free (xml);
      g_warning ("%s: Failed to parse entity", __FUNCTION__);
      return -1;
    }
  g_free (xml);

  if (strcmp (entity_name (entity), "oval_definitions") == 0)
    {
      int definition_count;
      entities_t children;
      entity_t definitions;

      definition_count = 0;
      children = entity->entities;
      while ((definitions = first_entity (children)))
        {
          if (strcmp (entity_name (definitions), "definitions") == 0)
            {
              entity_t definition;
              entities_t grandchildren;

              grandchildren = definitions->entities;
              while ((definition = first_entity (grandchildren)))
                {
                  if (strcmp (entity_name (definition), "definition") == 0)
                    definition_count++;
                  grandchildren = next_entities (grandchildren);
                }
            }
          children = next_entities (children);
        }

      free_entity (entity);
      if (definition_count == 0)
        {
          g_warning ("%s: No OVAL definitions found", __FUNCTION__);
          return -1;
        }
      else
        return 0;
    }

  if (strcmp (entity_name (entity), "oval_variables") == 0)
    {
      int variable_count;
      entities_t children;
      entity_t variables;

      variable_count = 0;
      children = entity->entities;
      while ((variables = first_entity (children)))
        {
          if (strcmp (entity_name (variables), "variables") == 0)
            {
              entity_t variable;
              entities_t grandchildren;

              grandchildren = variables->entities;
              while ((variable = first_entity (grandchildren)))
                {
                  if (strcmp (entity_name (variable), "variable") == 0)
                    variable_count++;
                  grandchildren = next_entities (grandchildren);
                }
            }
          children = next_entities (children);
        }

      free_entity (entity);
      if (variable_count == 0)
        {
          g_warning ("%s: No OVAL variables found", __FUNCTION__);
          return -1;
        }
      else
        return 0;
    }

  if (strcmp (entity_name (entity), "oval_system_characteristics") == 0)
    {
      g_warning ("%s: File is an OVAL System Characteristics file",
                 __FUNCTION__);
      return -1;
    }

  if (strcmp (entity_name (entity), "oval_results") == 0)
    {
      g_warning ("%s: File is an OVAL Results one", __FUNCTION__);
      return -1;
    }

  g_warning ("%s: Root tag neither oval_definitions nor oval_variables",
             __FUNCTION__);
  free_entity (entity);
  return -1;
}

/**
 * @brief Update OVALDEF info from a single XML feed file.
 *
 * @param[in]  file_and_date     Array containing XML path and timestamp.
 * @param[in]  last_scap_update  Time of last SCAP update.
 * @param[in]  last_ovaldef_update   Time of last update to an ovaldef.
 * @param[in]  private           Whether this is from the user's private dir.
 *
 * @return 0 nothing to do, 1 updated, -1 error.
 */
static int
update_ovaldef_xml (gchar **file_and_date,
                    int last_scap_update,
                    int last_ovaldef_update,
                    int private)
{
  GError *error;
  entity_t entity, child;
  entities_t children;
  const gchar *xml_path, *oval_timestamp;
  gchar *xml_basename, *xml, *quoted_xml_basename;
  gsize xml_len;
  GStatBuf state;
  int last_oval_update, file_timestamp;
  int transaction_size = 0;

  /* Setup variables. */

  xml_path = file_and_date[0];
  assert (xml_path);

  g_debug ("%s: xml_path: %s", __FUNCTION__, xml_path);

  /* The timestamp from the OVAL XML. */
  oval_timestamp = file_and_date[1];

  if (g_stat (xml_path, &state))
    {
      g_warning ("%s: Failed to stat OVAL file %s: %s",
                 __FUNCTION__,
                 xml_path,
                 strerror (errno));
      return -1;
    }

  if ((state.st_mtime - (state.st_mtime % 60)) <= last_scap_update)
    {
      g_info ("Skipping %s, file is older than last revision"
              " (this is not an error)",
              xml_path);
      return 0;
    }

  xml_basename = strstr (xml_path, GVM_SCAP_DATA_DIR);
  if (xml_basename == NULL)
    {
      g_warning (
        "%s: xml_path missing GVM_SCAP_DATA_DIR: %s", __FUNCTION__, xml_path);
      return -1;
    }
  xml_basename += strlen (GVM_SCAP_DATA_DIR);

  quoted_xml_basename = sql_quote (xml_basename);

  /* The last time this file was updated in the db. */
  last_oval_update = sql_int ("SELECT max(modification_time)"
                              " FROM scap.ovaldefs"
                              " WHERE xml_file = '%s';",
                              quoted_xml_basename);

  if (oval_timestamp && (parse_iso_time (oval_timestamp) <= last_oval_update))
    {
      g_free (quoted_xml_basename);
      g_info ("Skipping %s, file has older timestamp than latest OVAL"
              " definition in database (this is not an error)",
              xml_path);
      return 0;
    }

  if (private)
    {
      /* Validate OVAL file. */

      if (verify_oval_file (xml_path))
        {
          g_info ("Validation failed for file '%s'", xml_path);
          g_free (quoted_xml_basename);
          return 0;
        }
    }

  /* Parse XML from the file. */

  g_info ("Updating %s", xml_path);

  error = NULL;
  g_file_get_contents (xml_path, &xml, &xml_len, &error);
  if (error)
    {
      g_warning (
        "%s: Failed to get contents: %s", __FUNCTION__, error->message);
      g_error_free (error);
      g_free (quoted_xml_basename);
      return -1;
    }

  if (parse_entity (xml, &entity))
    {
      g_free (xml);
      g_warning ("%s: Failed to parse entity", __FUNCTION__);
      g_free (quoted_xml_basename);
      return -1;
    }
  g_free (xml);

  /* Fill the db according to the XML. */

  // sql_begin_immediate ();

  sql ("INSERT INTO ovalfiles (xml_file)"
       " SELECT '%s' WHERE NOT EXISTS (SELECT * FROM ovalfiles"
       "                               WHERE xml_file = '%s');",
       quoted_xml_basename,
       quoted_xml_basename);

  // sql_commit ();
  // sql_begin_immediate ();

  oval_oval_definitions_date (entity, &file_timestamp);

  children = entity->entities;
  while ((child = first_entity (children)))
    {
      entities_t definitions;
      entity_t definition;

      if (strcmp (entity_name (child), "definitions"))
        {
          children = next_entities (children);
          continue;
        }

      definitions = child->entities;
      while ((definition = first_entity (definitions)))
        {
          if (strcmp (entity_name (definition), "definition") == 0)
            {
              int definition_date_newest, definition_date_oldest;
              gchar *quoted_id, *quoted_oval_id;

              /* The newest and oldest of this definition's dates (created,
               * modified, etc), from the OVAL XML. */
              oval_definition_dates (
                definition, &definition_date_newest, &definition_date_oldest);

              if (definition_date_oldest
                  && (definition_date_oldest <= last_oval_update))
                {
                  const char *id;

                  id = entity_attribute (definition, "id");
                  quoted_oval_id = sql_quote (id ? id : "");
                  g_info ("%s: Filtered %s (%i)",
                          __FUNCTION__,
                          quoted_oval_id,
                          definition_date_oldest);
                  g_free (quoted_oval_id);
                }
              else
                {
                  entity_t metadata, title, description, repository, reference;
                  entity_t status;
                  entities_t references;
                  const char *deprecated, *version;
                  gchar *id, *quoted_title, *quoted_class, *quoted_description;
                  gchar *quoted_status;
                  int cve_count;

                  if (entity_attribute (definition, "id") == NULL)
                    {
                      g_warning ("%s: oval_definition missing id",
                                 __FUNCTION__);
                      free_entity (entity);
                      goto fail;
                    }

                  metadata = entity_child (definition, "metadata");
                  if (metadata == NULL)
                    {
                      g_warning ("%s: metadata missing", __FUNCTION__);
                      free_entity (entity);
                      goto fail;
                    }

                  title = entity_child (metadata, "title");
                  if (title == NULL)
                    {
                      g_warning ("%s: title missing", __FUNCTION__);
                      free_entity (entity);
                      goto fail;
                    }

                  description = entity_child (metadata, "description");
                  if (description == NULL)
                    {
                      g_warning ("%s: description missing", __FUNCTION__);
                      free_entity (entity);
                      goto fail;
                    }

                  repository = entity_child (metadata, "oval_repository");
                  if (repository == NULL)
                    {
                      g_warning ("%s: oval_repository missing", __FUNCTION__);
                      free_entity (entity);
                      goto fail;
                    }

                  cve_count = 0;
                  references = metadata->entities;
                  while ((reference = first_entity (references)))
                    {
                      if ((strcmp (entity_name (reference), "reference") == 0)
                          && entity_attribute (reference, "source")
                          && (strcasecmp (
                                entity_attribute (reference, "source"), "cve")
                              == 0))
                        cve_count++;
                      references = next_entities (references);
                    }

                  deprecated = entity_attribute (definition, "deprecated");

                  id = g_strdup_printf (
                    "%s_%s", entity_attribute (definition, "id"), xml_basename);
                  quoted_id = sql_quote (id);
                  g_free (id);
                  quoted_oval_id =
                    sql_quote (entity_attribute (definition, "id"));

                  version = entity_attribute (definition, "version");
                  if (g_regex_match_simple ("^[0-9]+$", (gchar *) version, 0, 0)
                      == 0)
                    {
                      g_warning (
                        "%s: invalid version: %s", __FUNCTION__, version);
                      free_entity (entity);
                      goto fail;
                    }

                  quoted_class =
                    sql_quote (entity_attribute (definition, "class"));
                  quoted_title = sql_quote (entity_text (title));
                  quoted_description = sql_quote (entity_text (description));
                  status = entity_child (repository, "status");
                  if (status && strlen (entity_text (status)))
                    quoted_status = sql_quote (entity_text (status));
                  else if (deprecated && strcasecmp (deprecated, "TRUE"))
                    quoted_status = sql_quote ("DEPRECATED");
                  else
                    quoted_status = sql_quote ("");

                  sql ("SELECT merge_ovaldef ('%s', '%s', '', %i, %i, %i, %i,"
                       "                      '%s', '%s', '%s', '%s', '%s',"
                       "                      %i);",
                       quoted_id,
                       quoted_oval_id,
                       definition_date_oldest == 0 ? file_timestamp
                                                   : definition_date_newest,
                       definition_date_oldest == 0 ? file_timestamp
                                                   : definition_date_oldest,
                       version,
                       (deprecated && strcasecmp (deprecated, "TRUE")) ? 1 : 0,
                       quoted_class,
                       quoted_title,
                       quoted_description,
                       quoted_xml_basename,
                       quoted_status,
                       cve_count);
                  increment_transaction_size (&transaction_size);
                  g_free (quoted_id);
                  g_free (quoted_class);
                  g_free (quoted_title);
                  g_free (quoted_description);
                  g_free (quoted_status);

                  references = metadata->entities;
                  while ((reference = first_entity (references)))
                    {
                      if ((strcmp (entity_name (reference), "reference") == 0)
                          && entity_attribute (reference, "source")
                          && (strcasecmp (
                                entity_attribute (reference, "source"), "cve")
                              == 0)
                          && entity_attribute (reference, "ref_id"))
                        {
                          gchar *quoted_ref_id;

                          quoted_ref_id =
                            sql_quote (entity_attribute (reference, "ref_id"));
                          sql (
                            "INSERT INTO affected_ovaldefs (cve, ovaldef)"
                            " SELECT cves.id, ovaldefs.id"
                            " FROM cves, ovaldefs"
                            " WHERE cves.name='%s'"
                            " AND ovaldefs.name = '%s'"
                            " AND NOT EXISTS (SELECT * FROM affected_ovaldefs"
                            "                 WHERE cve = cves.id"
                            "                 AND ovaldef = ovaldefs.id);",
                            quoted_ref_id,
                            quoted_oval_id);
                          increment_transaction_size (&transaction_size);
                        }
                      references = next_entities (references);
                    }

                  g_free (quoted_oval_id);
                }
            }
          definitions = next_entities (definitions);
        }
      children = next_entities (children);
    }

  /* Cleanup. */

  g_free (quoted_xml_basename);
  free_entity (entity);
  // sql_commit ();
  return 1;

fail:
  g_free (quoted_xml_basename);
  g_warning ("Update of OVAL definitions failed at file '%s'", xml_path);
  // sql_commit ();
  return -1;
}

/**
 * @brief Extract generator timestamp from OVAL element.
 *
 * @param[in]  entity   OVAL element.
 *
 * @return Freshly allocated timestamp if found, else NULL.
 */
static gchar *
oval_generator_timestamp (entity_t entity)
{
  gchar *generator_name;
  entity_t generator;

  generator_name = g_strdup ("generator");
  generator = entity_child (entity, generator_name);
  g_free (generator_name);
  if (generator)
    {
      entity_t timestamp;
      timestamp = entity_child (generator, "oval:timestamp");
      if (timestamp)
        {
          gchar *ret;
          ret = g_strdup (entity_text (timestamp));
          return ret;
        }
    }

  return NULL;
}

/**
 * @brief Extract timestamp from OVAL XML.
 *
 * @param[in]  xml  OVAL XML.
 *
 * @return Freshly allocated timestamp, else NULL.
 */
static gchar *
oval_timestamp (const gchar *xml)
{
  entity_t entity;

  if (parse_entity (xml, &entity))
    {
      g_warning ("%s: Failed to parse entity: %s", __FUNCTION__, xml);
      return NULL;
    }

  if (strcmp (entity_name (entity), "oval_definitions") == 0)
    {
      gchar *timestamp;

      timestamp = oval_generator_timestamp (entity);
      if (timestamp)
        {
          free_entity (entity);
          return timestamp;
        }
    }

  if (strcmp (entity_name (entity), "oval_variables") == 0)
    {
      gchar *timestamp;

      timestamp = oval_generator_timestamp (entity);
      if (timestamp)
        {
          free_entity (entity);
          return timestamp;
        }
    }

  if (strcmp (entity_name (entity), "oval_system_characteristics") == 0)
    {
      gchar *timestamp;

      timestamp = oval_generator_timestamp (entity);
      if (timestamp)
        {
          free_entity (entity);
          return timestamp;
        }
    }

  g_warning ("%s: No timestamp: %s", __FUNCTION__, xml);
  return NULL;
}

/**
 * @brief Files for update_scap_ovaldefs.
 */
static array_t *oval_files = NULL;

/**
 * @brief Add an OVAL file to oval_files.
 *
 * @param[in]  path       Path of file.
 * @param[in]  stat       Status of file.
 * @param[in]  flag       Dummy arg for nftw.
 * @param[in]  traversal  Dummy arg for nftw.
 *
 * @return 0 success, -1 error.
 */
static int
oval_files_add (const char *path,
                const struct stat *stat,
                int flag,
                struct FTW *traversal)
{
  GError *error;
  gchar **pair, *oval_xml, *timestamp;
  gsize len;
  const char *dot;

  if (gvm_file_check_is_dir (path))
    return 0;

  dot = rindex (path, '.');
  if ((dot == NULL) || strcasecmp (dot, ".xml"))
    return 0;

  g_debug ("%s: path: %s", __FUNCTION__, path);

  error = NULL;
  g_file_get_contents (path, &oval_xml, &len, &error);
  if (error)
    {
      g_warning ("%s: Failed get contents of %s: %s",
                 __FUNCTION__,
                 path,
                 error->message);
      g_error_free (error);
      return -1;
    }

  /* Parse timestamp. */

  timestamp = oval_timestamp (oval_xml);
  g_free (oval_xml);

  /* Add file-timestamp pair to OVAL files. */

  pair = g_malloc (sizeof (gchar *) * 2);
  pair[0] = g_strdup (path);
  pair[1] = timestamp;

  array_add (oval_files, pair);

  return 0;
}

/**
 * @brief Compare OVAL files.
 *
 * @param[in]  one  First file.
 * @param[in]  two  Second file.
 *
 * @return 0 same, 1 one is greater than two, -1 two is greater than one.
 */
static gint
oval_files_compare (gconstpointer one, gconstpointer two)
{
  gchar **file_info_one, **file_info_two;

  file_info_one = *((gchar ***) one);
  file_info_two = *((gchar ***) two);

  if (file_info_one[1] == NULL)
    {
      if (file_info_two[1] == NULL)
        return 0;
      return -1;
    }

  if (file_info_two[1] == NULL)
    return 1;

  return strcmp (file_info_one[1], file_info_two[1]);
}

/**
 * @brief Free oval_files.
 */
static void
oval_files_free ()
{
  int index;

  index = 0;
  while (index < oval_files->len)
    {
      gchar **pair;

      pair = g_ptr_array_index (oval_files, index);
      g_free (pair[0]);
      g_free (pair[1]);
      index++;
    }
  array_free (oval_files);
  oval_files = NULL;
}

/**
 * @brief Update SCAP OVALDEFs.
 *
 * Assume that the databases are attached.
 *
 * @param[in]  last_scap_update  Time of last SCAP update from meta.
 * @param[in]  private           Whether to update private SCAP data, instead
 *                               of the feed data.
 *
 * @return 0 nothing to do, 1 updated, -1 error.
 */
static int
update_scap_ovaldefs (int last_scap_update, int private)
{
  int count, last_oval_update, updated_scap_ovaldefs;
  gchar *oval_dir;
  guint index;
  struct stat state;

  assert (oval_files == NULL);

  if (private)
    g_info ("Updating user OVAL definitions.");
  else
    g_info ("Updating OVAL data");

  /* Get a list of the OVAL files. */

  if (private)
    {
      const char *subdir;

      subdir = getenv ("PRIVATE_SUBDIR");
      if ((subdir == NULL) || (strlen (subdir) == 0))
        subdir = "private";

      oval_dir = g_build_filename (GVM_SCAP_DATA_DIR, subdir, "oval", NULL);
    }
  else
    oval_dir = g_build_filename (GVM_SCAP_DATA_DIR, "oval", NULL);

  g_debug ("%s: private: %i", __FUNCTION__, private);
  g_debug ("%s: oval_dir: %s", __FUNCTION__, oval_dir);

  /* Pairs of pointers, pair[0]: absolute pathname, pair[1]: oval timestamp. */
  oval_files = make_array ();

  if (g_lstat (oval_dir, &state))
    {
      if (errno == ENOENT)
        {
          if (private)
            g_debug ("%s: no private OVAL dir (%s)", __FUNCTION__, oval_dir);
          else
            g_warning ("%s: no OVAL dir (%s)", __FUNCTION__, oval_dir);
          g_free (oval_dir);
          oval_files_free ();
          return 0;
        }
      g_warning ("%s: failed to lstat '%s': %s",
                 __FUNCTION__,
                 oval_dir,
                 strerror (errno));
      g_free (oval_dir);
      oval_files_free ();
      return -1;
    }

  if (nftw (oval_dir, oval_files_add, 20, 0) == -1)
    {
      oval_files_free ();
      if (errno == ENOENT)
        {
          if (private)
            g_debug ("%s: nftw of private '%s': %s",
                     __FUNCTION__,
                     oval_dir,
                     strerror (errno));
          else
            g_warning (
              "%s: nftw of '%s': %s", __FUNCTION__, oval_dir, strerror (errno));
          g_free (oval_dir);
          oval_files_free ();
          return 0;
        }
      g_warning ("%s: failed to traverse '%s': %s",
                 __FUNCTION__,
                 oval_dir,
                 strerror (errno));
      g_free (oval_dir);
      oval_files_free ();
      return -1;
    }

  /* Sort the list by the OVAL timestamp. */

  g_ptr_array_sort (oval_files, oval_files_compare);

  if (private)
    {
      GError *error;
      GDir *directory;
      const gchar *entry;

      /* Check for files that aren't .xml or .asc. */

      error = NULL;
      directory = g_dir_open (oval_dir, 0, &error);

      if (directory == NULL)
        {
          assert (error);

          if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
            {
              g_warning ("No user data directory '%s' found.", oval_dir);
              g_free (oval_dir);
              g_error_free (error);
            }
          else
            {
              g_warning (
                "g_dir_open (%s) failed - %s", oval_dir, error->message);
              g_free (oval_dir);
              g_error_free (error);
              oval_files_free ();
              return -1;
            }
        }

      entry = NULL;
      while ((entry = g_dir_read_name (directory)) != NULL)
        {
          if (g_str_has_suffix (entry, ".xml") < 0)
            continue;
          if (g_str_has_suffix (entry, ".asc") < 0)
            continue;
          g_warning ("Found non-XML and non-signature file '%s'.", entry);
        }
      g_dir_close (directory);
    }

  /* Process each file in the list, in the sorted order. */

  last_oval_update = sql_int ("SELECT max (modification_time)"
                              " FROM scap.ovaldefs;");

  count = 0;
  updated_scap_ovaldefs = 0;
  for (index = 0; index < oval_files->len; index++)
    {
      gchar **pair;

      pair = g_ptr_array_index (oval_files, index);
      switch (
        update_ovaldef_xml (pair, last_scap_update, last_oval_update, private))
        {
        case 0:
          break;
        case 1:
          updated_scap_ovaldefs = 1;
          break;
        default:
          oval_files_free ();
          g_free (oval_dir);
          return -1;
        }
      count++;
    }

  if (count == 0)
    g_warning ("%s: No XML files found in %s", __FUNCTION__, oval_dir);

  if (private)
    {
      GString *oval_files_clause;
      int first;
      iterator_t files;

      /* Clean up user data. */

      g_info ("Cleaning up user OVAL data");

      g_debug ("%s: GVM_SCAP_DATA_DIR: %s", __FUNCTION__, GVM_SCAP_DATA_DIR);

      oval_files_clause = g_string_new (" AND (xml_file NOT IN (");
      first = 1;
      for (index = 0; index < oval_files->len; index++)
        {
          gchar **pair;
          char *suffix;

          pair = g_ptr_array_index (oval_files, index);
          g_debug ("%s: pair[0]: %s", __FUNCTION__, pair[0]);
          suffix = strstr (pair[0], GVM_SCAP_DATA_DIR);
          if (suffix == NULL)
            {
              g_warning ("%s: pair[0] missing GVM_SCAP_DATA_DIR: %s",
                         __FUNCTION__,
                         pair[0]);
              g_free (oval_dir);
              oval_files_free ();
              return -1;
            }
          suffix += strlen (GVM_SCAP_DATA_DIR);
          g_string_append_printf (
            oval_files_clause, "%s'%s'", first ? "" : ", ", suffix);
          first = 0;
        }
      g_string_append (oval_files_clause, "))");

      init_iterator (&files,
                     "SELECT DISTINCT xml_file FROM scap.ovaldefs"
                     " WHERE (xml_file NOT LIKE 'oval/%%')"
                     "%s",
                     oval_files_clause->str);
      first = 1;
      while (next (&files))
        {
          if (first)
            g_info ("Removing definitions formerly inserted from:");
          g_info ("%s", iterator_string (&files, 0));
          first = 0;
        }
      cleanup_iterator (&files);

      sql ("DELETE FROM scap.ovaldefs"
           " WHERE (xml_file NOT LIKE 'oval/%%')"
           "%s;",
           oval_files_clause->str);

      g_string_free (oval_files_clause, TRUE);
    }

  /* Cleanup. */

  g_free (oval_dir);
  oval_files_free ();
  return updated_scap_ovaldefs;
}

/* CERT and SCAP update. */

/**
 * @brief Write start time to sync lock file.
 *
 * @param[in]  lockfile  Lock file.
 */
static void
write_sync_start (int lockfile)
{
  time_t now;
  char *now_string;

  now = time (NULL);
  now_string = ctime (&now);
  while (*now_string)
    {
      ssize_t count;
      count = write (lockfile, now_string, strlen (now_string));
      if (count < 0)
        {
          if (errno == EAGAIN || errno == EINTR)
            /* Interrupted, try write again. */
            continue;
          g_warning ("%s: failed to write to lockfile: %s",
                     __FUNCTION__,
                     strerror (errno));
          break;
        }
      now_string += count;
    }
}

/**
 * @brief Reinit a db.
 *
 * @param[in]  name  Name of db.
 *
 * @return 0 success, -1 error.
 */
static int
manage_db_reinit (const gchar *name)
{
  manage_db_remove (name);
  if (manage_db_init (name))
    {
      g_warning ("Could not reinitialize %s database", name);
      return -1;
    }
  return 0;
}

/**
 * @brief Sync a SecInfo DB.
 *
 * @param[in]  sigmask_current    Sigmask to restore in child.
 * @param[in]  update             Function to do the sync.
 * @param[in]  process_title      Process title.
 * @param[in]  lockfile_basename  Basename for lockfile.
 */
static void
sync_secinfo (sigset_t *sigmask_current,
              int (*update) (int),
              const gchar *process_title,
              const gchar *lockfile_basename)
{
  int pid, lockfile;
  gchar *lockfile_name;

  /* Fork a child to sync the db, so that the parent can return to the main
   * loop. */

  pid = fork ();
  switch (pid)
    {
    case 0:
      /* Child.  Carry on to sync the db, reopen the database (required
       * after fork). */

      /* Restore the sigmask that was blanked for pselect in the parent. */
      pthread_sigmask (SIG_SETMASK, sigmask_current, NULL);

      /* Cleanup so that exit works. */

      cleanup_manage_process (FALSE);

      /* Open the lock file. */

      lockfile_name =
        g_build_filename (g_get_tmp_dir (), lockfile_basename, NULL);

      lockfile = open (lockfile_name,
                       O_RDWR | O_CREAT | O_APPEND,
                       /* "-rw-r--r--" */
                       S_IWUSR | S_IRUSR | S_IROTH | S_IRGRP);
      if (lockfile == -1)
        {
          g_warning ("%s: failed to open lock file '%s': %s",
                     __FUNCTION__,
                     lockfile_name,
                     strerror (errno));
          g_free (lockfile_name);
          exit (EXIT_FAILURE);
        }

      if (flock (lockfile, LOCK_EX | LOCK_NB)) /* Exclusive, Non blocking. */
        {
          if (errno == EWOULDBLOCK)
            g_debug ("%s: skipping, sync in progress", __FUNCTION__);
          else
            g_debug ("%s: flock: %s", __FUNCTION__, strerror (errno));
          g_free (lockfile_name);
          exit (EXIT_SUCCESS);
        }

      /* Init. */

      reinit_manage_process ();
      manage_session_init (current_credentials.uuid);

      break;

    case -1:
      /* Parent on error.  Reschedule and continue to next task. */
      g_warning ("%s: fork failed", __FUNCTION__);
      return;

    default:
      /* Parent.  Continue to next task. */
      return;
    }

  proctitle_set (process_title);

  if (update (lockfile) == 0)
    {
      check_alerts ();
    }

  /* Close the lock file. */

  if (close (lockfile))
    {
      g_free (lockfile_name);
      g_warning (
        "%s: failed to close lock file: %s", __FUNCTION__, strerror (errno));
      exit (EXIT_FAILURE);
    }

  g_free (lockfile_name);

  exit (EXIT_SUCCESS);
}

/**
 * @brief Get the feed timestamp.
 *
 * @param[in]  name  Feed type: SCAP or CERT.
 *
 * @return Timestamp from feed.  0 if missing.  -1 on error.
 */
static int
manage_feed_timestamp (const gchar *name)
{
  GError *error;
  gchar *timestamp;
  gsize len;
  time_t stamp;

  error = NULL;
  if (strcasecmp (name, "scap") == 0)
    g_file_get_contents (
      GVM_SCAP_DATA_DIR "/timestamp", &timestamp, &len, &error);
  else
    g_file_get_contents (
      GVM_CERT_DATA_DIR "/timestamp", &timestamp, &len, &error);
  if (error)
    {
      if (error->code == G_FILE_ERROR_NOENT)
        stamp = 0;
      else
        {
          g_warning (
            "%s: Failed to get timestamp: %s", __FUNCTION__, error->message);
          return -1;
        }
    }
  else
    {
      if (strlen (timestamp) < 8)
        {
          g_warning (
            "%s: Feed timestamp too short: %s", __FUNCTION__, timestamp);
          g_free (timestamp);
          return -1;
        }

      timestamp[8] = '\0';
      stamp = parse_feed_timestamp (timestamp);
      g_free (timestamp);
      if (stamp == 0)
        return -1;
    }

  return stamp;
}

/* CERT update. */

/**
 * @brief Ensure CERT db is at the right version, and in the right mode.
 *
 * @return 0 success, -1 error.
 */
int
check_cert_db_version ()
{
  switch (manage_cert_db_version ())
    {
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
      g_info ("Reinitialization of the database necessary");
      return manage_db_reinit ("cert");
      break;
    }
  return 0;
}

/**
 * @brief Update timestamp in CERT db from feed timestamp.
 *
 * @return 0 success, -1 error.
 */
static int
update_cert_timestamp ()
{
  GError *error;
  gchar *timestamp;
  gsize len;
  time_t stamp;

  error = NULL;
  g_file_get_contents (
    GVM_CERT_DATA_DIR "/timestamp", &timestamp, &len, &error);
  if (error)
    {
      if (error->code == G_FILE_ERROR_NOENT)
        stamp = 0;
      else
        {
          g_warning (
            "%s: Failed to get timestamp: %s", __FUNCTION__, error->message);
          return -1;
        }
    }
  else
    {
      if (strlen (timestamp) < 8)
        {
          g_warning (
            "%s: Feed timestamp too short: %s", __FUNCTION__, timestamp);
          g_free (timestamp);
          return -1;
        }

      timestamp[8] = '\0';
      g_debug ("%s: parsing: %s", __FUNCTION__, timestamp);
      stamp = parse_feed_timestamp (timestamp);
      g_free (timestamp);
      if (stamp == 0)
        return -1;
    }

  g_debug ("%s: setting last_update: %lld", __FUNCTION__, (long long) stamp);
  sql ("UPDATE cert.meta SET value = '%lld' WHERE name = 'last_update';",
       (long long) stamp);

  return 0;
}

/**
 * @brief Update DFN-CERT Max CVSS.
 *
 * @param[in]  updated_dfn_cert  Whether CERT-Bund updated.
 * @param[in]  last_cert_update  Time of last CERT update.
 * @param[in]  last_scap_update  Time of last SCAP update.
 */
static void
update_cvss_dfn_cert (int updated_dfn_cert,
                      int last_cert_update,
                      int last_scap_update)
{
  /* TODO greenbone-certdata-sync did retries. */

  if (updated_dfn_cert || (last_scap_update > last_cert_update))
    {
      g_info ("Updating Max CVSS for DFN-CERT");
      sql_recursive_triggers_off ();
      sql ("UPDATE cert.dfn_cert_advs"
           " SET max_cvss = (SELECT max (cvss)"
           "                 FROM scap.cves"
           "                 WHERE name"
           "                 IN (SELECT cve_name"
           "                     FROM cert.dfn_cert_cves"
           "                     WHERE adv_id = dfn_cert_advs.id)"
           "                 AND cvss != 0.0);");

      g_info ("Updating DFN-CERT CVSS max succeeded.");
    }
  else
    g_info ("Updating DFN-CERT CVSS max succeeded (nothing to do).");
}

/**
 * @brief Update CERT-Bund Max CVSS.
 *
 * @param[in]  updated_cert_bund  Whether CERT-Bund updated.
 * @param[in]  last_cert_update  Time of last CERT update.
 * @param[in]  last_scap_update  Time of last SCAP update.
 */
static void
update_cvss_cert_bund (int updated_cert_bund,
                       int last_cert_update,
                       int last_scap_update)
{
  /* TODO greenbone-certdata-sync did retries. */

  if (updated_cert_bund || (last_scap_update > last_cert_update))
    {
      g_info ("Updating Max CVSS for CERT-Bund");
      sql_recursive_triggers_off ();
      sql ("UPDATE cert.cert_bund_advs"
           " SET max_cvss = (SELECT max (cvss)"
           "                 FROM scap.cves"
           "                 WHERE name"
           "                       IN (SELECT cve_name"
           "                           FROM cert.cert_bund_cves"
           "                           WHERE adv_id = cert_bund_advs.id)"
           "                 AND cvss != 0.0);");

      g_info ("Updating CERT-Bund CVSS max succeeded.");
    }
  else
    g_info ("Updating CERT-Bund CVSS max succeeded (nothing to do).");
}

/**
 * @brief Sync the CERT DB.
 *
 * @param[in]  lockfile  Lock file.
 *
 * @return 0 success, -1 error.
 */
static int
sync_cert (int lockfile)
{
  int last_feed_update, last_cert_update, last_scap_update, updated_dfn_cert;
  int updated_cert_bund;

  if (manage_cert_db_exists ())
    {
      if (check_cert_db_version ())
        return -1;
    }
  else
    {
      g_info ("Initializing CERT database");
      if (manage_db_init ("cert"))
        {
          g_warning ("%s: Could not initialize CERT database", __FUNCTION__);
          return -1;
        }
    }

  last_cert_update = 0;
  if (manage_cert_loaded ())
    last_cert_update = sql_int ("SELECT coalesce ((SELECT value FROM cert.meta"
                                "                  WHERE name = 'last_update'),"
                                "                 '-1');");

  if (last_cert_update == -1)
    {
      g_warning ("%s: Inconsistent data. Resetting CERT database.",
                 __FUNCTION__);
      if (manage_db_reinit ("cert"))
        {
          g_warning ("%s: could not reinitialize CERT database", __FUNCTION__);
          return -1;
        }
      last_cert_update = 0;
    }

  last_feed_update = manage_feed_timestamp ("cert");
  if (last_feed_update == -1)
    return -1;

  if (last_cert_update >= last_feed_update)
    return -1;

  g_debug ("%s: sync", __FUNCTION__);

  write_sync_start (lockfile);

  manage_db_check_mode ("cert");

  if (manage_db_check ("cert"))
    {
      g_warning ("%s: Database broken, resetting CERT database", __FUNCTION__);
      if (manage_db_reinit ("cert"))
        {
          g_warning ("%s: could not reinitialize CERT database", __FUNCTION__);
          goto fail;
        }
    }

  if (manage_update_cert_db_init ())
    goto fail;

  g_info ("%s: Updating data from feed", __FUNCTION__);

  g_debug ("%s: update dfn", __FUNCTION__);

  updated_dfn_cert = update_dfn_cert_advisories (last_cert_update);
  if (updated_dfn_cert == -1)
    {
      manage_update_cert_db_cleanup ();
      goto fail;
    }

  g_debug ("%s: update bund", __FUNCTION__);

  updated_cert_bund = update_cert_bund_advisories (last_cert_update);
  if (updated_cert_bund == -1)
    {
      manage_update_cert_db_cleanup ();
      goto fail;
    }

  g_debug ("%s: update cvss", __FUNCTION__);

  last_scap_update = 0;
  if (manage_scap_loaded ())
    last_scap_update = sql_int ("SELECT coalesce ((SELECT value FROM scap.meta"
                                "                  WHERE name = 'last_update'),"
                                "                 '0');");
  g_debug ("%s: last_scap_update: %i", __FUNCTION__, last_scap_update);

  update_cvss_dfn_cert (updated_dfn_cert, last_cert_update, last_scap_update);
  update_cvss_cert_bund (updated_cert_bund, last_cert_update, last_scap_update);

  g_debug ("%s: update timestamp", __FUNCTION__);

  if (update_cert_timestamp ())
    {
      manage_update_cert_db_cleanup ();
      goto fail;
    }

  g_info ("%s: Updating CERT info succeeded.", __FUNCTION__);

  manage_update_cert_db_cleanup ();

  /* Clear date from lock file. */

  if (ftruncate (lockfile, 0))
    g_warning (
      "%s: failed to ftruncate lockfile: %s", __FUNCTION__, strerror (errno));

  return 0;

fail:
  /* Clear date from lock file. */

  if (ftruncate (lockfile, 0))
    g_warning (
      "%s: failed to ftruncate lockfile: %s", __FUNCTION__, strerror (errno));

  return -1;
}

/**
 * @brief Sync the CERT DB.
 *
 * @param[in]  sigmask_current  Sigmask to restore in child.
 */
void
manage_sync_cert (sigset_t *sigmask_current)
{
  sync_secinfo (
    sigmask_current, sync_cert, "mageni-sqlite: Updating CERT", "mageni-sync-cert");
}

/* SCAP update. */

/**
 * @brief Ensure SCAP db is at the right version, and in the right mode.
 *
 * @return 0 success, -1 error.
 */
int
check_scap_db_version ()
{
  switch (manage_scap_db_version ())
    {
    /* TODO The sync script had a whole lot of migrators in here. */
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
    case 13:
    case 14:
      g_info ("Reinitialization of the database necessary");
      return manage_db_reinit ("scap");
      break;
    }
  return 0;
}

/**
 * @brief Update timestamp in SCAP db from feed timestamp.
 *
 * @return 0 success, -1 error.
 */
static int
update_scap_timestamp ()
{
  GError *error;
  gchar *timestamp;
  gsize len;
  time_t stamp;

  error = NULL;
  g_file_get_contents (
    GVM_SCAP_DATA_DIR "/timestamp", &timestamp, &len, &error);
  if (error)
    {
      if (error->code == G_FILE_ERROR_NOENT)
        stamp = 0;
      else
        {
          g_warning (
            "%s: Failed to get timestamp: %s", __FUNCTION__, error->message);
          return -1;
        }
    }
  else
    {
      if (strlen (timestamp) < 8)
        {
          g_warning (
            "%s: Feed timestamp too short: %s", __FUNCTION__, timestamp);
          g_free (timestamp);
          return -1;
        }

      timestamp[8] = '\0';
      g_debug ("%s: parsing: %s", __FUNCTION__, timestamp);
      stamp = parse_feed_timestamp (timestamp);
      g_free (timestamp);
      if (stamp == 0)
        return -1;
    }

  g_debug ("%s: setting last_update: %lld", __FUNCTION__, (long long) stamp);
  sql ("UPDATE scap.meta SET value = '%lld' WHERE name = 'last_update';",
       (long long) stamp);

  return 0;
}

/**
 * @brief Update CERT-Bund Max CVSS.
 *
 * @param[in]  updated_cves      Whether CVEs were updated.
 * @param[in]  updated_cpes      Whether CPEs were updated.
 * @param[in]  updated_ovaldefs  Whether OVAL defs were updated.
 */
static void
update_scap_cvss (int updated_cves, int updated_cpes, int updated_ovaldefs)
{
  /* TODO greenbone-scapdata-sync did retries. */

  if (updated_cves || updated_cpes)
    {
      g_info ("Updating CVSS scores and CVE counts for CPEs");
      sql_recursive_triggers_off ();
      sql ("UPDATE scap.cpes"
           " SET max_cvss = (SELECT max (cvss)"
           "                 FROM scap.cves"
           "                 WHERE id IN (SELECT cve"
           "                              FROM scap.affected_products"
           "                              WHERE cpe=cpes.id)),"
           "     cve_refs = (SELECT count (cve)"
           "                 FROM scap.affected_products"
           "                 WHERE cpe=cpes.id);");
    }
  else
    g_info ("No CPEs or CVEs updated, skipping CVSS and CVE recount for CPEs.");

  if (updated_cves || updated_ovaldefs)
    {
      g_info ("Updating CVSS scores for OVAL definitions");
      sql_recursive_triggers_off ();
      sql ("UPDATE scap.ovaldefs"
           " SET max_cvss = (SELECT max (cvss)"
           "                 FROM scap.cves"
           "                 WHERE id IN (SELECT cve"
           "                              FROM scap.affected_ovaldefs"
           "                              WHERE ovaldef=ovaldefs.id)"
           "                 AND cvss != 0.0);");
    }
  else
    g_info ("No OVAL definitions or CVEs updated,"
            " skipping CVSS recount for OVAL definitions.");
}

/**
 * @brief Update SCAP placeholder CVES.
 *
 * @param[in]  updated_cves  Whether the CVEs were updated.
 */
static void
update_scap_placeholders (int updated_cves)
{
  /* TODO greenbone-scapdata-sync did retries. */

  if (updated_cves)
    {
      g_info ("Updating placeholder CPEs");
      sql ("UPDATE scap.cpes"
           " SET creation_time = (SELECT min (creation_time)"
           "                      FROM scap.cves"
           "                      WHERE id IN (SELECT cve"
           "                                   FROM scap.affected_products"
           "                                   WHERE cpe=cpes.id)),"
           "     modification_time = (SELECT min(creation_time)"
           "                          FROM scap.cves"
           "                          WHERE id IN (SELECT cve"
           "                                       FROM scap.affected_products"
           "                                       WHERE cpe=cpes.id))"
           " WHERE cpes.title IS NULL;");
    }
  else
    g_info ("No CVEs updated, skipping placeholder CPE update.");
}

/**
 * @brief Sync the SCAP DB.
 *
 * @param[in]  lockfile  Lock file.
 *
 * @return 0 success, -1 error.
 */
static int
sync_scap (int lockfile)
{
  int last_feed_update, last_scap_update;
  int updated_scap_ovaldefs, updated_scap_cpes, updated_scap_cves;

  if (manage_scap_db_exists ())
    {
      if (check_scap_db_version ())
        return -1;
    }
  else
    {
      g_info ("%s: Initializing SCAP database", __FUNCTION__);

      if (manage_db_init ("scap"))
        {
          g_warning ("%s: Could not initialize SCAP database", __FUNCTION__);
          return -1;
        }
    }

  last_scap_update = -1;
  if (manage_scap_loaded ())
    last_scap_update = sql_int ("SELECT coalesce ((SELECT value FROM scap.meta"
                                "                  WHERE name = 'last_update'),"
                                "                 '-1');");

  if (last_scap_update == -1)
    {
      g_warning ("%s: Inconsistent data, resetting SCAP database",
                 __FUNCTION__);
      if (manage_db_reinit ("scap"))
        {
          g_warning ("%s: could not reinitialize SCAP database", __FUNCTION__);
          return -1;
        }
      last_scap_update = 0;
    }

  last_feed_update = manage_feed_timestamp ("scap");
  if (last_feed_update == -1)
    return -1;

  if (last_scap_update >= last_feed_update)
    return -1;

  g_debug ("%s: sync", __FUNCTION__);

  write_sync_start (lockfile);

  manage_db_check_mode ("scap");

  if (manage_db_check ("scap"))
    {
      g_warning ("%s: Database broken, resetting SCAP database", __FUNCTION__);
      if (manage_db_reinit ("scap"))
        {
          g_warning ("%s: could not reinitialize SCAP database", __FUNCTION__);
          goto fail;
        }
    }

  if (manage_update_scap_db_init ())
    goto fail;

  g_info ("%s: Updating data from feed", __FUNCTION__);

  g_debug ("%s: update cpes", __FUNCTION__);

  updated_scap_cpes = update_scap_cpes (last_scap_update);
  if (updated_scap_cpes == -1)
    {
      manage_update_scap_db_cleanup ();
      goto fail;
    }

  g_debug ("%s: update cves", __FUNCTION__);

  updated_scap_cves = update_scap_cves (last_scap_update);
  if (updated_scap_cves == -1)
    {
      manage_update_scap_db_cleanup ();
      goto fail;
    }

  g_debug ("%s: update ovaldefs", __FUNCTION__);

  updated_scap_ovaldefs =
    update_scap_ovaldefs (last_scap_update, 0 /* Feed data. */);
  if (updated_scap_ovaldefs == -1)
    {
      manage_update_scap_db_cleanup ();
      goto fail;
    }

  g_debug ("%s: updating user defined data", __FUNCTION__);

  switch (update_scap_ovaldefs (last_scap_update, 1 /* Private data. */))
    {
    case 0:
      break;
    case -1:
      manage_update_scap_db_cleanup ();
      goto fail;
    default:
      updated_scap_ovaldefs = 1;
      break;
    }

  update_scap_cvss (
    updated_scap_cves, updated_scap_cpes, updated_scap_ovaldefs);
  update_scap_placeholders (updated_scap_cves);

  g_debug ("%s: update timestamp", __FUNCTION__);

  if (update_scap_timestamp ())
    {
      manage_update_scap_db_cleanup ();
      goto fail;
    }

  g_info ("%s: Updating SCAP info succeeded", __FUNCTION__);

  manage_update_scap_db_cleanup ();

  /* Clear date from lock file. */

  if (ftruncate (lockfile, 0))
    g_warning (
      "%s: failed to ftruncate lockfile: %s", __FUNCTION__, strerror (errno));

  return 0;

fail:
  /* Clear date from lock file. */

  if (ftruncate (lockfile, 0))
    g_warning (
      "%s: failed to ftruncate lockfile: %s", __FUNCTION__, strerror (errno));

  return -1;
}

/**
 * @brief Sync the SCAP DB.
 *
 * @param[in]  sigmask_current  Sigmask to restore in child.
 */
void
manage_sync_scap (sigset_t *sigmask_current)
{
  sync_secinfo (
    sigmask_current, sync_scap, "mageni-sqlite: Updating SCAP", "mageni-sync-scap");
}

/**
 * @brief Set the SecInfo update commit size.
 *
 * @param new_commit_size The new SecInfo update commit size.
 */
void
set_secinfo_commit_size (int new_commit_size)
{
  if (new_commit_size < 0)
    secinfo_commit_size = 0;
  else
    secinfo_commit_size = new_commit_size;
}
