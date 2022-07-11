/* Copyright (C) 2010-2018 Greenbone Networks GmbH
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

/*
 * @file manage_sql_secinfo.h
 * @brief Manager Manage library: SQL backend headers.
 */

#include <signal.h>

#ifndef _GVMD_MANAGE_SQL_SECINFO_H
#define _GVMD_MANAGE_SQL_SECINFO_H

/**
 * @brief SQL to check if a result has CERT Bunds.
 */
#define SECINFO_SQL_RESULT_HAS_CERT_BUNDS              \
  "(SELECT EXISTS (SELECT * FROM cert_bund_cves"       \
  "                WHERE cve_name IN (SELECT cve_name" \
  "                                   FROM nvt_cves"   \
  "                                   WHERE oid = results.nvt)))"

/**
 * @brief SQL to check if a result has CERT Bunds.
 */
#define SECINFO_SQL_RESULT_HAS_DFN_CERTS               \
  "(SELECT EXISTS (SELECT * FROM dfn_cert_cves"        \
  "                WHERE cve_name IN (SELECT cve_name" \
  "                                   FROM nvt_cves"   \
  "                                   WHERE oid = results.nvt)))"

/**
 * @brief Filter columns for CVE iterator.
 */
#define CVE_INFO_ITERATOR_FILTER_COLUMNS                                   \
  {                                                                        \
    GET_ITERATOR_FILTER_COLUMNS, "vector", "complexity", "authentication", \
      "confidentiality_impact", "integrity_impact", "availability_impact", \
      "products", "cvss", "description", "severity", "published", NULL     \
  }

/**
 * @brief CVE iterator columns.
 */
#define CVE_INFO_ITERATOR_COLUMNS                                            \
  {                                                                          \
    GET_ITERATOR_COLUMNS_PREFIX (""), {"''", "_owner", KEYWORD_TYPE_STRING}, \
      {"0", NULL, KEYWORD_TYPE_INTEGER},                                     \
      {"vector", NULL, KEYWORD_TYPE_STRING},                                 \
      {"complexity", NULL, KEYWORD_TYPE_STRING},                             \
      {"authentication", NULL, KEYWORD_TYPE_STRING},                         \
      {"confidentiality_impact", NULL, KEYWORD_TYPE_STRING},                 \
      {"integrity_impact", NULL, KEYWORD_TYPE_STRING},                       \
      {"availability_impact", NULL, KEYWORD_TYPE_STRING},                    \
      {"products", NULL, KEYWORD_TYPE_STRING},                               \
      {"cvss", NULL, KEYWORD_TYPE_DOUBLE},                                   \
      {"description", NULL, KEYWORD_TYPE_STRING},                            \
      {"cvss", "severity", KEYWORD_TYPE_DOUBLE},                             \
      {"creation_time", "published", KEYWORD_TYPE_INTEGER},                  \
    {                                                                        \
      NULL, NULL, KEYWORD_TYPE_UNKNOWN                                       \
    }                                                                        \
  }

/**
 * @brief Filter columns for CVE iterator.
 */
#define CPE_INFO_ITERATOR_FILTER_COLUMNS                                \
  {                                                                     \
    GET_ITERATOR_FILTER_COLUMNS, "title", "status", "deprecated_by_id", \
      "max_cvss", "cves", "nvd_id", "severity", NULL                    \
  }

/**
 * @brief CPE iterator columns.
 */
#define CPE_INFO_ITERATOR_COLUMNS                                              \
  {                                                                            \
    GET_ITERATOR_COLUMNS_PREFIX (""), {"''", "_owner", KEYWORD_TYPE_STRING},   \
      {"0", NULL, KEYWORD_TYPE_INTEGER}, {"title", NULL, KEYWORD_TYPE_STRING}, \
      {"status", NULL, KEYWORD_TYPE_STRING},                                   \
      {"deprecated_by_id", NULL, KEYWORD_TYPE_INTEGER},                        \
      {"max_cvss", NULL, KEYWORD_TYPE_DOUBLE},                                 \
      {"cve_refs", "cves", KEYWORD_TYPE_INTEGER},                              \
      {"nvd_id", NULL, KEYWORD_TYPE_INTEGER},                                  \
      {"max_cvss", "severity", KEYWORD_TYPE_DOUBLE},                           \
    {                                                                          \
      NULL, NULL, KEYWORD_TYPE_UNKNOWN                                         \
    }                                                                          \
  }

/**
 * @brief Filter columns for OVALDEF iterator.
 */
#define OVALDEF_INFO_ITERATOR_FILTER_COLUMNS                                \
  {                                                                         \
    GET_ITERATOR_FILTER_COLUMNS, "version", "deprecated", "class", "title", \
      "description", "file", "status", "max_cvss", "cves", "severity", NULL \
  }

/**
 * @brief OVALDEF iterator columns.
 */
#define OVALDEF_INFO_ITERATOR_COLUMNS                                        \
  {                                                                          \
    GET_ITERATOR_COLUMNS_PREFIX (""), {"''", "_owner", KEYWORD_TYPE_STRING}, \
      {"0", NULL, KEYWORD_TYPE_INTEGER},                                     \
      {"version", NULL, KEYWORD_TYPE_INTEGER},                               \
      {"deprecated", NULL, KEYWORD_TYPE_INTEGER},                            \
      {"def_class", "class", KEYWORD_TYPE_STRING},                           \
      {"title", NULL, KEYWORD_TYPE_STRING},                                  \
      {"description", NULL, KEYWORD_TYPE_STRING},                            \
      {"xml_file", "file", KEYWORD_TYPE_STRING},                             \
      {"status", NULL, KEYWORD_TYPE_STRING},                                 \
      {"max_cvss", NULL, KEYWORD_TYPE_DOUBLE},                               \
      {"cve_refs", "cves", KEYWORD_TYPE_INTEGER},                            \
      {"max_cvss", "severity", KEYWORD_TYPE_DOUBLE},                         \
    {                                                                        \
      NULL, NULL, KEYWORD_TYPE_UNKNOWN                                       \
    }                                                                        \
  }

/**
 * @brief Filter columns for CERT_BUND_ADV iterator.
 */
#define CERT_BUND_ADV_INFO_ITERATOR_FILTER_COLUMNS                       \
  {                                                                      \
    GET_ITERATOR_FILTER_COLUMNS, "title", "summary", "cves", "max_cvss", \
      "severity", NULL                                                   \
  }

/**
 * @brief CERT_BUND_ADV iterator columns.
 */
#define CERT_BUND_ADV_INFO_ITERATOR_COLUMNS                                    \
  {                                                                            \
    GET_ITERATOR_COLUMNS_PREFIX (""), {"''", "_owner", KEYWORD_TYPE_STRING},   \
      {"0", NULL, KEYWORD_TYPE_INTEGER}, {"title", NULL, KEYWORD_TYPE_STRING}, \
      {"summary", NULL, KEYWORD_TYPE_STRING},                                  \
      {"cve_refs", "cves", KEYWORD_TYPE_INTEGER},                              \
      {"max_cvss", NULL, KEYWORD_TYPE_DOUBLE},                                 \
      {"max_cvss", "severity", KEYWORD_TYPE_DOUBLE},                           \
    {                                                                          \
      NULL, NULL, KEYWORD_TYPE_UNKNOWN                                         \
    }                                                                          \
  }

/**
 * @brief Filter columns for DFN_CERT_ADV iterator.
 */
#define DFN_CERT_ADV_INFO_ITERATOR_FILTER_COLUMNS                        \
  {                                                                      \
    GET_ITERATOR_FILTER_COLUMNS, "title", "summary", "cves", "max_cvss", \
      "severity", NULL                                                   \
  }

/**
 * @brief DFN_CERT_ADV iterator columns.
 */
#define DFN_CERT_ADV_INFO_ITERATOR_COLUMNS                                     \
  {                                                                            \
    GET_ITERATOR_COLUMNS_PREFIX (""), {"''", "_owner", KEYWORD_TYPE_STRING},   \
      {"0", NULL, KEYWORD_TYPE_INTEGER}, {"title", NULL, KEYWORD_TYPE_STRING}, \
      {"summary", NULL, KEYWORD_TYPE_STRING},                                  \
      {"cve_refs", "cves", KEYWORD_TYPE_INTEGER},                              \
      {"max_cvss", NULL, KEYWORD_TYPE_DOUBLE},                                 \
      {"max_cvss", "severity", KEYWORD_TYPE_DOUBLE},                           \
    {                                                                          \
      NULL, NULL, KEYWORD_TYPE_UNKNOWN                                         \
    }                                                                          \
  }

/**
 * @brief Filter columns for All SecInfo iterator.
 */
#define ALL_INFO_ITERATOR_FILTER_COLUMNS                           \
  {                                                                \
    GET_ITERATOR_FILTER_COLUMNS, "type", "extra", "severity", NULL \
  }

/**
 * @brief All SecInfo iterator columns.
 */
#define ALL_INFO_ITERATOR_COLUMNS                                             \
  {                                                                           \
    {"id", NULL, KEYWORD_TYPE_INTEGER}, {"uuid", NULL, KEYWORD_TYPE_STRING},  \
      {"name", NULL, KEYWORD_TYPE_STRING},                                    \
      {"comment", NULL, KEYWORD_TYPE_STRING},                                 \
      {"iso_time (created)", NULL, KEYWORD_TYPE_STRING},                      \
      {"iso_time (modified)", NULL, KEYWORD_TYPE_STRING},                     \
      {"created", NULL, KEYWORD_TYPE_INTEGER},                                \
      {"modified", NULL, KEYWORD_TYPE_INTEGER},                               \
      {"''", "_owner", KEYWORD_TYPE_STRING},                                  \
      {"0", NULL, KEYWORD_TYPE_INTEGER}, {"type", NULL, KEYWORD_TYPE_STRING}, \
      {"extra", NULL, KEYWORD_TYPE_STRING},                                   \
      {"severity", NULL, KEYWORD_TYPE_DOUBLE},                                \
    {                                                                         \
      NULL, NULL, KEYWORD_TYPE_UNKNOWN                                        \
    }                                                                         \
  }

/**
 * @brief All SecInfo iterator columns.
 */
#define ALL_INFO_ITERATOR_COLUMNS_ARGS(type, extra, severity)                 \
  {                                                                           \
    {"id", NULL, KEYWORD_TYPE_INTEGER}, {"uuid", NULL, KEYWORD_TYPE_STRING},  \
      {"name", NULL, KEYWORD_TYPE_STRING},                                    \
      {"comment", NULL, KEYWORD_TYPE_STRING},                                 \
      {"iso_time (created)", NULL, KEYWORD_TYPE_STRING},                      \
      {"iso_time (modified)", NULL, KEYWORD_TYPE_STRING},                     \
      {"created", NULL, KEYWORD_TYPE_INTEGER},                                \
      {"modified", NULL, KEYWORD_TYPE_INTEGER},                               \
      {"''", "_owner", KEYWORD_TYPE_STRING},                                  \
      {"0", NULL, KEYWORD_TYPE_INTEGER}, {type, "type", KEYWORD_TYPE_STRING}, \
      {extra, "extra", KEYWORD_TYPE_STRING},                                  \
      {severity, "severity", KEYWORD_TYPE_DOUBLE},                            \
    {                                                                         \
      NULL, NULL, KEYWORD_TYPE_UNKNOWN                                        \
    }                                                                         \
  }

/**
 * @brief All SecInfo iterator column union.
 */
#define ALL_INFO_UNION_COLUMNS                                                \
  "(SELECT " GET_ITERATOR_COLUMNS_STRING ", '' AS _owner, 'cve' AS type,"     \
  "        description AS extra, cvss AS severity"                            \
  " FROM cves"                                                                \
  " UNION ALL SELECT " GET_ITERATOR_COLUMNS_STRING ", '' AS _owner,"          \
  "                  'cpe' AS type, title AS extra, max_cvss AS severity"     \
  "           FROM cpes"                                                      \
  " UNION ALL SELECT " GET_ITERATOR_COLUMNS_STRING ", '' AS _owner,"          \
  "                  'nvt' AS type, tag AS extra,"                            \
  "                  CAST (cvss_base AS float) AS severity"                   \
  "           FROM nvts"                                                      \
  " UNION ALL SELECT " GET_ITERATOR_COLUMNS_STRING ", '' AS _owner,"          \
  "                  'cert_bund_adv' AS type, title AS extra,"                \
  "                  max_cvss AS severity"                                    \
  "           FROM cert_bund_advs"                                            \
  " UNION ALL SELECT " GET_ITERATOR_COLUMNS_STRING ", '' AS _owner,"          \
  "                  'dfn_cert_adv' AS type, title AS extra,"                 \
  "                  max_cvss AS severity"                                    \
  "           FROM dfn_cert_advs"                                             \
  " UNION ALL SELECT " GET_ITERATOR_COLUMNS_STRING ", '' AS _owner,"          \
  "                  'ovaldef' AS type, title AS extra, max_cvss AS severity" \
  "           FROM ovaldefs)"                                                 \
  " AS allinfo"

/**
 * @brief All SecInfo iterator column union, with specifiers for LIMIT clause.
 */
#define ALL_INFO_UNION_COLUMNS_LIMIT                                         \
  "(SELECT * FROM (SELECT " GET_ITERATOR_COLUMNS_STRING ","                  \
  "                       CAST ('' AS text) AS _owner,"                      \
  "                       CAST ('cve' AS text) AS type,"                     \
  "                       description as extra, cvss as severity"            \
  "                FROM cves"                                                \
  "                %s%s"                                                     \
  "                %s"                                                       \
  "                %s)"                                                      \
  "               AS union_sub_1"                                            \
  " UNION ALL"                                                               \
  " SELECT * FROM (SELECT " GET_ITERATOR_COLUMNS_STRING ","                  \
  "                       CAST ('' AS text) AS _owner,"                      \
  "                       CAST ('cpe' AS text) AS type, title as extra,"     \
  "                       max_cvss as severity"                              \
  "                FROM cpes"                                                \
  "                %s%s"                                                     \
  "                %s"                                                       \
  "                %s)"                                                      \
  "               AS union_sub_2"                                            \
  " UNION ALL"                                                               \
  " SELECT * FROM (SELECT " GET_ITERATOR_COLUMNS_STRING ","                  \
  "                       CAST ('' AS text) AS _owner,"                      \
  "                       CAST ('nvt' AS text) AS type,"                     \
  "                       tag AS extra,"                                     \
  "                       CAST (cvss_base AS float) as severity"             \
  "                FROM nvts"                                                \
  "                %s%s"                                                     \
  "                %s"                                                       \
  "                %s)"                                                      \
  "               AS union_sub_3"                                            \
  " UNION ALL"                                                               \
  " SELECT * FROM (SELECT " GET_ITERATOR_COLUMNS_STRING ","                  \
  "                       CAST ('' AS text) AS _owner,"                      \
  "                       CAST ('cert_bund_adv' AS text) AS type,"           \
  "                       title as extra,"                                   \
  "                       max_cvss as severity"                              \
  "                FROM cert_bund_advs"                                      \
  "                %s%s"                                                     \
  "                %s"                                                       \
  "                %s)"                                                      \
  "               AS union_sub_4"                                            \
  " UNION ALL"                                                               \
  " SELECT * FROM (SELECT " GET_ITERATOR_COLUMNS_STRING ","                  \
  "                       CAST ('' AS text) AS _owner,"                      \
  "                       CAST ('dfn_cert_adv' AS text) AS type,"            \
  "                       title as extra,"                                   \
  "                       max_cvss as severity"                              \
  "                FROM dfn_cert_advs"                                       \
  "                %s%s"                                                     \
  "                %s"                                                       \
  "                %s)"                                                      \
  "               AS union_sub_5"                                            \
  " UNION ALL"                                                               \
  " SELECT * FROM (SELECT " GET_ITERATOR_COLUMNS_STRING ","                  \
  "                       CAST ('' AS text) AS _owner,"                      \
  "                       CAST ('ovaldef' AS text) AS type, title as extra," \
  "                       max_cvss as severity"                              \
  "                FROM ovaldefs"                                            \
  "                %s%s"                                                     \
  "                %s"                                                       \
  "                %s)"                                                      \
  "               AS union_sub_6)"                                           \
  " AS allinfo"

/**
 * @brief Default for secinfo_commit_size.
 */
#define SECINFO_COMMIT_SIZE_DEFAULT 0

void
manage_sync_scap (sigset_t *);

void
manage_sync_cert (sigset_t *);

int
check_scap_db_version ();

int
check_cert_db_version ();

int
get_secinfo_commit_size ();

void
set_secinfo_commit_size (int);

#endif /* not _GVMD_MANAGE_SQL_SECINFO_H */
