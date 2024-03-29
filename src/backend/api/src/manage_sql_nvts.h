/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2010-2018 Greenbone Networks GmbH
 * SPDX-FileComment: SQL backend headers.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef _GVMD_MANAGE_SQL_NVTS_H
#define _GVMD_MANAGE_SQL_NVTS_H

/**
 * @brief Filter columns for NVT info iterator.
 */
#define NVT_INFO_ITERATOR_FILTER_COLUMNS                                    \
  {                                                                         \
    GET_ITERATOR_FILTER_COLUMNS, "version", "cve", "bid", "xref", "family", \
      "cvss_base", "severity", "cvss", "script_tags", "qod", "qod_type",    \
      "solution_type", NULL                                                 \
  }

/**
 * @brief NVT iterator columns.
 */
#define NVT_ITERATOR_COLUMNS                                                   \
  {                                                                            \
    GET_ITERATOR_COLUMNS_PREFIX (""), {"''", "_owner", KEYWORD_TYPE_STRING},   \
      {"0", NULL, KEYWORD_TYPE_INTEGER}, {"oid", NULL, KEYWORD_TYPE_STRING},   \
      {"modification_time", "version", KEYWORD_TYPE_INTEGER},                  \
      {"name", NULL, KEYWORD_TYPE_STRING}, {"cve", NULL, KEYWORD_TYPE_STRING}, \
      {"bid", NULL, KEYWORD_TYPE_STRING}, {"xref", NULL, KEYWORD_TYPE_STRING}, \
      {"tag", NULL, KEYWORD_TYPE_STRING},                                      \
      {"category", NULL, KEYWORD_TYPE_STRING},                                 \
      {"family", NULL, KEYWORD_TYPE_STRING},                                   \
      {"cvss_base", NULL, KEYWORD_TYPE_DOUBLE},                                \
      {"cvss_base", "severity", KEYWORD_TYPE_DOUBLE},                          \
      {"cvss_base", "cvss", KEYWORD_TYPE_DOUBLE},                              \
      {"qod", NULL, KEYWORD_TYPE_INTEGER},                                     \
      {"qod_type", NULL, KEYWORD_TYPE_STRING},                                 \
      {"solution_type", NULL, KEYWORD_TYPE_STRING},                            \
      {"tag", "script_tags", KEYWORD_TYPE_STRING},                             \
    {                                                                          \
      NULL, NULL, KEYWORD_TYPE_UNKNOWN                                         \
    }                                                                          \
  }

/**
 * @brief NVT iterator columns.
 */
#define NVT_ITERATOR_COLUMNS_NVTS                                              \
  {                                                                            \
    GET_ITERATOR_COLUMNS_PREFIX ("nvts."),                                     \
      {"''", "_owner", KEYWORD_TYPE_STRING}, {"0", NULL, KEYWORD_TYPE_STRING}, \
      {"oid", NULL, KEYWORD_TYPE_STRING},                                      \
      {"modification_time", "version", KEYWORD_TYPE_INTEGER},                  \
      {"nvts.name", NULL, KEYWORD_TYPE_STRING},                                \
      {"cve", NULL, KEYWORD_TYPE_STRING}, {"bid", NULL, KEYWORD_TYPE_STRING},  \
      {"xref", NULL, KEYWORD_TYPE_STRING}, {"tag", NULL, KEYWORD_TYPE_STRING}, \
      {"category", NULL, KEYWORD_TYPE_STRING},                                 \
      {"nvts.family", NULL, KEYWORD_TYPE_STRING},                              \
      {"cvss_base", NULL, KEYWORD_TYPE_DOUBLE},                                \
      {"cvss_base", "severity", KEYWORD_TYPE_DOUBLE},                          \
      {"cvss_base", "cvss", KEYWORD_TYPE_DOUBLE},                              \
      {"qod", NULL, KEYWORD_TYPE_INTEGER},                                     \
      {"qod_type", NULL, KEYWORD_TYPE_STRING},                                 \
      {"solution_type", NULL, KEYWORD_TYPE_STRING},                            \
      {"tag", "script_tags", KEYWORD_TYPE_STRING},                             \
    {                                                                          \
      NULL, NULL, KEYWORD_TYPE_UNKNOWN                                         \
    }                                                                          \
  }

void
check_db_nvts ();

int
check_config_families ();

void
manage_sync_nvts (int (*) ());

#endif /* not _GVMD_MANAGE_SQL_NVTS_H */
