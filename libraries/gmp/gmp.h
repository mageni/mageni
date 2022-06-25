/* Copyright (C) 2009-2019 Greenbone Networks GmbH
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
 * @file
 * @brief API for Greenbone Management Protocol communication.
 */

#ifndef _GVM_GMP_H
#define _GVM_GMP_H

#include "../base/array.h"       /* for array_t */
#include "../util/serverutils.h" /* for gvm_connection_t */
#include "../util/xmlutils.h"    /* for entity_t */

#include <glib.h>          /* for gchar */
#include <glib/gtypes.h>   /* for gsize */
#include <gnutls/gnutls.h> /* for gnutls_session_t */
#include <stddef.h>        /* for NULL */

/**
 * @brief Struct holding options for authentication.
 */
typedef struct
{
  int timeout;          ///< Timeout for authentication.
  const char *username; ///< Password.
  const char *password; ///< Username.
  char **role;          ///< [out] Role.
  char **severity;      ///< [out] Severity class setting.
  char **timezone;      ///< [out] Timezone if any, else NULL.
  char **pw_warning;    ///< [out] Password warning, NULL if password is okay.
} gmp_authenticate_info_opts_t;

/**
 * @brief Sensible default values for gmp_authenticate_info_opts_t
 */
static const gmp_authenticate_info_opts_t gmp_authenticate_info_opts_defaults =
  {0, NULL, NULL, NULL, NULL, NULL, NULL};

/**
 * @brief Struct holding options for gmp get_report command.
 */
typedef struct
{
  const char *sort_field;
  const char *sort_order;
  const char *format_id; ///< ID of required report format.
  const char *levels;    ///< Result levels to include.
  const char *report_id; ///< ID of single report to get.
  int first_result;      ///< First result to get.
  int max_results;       ///< Maximum number of results to return.
  int timeout;           ///< Timeout for GMP response.
  int host_first_result; ///< Skip over results before this result number.
  int host_max_results;  ///< Maximum number of results to return.
  int autofp; ///< Whether to trust vendor security updates. 0 No, 1 full match,
              ///< 2 partial.
  char *type; ///< Type of report.
  char *filter;          ///< Term to filter results.
  char *filt_id;         ///< ID of filter, to filter results.
  char *host;            ///< Host for asset report.
  char *pos;             ///< Position of report from end.
  char *timezone;        ///< Timezone.
  char *alert_id;        ///< ID of alert.
  char *delta_report_id; ///< ID of report to compare single report to.
  char *delta_states;    ///< Delta states (Changed Gone New Same) to include.
  char *host_levels;     ///< Letter encoded threat level filter, for hosts.
  char *search_phrase;   ///< Search phrase result filter.
  char *host_search_phrase; ///< Search phrase result filter.
  char *min_cvss_base;      ///< Minimum CVSS base filter.
  char *min_qod;            ///< Minimum QoD filter.
  /* Boolean flags: */
  int notes;             ///< Whether to include associated notes.
  int notes_details;     ///< Whether to include details of above.
  int overrides;         ///< Whether to include overrides in the report.
  int override_details;  ///< If overrides, whether to include details.
  int apply_overrides;   ///< Whether overrides are applied.
  int result_hosts_only; ///< Whether to include only hosts that have results.
  int ignore_pagination; ///< Whether to ignore pagination filters.
} gmp_get_report_opts_t;

/**
 * @brief Sensible default values for gmp_get_report_opts_t.
 */
static const gmp_get_report_opts_t gmp_get_report_opts_defaults = {
  "ROWID",
  "ascending",
  "a994b278-1f62-11e1-96ac-406186ea4fc5",
  "hmlgd",
  NULL,
  1,
  -1,
  0,
  0,
  0,
  0,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  0,
  0,
  0,
  0,
  0,
  0,
  0};

/**
 * @brief Struct holding options for gmp get_tasks command.
 */
typedef struct
{
  const char *filter;  ///< Filter argument.
  int timeout;         ///< Timeout for GMP response.
  const char *actions; ///< Actions argument.
  /* Boolean flags: */
  int details; ///< Whether to include overrides in the tasks.
  int rcfile;  ///< Ignored.  Removed since GMP 6.0.
} gmp_get_tasks_opts_t;

/**
 * @brief Sensible default values for gmp_get_tasks_opts_t.
 */
static const gmp_get_tasks_opts_t gmp_get_tasks_opts_defaults = {"", 0, NULL, 0,
                                                                 0};

/**
 * @brief Struct holding options for gmp get_tasks command.
 */
typedef struct
{
  const char *actions; ///< Actions argument.
  const char *task_id; ///< ID of single task to get.
  /* Boolean flags: */
  int details; ///< Whether to include overrides in the tasks.
  int rcfile;  ///< Ignored.  Removed since GMP 6.0.
} gmp_get_task_opts_t;

/**
 * @brief Sensible default values for gmp_get_tasks_opts_t.
 */
static const gmp_get_task_opts_t gmp_get_task_opts_defaults = {NULL, NULL, 0,
                                                               0};

/**
 * @brief Struct holding options for gmp create_task command.
 */
typedef struct
{
  array_t *alert_ids;         ///< Array of alert IDs.
  const char *config_id;      ///< ID of config.
  const char *scanner_id;     ///< ID of task scanner.
  const char *schedule_id;    ///< ID of task schedule.
  const char *slave_id;       ///< ID of task schedule.
  const char *target_id;      ///< ID of target.
  const char *name;           ///< Name of task.
  const char *comment;        ///< Comment on task.
  const char *hosts_ordering; ///< Order for scanning target hosts.
  const char *observers;      ///< Comma-separated string of observer users.
  array_t *observer_groups;   ///< IDs of observer groups.
  int schedule_periods;       ///< Number of periods the schedule must run for.
  /* Preferences */
  const char *in_assets;    ///< In assets preference.
  const char *max_hosts;    ///< Max hosts preference.
  const char *max_checks;   ///< Max checks preference.
  const char *source_iface; ///< Source iface preference.
  /* Boolean flags: */
  int alterable; ///< Whether the task is alterable.
} gmp_create_task_opts_t;

/**
 * @brief Sensible default values for gmp_get_report_opts_t.
 */
static const gmp_create_task_opts_t gmp_create_task_opts_defaults = {
  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
  NULL, NULL, 0,    NULL, NULL, NULL, NULL, 0};

/**
 * @brief Struct holding options for gmp create_target command.
 */
typedef struct
{
  int ssh_credential_port;        ///< Port for SSH access.
  const char *ssh_credential_id;  ///< ID of SSH credential.
  const char *smb_credential_id;  ///< ID of SMB credential.
  const char *esxi_credential_id; ///< ID of ESXi credential.
  const char *snmp_credential_id; ///< ID of SNMP credential.
  const char *port_range;         ///< Port range.
  const char *name;               ///< Name of target.
  const char *comment;            ///< Comment on target.
  const char *hosts;              ///< Name of target.
  const char *exclude_hosts;      ///< Hosts to exclude.
  const char *alive_tests;        ///< Alive tests.
  /* Boolean flags: */
  int reverse_lookup_only;  ///< Scanner pref reverse_lookup_only.
  int reverse_lookup_unify; ///< Scanner pref reverse_lookup_unify.
} gmp_create_target_opts_t;

/**
 * @brief Sensible default values for gmp_get_report_opts_t.
 */
static const gmp_create_target_opts_t gmp_create_target_opts_defaults = {
  0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, 0};

/**
 * @brief Struct holding options for gmp get_system_reports command.
 */
typedef struct
{
  const char *name;       ///< Name of report.
  const char *duration;   ///< Duration.
  const char *start_time; ///< Time of first data point.
  const char *end_time;   ///< Time of last data point.
  const char *slave_id;   ///< ID of the slave to get report from.
  int brief;              ///< Brief flag.
} gmp_get_system_reports_opts_t;

/**
 * @brief Sensible default values for gmp_get_report_opts_t.
 */
static const gmp_get_system_reports_opts_t
  gmp_get_system_reports_opts_defaults = {NULL, NULL, NULL, NULL, NULL, 0};

/**
 * @brief Struct holding options for gmp create_lsc_credential command.
 */
typedef struct
{
  const char *name;              ///< Name of LSC credential.
  const char *community;         ///< SNMP community.
  const char *login;             ///< Login.
  const char *passphrase;        ///< Passphrase.
  const char *private_key;       ///< Private key.
  const char *auth_algorithm;    ///< SNMP authentication algorithm.
  const char *privacy_password;  ///< SNMP privacy password.
  const char *privacy_algorithm; ///< SNMP privacy algorithm.
  const char *comment;           ///< Comment on LSC credential.
} gmp_create_lsc_credential_opts_t;

/**
 * @brief Sensible default values for gmp_create_lsc_credential_opts_t.
 */
static const gmp_create_lsc_credential_opts_t
  gmp_create_lsc_credential_opts_defaults = {NULL, NULL, NULL, NULL, NULL,
                                             NULL, NULL, NULL, NULL};

/**
 * @brief Struct holding options for various gmp delete_[...] commands.
 */
typedef struct
{
  int ultimate; /// Whether to delete ultimately.
} gmp_delete_opts_t;

/**
 * @brief Sensible default values for gmp_get_report_opts_t.
 */
static const gmp_delete_opts_t gmp_delete_opts_defaults = {0};

/**
 * @brief Default values for gmp_get_report_opts_t for ultimate deletion.
 */
static const gmp_delete_opts_t gmp_delete_opts_ultimate_defaults = {1};

int
gmp_read_create_response (gnutls_session_t *, gchar **);

const char *
gmp_task_status (entity_t status_response);

int
gmp_ping (gnutls_session_t *, int);

int
gmp_ping_c (gvm_connection_t *, int, gchar **);

int
gmp_authenticate (gnutls_session_t *session, const char *username,
                  const char *password);

int
gmp_authenticate_info_ext (gnutls_session_t *, gmp_authenticate_info_opts_t);

int
gmp_authenticate_info_ext_c (gvm_connection_t *, gmp_authenticate_info_opts_t);

int
gmp_create_task (gnutls_session_t *, const char *, const char *, const char *,
                 const char *, gchar **);

int
gmp_create_task_ext (gnutls_session_t *, gmp_create_task_opts_t, gchar **);

int
gmp_start_task_report (gnutls_session_t *, const char *, char **);

int
gmp_start_task_report_c (gvm_connection_t *, const char *, char **);

int
gmp_stop_task (gnutls_session_t *, const char *);

int
gmp_stop_task_c (gvm_connection_t *, const char *);

int
gmp_resume_task_report (gnutls_session_t *, const char *, char **);

int
gmp_resume_task_report_c (gvm_connection_t *, const char *, char **);

int
gmp_get_tasks (gnutls_session_t *, const char *, int, int, entity_t *);

int
gmp_get_tasks_ext (gnutls_session_t *, gmp_get_tasks_opts_t, entity_t *);

int
gmp_get_task_ext (gnutls_session_t *, gmp_get_task_opts_t, entity_t *);

int
gmp_get_targets (gnutls_session_t *, const char *, int, int, entity_t *);

int
gmp_get_report_ext (gnutls_session_t *, gmp_get_report_opts_t, entity_t *);

int
gmp_delete_port_list_ext (gnutls_session_t *, const char *, gmp_delete_opts_t);

int
gmp_delete_task (gnutls_session_t *, const char *);

int
gmp_delete_task_ext (gnutls_session_t *, const char *, gmp_delete_opts_t);

int
gmp_modify_task_file (gnutls_session_t *, const char *, const char *,
                      const void *, gsize);

int
gmp_delete_report (gnutls_session_t *, const char *);

int
gmp_create_target_ext (gnutls_session_t *, gmp_create_target_opts_t, gchar **);

int
gmp_delete_target_ext (gnutls_session_t *, const char *, gmp_delete_opts_t);

int
gmp_delete_config_ext (gnutls_session_t *, const char *, gmp_delete_opts_t);

int
gmp_create_lsc_credential_ext (gnutls_session_t *,
                               gmp_create_lsc_credential_opts_t, gchar **);

int
gmp_create_lsc_credential (gnutls_session_t *, const char *, const char *,
                           const char *, const char *, gchar **);

int
gmp_create_lsc_credential_key (gnutls_session_t *, const char *, const char *,
                               const char *, const char *, const char *,
                               gchar **);

int
gmp_delete_lsc_credential_ext (gnutls_session_t *, const char *,
                               gmp_delete_opts_t);

int
gmp_get_system_reports (gnutls_session_t *, const char *, int, entity_t *);

int
gmp_get_system_reports_ext (gnutls_session_t *, gmp_get_system_reports_opts_t,
                            entity_t *);

#endif /* not _GVM_GMP_H */
