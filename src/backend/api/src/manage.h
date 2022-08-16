/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2009-2018 Greenbone Networks GmbH
 * SPDX-FileComment: This file defines a management library for implementing managers
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef _GVMD_MANAGE_H
#define _GVMD_MANAGE_H

#include "iterator.h"

#include <glib.h>
#include <gnutls/gnutls.h>
#include "../../libraries/base/array.h"       /* for array_t */
#include "../../libraries/base/credentials.h" /* for credentials_t */
#include "../../libraries/base/networking.h"  /* for port_protocol_t */
#include "../../libraries/base/nvti.h"        /* for nvti_t */
#include "../../libraries/osp/osp.h"          /* for osp_connection_t */
#include "../../libraries/util/authutils.h"   /* for auth_method_t */
#include "../../libraries/util/serverutils.h" /* for gvm_connection_t */
#include <stdio.h>

/**
 * @brief Flag with all Glib log levels.
 */
#define ALL_LOG_LEVELS \
  (G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION)

/**
 * @brief Defines g_info for glib versions older than 2.40.
 */
#ifndef g_info
#define g_info(...) g_log (G_LOG_DOMAIN, G_LOG_LEVEL_INFO, __VA_ARGS__)
#endif /* g_info not defined */

/**
 * @brief Name value pair.
 */
typedef struct
{
  gchar *name;  ///< Name.
  gchar *value; ///< Param value.
} name_value_t;

/**
 * @brief Fork helper function type.
 */
typedef int (*manage_connection_forker_t) (gvm_connection_t *conn,
                                           const gchar *uuid);

int
init_manage (GSList *,
             int,
             const gchar *,
             int,
             int,
             int,
             int,
             manage_connection_forker_t,
             int);

int
init_manage_helper (GSList *, const gchar *, int);

void
init_manage_process (int, const gchar *);

void cleanup_manage_process (gboolean);

void
manage_cleanup_process_error (int);

void
manage_reset_currents ();

/* Commands. */

/**
 * @brief A command.
 */
typedef struct
{
  gchar *name;    ///< Command name.
  gchar *summary; ///< Summary of command.
} command_t;

/**
 * @brief The GMP command list.
 */
extern command_t gmp_commands[];

/* Certificate and key management. */

gchar *
truncate_certificate (const gchar *);

gchar *
truncate_private_key (const gchar *);

int
get_certificate_info (const gchar *, time_t *, time_t *, gchar **, gchar **);

gchar *certificate_iso_time (time_t);

const gchar *certificate_time_status (time_t, time_t);

/* Credentials. */

extern credentials_t current_credentials;

int
authenticate (credentials_t *);

/* Database. */

int
manage_backup_db (const gchar *);

int
manage_db_supported_version ();

int
manage_db_version ();

int
manage_scap_db_supported_version ();

int
manage_scap_db_version ();

int
manage_cert_db_supported_version ();

int
manage_cert_db_version ();

char *
port_name_formatted (const char *);

void
set_db_version (int version);

char *
manage_port_name (int, const char *);

int
manage_migrate (GSList *, const gchar *);

int
manage_encrypt_all_credentials (GSList *, const gchar *);

int
manage_decrypt_all_credentials (GSList *, const gchar *);

void
manage_session_set_timezone (const char *);

void
manage_transaction_start ();

void manage_transaction_stop (gboolean);

/* Task structures. */

extern short scanner_active;

/** @todo Should be in otp.c/h. */
/**
 * @brief A port.
 */
typedef struct
{
  unsigned int number;      ///< Port number.
  port_protocol_t protocol; ///< Port protocol (TCP, UDP, ...).
  char *string;             ///< Original string describing port.
} port_t;

/** @todo Should be in otp.c/h. */
/**
 * @brief The record of a message.
 */
typedef struct
{
  char *host;        ///< Host message describes.
  char *hostname;    ///< Hostname message describes.
  port_t port;       ///< The port.
  char *description; ///< Description of the message.
  char *oid;         ///< NVT identifier.
} message_t;

/**
 * @brief Task statuses, also used as scan/report statuses.
 *
 * These numbers are used in the database, so if the number associated with
 * any symbol changes then a migrator must be added to update existing data.
 */
typedef enum
{
  TASK_STATUS_DELETE_REQUESTED = 0,
  TASK_STATUS_DONE = 1,
  TASK_STATUS_NEW = 2,
  TASK_STATUS_REQUESTED = 3,
  TASK_STATUS_RUNNING = 4,
  TASK_STATUS_STOP_REQUESTED = 10,
  TASK_STATUS_STOP_WAITING = 11,
  TASK_STATUS_STOPPED = 12,
  TASK_STATUS_INTERRUPTED = 13,
  TASK_STATUS_DELETE_ULTIMATE_REQUESTED = 14,
  TASK_STATUS_STOP_REQUESTED_GIVEUP = 15,
  TASK_STATUS_DELETE_WAITING = 16,
  TASK_STATUS_DELETE_ULTIMATE_WAITING = 17,
  TASK_STATUS_SCHEDULED = 18
} task_status_t;

/**
 * Minimum value for number of reports to keep on auto_delete
 */
#define AUTO_DELETE_KEEP_MIN 2

/**
 * Maximum value for number of reports to keep on auto_delete
 */
#define AUTO_DELETE_KEEP_MAX 1200

/**
 * @brief Alive tests.
 *
 * These numbers are used in the database, so if the number associated with
 * any symbol changes then a migrator must be added to update existing data.
 */
typedef enum
{
  ALIVE_TEST_TCP_ACK_SERVICE = 1,
  ALIVE_TEST_ICMP = 2,
  ALIVE_TEST_ARP = 4,
  ALIVE_TEST_CONSIDER_ALIVE = 8,
  ALIVE_TEST_TCP_SYN_SERVICE = 16
} alive_test_t;

/**
 * @brief Scanner types.
 *
 * These numbers are used in the database, so if the number associated with
 * any symbol changes then a migrator must be added to update existing data.
 */
typedef enum scanner_type
{
  SCANNER_TYPE_NONE = 0,
  SCANNER_TYPE_OSP,
  SCANNER_TYPE_OPENVAS,
  SCANNER_TYPE_CVE,
  SCANNER_TYPE_GMP,
  SCANNER_TYPE_MAX,
} scanner_type_t;

typedef long long int agent_t;
typedef long long int config_t;
typedef long long int credential_t;
typedef long long int alert_t;
typedef long long int filter_t;
typedef long long int group_t;
typedef long long int host_t;
typedef long long int tag_t;
typedef long long int target_t;
typedef long long int task_t;
typedef long long int ticket_t;
typedef long long int result_t;
typedef long long int report_t;
typedef long long int report_host_t;
typedef long long int report_format_t;
typedef long long int report_format_param_t;
typedef long long int role_t;
typedef long long int note_t;
typedef long long int nvt_t;
typedef long long int override_t;
typedef long long int permission_t;
typedef long long int port_list_t;
typedef long long int port_range_t;
typedef long long int schedule_t;
typedef long long int scanner_t;
typedef long long int setting_t;
typedef long long int user_t;

/* GMP GET. */

/**
 * @brief filt_id value to use term or built-in default filter.
 */
#define FILT_ID_NONE "0"

/**
 * @brief filt_id value to use the filter in the user setting if possible.
 */
#define FILT_ID_USER_SETTING "-2"

/**
 * @brief Command data for a get command.
 */
typedef struct
{
  int details;                  ///< Boolean.  Whether to include full details.
  char *filt_id;                ///< Filter ID.  Overrides "filter".
  char *filter;                 ///< Filter term.
  char *filter_replace;         ///< Column to replace in filter.
  char *filter_replacement;     ///< Filter term to replace the one in filt_id.
  char *id;                     ///< ID of single item to get.
  int trash;                    ///< Boolean.  Whether to return from trashcan.
  gchar *type;                  ///< Type of resource.
  gchar *subtype;               ///< Subtype, or NULL.
  int ignore_max_rows_per_page; ///< Whether to ignore the Max Rows Per Page
                                ///< setting.
  int ignore_pagination; ///< Whether to ignore the pagination (first and max).
  int minimal;           ///< Whether to respond with minimal information.
} get_data_t;

void
get_data_reset (get_data_t *);

resource_t
get_iterator_resource (iterator_t *);

const char *
get_iterator_uuid (iterator_t *);

const char *
get_iterator_name (iterator_t *);

const char *
get_iterator_comment (iterator_t *);

const char *
get_iterator_creation_time (iterator_t *);

const char *
get_iterator_modification_time (iterator_t *);

const char *
get_iterator_owner_name (iterator_t *);

user_t
get_iterator_owner (iterator_t *);

/* Resources. */

int
manage_resource_name (const char *, const char *, char **);

int
manage_trash_resource_name (const char *, const char *, char **);

int
resource_count (const char *, const get_data_t *);

int
resource_id_exists (const char *, const char *);

int
trash_id_exists (const char *, const char *);

gboolean
find_resource (const char *, const char *, resource_t *);

const char *
type_name_plural (const char *);

const char *
type_name (const char *);

int
type_is_scap (const char *);

int
delete_resource (const char *, const char *, int);

/* Events and Alerts. */

/**
 * @brief Data about a report sent by an alert.
 */
typedef struct
{
  gchar *local_filename;     ///< Path to the local report file.
  gchar *remote_filename;    ///< Path or filename to send to / as.
  gchar *content_type;       ///< The MIME content type of the report.
  gchar *report_format_name; ///< Name of the report format used.
} alert_report_data_t;

void
alert_report_data_free (alert_report_data_t *);

void
alert_report_data_reset (alert_report_data_t *);

/**
 * @brief Default format string for alert email, when including report.
 */
#define ALERT_MESSAGE_INCLUDE                                                 \
  "Task '$n': $e\n"                                                           \
  "\n"                                                                        \
  "After the event $e,\n"                                                     \
  "the following condition was met: $c\n"                                     \
  "\n"                                                                        \
  "This email escalation is configured to apply report format '$r'.\n"        \
  "Full details and other report formats are available on the scan engine.\n" \
  "\n"                                                                        \
  "$t"                                                                        \
  "\n"                                                                        \
  "$i"                                                                        \
  "\n"                                                                        \
  "\n"                                                                        \
  "Note:\n"                                                                   \
  "This email was sent to you as a configured security scan escalation.\n"    \
  "Please contact your local system administrator if you think you\n"         \
  "should not have received it.\n"

/**
 * @brief Default format string for SecInfo alert email, when including report.
 */
#define SECINFO_ALERT_MESSAGE_INCLUDE                                         \
  "Task '$n': $e\n"                                                           \
  "\n"                                                                        \
  "After the event $e,\n"                                                     \
  "the following condition was met: $c\n"                                     \
  "\n"                                                                        \
  "This email escalation is configured to apply report format '$r'.\n"        \
  "Full details and other report formats are available on the scan engine.\n" \
  "\n"                                                                        \
  "$t"                                                                        \
  "\n"                                                                        \
  "$i"                                                                        \
  "\n"                                                                        \
  "\n"                                                                        \
  "Note:\n"                                                                   \
  "This email was sent to you as a configured security scan escalation.\n"    \
  "Please contact your local system administrator if you think you\n"         \
  "should not have received it.\n"

/**
 * @brief Default format string for alert email, when attaching report.
 */
#define ALERT_MESSAGE_ATTACH                                                  \
  "Task '$n': $e\n"                                                           \
  "\n"                                                                        \
  "After the event $e,\n"                                                     \
  "the following condition was met: $c\n"                                     \
  "\n"                                                                        \
  "This email escalation is configured to attach report format '$r'.\n"       \
  "Full details and other report formats are available on the scan engine.\n" \
  "\n"                                                                        \
  "$t"                                                                        \
  "\n"                                                                        \
  "Note:\n"                                                                   \
  "This email was sent to you as a configured security scan escalation.\n"    \
  "Please contact your local system administrator if you think you\n"         \
  "should not have received it.\n"

/**
 * @brief Default format string for SecInfo alert email, when attaching report.
 */
#define SECINFO_ALERT_MESSAGE_ATTACH                                          \
  "Task '$n': $e\n"                                                           \
  "\n"                                                                        \
  "After the event $e,\n"                                                     \
  "the following condition was met: $c\n"                                     \
  "\n"                                                                        \
  "This email escalation is configured to attach report format '$r'.\n"       \
  "Full details and other report formats are available on the scan engine.\n" \
  "\n"                                                                        \
  "$t"                                                                        \
  "\n"                                                                        \
  "Note:\n"                                                                   \
  "This email was sent to you as a configured security scan escalation.\n"    \
  "Please contact your local system administrator if you think you\n"         \
  "should not have received it.\n"

/**
 * @brief Default description format string for vFire alert.
 */
#define ALERT_VFIRE_CALL_DESCRIPTION                                          \
  "GVM Task '$n': $e\n"                                                       \
  "\n"                                                                        \
  "After the event $e,\n"                                                     \
  "the following condition was met: $c\n"                                     \
  "\n"                                                                        \
  "This ticket includes reports in the following format(s):\n"                \
  "$r.\n"                                                                     \
  "Full details and other report formats are available on the scan engine.\n" \
  "\n"                                                                        \
  "$t"                                                                        \
  "\n"                                                                        \
  "Note:\n"                                                                   \
  "This ticket was created automatically as a security scan escalation.\n"    \
  "Please contact your local system administrator if you think it\n"          \
  "was created or assigned erroneously.\n"

/**
 * @brief Types of task events.
 */
typedef enum
{
  EVENT_ERROR,
  EVENT_TASK_RUN_STATUS_CHANGED,
  EVENT_NEW_SECINFO,
  EVENT_UPDATED_SECINFO,
  EVENT_TICKET_RECEIVED,
  EVENT_ASSIGNED_TICKET_CHANGED,
  EVENT_OWNED_TICKET_CHANGED
} event_t;

/**
 * @brief Types of alerts.
 */
typedef enum
{
  ALERT_METHOD_ERROR,
  ALERT_METHOD_EMAIL,
  ALERT_METHOD_HTTP_GET,
  ALERT_METHOD_SOURCEFIRE,
  ALERT_METHOD_START_TASK,
  ALERT_METHOD_SYSLOG,
  ALERT_METHOD_VERINICE,
  ALERT_METHOD_SEND,
  ALERT_METHOD_SCP,
  ALERT_METHOD_SNMP,
  ALERT_METHOD_SMB,
  ALERT_METHOD_TIPPINGPOINT,
  ALERT_METHOD_VFIRE,
} alert_method_t;

/**
 * @brief Types of alert conditions.
 */
typedef enum
{
  ALERT_CONDITION_ERROR,
  ALERT_CONDITION_ALWAYS,
  ALERT_CONDITION_SEVERITY_AT_LEAST,
  ALERT_CONDITION_SEVERITY_CHANGED,
  ALERT_CONDITION_FILTER_COUNT_AT_LEAST,
  ALERT_CONDITION_FILTER_COUNT_CHANGED
} alert_condition_t;

int
manage_check_alerts (GSList *, const gchar *);

int
create_alert (const char *,
              const char *,
              const char *,
              const char *,
              event_t,
              GPtrArray *,
              alert_condition_t,
              GPtrArray *,
              alert_method_t,
              GPtrArray *,
              alert_t *);

int
copy_alert (const char *, const char *, const char *, alert_t *);

int
modify_alert (const char *,
              const char *,
              const char *,
              const char *,
              const char *,
              event_t,
              GPtrArray *,
              alert_condition_t,
              GPtrArray *,
              alert_method_t,
              GPtrArray *);

int
delete_alert (const char *, int);

char *alert_uuid (alert_t);

gboolean
find_alert_with_permission (const char *, alert_t *, const char *);

int
manage_alert (const char *, const char *, event_t, const void *, gchar **);

int
manage_test_alert (const char *, gchar **);

int alert_in_use (alert_t);

int trash_alert_in_use (alert_t);

int alert_writable (alert_t);

int trash_alert_writable (alert_t);

int
alert_count (const get_data_t *);

int
init_alert_iterator (iterator_t *, const get_data_t *);

int
alert_iterator_event (iterator_t *);

int
alert_iterator_condition (iterator_t *);

int
alert_iterator_method (iterator_t *);

char *
alert_iterator_filter_uuid (iterator_t *);

char *
alert_iterator_filter_name (iterator_t *);

int
alert_iterator_filter_trash (iterator_t *);

int
alert_iterator_filter_readable (iterator_t *);

int
alert_iterator_active (iterator_t *);

const char *alert_condition_name (alert_condition_t);

gchar *alert_condition_description (alert_condition_t, alert_t);

const char *event_name (event_t);

gchar *
event_description (event_t, const void *, const char *);

const char *alert_method_name (alert_method_t);

alert_condition_t
alert_condition_from_name (const char *);

event_t
event_from_name (const char *);

alert_method_t
alert_method_from_name (const char *);

void
init_alert_data_iterator (iterator_t *, alert_t, int, const char *);

const char *
alert_data_iterator_name (iterator_t *);

const char *
alert_data_iterator_data (iterator_t *);

void
init_alert_task_iterator (iterator_t *, alert_t, int);

const char *
alert_task_iterator_name (iterator_t *);

const char *
alert_task_iterator_uuid (iterator_t *);

int
alert_task_iterator_readable (iterator_t *);

void
init_task_alert_iterator (iterator_t *, task_t);

const char *
task_alert_iterator_uuid (iterator_t *);

const char *
task_alert_iterator_name (iterator_t *);

/* Task global variables and preprocessor variables. */

/**
 * @brief The task currently running on the scanner.
 */
extern task_t current_scanner_task;

extern report_t global_current_report;

/* Task code specific to the representation of tasks. */

unsigned int
task_count (const get_data_t *);

int
init_task_iterator (iterator_t *, const get_data_t *);

task_status_t
task_iterator_run_status (iterator_t *);

const char *
task_iterator_run_status_name (iterator_t *);

int
task_iterator_total_reports (iterator_t *);

int
task_iterator_finished_reports (iterator_t *);

const char *
task_iterator_first_report (iterator_t *);

const char *
task_iterator_last_report (iterator_t *);

report_t
task_iterator_current_report (iterator_t *);

const char *
task_iterator_hosts_ordering (iterator_t *);

scanner_t
task_iterator_scanner (iterator_t *);

int
task_uuid (task_t, char **);

int task_in_trash (task_t);

int
task_in_trash_id (const gchar *);

int task_in_use (task_t);

int trash_task_in_use (task_t);

int task_writable (task_t);

int task_alterable (task_t);

int trash_task_writable (task_t);

int task_average_scan_duration (task_t);

char *task_owner_name (task_t);

char *task_name (task_t);

char *task_comment (task_t);

char *task_hosts_ordering (task_t);

scanner_t task_scanner (task_t);

int task_scanner_in_trash (task_t);

config_t task_config (task_t);

char *task_config_uuid (task_t);

char *task_config_name (task_t);

int task_config_in_trash (task_t);

void set_task_config (task_t, config_t);

target_t task_target (task_t);

int task_target_in_trash (task_t);

void set_task_target (task_t, target_t);

void
set_task_hosts_ordering (task_t, const char *);

void set_task_scanner (task_t, scanner_t);

char *task_description (task_t);

void
set_task_description (task_t, char *, gsize);

task_status_t task_run_status (task_t);

void set_task_run_status (task_t, task_status_t);

int
task_result_count (task_t, int);

report_t task_running_report (task_t);

int task_upload_progress (task_t);

void
set_task_start_time_epoch (task_t, int);

void
set_task_start_time_otp (task_t, char *);

void
set_task_end_time (task_t task, char *time);

void set_task_end_time_epoch (task_t, time_t);

void add_task_alert (task_t, alert_t);

void
set_task_alterable (task_t, int);

int
set_task_groups (task_t, array_t *, gchar **);

int
set_task_schedule (task_t, schedule_t, int);

int
set_task_schedule_periods (const gchar *, int);

int
set_task_schedule_periods_id (task_t, int);

unsigned int task_report_count (task_t);

int
task_last_report (task_t, report_t *);

const char *
task_iterator_trend_counts (iterator_t *,
                            int,
                            int,
                            int,
                            double,
                            int,
                            int,
                            int,
                            double);

const char *
task_trend (task_t, int, int);

int task_schedule_periods (task_t);

int
task_schedule_periods_uuid (const gchar *);

schedule_t task_schedule (task_t);

schedule_t
task_schedule_uuid (const gchar *);

int task_schedule_in_trash (task_t);

time_t
task_schedule_next_time_uuid (const gchar *);

int task_schedule_next_time (task_t);

char *
task_severity (task_t, int, int, int);

int task_debugs_size (task_t);

int task_holes_size (task_t);

int task_infos_size (task_t);

int task_logs_size (task_t);

int task_warnings_size (task_t);

int task_false_positive_size (task_t);

task_t
make_task (char *, char *, int, int);

void make_task_complete (task_t);

int
copy_task (const char *, const char *, const char *, int, task_t *);

void
set_task_name (task_t, const char *);

gboolean
find_task_with_permission (const char *, task_t *, const char *);

gboolean
find_trash_task_with_permission (const char *, task_t *, const char *);

void reset_task (task_t);

int
set_task_parameter (task_t, const char *, char *);

char *task_observers (task_t);

int
set_task_observers (task_t, const gchar *);

int
request_delete_task_uuid (const char *, int);

int
request_delete_task (task_t *);

int
delete_task (task_t, int);

/* For otp.c. */
int
delete_task_lock (task_t, int);

void
append_to_task_comment (task_t, const char *, int);

void
add_task_description_line (task_t, const char *, size_t);

void
set_scan_ports (report_t, const char *, unsigned int, unsigned int);

void
append_task_open_port (task_t task, const char *, const char *);

int
manage_task_update_file (const gchar *, const char *, const void *);

int
manage_task_remove_file (const gchar *, const char *);

int
modify_task (const gchar *,
             const gchar *,
             const gchar *,
             const gchar *,
             const gchar *,
             const gchar *,
             const gchar *,
             array_t *,
             const gchar *,
             array_t *,
             const gchar *,
             const gchar *,
             array_t *,
             const gchar *,
             gchar **,
             gchar **);

void
init_config_file_iterator (iterator_t *, const char *, const char *);

const char *
config_file_iterator_content (iterator_t *);

int
config_file_iterator_length (iterator_t *);

void
init_config_task_iterator (iterator_t *, config_t, int);

const char *
config_task_iterator_name (iterator_t *);

const char *
config_task_iterator_uuid (iterator_t *);

int
config_task_iterator_readable (iterator_t *);

/* General severity related facilities. */

int
severity_in_level (double, const char *);

int
severity_matches_ov (double, double);

const char *
severity_to_level (double, int);

const char *
severity_to_type (double);

/**
 * @brief Severity data for result count cache.
 */
typedef struct
{
  int *counts; ///< Counts.
  int total;   ///< Total.
  double max;  ///< Max.
} severity_data_t;

double
severity_data_value (int);

void
init_severity_data (severity_data_t *);

void
cleanup_severity_data (severity_data_t *);

void
severity_data_add (severity_data_t *, double);

void
severity_data_add_count (severity_data_t *, double, int);

void
severity_data_level_counts (const severity_data_t *,
                            const gchar *,
                            int *,
                            int *,
                            int *,
                            int *,
                            int *,
                            int *,
                            int *);

/* General task facilities. */

const char *run_status_name (task_status_t);

int
start_task (const char *, char **);

int
stop_task (const char *);

int
resume_task (const char *, char **);

int
move_task (const char *, const char *);

/* Access control. */

int
user_may (const char *);

extern int
user_can_everything (const char *);

extern int
user_can_super_everyone (const char *);

extern int
user_has_super (const char *, user_t);

/* Results. */

/**
 * @brief SQL list of LSC families.
 */
#define LSC_FAMILY_LIST                \
  "'AIX Local Security Checks',"       \
  " 'CentOS Local Security Checks',"   \
  " 'Debian Local Security Checks',"   \
  " 'Fedora Local Security Checks',"   \
  " 'FreeBSD Local Security Checks',"  \
  " 'Gentoo Local Security Checks',"   \
  " 'HP-UX Local Security Checks',"    \
  " 'Mac OS X Local Security Checks'," \
  " 'Mandrake Local Security Checks'," \
  " 'Red Hat Local Security Checks',"  \
  " 'Solaris Local Security Checks',"  \
  " 'SuSE Local Security Checks',"     \
  " 'Ubuntu Local Security Checks',"   \
  " 'Windows : Microsoft Bulletins',"  \
  " 'Privilege escalation'"

gboolean
find_result_with_permission (const char *, result_t *, const char *);

int
result_uuid (result_t, char **);

int
result_detection_reference (result_t,
                            report_t,
                            const char *,
                            const char *,
                            char **,
                            char **,
                            char **,
                            char **);

/* Reports. */

/** @todo How is this documented? */
#define OVAS_MANAGE_REPORT_ID_LENGTH UUID_LEN_STR

/**
 * @brief Default apply_overrides setting
 */
#define APPLY_OVERRIDES_DEFAULT 0

/**
 * @brief Default quality of detection percentage.
 */
#define QOD_DEFAULT 75

/**
 * @brief Default min quality of detection percentage for filters.
 */
#define MIN_QOD_DEFAULT 1

void
reports_clear_count_cache (int);

void
reports_clear_count_cache_for_override (override_t, int);

void
init_report_counts_build_iterator (iterator_t *,
                                   report_t,
                                   int,
                                   int,
                                   const char *);

double
report_severity (report_t, int, int);

int report_host_count (report_t);

int
report_result_host_count (report_t, int);

gboolean
find_report_with_permission (const char *, report_t *, const char *);

report_t
make_report (task_t, const char *, task_status_t);

int
qod_from_type (const char *);

result_t
make_result (task_t,
             const char *,
             const char *,
             const char *,
             const char *,
             const char *,
             const char *);

result_t
make_osp_result (task_t,
                 const char *,
                 const char *,
                 const char *,
                 const char *,
                 const char *,
                 const char *,
                 int);

result_t
make_cve_result (task_t, const char *, const char *, double, const char *);

/**
 * @brief A CREATE_REPORT result.
 */
typedef struct
{
  char *description;      ///< Description of NVT.
  char *host;             ///< Host.
  char *hostname;         ///< Hostname.
  char *nvt_oid;          ///< OID of NVT.
  char *scan_nvt_version; ///< Version of NVT used at scan time.
  char *port;             ///< Port.
  char *qod;              ///< QoD (quality of detection).
  char *qod_type;         ///< QoD type.
  char *severity;         ///< Severity score.
  char *threat;           ///< Threat.
} create_report_result_t;

/**
 * @brief A host detail for create_report.
 */
typedef struct
{
  char *ip;          ///< IP.
  char *name;        ///< Detail name.
  char *source_desc; ///< Source description.
  char *source_name; ///< Source name.
  char *source_type; ///< Source type.
  char *value;       ///< Detail value.
} host_detail_t;

void
host_detail_free (host_detail_t *);

void
insert_report_host_detail (report_t,
                           const char *,
                           const char *,
                           const char *,
                           const char *,
                           const char *,
                           const char *);

int
manage_report_host_detail (report_t, const char *, const char *);

void hosts_set_identifiers (report_t);

void
hosts_set_max_severity (report_t, int *, int *);

void
hosts_set_details (report_t report);

void clear_duration_schedules (task_t);

void update_duration_schedule_periods (task_t);

int
create_report (array_t *,
               const char *,
               const char *,
               const char *,
               const char *,
               const char *,
               const char *,
               array_t *,
               array_t *,
               array_t *,
               char **);

void report_add_result (report_t, result_t);

char *report_uuid (report_t);

void
report_set_slave_uuid (report_t, const gchar *);

void
report_set_slave_name (report_t, const gchar *);

void
report_set_slave_host (report_t, const gchar *);

void
report_set_slave_port (report_t, int);

void
report_set_slave_username (report_t, const gchar *);

void
report_set_slave_password (report_t, const gchar *);

void
report_set_source_iface (report_t, const gchar *);

int
task_last_resumable_report (task_t, report_t *);

gchar *task_second_last_report_id (task_t);

gchar *
report_path_task_uuid (gchar *);

gboolean
report_task (report_t, task_t *);

char *report_slave_task_uuid (report_t);

int
report_scan_result_count (report_t,
                          const char *,
                          const char *,
                          int,
                          const char *,
                          const char *,
                          int,
                          int,
                          int *);

int
report_counts (const char *,
               int *,
               int *,
               int *,
               int *,
               int *,
               int *,
               double *,
               int,
               int,
               int);

int
report_counts_id (report_t,
                  int *,
                  int *,
                  int *,
                  int *,
                  int *,
                  int *,
                  double *,
                  const get_data_t *,
                  const char *);

int
report_counts_id_no_filt (report_t,
                          int *,
                          int *,
                          int *,
                          int *,
                          int *,
                          int *,
                          double *,
                          const get_data_t *,
                          const char *);

get_data_t *
report_results_get_data (int, int, int, int, int);

int scan_start_time_epoch (report_t);

char *
scan_start_time_uuid (const char *);

char *
scan_end_time_uuid (const char *);

void
set_scan_start_time_otp (report_t, const char *);

void set_scan_start_time_epoch (report_t, time_t);

void
set_scan_end_time (report_t, const char *);

void
set_scan_end_time_otp (report_t, const char *);

void set_scan_end_time_epoch (report_t, time_t);

void
set_scan_host_start_time_otp (report_t, const char *, const char *);

int
scan_host_end_time (report_t, const char *);

void
set_scan_host_end_time (report_t, const char *, const char *);

void
set_scan_host_end_time_otp (report_t, const char *, const char *);

int
report_timestamp (const char *, gchar **);

int
modify_report (const char *, const char *);

int
delete_report (const char *, int);

int
report_count (const get_data_t *);

int
init_report_iterator (iterator_t *, const get_data_t *);

void
init_report_iterator_task (iterator_t *, task_t);

void
init_report_errors_iterator (iterator_t *, report_t);

const char *
report_iterator_uuid (iterator_t *);

int
result_count (const get_data_t *, report_t, const char *);

int
init_result_get_iterator (iterator_t *,
                          const get_data_t *,
                          report_t,
                          const char *,
                          const gchar *);

gboolean
next_report (iterator_t *, report_t *);

result_t
result_iterator_result (iterator_t *);

const char *
result_iterator_host (iterator_t *);

const char *
result_iterator_port (iterator_t *);

const char *
result_iterator_nvt_oid (iterator_t *);

const char *
result_iterator_nvt_name (iterator_t *);

const char *
result_iterator_nvt_family (iterator_t *);

const char *
result_iterator_nvt_cvss_base (iterator_t *);

const char *
result_iterator_nvt_cve (iterator_t *);

const char *
result_iterator_nvt_bid (iterator_t *);

const char *
result_iterator_nvt_xref (iterator_t *);

const char *
result_iterator_nvt_tag (iterator_t *);

const char *
result_iterator_descr (iterator_t *);

task_t
result_iterator_task (iterator_t *);

report_t
result_iterator_report (iterator_t *);

const char *
result_iterator_scan_nvt_version (iterator_t *);

const char *
result_iterator_original_severity (iterator_t *);

double
result_iterator_severity_double (iterator_t *);

const char *
result_iterator_original_level (iterator_t *);

const char *
result_iterator_level (iterator_t *);

const char *
result_iterator_solution_type (iterator_t *);

const char *
result_iterator_qod (iterator_t *);

const char *
result_iterator_qod_type (iterator_t *);

const char *
result_iterator_hostname (iterator_t *);

const char *
result_iterator_date (iterator_t *);

const char *
result_iterator_detected_by_oid (iterator_t *);

const char *
result_iterator_asset_host_id (iterator_t *);

int
result_iterator_may_have_notes (iterator_t *);

int
result_iterator_may_have_overrides (iterator_t *);

int
result_iterator_may_have_tickets (iterator_t *);

int
result_iterator_has_cert_bunds (iterator_t *);

int
result_iterator_has_dfn_certs (iterator_t *);

void
init_report_host_iterator (iterator_t *, report_t, const char *, report_host_t);

const char *
host_iterator_host (iterator_t *);

const char *
host_iterator_start_time (iterator_t *);

const char *
host_iterator_end_time (iterator_t *);

int
host_iterator_current_port (iterator_t *);

int
host_iterator_max_port (iterator_t *);

int
collate_message_type (void *data, int, const void *, int, const void *);

void trim_partial_report (report_t);

int
report_progress (report_t, task_t, gchar **);

gchar *
manage_report (report_t,
               report_t,
               const get_data_t *,
               report_format_t,
               int,
               int,
               const char *,
               gsize *,
               gchar **,
               gchar **,
               gchar **,
               gchar **,
               gchar **);

int
manage_send_report (report_t,
                    report_t,
                    report_format_t,
                    const get_data_t *,
                    int,
                    int,
                    int,
                    int,
                    int,
                    gboolean (*) (const char *,
                                  int (*) (const char *, void *),
                                  void *),
                    int (*) (const char *, void *),
                    void *,
                    const char *,
                    const char *,
                    const char *,
                    int,
                    const char *,
                    const char *,
                    int,
                    int,
                    const gchar *);

/* Reports. */

gchar *
app_location (report_host_t, const gchar *);

void
init_host_prognosis_iterator (iterator_t *,
                              report_host_t,
                              int,
                              int,
                              const char *,
                              const char *,
                              int,
                              const char *);

double
prognosis_iterator_cvss_double (iterator_t *);

const char *
prognosis_iterator_cpe (iterator_t *);

const char *
prognosis_iterator_cve (iterator_t *);

const char *
prognosis_iterator_description (iterator_t *);

/* Targets. */

/**
 * @brief Absolute maximum number of IPs per target.
 *
 * The number of 70000 is chosen to cover "192.168.0.0-192.168.255.255".
 */
#define MANAGE_ABSOLUTE_MAX_IPS_PER_TARGET 70000

/**
 * @brief Default maximum number of hosts a target may specify.
 */
#define MANAGE_MAX_HOSTS 4095

/**
 * @brief Default maximum number of hosts a user host access may specify.
 */
#define MANAGE_USER_MAX_HOSTS 16777216

int
manage_max_hosts ();

void
manage_filter_controls (const gchar *, int *, int *, gchar **, int *);

void
manage_report_filter_controls (const gchar *,
                               int *,
                               int *,
                               gchar **,
                               int *,
                               int *,
                               gchar **,
                               gchar **,
                               gchar **,
                               gchar **,
                               int *,
                               int *,
                               int *,
                               int *,
                               int *,
                               gchar **);

gchar *
manage_clean_filter (const gchar *);

gchar *
manage_clean_filter_remove (const gchar *, const gchar *);

int
manage_count_hosts (const char *, const char *);

gboolean
find_target_with_permission (const char *, target_t *, const char *);

int
create_target (const char *,
               const char *,
               const char *,
               const char *,
               const char *,
               const char *,
               const char *,
               credential_t,
               const char *,
               credential_t,
               credential_t,
               credential_t,
               const char *,
               const char *,
               const char *,
               target_t *);

int
copy_target (const char *, const char *, const char *, target_t *);

int
modify_target (const char *,
               const char *,
               const char *,
               const char *,
               const char *,
               const char *,
               const char *,
               const char *,
               const char *,
               const char *,
               const char *,
               const char *,
               const char *,
               const char *);

int
delete_target (const char *, int);

int
target_count (const get_data_t *);

void
init_user_target_iterator (iterator_t *, target_t);

void
init_target_iterator_one (iterator_t *, target_t);

int
init_target_iterator (iterator_t *, const get_data_t *);

const char *
target_iterator_hosts (iterator_t *);

const char *
target_iterator_exclude_hosts (iterator_t *);

const char *
target_iterator_reverse_lookup_only (iterator_t *);

const char *
target_iterator_reverse_lookup_unify (iterator_t *);

const char *
target_iterator_comment (iterator_t *);

int
target_iterator_ssh_credential (iterator_t *);

const char *
target_iterator_ssh_port (iterator_t *);

int
target_iterator_smb_credential (iterator_t *);

int
target_iterator_esxi_credential (iterator_t *);

int
target_iterator_snmp_credential (iterator_t *);

int
target_iterator_ssh_trash (iterator_t *);

int
target_iterator_smb_trash (iterator_t *);

int
target_iterator_esxi_trash (iterator_t *);

int
target_iterator_snmp_trash (iterator_t *);

const char *
target_iterator_port_list_uuid (iterator_t *);

const char *
target_iterator_port_list_name (iterator_t *);

int
target_iterator_port_list_trash (iterator_t *);

const char *
target_iterator_alive_tests (iterator_t *);

char *target_uuid (target_t);

char *trash_target_uuid (target_t);

char *target_name (target_t);

char *trash_target_name (target_t);

int trash_target_readable (target_t);

char *target_hosts (target_t);

char *target_exclude_hosts (target_t);

char *target_reverse_lookup_only (target_t);

char *target_reverse_lookup_unify (target_t);

char *target_port_range (target_t);

char *target_ssh_port (target_t);

int target_in_use (target_t);

int trash_target_in_use (target_t);

int target_writable (target_t);

int trash_target_writable (target_t);

char *
target_ssh_credential_name (const char *);

void
init_target_task_iterator (iterator_t *, target_t);

const char *
target_task_iterator_name (iterator_t *);

const char *
target_task_iterator_uuid (iterator_t *);

int
target_task_iterator_readable (iterator_t *);

credential_t
target_credential (target_t, const char *);

credential_t
trash_target_credential (target_t, const char *);

int
trash_target_credential_location (target_t, const char *);

int
target_login_port (target_t, const char *);

int
trash_target_login_port (target_t, const char *);

/* Configs. */

/**
 * @brief An NVT preference.
 */
typedef struct
{
  char *name;          ///< Name of preference.
  char *type;          ///< Type of preference (radio, password, ...).
  char *value;         ///< Value of preference.
  char *nvt_name;      ///< Name of NVT preference affects.
  char *nvt_oid;       ///< OID of NVT preference affects.
  array_t *alts;       ///< Array of gchar's.  Alternate values for radio type.
  char *default_value; ///< Default value of preference.
  char *hr_name;       ///< Extended, more human-readable name used by OSP.
} preference_t;

/**
 * @brief An NVT selector.
 */
typedef struct
{
  char *name;          ///< Name of NVT selector.
  char *type;          ///< Name of NVT selector.
  int include;         ///< Whether family/NVT is included or excluded.
  char *family_or_nvt; ///< Family or NVT that this selector selects.
} nvt_selector_t;

int
create_config (const char *,
               const char *,
               const array_t *,
               const array_t *,
               const char *,
               config_t *,
               char **);

int
create_config_from_scanner (const char *, const char *, const char *, char **);

int
copy_config (const char *, const char *, const char *, config_t *);

int
delete_config (const char *, int);

int
sync_config (const char *);

gboolean
find_config_with_permission (const char *, config_t *, const char *);

char *config_uuid (config_t);

int config_type (config_t);

char *
config_nvt_timeout (config_t, const char *);

void
init_user_config_iterator (iterator_t *, config_t, int, int, const char *);

int
init_config_iterator (iterator_t *, const get_data_t *);

const char *
config_iterator_nvt_selector (iterator_t *);

int
config_iterator_nvt_count (iterator_t *);

int
config_iterator_family_count (iterator_t *);

int
config_iterator_nvts_growing (iterator_t *);

int
config_iterator_type (iterator_t *);

int
config_iterator_families_growing (iterator_t *);

scanner_t
config_iterator_scanner (iterator_t *);

int
config_iterator_scanner_trash (iterator_t *);

char *config_nvt_selector (config_t);

int config_in_use (config_t);

int config_writable (config_t);

int
config_count (const get_data_t *);

int trash_config_in_use (config_t);

int trash_config_writable (config_t);

int
trash_config_readable_uuid (const gchar *);

int config_families_growing (config_t);

int config_nvts_growing (config_t);

int create_task_check_config_scanner (config_t, scanner_t);

int
modify_task_check_config_scanner (task_t, const char *, const char *);

int
manage_set_config_preference (const gchar *,
                              const char *,
                              const char *,
                              const char *);

void
init_preference_iterator (iterator_t *, config_t);

const char *
preference_iterator_name (iterator_t *);

const char *
preference_iterator_value (iterator_t *);

const char *
preference_iterator_type (iterator_t *);

const char *
preference_iterator_default (iterator_t *);

const char *
preference_iterator_hr_name (iterator_t *);

int
manage_set_config (const gchar *, const char *, const char *, const char *);

int
manage_set_config_nvts (const gchar *, const char *, GPtrArray *);

int
manage_set_config_families (const gchar *,
                            GPtrArray *,
                            GPtrArray *,
                            GPtrArray *,
                            int);

void
init_config_timeout_iterator (iterator_t *, config_t);

const char *
config_timeout_iterator_oid (iterator_t *);

const char *
config_timeout_iterator_nvt_name (iterator_t *);

const char *
config_timeout_iterator_value (iterator_t *);

void update_config_preference (const char *, const char *, const char *,
                               const char *, gboolean);

/* NVT's. */

char *manage_nvt_name (nvt_t);

char *
nvt_oid (const char *);

char *
nvts_feed_version ();

void
set_nvts_feed_version (const char *);

gboolean
find_nvt (const char *, nvt_t *);

int
init_nvt_info_iterator (iterator_t *, get_data_t *, const char *);

int
nvt_info_count (const get_data_t *);

void
init_nvt_iterator (iterator_t *,
                   nvt_t,
                   config_t,
                   const char *,
                   const char *,
                   int,
                   const char *);

void
init_cve_nvt_iterator (iterator_t *, const char *, int, const char *);

const char *
nvt_iterator_oid (iterator_t *);

const char *
nvt_iterator_version (iterator_t *);

const char *
nvt_iterator_name (iterator_t *);

const char *
nvt_iterator_description (iterator_t *);

const char *
nvt_iterator_copyright (iterator_t *);

const char *
nvt_iterator_cve (iterator_t *);

const char *
nvt_iterator_bid (iterator_t *);

const char *
nvt_iterator_xref (iterator_t *);

const char *
nvt_iterator_tag (iterator_t *);

int
nvt_iterator_category (iterator_t *);

const char *
nvt_iterator_family (iterator_t *);

const char *
nvt_iterator_cvss_base (iterator_t *);

const char *
nvt_iterator_qod (iterator_t *);

const char *
nvt_iterator_qod_type (iterator_t *iterator);

const char *
nvt_iterator_solution_type (iterator_t *);

char *
nvt_default_timeout (const char *);

int
family_nvt_count (const char *);

void
manage_complete_nvt_cache_update (GList *, GList *);

/* NVT selectors. */

/**
 * @brief NVT selector type for "all" rule.
 */
#define NVT_SELECTOR_TYPE_ALL 0

/**
 * @brief NVT selector type for "family" rule.
 */
#define NVT_SELECTOR_TYPE_FAMILY 1

/**
 * @brief NVT selector type for "NVT" rule.
 */
#define NVT_SELECTOR_TYPE_NVT 2

/**
 * @brief Special NVT selector type for selecting all types in interfaces.
 */
#define NVT_SELECTOR_TYPE_ANY 999

void
init_family_iterator (iterator_t *, int, const char *, int);

const char *
family_iterator_name (iterator_t *);

int
nvt_selector_family_growing (const char *, const char *, int);

int
nvt_selector_family_count (const char *, int);

int
nvt_selector_nvt_count (const char *, const char *, int);

void
init_nvt_selector_iterator (iterator_t *, const char *, config_t, int);

const char *
nvt_selector_iterator_nvt (iterator_t *);

const char *
nvt_selector_iterator_name (iterator_t *);

int
nvt_selector_iterator_include (iterator_t *);

int
nvt_selector_iterator_type (iterator_t *);

/* NVT preferences. */

void
manage_nvt_preference_add (const char *, const char *);

void
manage_nvt_preferences_enable ();

void
init_nvt_preference_iterator (iterator_t *, const char *);

const char *
nvt_preference_iterator_name (iterator_t *);

const char *
nvt_preference_iterator_value (iterator_t *);

char *
nvt_preference_iterator_config_value (iterator_t *, config_t);

char *
nvt_preference_iterator_real_name (iterator_t *);

char *
nvt_preference_iterator_type (iterator_t *);

char *
nvt_preference_iterator_nvt (iterator_t *);

int
nvt_preference_count (const char *);

gchar *
get_nvti_xml (iterator_t *, int, int, int, const char *, config_t, int);

char *
task_preference_value (task_t, const char *);

int
set_task_preferences (task_t, array_t *);

void
init_task_group_iterator (iterator_t *, task_t);

const char *
task_group_iterator_name (iterator_t *);

const char *
task_group_iterator_uuid (iterator_t *);

void
init_task_role_iterator (iterator_t *, task_t);

const char *
task_role_iterator_name (iterator_t *);

const char *
task_role_iterator_uuid (iterator_t *);

/* Credentials. */

/**
 * @brief Export formats for credentials
 */
typedef enum
{
  CREDENTIAL_FORMAT_NONE = 0,  /// normal XML output
  CREDENTIAL_FORMAT_KEY = 1,   /// public key
  CREDENTIAL_FORMAT_RPM = 2,   /// RPM package
  CREDENTIAL_FORMAT_DEB = 3,   /// DEB package
  CREDENTIAL_FORMAT_EXE = 4,   /// EXE installer
  CREDENTIAL_FORMAT_PEM = 5,   /// Certificate PEM
  CREDENTIAL_FORMAT_ERROR = -1 /// Error / Invalid format
} credential_format_t;

gboolean
find_credential_with_permission (const char *, credential_t *, const char *);

int
create_credential (const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   credential_t *);

int
copy_credential (const char *, const char *, const char *, credential_t *);

int
modify_credential (const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *);

int
delete_credential (const char *, int);

int
credential_count (const get_data_t *);

void
set_credential_privacy_algorithm (credential_t, const char *);

void
set_credential_public_key (credential_t, const char *);

void
init_credential_iterator_one (iterator_t *, credential_t);

int
init_credential_iterator (iterator_t *, const get_data_t *);

const char *
credential_iterator_login (iterator_t *);

const char *
credential_iterator_auth_algorithm (iterator_t *);

const char *
credential_iterator_privacy_algorithm (iterator_t *);

const char *
credential_iterator_password (iterator_t *);

const char *
credential_iterator_community (iterator_t *);

const char *
credential_iterator_privacy_password (iterator_t *);

const char *
credential_iterator_public_key (iterator_t *);

const char *
credential_iterator_private_key (iterator_t *);

const char *
credential_iterator_type (iterator_t *);

int
credential_iterator_allow_insecure (iterator_t *);

const char *
credential_full_type (const char *);

char *
credential_iterator_rpm (iterator_t *);

char *
credential_iterator_deb (iterator_t *);

char *
credential_iterator_exe (iterator_t *);

const char *
credential_iterator_certificate (iterator_t *);

gboolean
credential_iterator_format_available (iterator_t *, credential_format_t);

gchar *
credential_iterator_formats_xml (iterator_t *iterator);

char *credential_uuid (credential_t);

char *trash_credential_uuid (credential_t);

char *credential_name (credential_t);

char *trash_credential_name (credential_t);

char *credential_type (credential_t);

void
init_credential_target_iterator (iterator_t *, credential_t, int);

const char *
credential_target_iterator_uuid (iterator_t *);

const char *
credential_target_iterator_name (iterator_t *);

int
credential_target_iterator_readable (iterator_t *);

void
init_credential_scanner_iterator (iterator_t *, credential_t, int);

const char *
credential_scanner_iterator_uuid (iterator_t *);

const char *
credential_scanner_iterator_name (iterator_t *);

int
credential_scanner_iterator_readable (iterator_t *);

int trash_credential_in_use (credential_t);

int credential_in_use (credential_t);

int trash_credential_writable (credential_t);

int credential_writable (credential_t);

int trash_credential_readable (credential_t);

gchar *
credential_value (credential_t, const char *);

gchar *
credential_encrypted_value (credential_t, const char *);

/* Agents. */

int
create_agent (const char *,
              const char *,
              const char *,
              const char *,
              const char *,
              const char *,
              const char *,
              agent_t *);

int
copy_agent (const char *, const char *, const char *, agent_t *);

int
modify_agent (const char *, const char *, const char *);

int
delete_agent (const char *, int);

int agent_in_use (agent_t);

int trash_agent_in_use (agent_t);

int trash_agent_writable (agent_t);

int agent_writable (agent_t);

int
verify_agent (const char *);

char *agent_uuid (agent_t);

int
agent_count (const get_data_t *);

int
init_agent_iterator (iterator_t *, const get_data_t *);

const char *
agent_iterator_installer_64 (iterator_t *);

const char *
agent_iterator_installer_filename (iterator_t *);

const char *
agent_iterator_trust (iterator_t *);

time_t
agent_iterator_trust_time (iterator_t *);

const char *
agent_iterator_howto_install (iterator_t *);

const char *
agent_iterator_howto_use (iterator_t *);

/* Assets. */

char *
result_host_asset_id (const char *, result_t);

char *host_uuid (resource_t);

host_t
host_notice (const char *,
             const char *,
             const char *,
             const char *,
             const char *,
             int,
             int);

void
init_host_identifier_iterator (iterator_t *, host_t, int, const char *);

const char *
host_identifier_iterator_value (iterator_t *);

const char *
host_identifier_iterator_source_type (iterator_t *);

const char *
host_identifier_iterator_source_id (iterator_t *);

const char *
host_identifier_iterator_source_data (iterator_t *);

int
host_identifier_iterator_source_orphan (iterator_t *);

const char *
host_identifier_iterator_os_id (iterator_t *);

const char *
host_identifier_iterator_os_title (iterator_t *);

int
init_asset_host_iterator (iterator_t *, const get_data_t *);

int
asset_iterator_writable (iterator_t *);

int
asset_iterator_in_use (iterator_t *);

const char *
asset_host_iterator_severity (iterator_t *);

int
asset_host_count (const get_data_t *);

int
init_asset_os_iterator (iterator_t *, const get_data_t *);

const char *
asset_os_iterator_title (iterator_t *);

int
asset_os_iterator_installs (iterator_t *);

const char *
asset_os_iterator_latest_severity (iterator_t *);

const char *
asset_os_iterator_highest_severity (iterator_t *);

const char *
asset_os_iterator_average_severity (iterator_t *);

int
asset_os_count (const get_data_t *);

int
total_asset_count (const get_data_t *);

void
init_os_host_iterator (iterator_t *, resource_t);

const char *
os_host_iterator_severity (iterator_t *);

void
init_host_detail_iterator (iterator_t *, resource_t);

const char *
host_detail_iterator_name (iterator_t *);

const char *
host_detail_iterator_value (iterator_t *);

const char *
host_detail_iterator_source_type (iterator_t *);

const char *
host_detail_iterator_source_id (iterator_t *);

int
modify_asset (const char *, const char *);

int
delete_asset (const char *, const char *, int);

int
create_asset_report (const char *, const char *);

int
create_asset_host (const char *, const char *, resource_t *);

/* Notes. */

gboolean
find_note_with_permission (const char *, note_t *, const char *);

int
create_note (const char *,
             const char *,
             const char *,
             const char *,
             const char *,
             const char *,
             const char *,
             task_t,
             result_t,
             note_t *);

int
copy_note (const char *, note_t *);

int
delete_note (const char *, int);

int
note_uuid (note_t, char **);

int
modify_note (const gchar *,
             const char *,
             const char *,
             const char *,
             const char *,
             const char *,
             const char *,
             const char *,
             const gchar *,
             const gchar *);

int
note_count (const get_data_t *, nvt_t, result_t, task_t);

int
init_note_iterator (iterator_t *, const get_data_t *, nvt_t, result_t, task_t);

const char *
note_iterator_nvt_oid (iterator_t *);

time_t
note_iterator_creation_time (iterator_t *);

time_t
note_iterator_modification_time (iterator_t *);

const char *
note_iterator_text (iterator_t *);

const char *
note_iterator_hosts (iterator_t *);

const char *
note_iterator_port (iterator_t *);

const char *
note_iterator_threat (iterator_t *);

task_t
note_iterator_task (iterator_t *);

result_t
note_iterator_result (iterator_t *);

time_t
note_iterator_end_time (iterator_t *);

int
note_iterator_active (iterator_t *);

const char *
note_iterator_nvt_name (iterator_t *);

const char *
note_iterator_nvt_type (iterator_t *);

const char *
note_iterator_severity (iterator_t *);

/* Overrides. */

gboolean
find_override_with_permission (const char *, override_t *, const char *);

int
create_override (const char *,
                 const char *,
                 const char *,
                 const char *,
                 const char *,
                 const char *,
                 const char *,
                 const char *,
                 const char *,
                 task_t,
                 result_t,
                 override_t *);

int
override_uuid (override_t, char **);

int
copy_override (const char *, override_t *);

int
delete_override (const char *, int);

int
modify_override (const gchar *,
                 const char *,
                 const char *,
                 const char *,
                 const char *,
                 const char *,
                 const char *,
                 const char *,
                 const char *,
                 const char *,
                 const gchar *,
                 const gchar *);

int
override_count (const get_data_t *, nvt_t, result_t, task_t);

int
init_override_iterator (iterator_t *,
                        const get_data_t *,
                        nvt_t,
                        result_t,
                        task_t);

const char *
override_iterator_nvt_oid (iterator_t *);

time_t
override_iterator_creation_time (iterator_t *);

time_t
override_iterator_modification_time (iterator_t *);

const char *
override_iterator_text (iterator_t *);

const char *
override_iterator_hosts (iterator_t *);

const char *
override_iterator_port (iterator_t *);

const char *
override_iterator_threat (iterator_t *);

const char *
override_iterator_new_threat (iterator_t *);

task_t
override_iterator_task (iterator_t *);

result_t
override_iterator_result (iterator_t *);

time_t
override_iterator_end_time (iterator_t *);

int
override_iterator_active (iterator_t *);

const char *
override_iterator_nvt_name (iterator_t *);

const char *
override_iterator_nvt_type (iterator_t *);

const char *
override_iterator_severity (iterator_t *);

const char *
override_iterator_new_severity (iterator_t *);

/* Scanner messaging. */

int
acknowledge_bye ();

int
acknowledge_feed_version_info ();

int
manage_check_current_task ();

/* System reports. */

/**
 * @brief A system report type iterator.
 */
typedef struct
{
  gchar **start;   ///< First type.
  gchar **current; ///< Current type.
} report_type_iterator_t;

int
init_system_report_type_iterator (report_type_iterator_t *,
                                  const char *,
                                  const char *);

void
cleanup_report_type_iterator (report_type_iterator_t *);

gboolean
next_report_type (report_type_iterator_t *);

const char *
report_type_iterator_name (report_type_iterator_t *);

const char *
report_type_iterator_title (report_type_iterator_t *);

int
manage_system_report (const char *,
                      const char *,
                      const char *,
                      const char *,
                      const char *,
                      char **);

/* Scanners. */

/**
 * @brief Default for slave update commit size.
 */
#define SLAVE_COMMIT_SIZE_DEFAULT 0

int
manage_create_scanner (GSList *,
                       const char *,
                       const char *,
                       const char *,
                       const char *,
                       const char *,
                       const char *,
                       const char *,
                       const char *);

int
manage_modify_scanner (GSList *,
                       const gchar *,
                       const char *,
                       const char *,
                       const char *,
                       const char *,
                       const char *,
                       const char *,
                       const char *,
                       const char *);

int
manage_delete_scanner (GSList *, const gchar *, const gchar *);

int
manage_verify_scanner (GSList *, const gchar *, const gchar *);

int
manage_get_scanners (GSList *, const gchar *);

int
create_scanner (const char *,
                const char *,
                const char *,
                const char *,
                const char *,
                scanner_t *,
                const char *,
                const char *);

int
copy_scanner (const char *, const char *, const char *, scanner_t *);

int
modify_scanner (const char *,
                const char *,
                const char *,
                const char *,
                const char *,
                const char *,
                const char *,
                const char *);

int
delete_scanner (const char *, int);

gboolean
find_scanner_with_permission (const char *, scanner_t *, const char *);

int scanner_in_use (scanner_t);

int trash_scanner_readable (scanner_t);

int trash_scanner_in_use (scanner_t);

int trash_scanner_writable (scanner_t);

int scanner_writable (scanner_t);

const char *
scanner_uuid_default ();

char *scanner_host (scanner_t);

int scanner_port (scanner_t);

int scanner_type (scanner_t);

char *scanner_ca_pub (scanner_t);

char *scanner_key_pub (scanner_t);

char *scanner_key_priv (scanner_t);

char *scanner_login (scanner_t);

char *scanner_password (scanner_t);

int
scanner_count (const get_data_t *);

int
init_scanner_iterator (iterator_t *, const get_data_t *);

const char *
scanner_iterator_host (iterator_t *);

int
scanner_iterator_port (iterator_t *);

int
scanner_iterator_type (iterator_t *);

const char *
scanner_iterator_credential_name (iterator_t *);

credential_t
scanner_iterator_credential (iterator_t *);

int
scanner_iterator_credential_trash (iterator_t *);

const char *
scanner_iterator_ca_pub (iterator_t *);

const char *
scanner_iterator_key_pub (iterator_t *);

const char *
scanner_iterator_credential_type (iterator_t *);

void
init_scanner_config_iterator (iterator_t *, scanner_t);

const char *
scanner_config_iterator_uuid (iterator_t *);

const char *
scanner_config_iterator_name (iterator_t *);

int
scanner_config_iterator_readable (iterator_t *);

void
init_scanner_task_iterator (iterator_t *, scanner_t);

const char *
scanner_task_iterator_uuid (iterator_t *);

const char *
scanner_task_iterator_name (iterator_t *);

int
scanner_task_iterator_readable (iterator_t *);

char *scanner_name (scanner_t);

char *scanner_uuid (scanner_t);

char *trash_scanner_name (scanner_t);

char *trash_scanner_uuid (scanner_t);

int
osp_get_version_from_iterator (iterator_t *,
                               char **,
                               char **,
                               char **,
                               char **,
                               char **,
                               char **);

int
osp_get_details_from_iterator (iterator_t *, char **, GSList **);

osp_connection_t *osp_scanner_connect (scanner_t);

int
verify_scanner (const char *, char **);

void
set_slave_commit_size (int);

/* Scheduling. */

/**
 * @brief Seconds between calls to manage_schedule.
 */
#define SCHEDULE_PERIOD 10

/**
 * @brief Minimum schedule timeout seconds.
 * This value must be greater than SCHEDULE_PERIOD.
 */
#define SCHEDULE_TIMEOUT_MIN_SECS 20

/**
 * @brief Default for schedule_timeout in minutes.
 */
#define SCHEDULE_TIMEOUT_DEFAULT 60

gboolean
find_schedule_with_permission (const char *, schedule_t *, const char *);

int
create_schedule (const char *,
                 const char *,
                 const char *,
                 time_t,
                 time_t,
                 time_t,
                 const char *,
                 time_t,
                 const char *,
                 schedule_t *,
                 gchar **);

int
copy_schedule (const char *, const char *, const char *, schedule_t *);

int
delete_schedule (const char *, int);

void
manage_auth_allow_all (int);

const gchar *
get_scheduled_user_uuid ();

void
set_scheduled_user_uuid (const gchar *uuid);

void
manage_sync (sigset_t *, int (*fork_update_nvt_cache) ());

int
manage_schedule (manage_connection_forker_t, gboolean, sigset_t *);

char *schedule_uuid (schedule_t);

char *schedule_name (schedule_t);

int schedule_duration (schedule_t);

int schedule_period (schedule_t);

int
schedule_info (schedule_t,
               int,
               time_t *,
               time_t *,
               int *,
               int *,
               int *,
               gchar **,
               gchar **);

int
init_schedule_iterator (iterator_t *, const get_data_t *);

time_t
schedule_iterator_first_time (iterator_t *);

time_t
schedule_iterator_next_time (iterator_t *);

time_t
schedule_iterator_period (iterator_t *);

time_t
schedule_iterator_period_months (iterator_t *);

time_t
schedule_iterator_duration (iterator_t *);

int
schedule_iterator_byday (iterator_t *);

gchar *
schedule_iterator_byday_string (iterator_t *);

const char *
schedule_iterator_timezone (iterator_t *);

time_t
schedule_iterator_initial_offset (iterator_t *);

const char *
schedule_iterator_icalendar (iterator_t *);

int trash_schedule_in_use (schedule_t);

int schedule_in_use (schedule_t);

int trash_schedule_writable (schedule_t);

int trash_schedule_readable (schedule_t);

int schedule_writable (schedule_t);

int
schedule_count (const get_data_t *);

void
init_schedule_task_iterator (iterator_t *, schedule_t);

const char *
schedule_task_iterator_uuid (iterator_t *);

const char *
schedule_task_iterator_name (iterator_t *);

int
schedule_task_iterator_readable (iterator_t *);

int
modify_schedule (const char *,
                 const char *,
                 const char *,
                 const char *,
                 time_t,
                 time_t,
                 time_t,
                 const char *,
                 time_t,
                 const char *,
                 gchar **);

int
get_schedule_timeout ();

void
set_schedule_timeout (int);

/* Report Formats. */

gboolean
find_report_format_with_permission (const char *,
                                    report_format_t *,
                                    const char *);

/**
 * @brief Struct for defining a report format param.
 */
typedef struct
{
  gchar *fallback; ///< Fallback value.
  gchar *name;     ///< Name.
  gchar *type;     ///< Type (boolean, string, integer, ...).
  gchar *type_max; ///< Maximum value for integer type.
  gchar *type_min; ///< Minimum value for integer type.
  gchar *value;    ///< Value of param.
} create_report_format_param_t;

int
create_report_format (const char *,
                      const char *,
                      const char *,
                      const char *,
                      const char *,
                      const char *,
                      int,
                      array_t *,
                      array_t *,
                      array_t *,
                      const char *,
                      report_format_t *);

int
copy_report_format (const char *, const char *, report_format_t *);

int
modify_report_format (const char *,
                      const char *,
                      const char *,
                      const char *,
                      const char *,
                      const char *,
                      const char *);

int
delete_report_format (const char *, int);

int
verify_report_format (const char *);

char *report_format_uuid (report_format_t);

char *report_format_owner_uuid (report_format_t);

char *report_format_name (report_format_t);

char *report_format_content_type (report_format_t);

char *report_format_extension (report_format_t);

int report_format_global (report_format_t);

int trash_report_format_global (report_format_t);

int report_format_predefined (report_format_t);

int report_format_active (report_format_t);

int report_format_trust (report_format_t);

int report_format_in_use (report_format_t);

int trash_report_format_in_use (report_format_t);

int trash_report_format_writable (report_format_t);

int report_format_writable (report_format_t);

int
report_format_count (const get_data_t *);

int
init_report_format_iterator (iterator_t *, const get_data_t *);

const char *
report_format_iterator_extension (iterator_t *);

const char *
report_format_iterator_content_type (iterator_t *);

const char *
report_format_iterator_description (iterator_t *);

int
report_format_iterator_active (iterator_t *);

const char *
report_format_iterator_signature (iterator_t *);

const char *
report_format_iterator_trust (iterator_t *);

const char *
report_format_iterator_summary (iterator_t *);

time_t
report_format_iterator_trust_time (iterator_t *);

void
init_report_format_alert_iterator (iterator_t *, report_format_t);

const char *
report_format_alert_iterator_name (iterator_t *);

const char *
report_format_alert_iterator_uuid (iterator_t *);

int
report_format_alert_iterator_readable (iterator_t *);

/**
 * @brief A report format file iterator.
 */
typedef struct
{
  GPtrArray *start;  ///< Array of files.
  gpointer *current; ///< Current file.
  gchar *dir_name;   ///< Dir holding files.
} file_iterator_t;

int
init_report_format_file_iterator (file_iterator_t *, report_format_t);

void
cleanup_file_iterator (file_iterator_t *);

gboolean
next_file (file_iterator_t *);

const char *
file_iterator_name (file_iterator_t *);

gchar *
file_iterator_content_64 (file_iterator_t *);

/**
 * @brief Report format param types.
 *
 * These numbers are used in the database, so if the number associated with
 * any symbol changes then a migrator must be added to update existing data.
 */
typedef enum
{
  REPORT_FORMAT_PARAM_TYPE_BOOLEAN = 0,
  REPORT_FORMAT_PARAM_TYPE_INTEGER = 1,
  REPORT_FORMAT_PARAM_TYPE_SELECTION = 2,
  REPORT_FORMAT_PARAM_TYPE_STRING = 3,
  REPORT_FORMAT_PARAM_TYPE_TEXT = 4,
  REPORT_FORMAT_PARAM_TYPE_REPORT_FORMAT_LIST = 5,
  REPORT_FORMAT_PARAM_TYPE_ERROR = 100
} report_format_param_type_t;

const char *report_format_param_type_name (report_format_param_type_t);

report_format_param_type_t
report_format_param_type_from_name (const char *);

void
init_report_format_param_iterator (iterator_t *,
                                   report_format_t,
                                   int,
                                   int,
                                   const char *);

report_format_param_t
report_format_param_iterator_param (iterator_t *);

const char *
report_format_param_iterator_name (iterator_t *);

const char *
report_format_param_iterator_value (iterator_t *);

const char *
report_format_param_iterator_type_name (iterator_t *);

report_format_param_type_t
report_format_param_iterator_type (iterator_t *);

long long int
report_format_param_iterator_type_min (iterator_t *);

long long int
report_format_param_iterator_type_max (iterator_t *);

const char *
report_format_param_iterator_fallback (iterator_t *);

void
init_param_option_iterator (iterator_t *,
                            report_format_param_t,
                            int,
                            const char *);

const char *
param_option_iterator_value (iterator_t *);

/* Groups. */

int
init_group_iterator (iterator_t *, const get_data_t *);

int
copy_group (const char *, const char *, const char *, group_t *);

int
create_group (const char *, const char *, const char *, int, group_t *);

int
delete_group (const char *, int);

char *group_uuid (group_t);

gchar *group_users (group_t);

int trash_group_in_use (group_t);

int group_in_use (group_t);

int trash_group_writable (group_t);

int group_writable (group_t);

int
group_count (const get_data_t *);

int
modify_group (const char *, const char *, const char *, const char *);

/* Permissions. */

int
create_permission (const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   permission_t *);

int
copy_permission (const char *, const char *, permission_t *);

char *permission_uuid (permission_t);

int
permission_is_admin (const char *);

int permission_in_use (permission_t);

int trash_permission_in_use (permission_t);

int permission_writable (permission_t);

int trash_permission_writable (permission_t);

int
permission_count (const get_data_t *);

int
init_permission_iterator (iterator_t *, const get_data_t *);

const char *
permission_iterator_resource_type (iterator_t *);

const char *
permission_iterator_resource_uuid (iterator_t *);

const char *
permission_iterator_resource_name (iterator_t *);

int
permission_iterator_resource_in_trash (iterator_t *);

int
permission_iterator_resource_orphan (iterator_t *);

int
permission_iterator_resource_readable (iterator_t *);

const char *
permission_iterator_subject_type (iterator_t *);

const char *
permission_iterator_subject_uuid (iterator_t *);

const char *
permission_iterator_subject_name (iterator_t *);

int
permission_iterator_subject_in_trash (iterator_t *);

int
permission_iterator_subject_readable (iterator_t *);

int
delete_permission (const char *, int);

int
modify_permission (const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *);

/* Permission caching */

void
delete_permissions_cache_for_resource (const char *, resource_t);

void delete_permissions_cache_for_user (user_t);

/* Port lists. */

gboolean
find_port_list (const char *, port_list_t *);

gboolean
find_port_list_with_permission (const char *, port_list_t *, const char *);

gboolean
find_port_range (const char *, port_list_t *);

int
create_port_list (const char *,
                  const char *,
                  const char *,
                  const char *,
                  array_t *,
                  port_list_t *);

int
copy_port_list (const char *, const char *, const char *, port_list_t *);

int
modify_port_list (const char *, const char *, const char *);

int
create_port_range (const char *,
                   const char *,
                   const char *,
                   const char *,
                   const char *,
                   port_range_t *);

int
delete_port_list (const char *, int);

int
delete_port_range (const char *, int);

int
port_list_count (const get_data_t *);

int
init_port_list_iterator (iterator_t *, const get_data_t *);

int
port_list_iterator_count_all (iterator_t *);

int
port_list_iterator_count_tcp (iterator_t *);

int
port_list_iterator_count_udp (iterator_t *);

char *port_list_uuid (port_list_t);

char *port_range_uuid (port_range_t);

int port_list_in_use (port_list_t);

int trash_port_list_in_use (port_list_t);

int trash_port_list_writable (port_list_t);

int port_list_writable (port_list_t);

#if 0
int
trash_port_list_in_use (port_list_t);
#endif

int
trash_port_list_readable_uuid (const gchar *);

void
init_port_range_iterator (iterator_t *, port_range_t, int, int, const char *);

const char *
port_range_iterator_uuid (iterator_t *);

const char *
port_range_iterator_comment (iterator_t *);

const char *
port_range_iterator_start (iterator_t *);

const char *
port_range_iterator_end (iterator_t *);

const char *
port_range_iterator_type (iterator_t *);

void
init_port_list_target_iterator (iterator_t *, port_list_t, int);

const char *
port_list_target_iterator_uuid (iterator_t *);

const char *
port_list_target_iterator_name (iterator_t *);

int
port_list_target_iterator_readable (iterator_t *);

/* Roles. */

int
init_role_iterator (iterator_t *, const get_data_t *);

int
copy_role (const char *, const char *, const char *, role_t *);

int
create_role (const char *, const char *, const char *, role_t *);

int
delete_role (const char *, int);

char *role_uuid (role_t);

gchar *role_users (role_t);

int trash_role_in_use (role_t);

int role_in_use (role_t);

int trash_role_writable (role_t);

int role_writable (role_t);

int
role_count (const get_data_t *);

int
modify_role (const char *, const char *, const char *, const char *);

/* Filter Utilities. */

/**
 * @brief Keyword type.
 */
typedef enum
{
  KEYWORD_TYPE_UNKNOWN,
  KEYWORD_TYPE_INTEGER,
  KEYWORD_TYPE_DOUBLE,
  KEYWORD_TYPE_STRING
} keyword_type_t;

/**
 * @brief Comparison returns.
 */
typedef enum
{
  KEYWORD_RELATION_APPROX,
  KEYWORD_RELATION_COLUMN_ABOVE,
  KEYWORD_RELATION_COLUMN_APPROX,
  KEYWORD_RELATION_COLUMN_EQUAL,
  KEYWORD_RELATION_COLUMN_BELOW,
  KEYWORD_RELATION_COLUMN_REGEXP
} keyword_relation_t;

/**
 * @brief Keyword.
 */
struct keyword
{
  gchar *column;               ///< The column prefix, or NULL.
  int equal;                   ///< Whether the keyword is like "=example".
  int integer_value;           ///< Integer value of the keyword.
  double double_value;         ///< Floating point value of the keyword.
  int quoted;                  ///< Whether the keyword was quoted.
  gchar *string;               ///< The keyword string, outer quotes removed.
  keyword_type_t type;         ///< Type of keyword.
  keyword_relation_t relation; ///< The relation.
};

/**
 * @brief Keyword type.
 */
typedef struct keyword keyword_t;

int
keyword_special (keyword_t *);

const char *keyword_relation_symbol (keyword_relation_t);

void
filter_free (array_t *);

array_t *
split_filter (const gchar *);

/* Filters. */

gboolean
find_filter (const char *, filter_t *);

gboolean
find_filter_with_permission (const char *, filter_t *, const char *);

char *filter_uuid (filter_t);

char *filter_name (filter_t);

gchar *
filter_term (const char *);

gchar *
filter_term_value (const char *, const char *);

int
filter_term_apply_overrides (const char *);

int
filter_term_autofp (const char *);

int
filter_term_min_qod (const char *);

int
create_filter (const char *,
               const char *,
               const char *,
               const char *,
               filter_t *);

int
copy_filter (const char *, const char *, const char *, filter_t *);

int
delete_filter (const char *, int);

int trash_filter_in_use (filter_t);

int filter_in_use (filter_t);

int trash_filter_writable (filter_t);

int filter_writable (filter_t);

int
filter_count (const get_data_t *);

int
init_filter_iterator (iterator_t *, const get_data_t *);

const char *
filter_iterator_type (iterator_t *);

const char *
filter_iterator_term (iterator_t *);

void
init_filter_alert_iterator (iterator_t *, filter_t);

const char *
filter_alert_iterator_name (iterator_t *);

const char *
filter_alert_iterator_uuid (iterator_t *);

int
filter_alert_iterator_readable (iterator_t *);

int
modify_filter (const char *,
               const char *,
               const char *,
               const char *,
               const char *);

/* Schema. */

int
manage_schema (gchar *, gchar **, gsize *, gchar **, gchar **);

/* Trashcan. */

int
manage_restore (const char *);

int
manage_empty_trashcan ();

/* Scanner tags. */

void
parse_tags (const char *, gchar **, gchar **);

/* SecInfo */

int
manage_read_info (gchar *, gchar *, gchar *, gchar **);

int
info_name_count (const gchar *, const gchar *);

/* SCAP. */

int
manage_scap_loaded ();

const char *
manage_scap_update_time ();

/* CPE. */

void
init_cpe_cve_iterator (iterator_t *, const char *, int, const char *);

int
init_cpe_info_iterator (iterator_t *, get_data_t *, const char *);

int
cpe_info_count (const get_data_t *get);

const char *
cpe_info_iterator_title (iterator_t *);

const char *
cpe_info_iterator_status (iterator_t *);

const char *
cpe_info_iterator_max_cvss (iterator_t *);

const char *
cpe_info_iterator_deprecated_by_id (iterator_t *);

const char *
cpe_info_iterator_cve_refs (iterator_t *);

const char *
cpe_info_iterator_nvd_id (iterator_t *);

/* CVE. */

const char *
cve_iterator_name (iterator_t *);

const char *
cve_iterator_cvss (iterator_t *);

const char *
cve_info_iterator_cvss (iterator_t *);

const char *
cve_info_iterator_vector (iterator_t *);

const char *
cve_info_iterator_complexity (iterator_t *);

const char *
cve_info_iterator_authentication (iterator_t *);

const char *
cve_info_iterator_confidentiality_impact (iterator_t *);

const char *
cve_info_iterator_integrity_impact (iterator_t *);

const char *
cve_info_iterator_availability_impact (iterator_t *);

const char *
cve_info_iterator_description (iterator_t *);

const char *
cve_info_iterator_products (iterator_t *);

int
init_cve_info_iterator (iterator_t *, get_data_t *, const char *);

int
cve_info_count (const get_data_t *get);

gchar *
cve_cvss_base (const gchar *);

/* OVAL definitions */
int
init_ovaldef_info_iterator (iterator_t *, get_data_t *, const char *);

int
ovaldef_info_count (const get_data_t *get);

const char *
ovaldef_info_iterator_version (iterator_t *);

const char *
ovaldef_info_iterator_deprecated (iterator_t *);

const char *
ovaldef_info_iterator_class (iterator_t *);

const char *
ovaldef_info_iterator_title (iterator_t *);

const char *
ovaldef_info_iterator_description (iterator_t *);

const char *
ovaldef_info_iterator_file (iterator_t *);

const char *
ovaldef_info_iterator_status (iterator_t *);

const char *
ovaldef_info_iterator_max_cvss (iterator_t *);

const char *
ovaldef_info_iterator_cve_refs (iterator_t *);

char *
ovaldef_severity (const char *);

char *
ovaldef_version (const char *);

char *
ovaldef_uuid (const char *, const char *);

char *
ovaldef_cves (const char *);

/* CERT data */
int
manage_cert_loaded ();

/* CERT-Bund */

int
init_cert_bund_adv_info_iterator (iterator_t *, get_data_t *, const char *);

int
cert_bund_adv_info_count (const get_data_t *get);

const char *
cert_bund_adv_info_iterator_title (iterator_t *);

const char *
cert_bund_adv_info_iterator_summary (iterator_t *);

const char *
cert_bund_adv_info_iterator_cve_refs (iterator_t *);

const char *
cert_bund_adv_info_iterator_max_cvss (iterator_t *);

void
init_cve_cert_bund_adv_iterator (iterator_t *, const char *, int, const char *);

void
init_nvt_cert_bund_adv_iterator (iterator_t *, const char *, int, const char *);

/* DFN-CERT */

int
init_dfn_cert_adv_info_iterator (iterator_t *, get_data_t *, const char *);

int
dfn_cert_adv_info_count (const get_data_t *get);

const char *
dfn_cert_adv_info_iterator_title (iterator_t *);

const char *
dfn_cert_adv_info_iterator_summary (iterator_t *);

const char *
dfn_cert_adv_info_iterator_cve_refs (iterator_t *);

const char *
dfn_cert_adv_info_iterator_max_cvss (iterator_t *);

void
init_cve_dfn_cert_adv_iterator (iterator_t *, const char *, int, const char *);

void
init_nvt_dfn_cert_adv_iterator (iterator_t *, const char *, int, const char *);

/* All SecInfo Data */

int
all_info_count (const get_data_t *);

int
total_info_count (const get_data_t *, int);

int
init_all_info_iterator (iterator_t *, get_data_t *, const char *);

const char *
all_info_iterator_type (iterator_t *);

const char *
all_info_iterator_extra (iterator_t *);

const char *
all_info_iterator_severity (iterator_t *);

void
init_ovaldi_file_iterator (iterator_t *);

const char *
ovaldi_file_iterator_name (iterator_t *);

/* Settings. */

int
manage_max_rows (int);

int
setting_count (const char *);

int
setting_is_default_ca_cert (const gchar *);

char *
setting_filter (const char *);

const char *
setting_severity ();

void
init_setting_iterator (iterator_t *,
                       const char *,
                       const char *,
                       int,
                       int,
                       int,
                       const char *);

const char *
setting_iterator_uuid (iterator_t *);

const char *
setting_iterator_name (iterator_t *);

const char *
setting_iterator_comment (iterator_t *);

const char *
setting_iterator_value (iterator_t *);

int
modify_setting (const gchar *, const gchar *, const gchar *, gchar **);

int
manage_modify_setting (GSList *,
                       const gchar *,
                       const gchar *,
                       const gchar *,
                       const char *);

char *
manage_default_ca_cert ();

/* Users. */

gboolean
find_user_by_name_with_permission (const char *, user_t *, const char *);

int
manage_create_user (GSList *,
                    const gchar *,
                    const gchar *,
                    const gchar *,
                    const gchar *);

int
manage_delete_user (GSList *, const gchar *, const gchar *, const gchar *);

int
manage_get_users (GSList *, const gchar *, const gchar *);

report_host_t
manage_report_host_add (report_t, const char *, time_t, time_t);

int
report_host_noticeable (report_t, const gchar *);

void report_host_set_end_time (report_host_t, time_t);

gchar *host_routes_xml (host_t);

int
manage_set_password (GSList *, const gchar *, const gchar *, const gchar *);

gchar *
manage_user_hash (const gchar *);

gchar *
manage_user_uuid (const gchar *, auth_method_t);

int
manage_user_exists (const gchar *, auth_method_t);

int
manage_scanner_set_default ();

int
copy_user (const char *, const char *, const char *, user_t *);

gchar *
keyfile_to_auth_conf_settings_xml (const gchar *);

int
init_user_iterator (iterator_t *, const get_data_t *);

const char *
user_iterator_role (iterator_t *);

const char *
user_iterator_method (iterator_t *);

const char *
user_iterator_hosts (iterator_t *);

int
user_iterator_hosts_allow (iterator_t *);

const char *
user_iterator_ifaces (iterator_t *);

int
user_iterator_ifaces_allow (iterator_t *);

void
init_user_group_iterator (iterator_t *, user_t);

const char *
user_group_iterator_uuid (iterator_t *);

const char *
user_group_iterator_name (iterator_t *);

int
user_group_iterator_readable (iterator_t *);

void
init_user_role_iterator (iterator_t *, user_t);

const char *
user_role_iterator_uuid (iterator_t *);

const char *
user_role_iterator_name (iterator_t *);

int
user_role_iterator_readable (iterator_t *);

int
create_user (const gchar *,
             const gchar *,
             const gchar *,
             const gchar *,
             int,
             const gchar *,
             int,
             const array_t *,
             array_t *,
             gchar **,
             array_t *,
             gchar **,
             gchar **,
             user_t *,
             int);

int
delete_user (const char *, const char *, int, int, const char *, const char *);

int
modify_user (const gchar *,
             gchar **,
             const gchar *,
             const gchar *,
             const gchar *,
             const gchar *,
             int,
             const gchar *,
             int,
             const array_t *,
             array_t *,
             gchar **,
             array_t *,
             gchar **,
             gchar **);

int user_in_use (user_t);

int trash_user_in_use (user_t);

int user_writable (user_t);

int trash_user_writable (user_t);

int
user_count (const get_data_t *);

gchar *
user_name (const char *);

char *user_uuid (user_t);

gchar *
user_ifaces (const char *);

int
user_ifaces_allow (const char *);

gchar *
user_hosts (const char *);

int
user_hosts_allow (const char *);

int
init_vuln_iterator (iterator_t *, const get_data_t *);

int
vuln_iterator_results (iterator_t *);

const char *
vuln_iterator_oldest (iterator_t *);

const char *
vuln_iterator_newest (iterator_t *);

const char *
vuln_iterator_type (iterator_t *);

int
vuln_iterator_hosts (iterator_t *);

double
vuln_iterator_severity (iterator_t *);

int
vuln_iterator_qod (iterator_t *);

int
vuln_count (const get_data_t *);

void
manage_get_ldap_info (int *, gchar **, gchar **, int *, gchar **);

void
manage_set_ldap_info (int, gchar *, gchar *, int, gchar *);

void
manage_get_radius_info (int *, char **, char **);

void
manage_set_radius_info (int, gchar *, gchar *);

/* Tags */

char *tag_uuid (target_t);

int
copy_tag (const char *, const char *, const char *, tag_t *);

int
create_tag (const char *,
            const char *,
            const char *,
            const char *,
            array_t *,
            const char *,
            const char *,
            tag_t *,
            gchar **);

int
delete_tag (const char *, int);

int
modify_tag (const char *,
            const char *,
            const char *,
            const char *,
            const char *,
            array_t *,
            const char *,
            const char *,
            const char *,
            gchar **);

int
init_tag_iterator (iterator_t *, const get_data_t *);

int
tag_count (const get_data_t *get);

const char *
tag_iterator_resource_type (iterator_t *);

int
tag_iterator_active (iterator_t *);

const char *
tag_iterator_value (iterator_t *);

int
tag_iterator_resources (iterator_t *);

resource_t
tag_resource_iterator_id (iterator_t *);

const char *
tag_resource_iterator_uuid (iterator_t *);

int
tag_resource_iterator_location (iterator_t *);

const char *
tag_resource_iterator_name (iterator_t *);

int
tag_resource_iterator_readable (iterator_t *);

int
init_tag_name_iterator (iterator_t *, const get_data_t *);

const char *
tag_name_iterator_name (iterator_t *);

int
init_resource_tag_iterator (iterator_t *,
                            const char *,
                            resource_t,
                            int,
                            const char *,
                            int);

const char *
resource_tag_iterator_uuid (iterator_t *);

const char *
resource_tag_iterator_name (iterator_t *);

const char *
resource_tag_iterator_value (iterator_t *);

const char *
resource_tag_iterator_comment (iterator_t *);

int
resource_tag_exists (const char *, resource_t, int);

int
resource_tag_count (const char *, resource_t, int);

int tag_in_use (tag_t);

int trash_tag_in_use (tag_t);

int tag_writable (tag_t);

int trash_tag_writable (tag_t);

/* Resource aggregates */

/**
 * @brief Sort data for aggregates commands.
 */
typedef struct
{
  gchar *field; ///< The field to sort by.
  gchar *stat;  ///< The statistic to sort by.
  int order;    ///< The sort order.
} sort_data_t;

void
sort_data_free (sort_data_t *);

int
init_aggregate_iterator (iterator_t *,
                         const char *,
                         const get_data_t *,
                         int,
                         GArray *,
                         const char *,
                         const char *,
                         GArray *,
                         GArray *,
                         int,
                         int,
                         const char *,
                         const char *);

int
aggregate_iterator_count (iterator_t *);

double
aggregate_iterator_min (iterator_t *, int);

double
aggregate_iterator_max (iterator_t *, int);

double
aggregate_iterator_mean (iterator_t *, int);

double
aggregate_iterator_sum (iterator_t *, int);

const char *
aggregate_iterator_text (iterator_t *, int, int);

const char *
aggregate_iterator_value (iterator_t *);

const char *
aggregate_iterator_subgroup_value (iterator_t *);

/* Feeds. */

#define NVT_FEED 1
#define SCAP_FEED 2
#define CERT_FEED 3

int
gvm_migrate_secinfo (int);

gboolean
gvm_sync_script_perform_selftest (const gchar *, gchar **);

gboolean
gvm_get_sync_script_identification (const gchar *, gchar **, int);

gboolean
gvm_get_sync_script_description (const gchar *, gchar **);

gboolean
gvm_get_sync_script_feed_version (const gchar *, gchar **);

/* Wizards. */

int
manage_run_wizard (const gchar *,
                   int (*) (void *, gchar *, gchar **),
                   void *,
                   array_t *,
                   int,
                   const char *,
                   gchar **,
                   gchar **,
                   gchar **);

/* Helpers. */

gchar *
xml_escape_text_truncated (const char *, size_t, const char *);

int
column_is_timestamp (const char *);

char *
type_columns (const char *);

char *
type_trash_columns (const char *);

gboolean
manage_migrate_needs_timezone (GSList *, const gchar *);

/* Optimize. */

int
manage_optimize (GSList *, const gchar *, const gchar *);

/* Signal management */

int
get_termination_signal ();

int
sql_cancel ();

#endif /* not _GVMD_MANAGE_H */
