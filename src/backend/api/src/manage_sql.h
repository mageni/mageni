/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2010-2018 Greenbone Networks GmbH
 * SPDX-FileComment: SQL backend headers.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef _GVMD_MANAGE_SQL_H
#define _GVMD_MANAGE_SQL_H

#include "manage.h"
#include "manage_utils.h"

#include "../../libraries/util/xmlutils.h" /* for entity_t */

/* Internal types and preprocessor definitions. */

/**
 * @brief UUID of 'Full and fast' config.
 */
#define CONFIG_UUID_FULL_AND_FAST "daba56c8-73ec-11df-a475-002264764cea"

/**
 * @brief UUID of 'Full and fast ultimate' config.
 */
#define CONFIG_UUID_FULL_AND_FAST_ULTIMATE \
  "698f691e-7489-11df-9d8c-002264764cea"

/**
 * @brief UUID of 'Full and very deep' config.
 */
#define CONFIG_UUID_FULL_AND_VERY_DEEP "708f25c4-7489-11df-8094-002264764cea"

/**
 * @brief UUID of 'Full and very deep ultimate' config.
 */
#define CONFIG_UUID_FULL_AND_VERY_DEEP_ULTIMATE \
  "74db13d6-7489-11df-91b9-002264764cea"

/**
 * @brief UUID of 'Empty' config.
 */
#define CONFIG_UUID_EMPTY "085569ce-73ed-11df-83c3-002264764cea"

/**
 * @brief UUID of 'Discovery' config.
 */
#define CONFIG_UUID_DISCOVERY "8715c877-47a0-438d-98a3-27c7a6ab2196"

/**
 * @brief UUID of 'Host Discovery' config.
 */
#define CONFIG_UUID_HOST_DISCOVERY "2d3f051c-55ba-11e3-bf43-406186ea4fc5"

/**
 * @brief UUID of 'System Discovery' config.
 */
#define CONFIG_UUID_SYSTEM_DISCOVERY "bbca7412-a950-11e3-9109-406186ea4fc5"

/**
 * @brief Location of a constituent of a trashcan resource.
 */
#define LOCATION_TABLE 0

/**
 * @brief Location of a constituent of a trashcan resource.
 */
#define LOCATION_TRASH 1

/**
 * @brief UUID of 'All' NVT selector.
 */
#define MANAGE_NVT_SELECTOR_UUID_ALL "54b45713-d4f4-4435-b20d-304c175ed8c5"

/**
 * @brief UUID of 'Discovery' NVT selector.
 */
#define MANAGE_NVT_SELECTOR_UUID_DISCOVERY \
  "0d9a2738-8fe2-4e22-8f26-bb886179e759"

/**
 * @brief UUID of 'Host Discovery' NVT selector.
 */
#define MANAGE_NVT_SELECTOR_UUID_HOST_DISCOVERY \
  "f5f80744-55c7-11e3-8dc6-406186ea4fc5"

/**
 * @brief UUID of 'System Discovery' NVT selector.
 */
#define MANAGE_NVT_SELECTOR_UUID_SYSTEM_DISCOVERY \
  "07045d1c-a951-11e3-8da7-406186ea4fc5"

/**
 * @brief Predefined role UUID.
 */
#define PERMISSION_UUID_ADMIN_EVERYTHING "b3b56a8c-c2fd-11e2-a135-406186ea4fc5"

/**
 * @brief Predefined role UUID.
 */
#define PERMISSION_UUID_SUPER_ADMIN_EVERYTHING \
  "a9801074-6fe2-11e4-9d81-406186ea4fc5"

/**
 * @brief UUID of 'OpenVAS Default' port list.
 */
#define PORT_LIST_UUID_DEFAULT "c7e03b6c-3bbe-11e1-a057-406186ea4fc5"

/**
 * @brief UUID of 'All TCP' port list.
 */
#define PORT_LIST_UUID_ALL_TCP "fd591a34-56fd-11e1-9f27-406186ea4fc5"

/**
 * @brief UUID of 'All TCP and Nmap 5.51 Top 100 UDP' port list.
 */
#define PORT_LIST_UUID_ALL_TCP_NMAP_5_51_TOP_100 \
  "730ef368-57e2-11e1-a90f-406186ea4fc5"

/**
 * @brief UUID of 'All TCP and Nmap 5.51 Top 1000 UDP' port list.
 */
#define PORT_LIST_UUID_ALL_TCP_NMAP_5_51_TOP_1000 \
  "9ddce1ae-57e7-11e1-b13c-406186ea4fc5"

/**
 * @brief UUID of 'All privileged TCP' port list.
 */
#define PORT_LIST_UUID_ALL_PRIV_TCP "492b72f4-56fe-11e1-98a7-406186ea4fc5"

/**
 * @brief UUID of 'All privileged TCP and UDP' port list.
 */
#define PORT_LIST_UUID_ALL_PRIV_TCP_UDP "5f2029f6-56fe-11e1-bb94-406186ea4fc5"

/**
 * @brief UUID of 'All privileged TCP and UDP' port list.
 */
#define PORT_LIST_UUID_ALL_IANA_TCP_2012 "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"

/**
 * @brief UUID of 'All privileged TCP and UDP' port list.
 */
#define PORT_LIST_UUID_ALL_IANA_TCP_UDP_2012 \
  "4a4717fe-57d2-11e1-9a26-406186ea4fc5"

/**
 * @brief UUID of 'Nmap 5.51 top 2000 TCP top 100 UDP' port list.
 */
#define PORT_LIST_UUID_NMAP_5_51_TOP_2000_TOP_100 \
  "ab33f6b0-57f8-11e1-96f5-406186ea4fc5"

/**
 * @brief Predefined role UUID.
 */
#define ROLE_UUID_ADMIN "7a8cb5b4-b74d-11e2-8187-406186ea4fc5"

/**
 * @brief Predefined role UUID.
 */
#define ROLE_UUID_GUEST "cc9cac5e-39a3-11e4-abae-406186ea4fc5"

/**
 * @brief Predefined role UUID.
 */
#define ROLE_UUID_INFO "5f8fd16c-c550-11e3-b6ab-406186ea4fc5"

/**
 * @brief Predefined role UUID.
 */
#define ROLE_UUID_MONITOR "12cdb536-480b-11e4-8552-406186ea4fc5"

/**
 * @brief Predefined role UUID.
 */
#define ROLE_UUID_USER "8d453140-b74d-11e2-b0be-406186ea4fc5"

/**
 * @brief Predefined role UUID.
 */
#define ROLE_UUID_SUPER_ADMIN "9c5a6ec6-6fe2-11e4-8cb6-406186ea4fc5"

/**
 * @brief Predefined role UUID.
 */
#define ROLE_UUID_OBSERVER "87a7ebce-b74d-11e2-a81f-406186ea4fc5"

/**
 * @brief UUID of 'OpenVAS Default' scanner.
 */
#define SCANNER_UUID_DEFAULT "08b69003-5fc2-4037-a479-93b440211c73"

/**
 * @brief UUID of 'CVE' scanner.
 */
#define SCANNER_UUID_CVE "6acd0832-df90-11e4-b9d5-28d24461215b"

/**
 * @brief UUID of 'Rows Per Page' setting.
 */
#define SETTING_UUID_ROWS_PER_PAGE "5f5a8712-8017-11e1-8556-406186ea4fc5"

/**
 * @brief UUID of 'Max Rows Per Page' setting.
 */
#define SETTING_UUID_MAX_ROWS_PER_PAGE "76374a7a-0569-11e6-b6da-28d24461215b"

/**
 * @brief UUID of 'Default CA Cert' setting.
 */
#define SETTING_UUID_DEFAULT_CA_CERT "9ac801ea-39f8-11e6-bbaa-28d24461215b"

/**
 * @brief UUID of 'Debian LSC Package Maintainer' setting.
 */
#define SETTING_UUID_LSC_DEB_MAINTAINER "2fcbeac8-4237-438f-b52a-540a23e7af97"

/**
 * @brief Trust constant for error.
 */
#define TRUST_ERROR 0

/**
 * @brief Trust constant for yes.
 */
#define TRUST_YES 1

/**
 * @brief Trust constant for no.
 */
#define TRUST_NO 2

/**
 * @brief Trust constant for unknown.
 */
#define TRUST_UNKNOWN 3

/**
 * @brief Number of milliseconds between timevals a and b (performs a-b).
 */
#define TIMEVAL_SUBTRACT_MS(a, b) \
  ((((a).tv_sec - (b).tv_sec) * 1000) + ((a).tv_usec - (b).tv_usec) / 1000)

/* Macros. */

/**
 * @brief Generate accessor for an SQL iterator.
 *
 * This convenience macro is used to generate an accessor returning a
 * const string pointer.
 *
 * @param[in]  name  Name of accessor.
 * @param[in]  col   Column number to access.
 */
#define DEF_ACCESS(name, col)              \
  const char *name (iterator_t *iterator)  \
  {                                        \
    const char *ret;                       \
    if (iterator->done)                    \
      return NULL;                         \
    ret = iterator_string (iterator, col); \
    return ret;                            \
  }

/* Iterator definitions. */

/**
 * @brief Iterator column.
 */
typedef struct
{
  gchar *select;       ///< Column for SELECT.
  gchar *filter;       ///< Filter column name.  NULL to use select_column.
  keyword_type_t type; ///< Type of column.
} column_t;

/**
 * @brief Filter columns for GET iterator.
 */
#define ANON_GET_ITERATOR_FILTER_COLUMNS "uuid", "created", "modified", "_owner"

/**
 * @brief Filter columns for GET iterator.
 */
#define GET_ITERATOR_FILTER_COLUMNS \
  "uuid", "name", "comment", "created", "modified", "_owner"

/**
 * @brief Columns for GET iterator, as a single string.
 *
 * @param[in]  prefix  Column prefix.
 */
#define GET_ITERATOR_COLUMNS_STRING                          \
  "id, uuid, name, comment, iso_time (creation_time),"       \
  " iso_time (modification_time), creation_time AS created," \
  " modification_time AS modified"

/**
 * @brief Columns for GET iterator.
 *
 * @param[in]  prefix  Column prefix.
 */
#define GET_ITERATOR_COLUMNS_PREFIX(prefix)                                 \
  {prefix "id", NULL, KEYWORD_TYPE_INTEGER},                                \
    {prefix "uuid", NULL, KEYWORD_TYPE_STRING},                             \
    {prefix "name", NULL, KEYWORD_TYPE_STRING},                             \
    {prefix "comment", NULL, KEYWORD_TYPE_STRING},                          \
    {" iso_time (" prefix "creation_time)", NULL, KEYWORD_TYPE_STRING},     \
    {" iso_time (" prefix "modification_time)", NULL, KEYWORD_TYPE_STRING}, \
    {prefix "creation_time", "created", KEYWORD_TYPE_INTEGER},              \
  {                                                                         \
    prefix "modification_time", "modified", KEYWORD_TYPE_INTEGER            \
  }

/**
 * @brief Columns for GET iterator.
 *
 * @param[in]  table  Table.
 */
#define GET_ITERATOR_COLUMNS(table)                            \
  GET_ITERATOR_COLUMNS_PREFIX (""),                            \
    {"(SELECT name FROM users AS inner_users"                  \
     " WHERE inner_users.id = " G_STRINGIFY (table) ".owner)", \
     "_owner",                                                 \
     KEYWORD_TYPE_STRING},                                     \
  {                                                            \
    "owner", NULL, KEYWORD_TYPE_INTEGER                        \
  }

/**
 * @brief Number of columns for GET iterator.
 */
#define GET_ITERATOR_COLUMN_COUNT 10

/* Variables */

extern gchar *gvmd_db_name;

/* Function prototypes */

typedef long long int rowid_t;

int
manage_db_empty ();

gboolean
host_nthlast_report_host (const char *, report_host_t *, int);

char *
report_host_ip (const char *);

gchar *
tag_value (const gchar *, const gchar *);

void trim_report (report_t);

int delete_report_internal (report_t);

int set_report_scan_run_status (report_t, task_status_t);

int
set_report_slave_progress (report_t, int);

int
update_from_slave (task_t, entity_t, entity_t *, int *);

void
set_report_slave_task_uuid (report_t, const char *);

int
set_task_requested (task_t, task_status_t *);

void
init_task_file_iterator (iterator_t *, task_t, const char *);
const char *
task_file_iterator_name (iterator_t *);
const char *
task_file_iterator_content (iterator_t *);

void set_task_schedule_next_time (task_t, time_t);

void
set_task_schedule_next_time_uuid (const gchar *, time_t);

void
init_otp_pref_iterator (iterator_t *, config_t, const char *);
const char *
otp_pref_iterator_name (iterator_t *);
const char *
otp_pref_iterator_value (iterator_t *);

port_list_t target_port_list (target_t);
credential_t target_ssh_credential (target_t);
credential_t target_smb_credential (target_t);
credential_t target_esxi_credential (target_t);

int
create_current_report (task_t, char **, task_status_t);

char *
alert_data (alert_t, const char *, const char *);

int
init_task_schedule_iterator (iterator_t *);

void
cleanup_task_schedule_iterator (iterator_t *);

task_t
task_schedule_iterator_task (iterator_t *);

const char *
task_schedule_iterator_task_uuid (iterator_t *);

schedule_t
task_schedule_iterator_schedule (iterator_t *);

const char *
task_schedule_iterator_icalendar (iterator_t *);

const char *
task_schedule_iterator_timezone (iterator_t *);

const char *
task_schedule_iterator_owner_uuid (iterator_t *);

const char *
task_schedule_iterator_owner_name (iterator_t *);

gboolean
task_schedule_iterator_timed_out (iterator_t *);

gboolean
task_schedule_iterator_start_due (iterator_t *);

gboolean
task_schedule_iterator_stop_due (iterator_t *);

time_t
task_schedule_iterator_initial_offset (iterator_t *);

int
set_task_schedule_uuid (const gchar *, schedule_t, int);

void
reinit_manage_process ();

int
manage_update_nvti_cache ();

int
manage_report_host_details (report_t, const char *, entity_t);

const char *run_status_name_internal (task_status_t);

gchar *
get_ovaldef_short_filename (char *);

void
update_config_cache_init (const char *);

alive_test_t target_alive_tests (target_t);

void
manage_session_init (const char *);

int
valid_gmp_command (const char *);

void
check_generate_scripts ();

void
auto_delete_reports ();

int
parse_iso_time (const char *);

void set_report_scheduled (report_t);

gchar *
resource_uuid (const gchar *, resource_t);

gboolean
find_resource_with_permission (const char *,
                               const char *,
                               resource_t *,
                               const char *,
                               int);

void
parse_osp_report (task_t, report_t, const char *);

void
reschedule_task (const gchar *);

void
insert_port_range (port_list_t, port_protocol_t, int, int);

int
manage_update_cert_db_init ();

void
manage_update_cert_db_cleanup ();

int
manage_update_scap_db_init ();

void
manage_update_scap_db_cleanup ();

int
manage_cert_db_exists ();

int
manage_scap_db_exists ();

void
manage_db_check_mode (const gchar *);

int
manage_db_check (const gchar *);

int
count (const char *,
       const get_data_t *,
       column_t *,
       column_t *,
       const char **,
       int,
       const char *,
       const char *,
       int);

int
init_get_iterator (iterator_t *,
                   const char *,
                   const get_data_t *,
                   column_t *,
                   column_t *,
                   const char **,
                   int,
                   const char *,
                   const char *,
                   int);

gchar *
columns_build_select (column_t *);

gchar *
filter_clause (const char *,
               const char *,
               const char **,
               column_t *,
               column_t *,
               int,
               gchar **,
               int *,
               int *,
               array_t **,
               gchar **);

void
check_alerts ();

int
manage_option_setup (GSList *, const gchar *);

void
manage_option_cleanup ();

void
update_all_config_caches ();

void
event (event_t, void *, resource_t, resource_t);

gboolean
find_trash (const char *, const char *, resource_t *);

void
tags_remove_resource (const char *, resource_t, int);

void
tags_set_locations (const char *, resource_t, resource_t, int);

void
permissions_set_locations (const char *, resource_t, resource_t, int);

void
permissions_set_orphans (const char *, resource_t, int);

int
copy_resource (const char *,
               const char *,
               const char *,
               const char *,
               const char *,
               int,
               resource_t *,
               resource_t *);

gboolean
resource_with_name_exists (const char *, const char *, resource_t);

int
create_permission_internal (const char *,
                            const char *,
                            const char *,
                            const char *,
                            const char *,
                            const char *,
                            permission_t *);

#endif /* not _GVMD_MANAGE_SQL_H */
