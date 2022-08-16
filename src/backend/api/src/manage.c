/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2009-2018 Greenbone Networks GmbH
 * SPDX-FileComment: This file defines a management library for implementing managers
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#define _XOPEN_SOURCE

/**
 * @brief Enable extra GNU functions.
 *
 * pthread_sigmask () needs this with glibc < 2.19
 */
#define _GNU_SOURCE

#include "manage.h"

#include "comm.h"
#include "manage_acl.h"
#include "manage_sql.h"
#include "manage_sql_nvts.h"
#include "manage_sql_secinfo.h"
#include "manage_sql_tickets.h"
#include "scanner.h"
#include "utils.h"

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <gnutls/x509.h> /* for gnutls_x509_crt_... */
#include "../../libraries/base/cvss.h"
#include "../../libraries/base/hosts.h"
#include "../../libraries/base/proctitle.h"
#include "../../libraries/gmp/gmp.h"
#include "../../libraries/util/fileutils.h"
#include "../../libraries/util/serverutils.h"
#include "../../libraries/util/uuidutils.h"
#include <locale.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief CPE selection stylesheet location.
 */
#define CPE_GETBYNAME_XSL MAGENI_SCAP_RES_DIR "/cpe_getbyname.xsl"

/**
 * @brief CVE selection stylesheet location.
 */
#define CVE_GETBYNAME_XSL MAGENI_SCAP_RES_DIR "/cve_getbyname.xsl"

/**
 * @brief OVALDEF selection stylesheet location.
 */
#define OVALDEF_GETBYNAME_XSL MAGENI_SCAP_RES_DIR "/ovaldef_getbyname.xsl"

/**
 * @brief CERT_BUND_ADV selection stylesheet location.
 */
#define CERT_BUND_ADV_GETBYNAME_XSL MAGENI_CERT_RES_DIR "/cert_bund_getbyname.xsl"

/**
 * @brief DFN_CERT_ADV selection stylesheet location.
 */
#define DFN_CERT_ADV_GETBYNAME_XSL MAGENI_CERT_RES_DIR "/dfn_cert_getbyname.xsl"

/**
 * @brief CPE dictionary location.
 */
#define CPE_DICT_FILENAME MAGENI_SCAP_DATA_DIR "/official-cpe-dictionary_v2.2.xml"

/**
 * @brief CVE data files location format string.
 *
 * %d should be the year expressed as YYYY.
 */
#define CVE_FILENAME_FMT MAGENI_SCAP_DATA_DIR "/nvdcve-2.0-%d.xml"

/**
 * @brief CERT-Bund data files location format string.
 *
 * %d should be the year without the century (expressed as YY),
 */
#define CERT_BUND_ADV_FILENAME_FMT MAGENI_CERT_DATA_DIR "/CB-K%02d.xml"

/**
 * @brief DFN-CERT data files location format string.
 *
 * First %d should be the year expressed as YYYY,
 * second %d should be should be Month expressed as MM.
 */
#define DFN_CERT_ADV_FILENAME_FMT MAGENI_CERT_DATA_DIR "/dfn-cert-%04d.xml"

/**
 * @brief SCAP timestamp location.
 */
#define SCAP_TIMESTAMP_FILENAME MAGENI_SCAP_DATA_DIR "/timestamp"

/**
 * @brief CERT timestamp location.
 */
#define CERT_TIMESTAMP_FILENAME MAGENI_CERT_DATA_DIR "/timestamp"

/**
 * @brief Default for Scanner max_checks preference.
 */
#define MAX_CHECKS_DEFAULT "4"

/**
 * @brief Default for Scanner max_hosts preference.
 */
#define MAX_HOSTS_DEFAULT "20"

extern volatile int termination_signal;

/**
 * @brief Number of minutes before overdue tasks timeout.
 */
static int schedule_timeout = SCHEDULE_TIMEOUT_DEFAULT;

/* Certificate and key management. */

/**
 * @brief Truncate a certificate, removing extra data.
 *
 * @param[in]  certificate    The certificate.
 *
 * @return  The truncated certificate as a newly allocated string or NULL.
 */
gchar *
truncate_certificate (const gchar *certificate)
{
  GString *cert_buffer;
  gchar *current_pos, *cert_start, *cert_end;
  gboolean done = FALSE;
  cert_buffer = g_string_new ("");

  current_pos = (gchar *) certificate;
  while (done == FALSE && *current_pos != '\0')
    {
      cert_start = NULL;
      cert_end = NULL;
      if (g_str_has_prefix (current_pos, "-----BEGIN CERTIFICATE-----"))
        {
          cert_start = current_pos;
          cert_end = strstr (cert_start, "-----END CERTIFICATE-----");
          if (cert_end)
            cert_end += strlen ("-----END CERTIFICATE-----");
          else
            done = TRUE;
        }
      else if (g_str_has_prefix (current_pos,
                                 "-----BEGIN TRUSTED CERTIFICATE-----"))
        {
          cert_start = current_pos;
          cert_end = strstr (cert_start, "-----END TRUSTED CERTIFICATE-----");
          if (cert_end)
            cert_end += strlen ("-----END TRUSTED CERTIFICATE-----");
          else
            done = TRUE;
        }
      else if (g_str_has_prefix (current_pos, "-----BEGIN PKCS7-----"))
        {
          cert_start = current_pos;
          cert_end = strstr (cert_start, "-----END PKCS7-----");
          if (cert_end)
            cert_end += strlen ("-----END PKCS7-----");
          else
            done = TRUE;
        }

      if (cert_start && cert_end)
        {
          g_string_append_len (cert_buffer, cert_start, cert_end - cert_start);
          g_string_append_c (cert_buffer, '\n');
        }
      current_pos++;
    }

  return g_string_free (cert_buffer, cert_buffer->len == 0);
}

/**
 * @brief Truncate a private key, removing extra data.
 *
 * @param[in]  private_key    The private key.
 *
 * @return  The truncated private key as a newly allocated string or NULL.
 */
gchar *
truncate_private_key (const gchar *private_key)
{
  gchar *key_start, *key_end;
  key_end = NULL;
  key_start = strstr (private_key, "-----BEGIN RSA PRIVATE KEY-----");
  if (key_start)
    {
      key_end = strstr (key_start, "-----END RSA PRIVATE KEY-----");

      if (key_end)
        key_end += strlen ("-----END RSA PRIVATE KEY-----");
      else
        return NULL;
    }

  if (key_start == NULL)
    {
      key_start = strstr (private_key, "-----BEGIN DSA PRIVATE KEY-----");
      if (key_start)
        {
          key_end = strstr (key_start, "-----END DSA PRIVATE KEY-----");

          if (key_end)
            key_end += strlen ("-----END DSA PRIVATE KEY-----");
          else
            return NULL;
        }
    }

  if (key_start == NULL)
    {
      key_start = strstr (private_key, "-----BEGIN EC PRIVATE KEY-----");
      if (key_start)
        {
          key_end = strstr (key_start, "-----END EC PRIVATE KEY-----");

          if (key_end)
            key_end += strlen ("-----END EC PRIVATE KEY-----");
          else
            return NULL;
        }
    }

  if (key_end && key_end[0] == '\n')
    key_end++;

  if (key_start == NULL || key_end == NULL)
    return NULL;
  else
    return g_strndup (key_start, key_end - key_start);
}

/**
 * @brief Gathers info from a certificate.
 *
 * @param[in]  certificate      The certificate to get data from.
 * @param[out] activation_time  Pointer to write activation time to.
 * @param[out] expiration_time  Pointer to write expiration time to.
 * @param[out] fingerprint      Pointer for newly allocated fingerprint.
 * @param[out] issuer           Pointer for newly allocated issuer DN.
 *
 * @return 0 success, -1 error.
 */
int
get_certificate_info (const gchar *certificate,
                      time_t *activation_time,
                      time_t *expiration_time,
                      gchar **fingerprint,
                      gchar **issuer)
{
  gchar *cert_truncated;

  cert_truncated = NULL;
  if (activation_time)
    *activation_time = -1;
  if (expiration_time)
    *expiration_time = -1;
  if (fingerprint)
    *fingerprint = NULL;
  if (issuer)
    *issuer = NULL;

  if (certificate)
    {
      int err;
      gnutls_datum_t cert_datum;
      gnutls_x509_crt_t gnutls_cert;

      cert_truncated = truncate_certificate (certificate);
      if (cert_truncated == NULL)
        {
          return -1;
        }
      cert_datum.data = (unsigned char *) cert_truncated;
      cert_datum.size = strlen (cert_truncated);

      gnutls_x509_crt_init (&gnutls_cert);
      err =
        gnutls_x509_crt_import (gnutls_cert, &cert_datum, GNUTLS_X509_FMT_PEM);
      if (err)
        {
          g_free (cert_truncated);
          return -1;
        }

      if (activation_time)
        {
          *activation_time = gnutls_x509_crt_get_activation_time (gnutls_cert);
        }

      if (expiration_time)
        {
          *expiration_time = gnutls_x509_crt_get_expiration_time (gnutls_cert);
        }

      if (fingerprint)
        {
          int i;
          size_t buffer_size = 16;
          unsigned char buffer[buffer_size];
          GString *string;

          string = g_string_new ("");

          gnutls_x509_crt_get_fingerprint (
            gnutls_cert, GNUTLS_DIG_MD5, buffer, &buffer_size);

          for (i = 0; i < buffer_size; i++)
            {
              if (i != 0)
                {
                  g_string_append_c (string, ':');
                }
              g_string_append_printf (string, "%02x", buffer[i]);
            }

          *fingerprint = string->str;
          g_string_free (string, FALSE);
        }

      if (issuer)
        {
          size_t buffer_size;
          gchar *buffer;
          gnutls_x509_crt_get_issuer_dn (gnutls_cert, NULL, &buffer_size);
          buffer = g_malloc (buffer_size);
          gnutls_x509_crt_get_issuer_dn (gnutls_cert, buffer, &buffer_size);

          *issuer = buffer;
        }

      gnutls_x509_crt_deinit (gnutls_cert);
      g_free (cert_truncated);
    }
  return 0;
}

/**
 * @brief Converts a certificate time to an ISO time string.
 *
 * @param[in] time  The time as a time_t.
 *
 * @return Newly allocated string.
 */
gchar *
certificate_iso_time (time_t time)
{
  if (time == 0)
    return (g_strdup ("unlimited"));
  else if (time == -1)
    return (g_strdup ("unknown"));
  else
    return (g_strdup (iso_time (&time)));
}

/**
 * @brief Tests the activation and expiration time of a certificate.
 *
 * @param[in] activates  Activation time.
 * @param[in] expires    Expiration time.
 *
 * @return Static status string.
 */
const gchar *
certificate_time_status (time_t activates, time_t expires)
{
  time_t now;
  time (&now);

  if (activates == -1 || expires == -1)
    return "unknown";
  else if (activates > now)
    return "inactive";
  else if (expires != 0 && expires < now)
    return "expired";
  else
    return "valid";
}

/* Helpers. */

/**
 * @brief Truncates text to a maximum length, optionally appends a suffix.
 *
 * Note: The string is modified in place instead of allocating a new one.
 * With the xml option the function will avoid cutting the string in the middle
 *  of XML entities, but element tags will be ignored.
 *
 * @param[in,out] string   The string to truncate.
 * @param[in]     max_len  The maximum length in bytes.
 * @param[in]     xml      Whether to preserve XML entities.
 * @param[in]     suffix   The suffix to append when the string is shortened.
 */
static void
truncate_text (gchar *string, size_t max_len, gboolean xml, const char *suffix)
{
  if (strlen (string) <= max_len)
    return;
  else
    {
      size_t offset;
      offset = max_len;

      // Move offset according according to suffix length
      if (suffix && strlen (suffix) < max_len)
        offset = offset - strlen (suffix);

      // Go back to start of UTF-8 character
      if (offset > 0 && (string[offset] & 0x80) == 0x80)
        {
          offset = g_utf8_find_prev_char (string, string + offset) - string;
        }

      if (xml)
        {
          // If the offset is in the middle of an XML entity,
          //  move the offset to the start of that entity.
          ssize_t entity_start_offset = offset;

          while (entity_start_offset >= 0 && string[entity_start_offset] != '&')
            {
              entity_start_offset--;
            }

          if (entity_start_offset >= 0)
            {
              char *entity_end = strchr (string + entity_start_offset, ';');
              if (entity_end && (entity_end - string) >= offset)
                offset = entity_start_offset;
            }
        }

      // Truncate the string, inserting the suffix if applicable
      if (suffix && strlen (suffix) < max_len)
        sprintf (string + offset, "%s", suffix);
      else
        string[offset] = '\0';
    }
}

/**
 * @brief XML escapes text truncating to a maximum length with a suffix.
 *
 * Note: The function will avoid cutting the string in the middle of XML
 *  entities.
 *
 * @param[in]  string   The string to truncate.
 * @param[in]  max_len  The maximum length in bytes.
 * @param[in]  suffix   The suffix to append when the string is shortened.
 *
 * @return Newly allocated string with XML escaped, truncated text.
 */
gchar *
xml_escape_text_truncated (const char *string,
                           size_t max_len,
                           const char *suffix)
{
  gchar *escaped;
  gssize orig_len;

  orig_len = strlen (string);
  if (orig_len <= max_len)
    escaped = g_markup_escape_text (string, -1);
  else
    {
      gchar *offset_next;
      ssize_t offset;

      offset_next = g_utf8_find_next_char (string + max_len, string + orig_len);
      offset = offset_next - string;
      escaped = g_markup_escape_text (string, offset);
    }

  truncate_text (escaped, max_len, TRUE, suffix);
  return escaped;
}

/**
 * @brief Free an slist of pointers, including the pointers.
 *
 * @param[in]  list  The list.
 */
static void
slist_free (GSList *list)
{
  GSList *head = list;
  while (list)
    {
      g_free (list->data);
      list = g_slist_next (list);
    }
  g_slist_free (head);
}

/**
 * @brief Return the plural name of a resource type.
 *
 * @param[in]  type  Resource type.
 *
 * @return Plural name of type.
 */
const char *
type_name_plural (const char *type)
{
  if (type == NULL)
    return "ERROR";

  if (strcasecmp (type, "cpe") == 0)
    return "CPEs";
  if (strcasecmp (type, "cve") == 0)
    return "CVEs";
  if (strcasecmp (type, "cert_bund_adv") == 0)
    return "CERT-Bund Advisories";
  if (strcasecmp (type, "dfn_cert_adv") == 0)
    return "DFN-CERT Advisories";
  if (strcasecmp (type, "nvt") == 0)
    return "NVTs";
  if (strcasecmp (type, "ovaldef") == 0)
    return "OVAL Definitions";

  return "ERROR";
}

/**
 * @brief Return the name of a resource type.
 *
 * @param[in]  type  Resource type.
 *
 * @return Name of type.
 */
const char *
type_name (const char *type)
{
  if (type == NULL)
    return "ERROR";

  if (strcasecmp (type, "cpe") == 0)
    return "CPE";
  if (strcasecmp (type, "cve") == 0)
    return "CVE";
  if (strcasecmp (type, "cert_bund_adv") == 0)
    return "CERT-Bund Advisory";
  if (strcasecmp (type, "dfn_cert_adv") == 0)
    return "DFN-CERT Advisory";
  if (strcasecmp (type, "nvt") == 0)
    return "NVT";
  if (strcasecmp (type, "ovaldef") == 0)
    return "OVAL Definition";

  return "ERROR";
}

/**
 * @brief Check if a type is a SCAP type.
 *
 * @param[in]  type  Resource type.
 *
 * @return Name of type.
 */
int
type_is_scap (const char *type)
{
  return (strcasecmp (type, "cpe") == 0) || (strcasecmp (type, "cve") == 0)
         || (strcasecmp (type, "ovaldef") == 0);
}

/**
 * @brief Check whether a resource is available.
 *
 * @param[in]   type        Type.
 * @param[out]  resource    Resource.
 * @param[out]  permission  Permission required for this operation.
 *
 * @return 0 success, -1 error, 99 permission denied.
 */
static int
check_available (const gchar *type,
                 resource_t resource,
                 const gchar *permission)
{
  if (resource)
    {
      gchar *uuid;
      resource_t found;

      uuid = resource_uuid (type, resource);
      if (find_resource_with_permission (type, uuid, &found, permission, 0))
        {
          g_free (uuid);
          return -1;
        }
      g_free (uuid);
      if (found == 0)
        return 99;

      return 0;
    }

  return -1;
}

/* Severity related functions. */

/**
 * @brief Get the message type of a threat.
 *
 * @param  threat  Threat.
 *
 * @return Static message type name if threat names a threat, else NULL.
 */
const char *
threat_message_type (const char *threat)
{
  if (strcasecmp (threat, "High") == 0)
    return "Alarm";
  if (strcasecmp (threat, "Medium") == 0)
    return "Alarm";
  if (strcasecmp (threat, "Low") == 0)
    return "Alarm";
  if (strcasecmp (threat, "Log") == 0)
    return "Log Message";
  if (strcasecmp (threat, "Debug") == 0)
    return "Debug Message";
  if (strcasecmp (threat, "Error") == 0)
    return "Error Message";
  if (strcasecmp (threat, "False Positive") == 0)
    return "False Positive";
  return NULL;
}

/**
 * @brief Get the threat of a message type.
 *
 * @param  type  Message type.
 *
 * @return Static threat name if type names a message type, else NULL.
 */
const char *
message_type_threat (const char *type)
{
  if (strcasecmp (type, "Alarm") == 0)
    return "Alarm";
  if (strcasecmp (type, "Security Hole") == 0)
    return "High";
  if (strcasecmp (type, "Security Warning") == 0)
    return "Medium";
  if (strcasecmp (type, "Security Note") == 0)
    return "Low";
  if (strcasecmp (type, "Log Message") == 0)
    return "Log";
  if (strcasecmp (type, "Debug Message") == 0)
    return "Debug";
  if (strcasecmp (type, "Error Message") == 0)
    return "Error";
  if (strcasecmp (type, "False Positive") == 0)
    return "False Positive";
  return NULL;
}

/**
 * @brief Check whether a severity falls within a threat level.
 *
 * @param[in]  severity  Severity.
 * @param[in]  level     Threat level.
 *
 * @return 1 if in level, else 0.
 */
int
severity_in_level (double severity, const char *level)
{
  const char *class;

  class = setting_severity ();
  if (strcmp (class, "classic") == 0)
    {
      if (strcmp (level, "high") == 0)
        return severity > 5 && severity <= 10;
      else if (strcmp (level, "medium") == 0)
        return severity > 2 && severity <= 5;
      else if (strcmp (level, "low") == 0)
        return severity > 0 && severity <= 2;
      else if (strcmp (level, "none") == 0 || strcmp (level, "log") == 0)
        return severity == 0;
      else
        return 0;
    }
  else if (strcmp (class, "pci-dss") == 0)
    {
      if (strcmp (level, "high") == 0)
        return severity >= 4.0;
      else if (strcmp (level, "none") == 0 || strcmp (level, "log") == 0)
        return severity >= 0.0 && severity < 4.0;
      else
        return 0;
    }
  else
    {
      /* NIST/BSI. */
      if (strcmp (level, "high") == 0)
        return severity >= 7 && severity <= 10;
      else if (strcmp (level, "medium") == 0)
        return severity >= 4 && severity < 7;
      else if (strcmp (level, "low") == 0)
        return severity > 0 && severity < 4;
      else if (strcmp (level, "none") == 0 || strcmp (level, "log") == 0)
        return severity == 0;
      else
        return 0;
    }
}

/**
 * @brief Check whether a severity matches an override's severity.
 *
 * Only used by SQLite backend.
 *
 * @param[in] severity     severity score
 * @param[in] ov_severity  override severity score to match
 *
 * @return 1 if matches, else 0.
 */
int
severity_matches_ov (double severity, double ov_severity)
{
  if (ov_severity <= 0.0)
    return severity == ov_severity;
  else
    return severity >= ov_severity;
}

/**
 * @brief Get the threat level matching a severity score.
 *
 * @param[in] severity  severity score
 * @param[in] mode      0 for normal levels, 1 to use "Alarm" for severity > 0.0
 *
 * @return the level as a static string
 */
const char *
severity_to_level (double severity, int mode)
{
  if (severity == SEVERITY_LOG)
    return "Log";
  else if (severity == SEVERITY_FP)
    return "False Positive";
  else if (severity == SEVERITY_DEBUG)
    return "Debug";
  else if (severity == SEVERITY_ERROR)
    return "Error";
  else if (severity > 0.0 && severity <= 10.0)
    {
      if (mode == 1)
        return ("Alarm");
      else if (severity_in_level (severity, "high"))
        return ("High");
      else if (severity_in_level (severity, "medium"))
        return ("Medium");
      else if (severity_in_level (severity, "low"))
        return ("Low");
      else
        return ("Log");
    }
  else
    {
      g_warning (
        "%s: Invalid severity score given: %f", __FUNCTION__, severity);
      return (NULL);
    }
}

/**
 * @brief Get the message type matching a severity score.
 *
 * @param[in] severity  severity score
 *
 * @return the message type as a static string
 */
const char *
severity_to_type (double severity)
{
  if (severity == SEVERITY_LOG)
    return "Log Message";
  else if (severity == SEVERITY_FP)
    return "False Positive";
  else if (severity == SEVERITY_DEBUG)
    return "Debug Message";
  else if (severity == SEVERITY_ERROR)
    return "Error Message";
  else if (severity > 0.0 && severity <= 10.0)
    return "Alarm";
  else
    {
      g_warning (
        "%s: Invalid severity score given: %f", __FUNCTION__, severity);
      return (NULL);
    }
}

/* Credentials. */

/**
 * @brief Current credentials during any GMP command.
 */
credentials_t current_credentials;

/* Reports. */

/**
 * @brief Delete all the reports for a task.
 *
 * It's up to the caller to ensure that this runs in a contention safe
 * context (for example within an SQL transaction).
 *
 * @param[in]  task  A task descriptor.
 *
 * @return 0 on success, -1 on error.
 */
int
delete_reports (task_t task)
{
  report_t report;
  iterator_t iterator;
  init_report_iterator_task (&iterator, task);
  while (next_report (&iterator, &report))
    if (delete_report_internal (report))
      {
        cleanup_iterator (&iterator);
        return -1;
      }
  cleanup_iterator (&iterator);
  return 0;
}

/**
 * @brief Create a basic filter term to get report results.
 *
 * @param[in]  first            First row.
 * @param[in]  rows             Number of rows.
 * @param[in]  apply_overrides  Whether to apply overrides.
 * @param[in]  autofp           Auto-FP value.
 * @param[in]  min_qod          Minimum QOD.
 *
 * @return Filter term.
 */
static gchar *
report_results_filter_term (int first,
                            int rows,
                            int apply_overrides,
                            int autofp,
                            int min_qod)
{
  return g_strdup_printf ("first=%d rows=%d"
                          " apply_overrides=%d autofp=%d min_qod=%d",
                          first,
                          rows,
                          apply_overrides,
                          autofp,
                          min_qod);
}

/**
 * @brief Create a new basic get_data_t struct to get report results.
 *
 * @param[in]  first            First row.
 * @param[in]  rows             Number of rows.
 * @param[in]  apply_overrides  Whether to apply overrides.
 * @param[in]  autofp           Auto-FP value.
 * @param[in]  min_qod          Minimum QOD.
 *
 * @return GET data struct.
 */
get_data_t *
report_results_get_data (int first,
                         int rows,
                         int apply_overrides,
                         int autofp,
                         int min_qod)
{
  get_data_t *get = g_malloc (sizeof (get_data_t));
  memset (get, 0, sizeof (get_data_t));
  get->type = g_strdup ("result");
  get->filter =
    report_results_filter_term (first, rows, apply_overrides, autofp, min_qod);

  return get;
}

/**
 * @brief Array index of severity 0.0 in the severity_data_t.counts array.
 */
#define ZERO_SEVERITY_INDEX 4

/**
 * @brief Convert a severity value into an index in the counts array.
 *
 * @param[in]   severity        Severity value.
 *
 * @return      The index, 0 for invalid severity scores.
 */
static int
severity_data_index (double severity)
{
  int ret;
  if (severity >= 0.0)
    ret =
      (int) (round (severity * SEVERITY_SUBDIVISIONS)) + ZERO_SEVERITY_INDEX;
  else if (severity == SEVERITY_FP || severity == SEVERITY_DEBUG
           || severity == SEVERITY_ERROR)
    ret = (int) (round (severity)) + ZERO_SEVERITY_INDEX;
  else
    ret = 0;

  return ret;
}

/**
 * @brief Convert an index in the counts array to a severity value.
 *
 * @param[in]   index   Index in the counts array.
 *
 * @return      The corresponding severity value.
 */
double
severity_data_value (int index)
{
  double ret;
  if (index <= ZERO_SEVERITY_INDEX && index > 0)
    ret = ((double) index) - ZERO_SEVERITY_INDEX;
  else if (index
           <= (ZERO_SEVERITY_INDEX + (SEVERITY_SUBDIVISIONS * SEVERITY_MAX)))
    ret = (((double) (index - ZERO_SEVERITY_INDEX)) / SEVERITY_SUBDIVISIONS);
  else
    ret = SEVERITY_MISSING;

  return ret;
}

/**
 * @brief Initialize a severity data structure.
 *
 * @param[in] data  The data structure to initialize.
 */
void
init_severity_data (severity_data_t *data)
{
  int max_i;
  max_i = ZERO_SEVERITY_INDEX + (SEVERITY_SUBDIVISIONS * SEVERITY_MAX);

  data->counts = g_malloc0 (sizeof (int) * (max_i + 1));

  data->total = 0;
  data->max = SEVERITY_MISSING;
}

/**
 * @brief Clean up a severity data structure.
 *
 * @param[in] data  The data structure to initialize.
 */
void
cleanup_severity_data (severity_data_t *data)
{
  g_free (data->counts);
}

/**
 * @brief Add a severity occurrence to the counts of a severity_data_t.
 *
 * @param[in]   severity_data   The severity count struct to add to.
 * @param[in]   severity        The severity to add.
 */
void
severity_data_add (severity_data_t *severity_data, double severity)
{
  (severity_data->counts)[severity_data_index (severity)]++;

  if (severity_data->total == 0 || severity_data->max <= severity)
    severity_data->max = severity;

  (severity_data->total)++;
}

/**
 * @brief Add a multiple severity occurrences to the counts of a
 * severity_data_t.
 *
 * @param[in]   severity_data   The severity count struct to add to.
 * @param[in]   severity        The severity to add.
 * @param[in]   count           The number of occurrences to add.
 */
void
severity_data_add_count (severity_data_t *severity_data,
                         double severity,
                         int count)
{
  (severity_data->counts)[severity_data_index (severity)] += count;

  if (severity_data->total == 0 || severity_data->max <= severity)
    severity_data->max = severity;

  (severity_data->total) += count;
}

/**
 * @brief Calculate the total of severity counts in a range.
 *
 * @param[in]  severity_data   The severity data struct to get counts from.
 * @param[in]  min_severity    The minimum severity included in the range.
 * @param[in]  max_severity    The maximum severity included in the range.
 *
 * @return     The total of severity counts in the specified range.
 */
static int
severity_data_range_count (const severity_data_t *severity_data,
                           double min_severity,
                           double max_severity)
{
  int i, i_max, count;

  i_max = severity_data_index (max_severity);
  count = 0;

  for (i = severity_data_index (min_severity); i <= i_max; i++)
    {
      count += (severity_data->counts)[i];
    }
  return count;
}

/**
 * @brief Count the occurrences of severities in the levels.
 *
 * @param[in] severity_data    The severity counts data to evaluate.
 * @param[in] severity_class   The severity class setting to use.
 * @param[out] errors          The number of error messages.
 * @param[out] debugs          The number of debug messages.
 * @param[out] false_positives The number of False Positives.
 * @param[out] logs            The number of Log messages.
 * @param[out] lows            The number of Low severity results.
 * @param[out] mediums         The number of Medium severity results.
 * @param[out] highs           The number of High severity results.
 */
void
severity_data_level_counts (const severity_data_t *severity_data,
                            const gchar *severity_class,
                            int *errors,
                            int *debugs,
                            int *false_positives,
                            int *logs,
                            int *lows,
                            int *mediums,
                            int *highs)
{
  if (errors)
    *errors =
      severity_data_range_count (severity_data,
                                 level_min_severity ("Error", severity_class),
                                 level_max_severity ("Error", severity_class));

  if (debugs)
    *debugs =
      severity_data_range_count (severity_data,
                                 level_min_severity ("Debug", severity_class),
                                 level_max_severity ("Debug", severity_class));

  if (false_positives)
    *false_positives = severity_data_range_count (
      severity_data,
      level_min_severity ("False Positive", severity_class),
      level_max_severity ("False Positive", severity_class));

  if (logs)
    *logs =
      severity_data_range_count (severity_data,
                                 level_min_severity ("Log", severity_class),
                                 level_max_severity ("Log", severity_class));

  if (lows)
    *lows =
      severity_data_range_count (severity_data,
                                 level_min_severity ("low", severity_class),
                                 level_max_severity ("low", severity_class));

  if (mediums)
    *mediums =
      severity_data_range_count (severity_data,
                                 level_min_severity ("medium", severity_class),
                                 level_max_severity ("medium", severity_class));

  if (highs)
    *highs =
      severity_data_range_count (severity_data,
                                 level_min_severity ("high", severity_class),
                                 level_max_severity ("high", severity_class));
}

/* Task globals. */

/**
 * @brief The task currently running on the scanner.
 */
task_t current_scanner_task = (task_t) 0;

/**
 * @brief The report of the current task.
 */
report_t global_current_report = (report_t) 0;

/* Alerts. */

/**
 * @brief Frees a alert_report_data_t struct, including contained data.
 *
 * @param[in]  data   The struct to free.
 */
void
alert_report_data_free (alert_report_data_t *data)
{
  if (data == NULL)
    return;

  alert_report_data_reset (data);
  g_free (data);
}

/**
 * @brief Frees content of an alert_report_data_t, but not the struct itself.
 *
 * @param[in]  data   The struct to free.
 */
void
alert_report_data_reset (alert_report_data_t *data)
{
  if (data == NULL)
    return;

  g_free (data->content_type);
  g_free (data->local_filename);
  g_free (data->remote_filename);
  g_free (data->report_format_name);

  memset (data, 0, sizeof (alert_report_data_t));
}

/**
 * @brief Get the name of an alert condition.
 *
 * @param[in]  condition  Condition.
 *
 * @return The name of the condition (for example, "Always").
 */
const char *
alert_condition_name (alert_condition_t condition)
{
  switch (condition)
    {
    case ALERT_CONDITION_ALWAYS:
      return "Always";
    case ALERT_CONDITION_FILTER_COUNT_AT_LEAST:
      return "Filter count at least";
    case ALERT_CONDITION_FILTER_COUNT_CHANGED:
      return "Filter count changed";
    case ALERT_CONDITION_SEVERITY_AT_LEAST:
      return "Severity at least";
    case ALERT_CONDITION_SEVERITY_CHANGED:
      return "Severity changed";
    default:
      return "Internal Error";
    }
}

/**
 * @brief Get the name of an alert event.
 *
 * @param[in]  event  Event.
 *
 * @return The name of the event (for example, "Run status changed").
 */
const char *
event_name (event_t event)
{
  switch (event)
    {
    case EVENT_TASK_RUN_STATUS_CHANGED:
      return "Task run status changed";
    case EVENT_NEW_SECINFO:
      return "New SecInfo arrived";
    case EVENT_UPDATED_SECINFO:
      return "Updated SecInfo arrived";
    case EVENT_TICKET_RECEIVED:
      return "Ticket received";
    case EVENT_ASSIGNED_TICKET_CHANGED:
      return "Assigned ticket changed";
    case EVENT_OWNED_TICKET_CHANGED:
      return "Owned ticket changed";
    default:
      return "Internal Error";
    }
}

/**
 * @brief Get a description of an alert condition.
 *
 * @param[in]  condition  Condition.
 * @param[in]  alert  Alert.
 *
 * @return Freshly allocated description of condition.
 */
gchar *
alert_condition_description (alert_condition_t condition, alert_t alert)
{
  switch (condition)
    {
    case ALERT_CONDITION_ALWAYS:
      return g_strdup ("Always");
    case ALERT_CONDITION_FILTER_COUNT_AT_LEAST:
      {
        char *level;
        gchar *ret;

        level = alert_data (alert, "condition", "severity");
        ret = g_strdup_printf ("Filter count at least %s", level ? level : "0");
        free (level);
        return ret;
      }
    case ALERT_CONDITION_FILTER_COUNT_CHANGED:
      return g_strdup ("Filter count changed");
    case ALERT_CONDITION_SEVERITY_AT_LEAST:
      {
        char *level = alert_data (alert, "condition", "severity");
        gchar *ret = g_strdup_printf ("Task severity is at least '%s'", level);
        free (level);
        return ret;
      }
    case ALERT_CONDITION_SEVERITY_CHANGED:
      {
        char *direction;
        direction = alert_data (alert, "condition", "direction");
        gchar *ret = g_strdup_printf ("Task severity %s", direction);
        free (direction);
        return ret;
      }
    default:
      return g_strdup ("Internal Error");
    }
}

/**
 * @brief Get a description of an alert event.
 *
 * @param[in]  event       Event.
 * @param[in]  event_data  Event data.
 * @param[in]  task_name   Name of task if required in description, else NULL.
 *
 * @return Freshly allocated description of event.
 */
gchar *
event_description (event_t event, const void *event_data, const char *task_name)
{
  switch (event)
    {
    case EVENT_TASK_RUN_STATUS_CHANGED:
      if (task_name)
        return g_strdup_printf (
          "The security scan task '%s' changed status to '%s'",
          task_name,
          run_status_name ((task_status_t) event_data));
      return g_strdup_printf ("Task status changed to '%s'",
                              run_status_name ((task_status_t) event_data));
      break;
    case EVENT_NEW_SECINFO:
      return g_strdup_printf ("New SecInfo arrived");
      break;
    case EVENT_UPDATED_SECINFO:
      return g_strdup_printf ("Updated SecInfo arrived");
      break;
    case EVENT_TICKET_RECEIVED:
      return g_strdup_printf ("Ticket received");
      break;
    case EVENT_ASSIGNED_TICKET_CHANGED:
      return g_strdup_printf ("Assigned ticket changed");
      break;
    case EVENT_OWNED_TICKET_CHANGED:
      return g_strdup_printf ("Owned ticket changed");
      break;
    default:
      return g_strdup ("Internal Error");
    }
}

/**
 * @brief Get the name of an alert method.
 *
 * @param[in]  method  Method.
 *
 * @return The name of the method (for example, "Email" or "SNMP").
 */
const char *
alert_method_name (alert_method_t method)
{
  switch (method)
    {
    case ALERT_METHOD_EMAIL:
      return "Email";
    case ALERT_METHOD_HTTP_GET:
      return "HTTP Get";
    case ALERT_METHOD_SCP:
      return "SCP";
    case ALERT_METHOD_SEND:
      return "Send";
    case ALERT_METHOD_SMB:
      return "SMB";
    case ALERT_METHOD_SNMP:
      return "SNMP";
    case ALERT_METHOD_SOURCEFIRE:
      return "Sourcefire Connector";
    case ALERT_METHOD_START_TASK:
      return "Start Task";
    case ALERT_METHOD_SYSLOG:
      return "Syslog";
    case ALERT_METHOD_TIPPINGPOINT:
      return "TippingPoint SMS";
    case ALERT_METHOD_VERINICE:
      return "verinice Connector";
    case ALERT_METHOD_VFIRE:
      return "Alemba vFire";
    default:
      return "Internal Error";
    }
}

/**
 * @brief Get an alert condition from a name.
 *
 * @param[in]  name  Condition name.
 *
 * @return The condition.
 */
alert_condition_t
alert_condition_from_name (const char *name)
{
  if (strcasecmp (name, "Always") == 0)
    return ALERT_CONDITION_ALWAYS;
  if (strcasecmp (name, "Filter count at least") == 0)
    return ALERT_CONDITION_FILTER_COUNT_AT_LEAST;
  if (strcasecmp (name, "Filter count changed") == 0)
    return ALERT_CONDITION_FILTER_COUNT_CHANGED;
  if (strcasecmp (name, "Severity at least") == 0)
    return ALERT_CONDITION_SEVERITY_AT_LEAST;
  if (strcasecmp (name, "Severity changed") == 0)
    return ALERT_CONDITION_SEVERITY_CHANGED;
  return ALERT_CONDITION_ERROR;
}

/**
 * @brief Get an event from a name.
 *
 * @param[in]  name  Event name.
 *
 * @return The event.
 */
event_t
event_from_name (const char *name)
{
  if (strcasecmp (name, "Task run status changed") == 0)
    return EVENT_TASK_RUN_STATUS_CHANGED;
  if (strcasecmp (name, "New SecInfo arrived") == 0)
    return EVENT_NEW_SECINFO;
  if (strcasecmp (name, "Updated SecInfo arrived") == 0)
    return EVENT_UPDATED_SECINFO;
  if (strcasecmp (name, "Ticket received") == 0)
    return EVENT_TICKET_RECEIVED;
  if (strcasecmp (name, "Assigned ticket changed") == 0)
    return EVENT_ASSIGNED_TICKET_CHANGED;
  if (strcasecmp (name, "Owned ticket changed") == 0)
    return EVENT_OWNED_TICKET_CHANGED;
  return EVENT_ERROR;
}

/**
 * @brief Get an alert method from a name.
 *
 * @param[in]  name  Method name.
 *
 * @return The method.
 */
alert_method_t
alert_method_from_name (const char *name)
{
  if (strcasecmp (name, "Email") == 0)
    return ALERT_METHOD_EMAIL;
  if (strcasecmp (name, "HTTP Get") == 0)
    return ALERT_METHOD_HTTP_GET;
  if (strcasecmp (name, "SCP") == 0)
    return ALERT_METHOD_SCP;
  if (strcasecmp (name, "Send") == 0)
    return ALERT_METHOD_SEND;
  if (strcasecmp (name, "SMB") == 0)
    return ALERT_METHOD_SMB;
  if (strcasecmp (name, "SNMP") == 0)
    return ALERT_METHOD_SNMP;
  if (strcasecmp (name, "Sourcefire Connector") == 0)
    return ALERT_METHOD_SOURCEFIRE;
  if (strcasecmp (name, "Start Task") == 0)
    return ALERT_METHOD_START_TASK;
  if (strcasecmp (name, "Syslog") == 0)
    return ALERT_METHOD_SYSLOG;
  if (strcasecmp (name, "TippingPoint SMS") == 0)
    return ALERT_METHOD_TIPPINGPOINT;
  if (strcasecmp (name, "verinice Connector") == 0)
    return ALERT_METHOD_VERINICE;
  if (strcasecmp (name, "Alemba vFire") == 0)
    return ALERT_METHOD_VFIRE;
  return ALERT_METHOD_ERROR;
}

/* General task facilities. */

/**
 * @brief Get the name of a run status.
 *
 * @param[in]  status  Run status.
 *
 * @return The name of the status (for example, "Done" or "Running").
 */
const char *
run_status_name (task_status_t status)
{
  switch (status)
    {
    case TASK_STATUS_DELETE_REQUESTED:
    case TASK_STATUS_DELETE_WAITING:
      return "Delete Requested";
    case TASK_STATUS_DELETE_ULTIMATE_REQUESTED:
    case TASK_STATUS_DELETE_ULTIMATE_WAITING:
      return "Ultimate Delete Requested";
    case TASK_STATUS_DONE:
      return "Done";
    case TASK_STATUS_NEW:
      return "New";

    case TASK_STATUS_REQUESTED:
      return "Requested";

    case TASK_STATUS_RUNNING:
      return "Running";

    case TASK_STATUS_STOP_REQUESTED_GIVEUP:
    case TASK_STATUS_STOP_REQUESTED:
    case TASK_STATUS_STOP_WAITING:
      return "Stop Requested";

    case TASK_STATUS_STOPPED:
      return "Stopped";
    default:
      return "Interrupted";
    }
}

/**
 * @brief Get the unique name of a run status.
 *
 * @param[in]  status  Run status.
 *
 * @return The name of the status (for example, "Done" or "Running").
 */
const char *
run_status_name_internal (task_status_t status)
{
  switch (status)
    {
    case TASK_STATUS_DELETE_REQUESTED:
      return "Delete Requested";
    case TASK_STATUS_DELETE_ULTIMATE_REQUESTED:
      return "Ultimate Delete Requested";
    case TASK_STATUS_DELETE_ULTIMATE_WAITING:
      return "Ultimate Delete Waiting";
    case TASK_STATUS_DELETE_WAITING:
      return "Delete Waiting";
    case TASK_STATUS_DONE:
      return "Done";
    case TASK_STATUS_NEW:
      return "New";

    case TASK_STATUS_REQUESTED:
      return "Requested";

    case TASK_STATUS_RUNNING:
      return "Running";

    case TASK_STATUS_STOP_REQUESTED_GIVEUP:
    case TASK_STATUS_STOP_REQUESTED:
      return "Stop Requested";

    case TASK_STATUS_STOP_WAITING:
      return "Stop Waiting";

    case TASK_STATUS_STOPPED:
      return "Stopped";
    default:
      return "Interrupted";
    }
}

/**
 * @brief Get files to send.
 *
 * @param  task  Task of interest.
 *
 * @return List of files to send, (NULL if none), data has to be freed with
 *         g_free.
 */
static GSList *
get_files_to_send (task_t task)
{
  iterator_t files;
  GSList *filelist = NULL;

  init_task_file_iterator (&files, task, NULL);
  while (next (&files))
    {
      const gchar *file_path = task_file_iterator_name (&files);
      filelist = g_slist_append (filelist, g_strdup (file_path));
    }
  cleanup_iterator (&files);

  return filelist;
}

/**
 * @brief Return the plugins of a config, as a semicolon separated string.
 *
 * @param[in]  config  Config.
 *
 * @return A string of semi-colon separated plugin IDS.
 */
static gchar *
nvt_selector_plugins (config_t config)
{
  GString *plugins;
  iterator_t families, nvts;
  gboolean first;

  first = TRUE;
  plugins = g_string_new ("");

  init_family_iterator (&families, 0, NULL, 1);
  while (next (&families))
    {
      const char *family = family_iterator_name (&families);
      if (family)
        {
          init_nvt_iterator (&nvts, 0, config, family, NULL, 1, NULL);
          while (next (&nvts))
            {
              if (first)
                first = FALSE;
              else
                g_string_append_c (plugins, ';');
              g_string_append (plugins, nvt_iterator_oid (&nvts));
            }
          cleanup_iterator (&nvts);
        }
    }
  cleanup_iterator (&families);

  return g_string_free (plugins, FALSE);
}

/**
 * @brief Return the real value of a preference.
 *
 * Take care of radio button options.
 *
 * @param[in]  name        Name of preference.
 * @param[in]  full_value  Entire value of preference.
 *
 * @return Real value of the preference.
 */
static gchar *
preference_value (const char *name, const char *full_value)
{
  char *bracket = strchr (name, '[');
  if (bracket)
    {
      if (strncmp (bracket, "[radio]:", strlen ("[radio]:")) == 0)
        {
          char *semicolon = strchr (full_value, ';');
          if (semicolon)
            return g_strndup (full_value, semicolon - full_value);
        }
    }
  return g_strdup (full_value);
}

/**
 * @brief Send the preferences from a config to the scanner.
 *
 * @param[in]  config        Config.
 * @param[in]  section_name  Name of preference section to send.
 * @param[in]  task_files    Files associated with the task.
 * @param[out] pref_files    Files associated with config (UUID, contents, ...).
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_config_preferences (config_t config,
                         const char *section_name,
                         GSList *task_files,
                         GPtrArray *pref_files)
{
  iterator_t prefs;

  init_otp_pref_iterator (&prefs, config, section_name);
  while (next (&prefs))
    {
      const char *pref_name = otp_pref_iterator_name (&prefs);
      char *value;

      if (strcmp (pref_name, "port_range") == 0)
        continue;

      if (send_to_server (pref_name))
        {
          cleanup_iterator (&prefs);
          return -1;
        }

      if (sendn_to_server (" <|> ", 5))
        {
          cleanup_iterator (&prefs);
          return -1;
        }

      value = preference_value (pref_name, otp_pref_iterator_value (&prefs));

      if (pref_files)
        {
          int type_start = -1, type_end = -1, count;

          /* LDAPsearch[entry]:Timeout value */
          count =
            sscanf (pref_name, "%*[^[][%n%*[^]]%n]:", &type_start, &type_end);
          if (count == 0 && type_start > 0 && type_end > 0
              && (strncmp (
                    pref_name + type_start, "file", type_end - type_start)
                  == 0))
            {
              GSList *head;
              char *uuid;

              /* A "file" preference.
               *
               * If the value of the preference is empty, then send an empty
               * value.
               *
               * If the value of the preference is the name of a task file,
               * then just send the preference value, otherwise send a UUID and
               * add the value to the list of preference files (pref_files). */

              if (strcmp (value, "") == 0)
                {
                  g_free (value);
                  if (sendn_to_server ("\n", 1))
                    {
                      cleanup_iterator (&prefs);
                      return -1;
                    }
                  continue;
                }

              head = task_files;
              while (head)
                {
                  if (strcmp (head->data, value) == 0)
                    break;
                  head = g_slist_next (head);
                }

              if (head == NULL)
                {
                  uuid = gvm_uuid_make ();
                  if (uuid == NULL)
                    {
                      g_free (value);
                      cleanup_iterator (&prefs);
                      return -1;
                    }

                  g_ptr_array_add (pref_files, (gpointer) uuid);
                  g_ptr_array_add (pref_files, (gpointer) value);

                  if (send_to_server (uuid))
                    {
                      free (uuid);
                      g_free (value);
                      cleanup_iterator (&prefs);
                      return -1;
                    }

                  if (sendn_to_server ("\n", 1))
                    {
                      free (uuid);
                      g_free (value);
                      cleanup_iterator (&prefs);
                      return -1;
                    }

                  continue;
                }
            }
        }

      if (send_to_server (value))
        {
          g_free (value);
          cleanup_iterator (&prefs);
          return -1;
        }
      g_free (value);

      if (sendn_to_server ("\n", 1))
        {
          cleanup_iterator (&prefs);
          return -1;
        }
    }
  cleanup_iterator (&prefs);
  return 0;
}

/**
 * @brief Send task preferences to the scanner.
 *
 * @param[in]  task  Task.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_task_preferences (task_t task)
{
  gchar *value;

  value = task_preference_value (task, "max_checks");
  if (sendf_to_server ("max_checks <|> %s\n",
                       value ? value : MAX_CHECKS_DEFAULT))
    {
      g_free (value);
      return -1;
    }
  g_free (value);

  value = task_preference_value (task, "max_hosts");
  if (sendf_to_server ("max_hosts <|> %s\n", value ? value : MAX_HOSTS_DEFAULT))
    {
      g_free (value);
      return -1;
    }
  g_free (value);

  value = task_preference_value (task, "source_iface");
  if (value && sendf_to_server ("source_iface <|> %s\n", value))
    {
      g_free (value);
      return -1;
    }
  g_free (value);

  return 0;
}

/**
 * @brief Send ifaces_allow and ifaces_deny preferences to scanner.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_ifaces_access_preferences (void)
{
  char *ifaces;
  int ifaces_allow;

  ifaces = user_ifaces (current_credentials.uuid);
  ifaces_allow = user_ifaces_allow (current_credentials.uuid);

  if (ifaces && strlen (ifaces))
    {
      char *pref;

      if (ifaces_allow == 1)
        pref = "ifaces_allow";
      else if (ifaces_allow == 0)
        pref = "ifaces_deny";
      else
        {
          g_free (ifaces);
          return 0;
        }

      if (sendf_to_server ("%s <|> %s\n", pref, ifaces))
        {
          g_free (ifaces);
          return -1;
        }
    }
  g_free (ifaces);
  return 0;
}

/**
 * @brief Send ifaces_allow and ifaces_deny preferences to scanner.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_hosts_access_preferences (void)
{
  char *hosts;
  int hosts_allow;

  hosts = user_hosts (current_credentials.uuid);
  hosts_allow = user_hosts_allow (current_credentials.uuid);

  if (hosts && strlen (hosts))
    {
      char *pref;

      if (hosts_allow == 1)
        pref = "hosts_allow";
      else if (hosts_allow == 0)
        pref = "hosts_deny";
      else
        {
          g_free (hosts);
          return 0;
        }

      if (sendf_to_server ("%s <|> %s\n", pref, hosts))
        {
          g_free (hosts);
          return -1;
        }
    }
  g_free (hosts);
  return 0;
}

/**
 * @brief Gives a comma-separated list of a report's finished hosts.
 *
 * @param[in]  stopped_report  Report.
 *
 * @return String of finished hosts if found, NULL otherwise.
 */
static char *
finished_hosts_str (report_t stopped_report)
{
  iterator_t hosts;
  char *str = NULL;

  if (stopped_report == 0)
    return NULL;
  init_report_host_iterator (&hosts, stopped_report, NULL, 0);
  while (next (&hosts))
    {
      const char *end_time = host_iterator_end_time (&hosts);

      if (end_time && strlen (end_time))
        {
          char *new_str =
            str ? g_strdup_printf ("%s, %s", str, host_iterator_host (&hosts))
                : g_strdup_printf ("%s", host_iterator_host (&hosts));
          g_free (str);
          str = new_str;
        }
    }
  return str;
}

/**
 * @brief Send some scanner preferences to the scanner.
 *
 * @param[in]  task            Task.
 * @param[in]  target          Scan target.
 * @param[in]  stopped_report  Previously stopped report, if any, else 0.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_scanner_preferences (task_t task, target_t target, report_t stopped_report)
{
  char *hosts_ordering, *exclude_hosts, *reverse_lookup_only;
  char *reverse_lookup_unify;

  /* Send ifaces_allow / ifaces_deny preferences. */
  if (send_ifaces_access_preferences ())
    return -1;

  /* Send hosts_allow / hosts_deny preferences. */
  if (send_hosts_access_preferences ())
    return -1;

  /* Send hosts_ordering preference. */
  hosts_ordering = task_hosts_ordering (task);
  if (hosts_ordering)
    {
      if (sendf_to_server ("hosts_ordering <|> %s\n", hosts_ordering))
        {
          free (hosts_ordering);
          return -1;
        }
      free (hosts_ordering);
    }

  /* Send exclude_hosts preference. */
  exclude_hosts = target_exclude_hosts (target);
  if (exclude_hosts)
    {
      char *finished, *str;

      finished = finished_hosts_str (stopped_report);
      if (finished)
        {
          str = g_strdup_printf ("%s, %s", exclude_hosts, finished);
          g_free (exclude_hosts);
          g_free (finished);
          exclude_hosts = str;
        }
    }
  else
    exclude_hosts = finished_hosts_str (stopped_report);

  if (exclude_hosts)
    {
      if (sendf_to_server ("exclude_hosts <|> %s\n", exclude_hosts))
        {
          free (exclude_hosts);
          return -1;
        }
      free (exclude_hosts);
    }

  /* Send reverse_lookup_only preference. */
  reverse_lookup_only = target_reverse_lookup_only (target);
  if (reverse_lookup_only == NULL || strcmp (reverse_lookup_only, "0") == 0)
    reverse_lookup_only = "no";
  else
    reverse_lookup_only = "yes";
  if (sendf_to_server ("reverse_lookup_only <|> %s\n", reverse_lookup_only))
    return -1;

  /* Send reverse_lookup_unify preference. */
  reverse_lookup_unify = target_reverse_lookup_unify (target);
  if (reverse_lookup_unify == NULL || strcmp (reverse_lookup_unify, "0") == 0)
    reverse_lookup_unify = "no";
  else
    reverse_lookup_unify = "yes";
  if (sendf_to_server ("reverse_lookup_unify <|> %s\n", reverse_lookup_unify))
    return -1;

  return 0;
}

/**
 * @brief Send a file to the scanner.
 *
 * @param[in]  name     File name.
 * @param[in]  content  File contents.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_file (const char *name, const char *content)
{
  size_t content_len = strlen (content);

  if (sendf_to_server ("CLIENT <|> ATTACHED_FILE\n"
                       "name: %s\n"
                       "content: octet/stream\n"
                       "bytes: %i\n",
                       name,
                       content_len))
    return -1;

  if (sendn_to_server (content, content_len))
    return -1;

  return 0;
}

/**
 * @brief Send a file from a task to the scanner.
 *
 * @param[in]  task  The task.
 * @param[in]  file  File name.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_task_file (task_t task, const char *file)
{
  iterator_t files;

  init_task_file_iterator (&files, task, file);
  while (next (&files))
    {
      gsize content_len;
      guchar *content;
      const char *content_64 = task_file_iterator_content (&files);

      content = g_base64_decode (content_64, &content_len);

      if (sendf_to_server ("CLIENT <|> ATTACHED_FILE\n"
                           "name: %s\n"
                           "content: octet/stream\n"
                           "bytes: %i\n",
                           file,
                           content_len))
        {
          g_free (content);
          cleanup_iterator (&files);
          return -1;
        }

      if (sendn_to_server (content, content_len))
        {
          g_free (content);
          cleanup_iterator (&files);
          return -1;
        }
      g_free (content);
    }
  cleanup_iterator (&files);
  return 0;
}

/**
 * @brief Send target "Alive Test" preferences to the scanner.
 *
 * @param[in]  target   Scan target.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_alive_test_preferences (target_t target)
{
  alive_test_t alive_test;

  alive_test = target_alive_tests (target);

  if (alive_test == 0)
    return 0;

  if (sendf_to_server ("Ping Host[checkbox]:Do a TCP ping <|> %s\n",
                       alive_test & ALIVE_TEST_TCP_ACK_SERVICE
                           || alive_test & ALIVE_TEST_TCP_SYN_SERVICE
                         ? "yes"
                         : "no"))
    return -1;

  if (sendf_to_server ("Ping Host[checkbox]:TCP ping tries also TCP-SYN ping"
                       " <|> %s\n",
                       ((alive_test & ALIVE_TEST_TCP_SYN_SERVICE)
                        && (alive_test & ALIVE_TEST_TCP_ACK_SERVICE))
                         ? "yes"
                         : "no"))
    return -1;

  if (sendf_to_server ("Ping Host[checkbox]:TCP ping tries only TCP-SYN ping"
                       " <|> %s\n",
                       ((alive_test & ALIVE_TEST_TCP_SYN_SERVICE)
                        && !(alive_test & ALIVE_TEST_TCP_ACK_SERVICE))
                         ? "yes"
                         : "no"))
    return -1;

  if (sendf_to_server ("Ping Host[checkbox]:Do an ICMP ping <|> %s\n",
                       (alive_test & ALIVE_TEST_ICMP) ? "yes" : "no"))
    return -1;

  if (sendf_to_server ("Ping Host[checkbox]:Use ARP <|> %s\n",
                       (alive_test & ALIVE_TEST_ARP) ? "yes" : "no"))
    return -1;

  if (sendf_to_server ("Ping Host[checkbox]:"
                       "Mark unrechable Hosts as dead (not scanning) <|> %s\n",
                       (alive_test & ALIVE_TEST_CONSIDER_ALIVE) ? "no" : "yes"))
    return -1;

  if (alive_test == ALIVE_TEST_CONSIDER_ALIVE)
    {
      /* Also select a method, otherwise Ping Host logs a warning. */
      if (sendf_to_server ("Ping Host[checkbox]:Do a TCP ping <|> yes\n"))
        return -1;
    }

  return 0;
}

/** @todo g_convert back to ISO-8559-1 for scanner? */

/* Slave tasks. */

/* Defined in gmp.c. */
void
buffer_config_preference_xml (GString *, iterator_t *, config_t, int);

/**
 * @brief Number of seconds to sleep between polls to slave.
 */
#define RUN_SLAVE_TASK_SLEEP_SECONDS 25

/**
 * @brief Slave credential UUID.
 */
static gchar *global_slave_ssh_credential_uuid = NULL;

/**
 * @brief Slave credential UUID.
 */
static gchar *global_slave_smb_credential_uuid = NULL;

/**
 * @brief Slave credential UUID.
 */
static gchar *global_slave_esxi_credential_uuid = NULL;

/**
 * @brief Slave credential UUID.
 */
static gchar *global_slave_snmp_credential_uuid = NULL;

/**
 * @brief Slave target UUID.
 */
static gchar *global_slave_target_uuid = NULL;

/**
 * @brief Slave target UUID.
 */
static gchar *global_slave_port_list_uuid = NULL;

/**
 * @brief Slave config UUID.
 */
static gchar *global_slave_config_uuid = NULL;

/**
 * @brief Slave task UUID.
 */
static gchar *global_slave_task_uuid = NULL;

/**
 * @brief Slave report UUID.
 */
static gchar *global_slave_report_uuid = NULL;

/**
 * @brief Slave session.
 */
static gvm_connection_t *global_slave_connection = NULL;

/**
 * @brief Update the locally cached task progress from the slave.
 *
 * @param[in]  get_tasks  Slave GET_TASKS response.
 *
 * @return 0 success, -1 error.
 */
static int
update_slave_progress (entity_t get_tasks)
{
  entity_t entity;

  entity = entity_child (get_tasks, "task");
  if (entity == NULL)
    return -1;
  entity = entity_child (entity, "progress");
  if (entity == NULL)
    return -1;

  if (global_current_report == 0)
    return -1;

  set_report_slave_progress (global_current_report,
                             atoi (entity_text (entity)));

  return 0;
}

/**
 * @brief Authenticate with a slave.
 *
 * @param[in]  connection  Connection.
 *
 * @return 0 success, -1 error.
 */
static int
connection_authenticate (gvm_connection_t *connection)
{
  gmp_authenticate_info_opts_t auth_opts;

  auth_opts = gmp_authenticate_info_opts_defaults;
  auth_opts.username = connection->username;
  auth_opts.password = connection->password;
  if (gmp_authenticate_info_ext_c (connection, auth_opts))
    return -1;
  return 0;
}

/**
 * @brief Authenticate with a slave.
 *
 * @param[in]  session  GNUTLS session.
 * @param[in]  slave    Slave.
 *
 * @return 0 success, -1 error.
 */
static int
slave_authenticate (gnutls_session_t *session, scanner_t slave)
{
  int ret;
  gchar *login, *password;

  login = scanner_login (slave);
  if (login == NULL)
    return -1;

  password = scanner_password (slave);
  if (password == NULL)
    {
      g_free (login);
      return -1;
    }

  ret = gmp_authenticate (session, login, password);
  g_free (login);
  g_free (password);
  if (ret)
    return -1;
  return 0;
}

/**
 * @brief Connect to a slave.
 *
 * @param[in]  connection  Connection.
 *
 * @return 0 success, -1 error, 1 auth failure.
 */
static int
slave_connect (gvm_connection_t *connection)
{
  char *ca_cert;

  connection->tls = 1;
  if (connection->ca_cert == NULL)
    ca_cert = manage_default_ca_cert ();
  else
    ca_cert = NULL;
  connection->socket =
    gvm_server_open_verify (&connection->session,
                            connection->host_string,
                            connection->port,
                            ca_cert ? ca_cert : connection->ca_cert,
                            connection->pub_key,
                            connection->priv_key,
                            1);
  if (connection->socket == -1)
    {
      g_warning ("%s: failed to open connection to %s on %i",
                 __FUNCTION__,
                 connection->host_string,
                 connection->port);
      return -1;
    }

  {
    int optval;
    optval = 1;
    if (setsockopt (
          connection->socket, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof (int)))
      {
        g_warning ("%s: failed to set SO_KEEPALIVE on slave socket: %s",
                   __FUNCTION__,
                   strerror (errno));
        gvm_connection_close (connection);
        return -1;
      }
  }

  g_debug ("   %s: connected", __FUNCTION__);

  /* Authenticate using the slave login. */

  if (connection_authenticate (connection))
    {
      gvm_connection_close (connection);
      return 1;
    }

  g_debug ("   %s: authenticated", __FUNCTION__);

  return 0;
}

/**
 * @brief Sleep then connect to slave.  Retry until success or giveup requested.
 *
 * @param[in]  connection  Connection.
 * @param[in]  task        Local task.
 *
 * @return 0 success, 3 giveup.
 */
static int
slave_sleep_connect (gvm_connection_t *connection, task_t task)
{
  do
    {
      if ((task_run_status (task) == TASK_STATUS_STOP_REQUESTED_GIVEUP)
          || (task_run_status (task) == TASK_STATUS_STOP_REQUESTED))
        {
          if (task_run_status (task) == TASK_STATUS_STOP_REQUESTED_GIVEUP)
            g_debug ("   %s: task stopped for giveup", __FUNCTION__);
          else
            g_debug ("   %s: task stopped", __FUNCTION__);
          set_task_run_status (current_scanner_task, TASK_STATUS_STOPPED);
          return 3;
        }
      g_debug (
        "   %s: sleeping for %i", __FUNCTION__, RUN_SLAVE_TASK_SLEEP_SECONDS);
      gvm_sleep (RUN_SLAVE_TASK_SLEEP_SECONDS);
    }
  while (slave_connect (connection));
  g_debug ("   %s: connected", __FUNCTION__);
  return 0;
}

/**
 * @brief Update end times, and optionally add host details.
 *
 * @param[in]  report            Report.
 *
 * @return 0 success, -1 error.
 */
static int
update_end_times (entity_t report)
{
  entity_t end;
  entities_t entities;

  /* Set the scan end time. */

  entities = report->entities;
  while ((end = first_entity (entities)))
    {
      if (strcmp (entity_name (end), "scan_end") == 0)
        {
          char *text;
          text = entity_text (end);
          while (*text && isspace (*text))
            text++;
          if (*text == '\0')
            break;
          set_task_end_time (current_scanner_task,
                             g_strdup (entity_text (end)));
          set_scan_end_time (global_current_report, entity_text (end));
          break;
        }
      entities = next_entities (entities);
    }

  /* Add host details and set the host end times. */

  entities = report->entities;
  while ((end = first_entity (entities)))
    {
      if (strcmp (entity_name (end), "host") == 0)
        {
          entity_t ip, time;
          char *text;

          ip = entity_child (end, "ip");
          if (ip == NULL)
            return -1;

          time = entity_child (end, "end");
          if (time == NULL)
            return -1;

          text = entity_text (time);
          while (*text && isspace (*text))
            text++;
          if ((*text != '\0')
              && (scan_host_end_time (global_current_report, entity_text (ip))
                  == 0))
            {
              set_scan_host_end_time (
                global_current_report, entity_text (ip), entity_text (time));
              if (manage_report_host_details (
                    global_current_report, entity_text (ip), end))
                return -1;
            }
        }

      entities = next_entities (entities);
    }

  return 0;
}

/**
 * @brief Cleanup slave.  Callback for atexit.
 */
static void
cleanup_slave ()
{
  if (global_slave_connection)
    {
      if (global_slave_task_uuid)
        gmp_stop_task (&global_slave_connection->session,
                       global_slave_task_uuid);
      gvm_connection_close (global_slave_connection);
    }
}

/**
 * @brief Get last report from GET_TASKS response.
 *
 * @param[in]  get_tasks  GET_TASKS response.
 *
 * @return Freshly allocated UUID of last report, or NULL.
 */
static gchar *
get_tasks_last_report (entity_t get_tasks)
{
  entity_t task;
  task = entity_child (get_tasks, "task");
  if (task)
    {
      entity_t get_tasks_current_report;
      get_tasks_current_report = entity_child (task, "current_report");
      if (global_current_report)
        {
          entity_t report;
          report = entity_child (get_tasks_current_report, "report");
          if (report && entity_attribute (report, "id"))
            return g_strdup (entity_attribute (report, "id"));
        }
      else
        {
          entity_t last_report;
          last_report = entity_child (task, "last_report");
          if (last_report)
            {
              entity_t report;
              report = entity_child (last_report, "report");
              if (report && entity_attribute (report, "id"))
                return g_strdup (entity_attribute (report, "id"));
            }
        }
    }
  return NULL;
}

/**
 * @brief Setup ID variables for slave_setup.
 *
 * @param[in]   connection  Connection to slave.
 * @param[in]   task        The task.
 * @param[in]   get_tasks   GET_TASKS response.
 * @param[out]  slave_config_uuid           UUID of slave config.
 * @param[out]  slave_target_uuid           UUID of slave target.
 * @param[out]  slave_port_list_uuid        UUID of slave port list.
 * @param[out]  slave_ssh_credential_uuid   UUID of slave SSH credential.
 * @param[out]  slave_smb_credential_uuid   UUID of slave SMB credential.
 * @param[out]  slave_esxi_credential_uuid  UUID of slave ESXi credential.
 * @param[out]  slave_snmp_credential_uuid  UUID of slave SNMP credential.
 *
 * @return 0 success, 1 giveup.
 */
static int
setup_ids (gvm_connection_t *connection,
           task_t task,
           entity_t get_tasks,
           gchar **slave_config_uuid,
           gchar **slave_target_uuid,
           gchar **slave_port_list_uuid,
           gchar **slave_ssh_credential_uuid,
           gchar **slave_smb_credential_uuid,
           gchar **slave_esxi_credential_uuid,
           gchar **slave_snmp_credential_uuid)
{
  entity_t get_tasks_task;

  assert (slave_config_uuid);
  assert (slave_target_uuid);
  assert (slave_port_list_uuid);
  assert (slave_ssh_credential_uuid);
  assert (slave_smb_credential_uuid);
  assert (slave_esxi_credential_uuid);
  assert (slave_snmp_credential_uuid);

  get_tasks_task = entity_child (get_tasks, "task");
  if (get_tasks_task)
    {
      entity_t entity;

      entity = entity_child (get_tasks_task, "config");
      if (entity && entity_attribute (entity, "id"))
        *slave_config_uuid = g_strdup (entity_attribute (entity, "id"));

      entity = entity_child (get_tasks_task, "target");
      if (entity && entity_attribute (entity, "id"))
        *slave_target_uuid = g_strdup (entity_attribute (entity, "id"));

      if (*slave_target_uuid)
        {
          entity_t get_targets;
          int ret;

          while (
            (ret = gmp_get_targets (
               &connection->session, *slave_target_uuid, 0, 0, &get_targets)))
            {
              if (ret == 404)
                {
                  /* Target missing. */
                  break;
                }
              else if (ret)
                {
                  gvm_connection_close (connection);
                  ret = slave_sleep_connect (connection, task);
                  if (ret == 3)
                    return 1;
                }
            }
          if (ret == 0)
            {
              entity_t target;
              target = entity_child (get_targets, "target");
              if (target)
                {
                  entity = entity_child (target, "port_list");
                  if (entity && entity_attribute (entity, "id"))
                    *slave_port_list_uuid =
                      g_strdup (entity_attribute (entity, "id"));

                  entity = entity_child (target, "ssh_credential");
                  if (entity && entity_attribute (entity, "id"))
                    *slave_ssh_credential_uuid =
                      g_strdup (entity_attribute (entity, "id"));

                  entity = entity_child (target, "smb_credential");
                  if (entity && entity_attribute (entity, "id"))
                    *slave_smb_credential_uuid =
                      g_strdup (entity_attribute (entity, "id"));

                  entity = entity_child (target, "esxi_credential");
                  if (entity && entity_attribute (entity, "id"))
                    *slave_esxi_credential_uuid =
                      g_strdup (entity_attribute (entity, "id"));

                  entity = entity_child (target, "snmp_credential");
                  if (entity && entity_attribute (entity, "id"))
                    *slave_snmp_credential_uuid =
                      g_strdup (entity_attribute (entity, "id"));
                }
              free_entity (get_targets);
            }
        }
    }
  return 0;
}

/**
 * @brief Set a task to interrupted.
 *
 * Expects global_current_report to match the task.
 *
 * @param[in]   task     Task
 * @param[in]   message  Message for error result.
 */
void
set_task_interrupted (task_t task, const gchar *message)
{
  set_task_run_status (task, TASK_STATUS_INTERRUPTED);
  if (global_current_report)
    {
      result_t result;
      result = make_result (task, "", "", "", "", "Error Message", message);
      report_add_result (global_current_report, result);
    }
}

/**
 * @brief Setup a task on a slave.
 *
 * @param[in]   connection  Connection to slave.
 * @param[in]   name        Name of task on slave.
 * @param[in]   task        The task.
 * @param[out]  target      Task target.
 * @param[out]  target_ssh_credential    Target SSH credential.
 * @param[out]  target_smb_credential    Target SMB credential.
 * @param[out]  target_esxi_credential    Target ESXi credential.
 * @param[out]  target_snmp_credential    Target SNMP credential.
 * @param[out]  last_stopped_report  Last stopped report if any, else 0.
 *
 * @return 0 success, 1 retry, 3 giveup.
 */
static int
slave_setup (gvm_connection_t *connection,
             const char *name,
             task_t task,
             target_t target,
             credential_t target_ssh_credential,
             credential_t target_smb_credential,
             credential_t target_esxi_credential,
             credential_t target_snmp_credential,
             report_t last_stopped_report)
{
  const int ret_giveup = 3;
  int ret_fail, next_result;
  iterator_t credentials, targets;
  gmp_delete_opts_t del_opts;

  ret_fail = 1;
  del_opts = gmp_delete_opts_ultimate_defaults;
  global_slave_connection = connection;

  /* Register a cleanup callback to stop the slave task if the process is
   * killed, for example by a reboot.  On restart Manager will set the task
   * status to Stopped, which will match the slave. */
  if (atexit (&cleanup_slave))
    {
      g_critical ("%s: failed to register `atexit' slave_cleanup function",
                  __FUNCTION__);
      goto fail;
    }

  if (last_stopped_report)
    {
      /* Resume the task on the slave. */

      global_slave_task_uuid = report_slave_task_uuid (last_stopped_report);
      if (global_slave_task_uuid == NULL)
        {
          /* This may happen if someone sets a slave on a local task.  Clear
           * all the report results and start the task from the beginning.  */
          trim_report (last_stopped_report);
          last_stopped_report = 0;
        }
      else
        {
          int ret;
          entity_t get_tasks;
          const char *status;

          /* Check if the task is running or complete on the slave. */

          while (
            (ret = gmp_get_tasks (
               &connection->session, global_slave_task_uuid, 0, 0, &get_tasks)))
            {
              if (ret == 404)
                {
                  /* Task missing.  Perhaps someone removed the task on the
                   * slave. Clear all the report results and start the task from
                   * the beginning. */
                  trim_report (last_stopped_report);
                  last_stopped_report = 0;
                  break;
                }
              else if (ret)
                {
                  gvm_connection_close (connection);
                  ret = slave_sleep_connect (connection, task);
                  if (ret == 3)
                    goto giveup;
                }
            }

          if (ret == 0)
            {
              status = gmp_task_status (get_tasks);
              if (status == NULL)
                {
                  /* An error somewhere.  Clear all the report results and
                   * start the task from the beginning. */
                  trim_report (last_stopped_report);
                  last_stopped_report = 0;
                }
              else if ((strcmp (status, "Running") == 0)
                       || (strcmp (status, "Done") == 0))
                {
                  /* Task on slave is Running or Done, continue using it as
                   * is. */

                  global_slave_report_uuid = get_tasks_last_report (get_tasks);
                  if (global_slave_report_uuid == NULL)
                    {
                      g_warning ("%s: slave report %s missing UUID",
                                 __FUNCTION__,
                                 global_slave_task_uuid);
                      goto fail;
                    }

                  setup_ids (connection,
                             task,
                             get_tasks,
                             &global_slave_config_uuid,
                             &global_slave_target_uuid,
                             &global_slave_port_list_uuid,
                             &global_slave_ssh_credential_uuid,
                             &global_slave_smb_credential_uuid,
                             &global_slave_esxi_credential_uuid,
                             &global_slave_snmp_credential_uuid);
                }
              else
                {
                  /* Task is there, try resume it. */
                  switch (gmp_resume_task_report (&connection->session,
                                                  global_slave_task_uuid,
                                                  &global_slave_report_uuid))
                    {
                    case 0:
                      if (global_slave_report_uuid == NULL)
                        goto fail;
                      setup_ids (connection,
                                 task,
                                 get_tasks,
                                 &global_slave_config_uuid,
                                 &global_slave_target_uuid,
                                 &global_slave_port_list_uuid,
                                 &global_slave_ssh_credential_uuid,
                                 &global_slave_smb_credential_uuid,
                                 &global_slave_esxi_credential_uuid,
                                 &global_slave_snmp_credential_uuid);
                      set_task_run_status (task, TASK_STATUS_REQUESTED);
                      break;
                    case 1:
                      /* The resume may have failed because the task slave
                       * changed or because someone removed the task on the
                       * slave.  Clear all the report results and start the task
                       * from the beginning.
                       *
                       * This and the if above both "leak" the resources on the
                       * slave, because on the report these resources are
                       * replaced with the new resources. */
                      trim_report (last_stopped_report);
                      last_stopped_report = 0;
                      break;
                    default:
                      free (global_slave_task_uuid);
                      goto fail;
                    }
                }
            }
        }
    }

  if (last_stopped_report == 0)
    {
      /* Create the target credentials on the slave. */

      if (target_ssh_credential)
        {
          init_credential_iterator_one (&credentials, target_ssh_credential);
          if (next (&credentials))
            {
              int ret;
              const char *user, *password, *private_key;
              gchar *user_copy, *password_copy, *private_key_copy;
              gmp_create_lsc_credential_opts_t opts;

              user = credential_iterator_login (&credentials);
              password = credential_iterator_password (&credentials);
              private_key = credential_iterator_private_key (&credentials);

              if (user == NULL || (private_key == NULL && password == NULL))
                {
                  cleanup_iterator (&credentials);
                  global_slave_ssh_credential_uuid = NULL;
                  g_warning ("Could not create slave SSH credential"
                             " (needs login and password or private key)."
                             " Continuing without credential.");
                }
              else
                {
                  user_copy = g_strdup (user);
                  password_copy = g_strdup (password);

                  opts = gmp_create_lsc_credential_opts_defaults;
                  opts.name = name;
                  opts.login = user_copy;
                  opts.passphrase = password_copy;
                  if (private_key)
                    {
                      private_key_copy = g_strdup (private_key);
                      opts.private_key = private_key_copy;
                    }
                  else
                    private_key_copy = NULL;
                  opts.comment = "Slave SSH credential created by Master";

                  cleanup_iterator (&credentials);

                  ret = gmp_create_lsc_credential_ext (
                    &connection->session,
                    opts,
                    &global_slave_ssh_credential_uuid);

                  g_free (user_copy);
                  g_free (password_copy);
                  g_free (private_key_copy);

                  if (ret)
                    {
                      g_warning ("Could not create slave SSH credential"
                                 " (status %d)."
                                 " Continuing without credential.",
                                 ret);
                      global_slave_ssh_credential_uuid = NULL;
                    }
                }
            }
        }

      if (target_smb_credential)
        {
          init_credential_iterator_one (&credentials, target_smb_credential);
          if (next (&credentials))
            {
              int ret;
              const char *user, *password;
              gchar *user_copy, *password_copy, *smb_name;
              gmp_create_lsc_credential_opts_t opts;

              user = credential_iterator_login (&credentials);
              password = credential_iterator_password (&credentials);

              if (user == NULL || password == NULL)
                {
                  cleanup_iterator (&credentials);
                  global_slave_smb_credential_uuid = NULL;
                  g_warning ("Could not create slave SMB credential"
                             " (missing login or password)."
                             " Continuing without credential.");
                }
              else
                {
                  user_copy = g_strdup (user);
                  password_copy = g_strdup (password);

                  opts = gmp_create_lsc_credential_opts_defaults;
                  smb_name = g_strdup_printf ("%ssmb", name);
                  opts.name = smb_name;
                  opts.login = user_copy;
                  opts.passphrase = password_copy;
                  opts.comment = "Slave SMB credential created by Master";

                  cleanup_iterator (&credentials);

                  ret = gmp_create_lsc_credential_ext (
                    &connection->session,
                    opts,
                    &global_slave_smb_credential_uuid);

                  g_free (smb_name);
                  g_free (user_copy);
                  g_free (password_copy);

                  if (ret)
                    {
                      g_warning ("Could not create slave SMB credential"
                                 " (status %d)."
                                 " Continuing without credential.",
                                 ret);
                      global_slave_smb_credential_uuid = NULL;
                    }
                }
            }
        }

      if (target_esxi_credential)
        {
          init_credential_iterator_one (&credentials, target_esxi_credential);
          if (next (&credentials))
            {
              int ret;
              const char *user, *password;
              gchar *user_copy, *password_copy, *esxi_name;
              gmp_create_lsc_credential_opts_t opts;

              user = credential_iterator_login (&credentials);
              password = credential_iterator_password (&credentials);

              if (user == NULL || password == NULL)
                {
                  cleanup_iterator (&credentials);
                  global_slave_esxi_credential_uuid = NULL;
                  g_warning ("Could not create slave ESXi credential"
                             " (missing login or password)."
                             " Continuing without credential.");
                }
              else
                {
                  user_copy = g_strdup (user);
                  password_copy = g_strdup (password);

                  opts = gmp_create_lsc_credential_opts_defaults;
                  esxi_name = g_strdup_printf ("%sesxi", name);
                  opts.name = esxi_name;
                  opts.login = user_copy;
                  opts.passphrase = password_copy;
                  opts.comment = "Slave ESXi credential created by Master";

                  cleanup_iterator (&credentials);

                  ret = gmp_create_lsc_credential_ext (
                    &connection->session,
                    opts,
                    &global_slave_esxi_credential_uuid);

                  g_free (esxi_name);
                  g_free (user_copy);
                  g_free (password_copy);
                  if (ret)
                    {
                      g_warning ("Could not create slave ESXi credential"
                                 " (status %d)."
                                 " Continuing without credential.",
                                 ret);
                      global_slave_esxi_credential_uuid = NULL;
                    }
                }
            }
        }

      if (target_snmp_credential)
        {
          init_credential_iterator_one (&credentials, target_snmp_credential);
          if (next (&credentials))
            {
              int ret;
              const char *community, *user, *password, *auth_algorithm;
              const char *privacy_password, *privacy_algorithm;
              gchar *community_copy, *user_copy, *password_copy;
              gchar *auth_algorithm_copy, *privacy_password_copy;
              gchar *privacy_algorithm_copy, *snmp_name;
              gmp_create_lsc_credential_opts_t opts;

              community = credential_iterator_community (&credentials);
              user = credential_iterator_login (&credentials);
              password = credential_iterator_password (&credentials);
              auth_algorithm =
                credential_iterator_auth_algorithm (&credentials);
              privacy_password =
                credential_iterator_privacy_password (&credentials);
              privacy_algorithm =
                credential_iterator_privacy_algorithm (&credentials);

              if (password && strcmp (password, "")
                  && (auth_algorithm == NULL || strcmp (auth_algorithm, "")))
                {
                  cleanup_iterator (&credentials);
                  global_slave_snmp_credential_uuid = NULL;
                  g_warning ("Could not create slave SNMP credential"
                             " (auth_algorithm must be set if password is"
                             " given)."
                             " Continuing without credential.");
                }
              else if (((privacy_password && strcmp (privacy_password, ""))
                        || (privacy_algorithm
                            && strcmp (privacy_algorithm, "")))
                       && (password == NULL || auth_algorithm == NULL
                           || privacy_password == NULL
                           || privacy_algorithm == NULL))
                {
                  cleanup_iterator (&credentials);
                  global_slave_snmp_credential_uuid = NULL;
                  g_warning ("Could not create slave SNMP credential"
                             " (password, auth_algorithm, privacy_password"
                             " and privacy_algorithm are mandatory if"
                             " privacy_password or privacy_algorithm are"
                             " given)."
                             " Continuing without credential.");
                }
              else
                {
                  community_copy = g_strdup (community ? community : "");
                  user_copy = g_strdup (user ? user : "");
                  password_copy = g_strdup (password ? password : "");
                  auth_algorithm_copy =
                    g_strdup (auth_algorithm ? auth_algorithm : "");
                  privacy_password_copy =
                    g_strdup (privacy_password ? privacy_password : "");
                  privacy_algorithm_copy =
                    g_strdup (privacy_algorithm ? privacy_algorithm : "");

                  opts = gmp_create_lsc_credential_opts_defaults;
                  snmp_name = g_strdup_printf ("%ssnmp", name);
                  opts.name = snmp_name;
                  opts.community = community_copy;
                  opts.login = user_copy;
                  opts.passphrase = password_copy;
                  opts.auth_algorithm = auth_algorithm_copy;
                  opts.privacy_password = privacy_password_copy;
                  opts.privacy_algorithm = privacy_algorithm_copy;
                  opts.comment = "Slave SNMP credential created by Master";

                  cleanup_iterator (&credentials);

                  ret = gmp_create_lsc_credential_ext (
                    &connection->session,
                    opts,
                    &global_slave_snmp_credential_uuid);

                  g_free (snmp_name);
                  g_free (community_copy);
                  g_free (user_copy);
                  g_free (password_copy);
                  g_free (auth_algorithm_copy);
                  g_free (privacy_password_copy);
                  g_free (privacy_algorithm_copy);
                  if (ret)
                    {
                      g_warning ("Could not create slave SNMP credential"
                                 " (status %d)."
                                 " Continuing without credential",
                                 ret);
                      global_slave_snmp_credential_uuid = NULL;
                    }
                }
            }
        }

      g_debug ("   %s: slave SSH credential uuid: %s",
               __FUNCTION__,
               global_slave_ssh_credential_uuid);

      g_debug ("   %s: slave SMB credential uuid: %s",
               __FUNCTION__,
               global_slave_smb_credential_uuid);

      g_debug ("   %s: slave ESXi credential uuid: %s",
               __FUNCTION__,
               global_slave_esxi_credential_uuid);

      g_debug ("   %s: slave SNMP credential uuid: %s",
               __FUNCTION__,
               global_slave_snmp_credential_uuid);

      /* Create the target on the slave. */

      init_target_iterator_one (&targets, target);
      if (next (&targets))
        {
          int ret;
          const char *hosts, *port, *exclude_hosts, *alive_tests;
          const char *reverse_lookup_only, *reverse_lookup_unify;
          const char *port_list_uuid;
          gchar *hosts_copy, *exclude_hosts_copy;
          gchar *alive_tests_copy, *port_range;
          gmp_create_target_opts_t opts;
          int ssh_port;
          entity_t get_targets, child;

          hosts = target_iterator_hosts (&targets);
          exclude_hosts = target_iterator_exclude_hosts (&targets);
          alive_tests = target_iterator_alive_tests (&targets);
          reverse_lookup_only = target_iterator_reverse_lookup_only (&targets);
          reverse_lookup_unify =
            target_iterator_reverse_lookup_unify (&targets);
          if (hosts == NULL)
            {
              cleanup_iterator (&targets);
              goto fail_credentials;
            }

          port = target_iterator_ssh_port (&targets);
          if (port == NULL)
            ssh_port = 0;
          else
            ssh_port = atoi (port);

          hosts_copy = g_strdup (hosts);
          exclude_hosts_copy = g_strdup (exclude_hosts);
          alive_tests_copy = g_strdup (alive_tests);
          port_range = target_port_range (get_iterator_resource (&targets));
          cleanup_iterator (&targets);

          opts = gmp_create_target_opts_defaults;
          opts.hosts = hosts_copy;
          opts.exclude_hosts = exclude_hosts_copy;
          opts.alive_tests = alive_tests_copy;
          opts.ssh_credential_id = global_slave_ssh_credential_uuid;
          opts.ssh_credential_port = ssh_port;
          opts.smb_credential_id = global_slave_smb_credential_uuid;
          opts.esxi_credential_id = global_slave_esxi_credential_uuid;
          opts.snmp_credential_id = global_slave_snmp_credential_uuid;
          opts.port_range = port_range;
          opts.name = name;
          opts.comment = "Slave target created by Master";
          opts.reverse_lookup_only =
            reverse_lookup_only ? atoi (reverse_lookup_only) : 0;
          opts.reverse_lookup_unify =
            reverse_lookup_unify ? atoi (reverse_lookup_unify) : 0;

          ret = gmp_create_target_ext (
            &connection->session, opts, &global_slave_target_uuid);
          g_free (hosts_copy);
          g_free (exclude_hosts_copy);
          g_free (alive_tests_copy);
          g_free (port_range);
          if (ret == -2)
            goto fail_credentials;
          if (ret)
            {
              set_task_interrupted (task,
                                    "Failed to create target on slave."
                                    "  Interrupting scan.");
              ret_fail = ret_giveup;
              goto fail_credentials;
            }

          if (gmp_get_targets (&connection->session,
                               global_slave_target_uuid,
                               0,
                               0,
                               &get_targets))
            goto fail_target;
          child = entity_child (get_targets, "target");
          if (child == NULL)
            {
              free_entity (get_targets);
              goto fail_target;
            }
          child = entity_child (child, "port_list");
          if (child == NULL)
            {
              free_entity (get_targets);
              goto fail_target;
            }
          port_list_uuid = entity_attribute (child, "id");
          if (port_list_uuid == NULL)
            {
              free_entity (get_targets);
              goto fail_target;
            }
          global_slave_port_list_uuid = g_strdup (port_list_uuid);
          free_entity (get_targets);
        }
      else
        {
          cleanup_iterator (&targets);
          goto fail_credentials;
        }

      g_debug (
        "   %s: slave target uuid: %s", __FUNCTION__, global_slave_target_uuid);

      /* Create the config on the slave. */

      {
        config_t config;
        iterator_t prefs, selectors;

        /* This must follow the GET_CONFIGS_RESPONSE export case. */

        config = task_config (task);
        if (config == 0)
          goto fail_target;

        if (gvm_server_sendf (&connection->session,
                              "<create_config>"
                              "<get_configs_response"
                              " status=\"200\""
                              " status_text=\"OK\">"
                              "<config id=\"XXX\">"
                              "<type>0</type>"
                              "<name>%s</name>"
                              "<comment>"
                              "Slave config created by Master"
                              "</comment>"
                              "<preferences>",
                              name))
          goto fail_target;

        /* Send NVT timeout preferences where a timeout has been
         * specified. */
        init_config_timeout_iterator (&prefs, config);
        while (next (&prefs))
          {
            const char *timeout;

            timeout = config_timeout_iterator_value (&prefs);

            if (timeout && strlen (timeout)
                && gvm_server_sendf (&connection->session,
                                     "<preference>"
                                     "<nvt oid=\"%s\">"
                                     "<name>%s</name>"
                                     "</nvt>"
                                     "<name>Timeout</name>"
                                     "<type>entry</type>"
                                     "<value>%s</value>"
                                     "</preference>",
                                     config_timeout_iterator_oid (&prefs),
                                     config_timeout_iterator_nvt_name (&prefs),
                                     timeout))
              {
                cleanup_iterator (&prefs);
                goto fail_target;
              }
          }
        cleanup_iterator (&prefs);

        init_nvt_preference_iterator (&prefs, NULL);
        while (next (&prefs))
          {
            GString *buffer = g_string_new ("");
            buffer_config_preference_xml (buffer, &prefs, config, 0);
            if (gvm_server_sendf (&connection->session, "%s", buffer->str))
              {
                cleanup_iterator (&prefs);
                goto fail_target;
              }
            g_string_free (buffer, TRUE);
          }
        cleanup_iterator (&prefs);

        if (gvm_server_sendf (&connection->session,
                              "</preferences>"
                              "<nvt_selectors>"))
          {
            cleanup_iterator (&prefs);
            goto fail_target;
          }

        init_nvt_selector_iterator (
          &selectors, NULL, config, NVT_SELECTOR_TYPE_ANY);
        while (next (&selectors))
          {
            int type = nvt_selector_iterator_type (&selectors);
            if (gvm_server_sendf (&connection->session,
                                  "<nvt_selector>"
                                  "<name>%s</name>"
                                  "<include>%i</include>"
                                  "<type>%i</type>"
                                  "<family_or_nvt>%s</family_or_nvt>"
                                  "</nvt_selector>",
                                  nvt_selector_iterator_name (&selectors),
                                  nvt_selector_iterator_include (&selectors),
                                  type,
                                  (type == NVT_SELECTOR_TYPE_ALL
                                     ? ""
                                     : nvt_selector_iterator_nvt (&selectors))))
              goto fail_target;
          }
        cleanup_iterator (&selectors);

        if (gvm_server_sendf (&connection->session,
                              "</nvt_selectors>"
                              "</config>"
                              "</get_configs_response>"
                              "</create_config>")
            || (gmp_read_create_response (&connection->session,
                                          &global_slave_config_uuid)
                != 201))
          goto fail_target;
      }

      g_debug (
        "   %s: slave config uuid: %s", __FUNCTION__, global_slave_config_uuid);

      /* Create the task on the slave. */

      {
        int ret;
        gchar *max_checks, *max_hosts, *source_iface;
        gchar *hosts_ordering, *comment;
        gmp_create_task_opts_t opts;
        char *name_task, *uuid_report, *uuid_task;

        opts = gmp_create_task_opts_defaults;
        opts.config_id = global_slave_config_uuid;
        opts.target_id = global_slave_target_uuid;
        opts.name = name;
        task_uuid (task, &uuid_task);
        name_task = task_name (task);
        uuid_report = report_uuid (global_current_report);
        comment = g_strdup_printf ("Slave task for master task %s (%s)"
                                   " report %s.",
                                   name_task,
                                   uuid_task,
                                   uuid_report);
        opts.comment = comment;
        free (uuid_task);
        free (name_task);
        free (uuid_report);

        max_checks = task_preference_value (task, "max_checks");
        max_hosts = task_preference_value (task, "max_hosts");
        source_iface = task_preference_value (task, "source_iface");
        hosts_ordering = task_hosts_ordering (task);

        opts.alterable = 0;
        opts.in_assets = "no";
        opts.max_checks = max_checks ? max_checks : MAX_CHECKS_DEFAULT;
        opts.max_hosts = max_hosts ? max_hosts : MAX_HOSTS_DEFAULT;
        opts.source_iface = source_iface;
        opts.hosts_ordering = hosts_ordering;

        opts.alert_ids = NULL;
        opts.observers = NULL;
        opts.observer_groups = NULL;
        opts.scanner_id = NULL;
        opts.schedule_id = NULL;
        opts.slave_id = NULL;

        ret = gmp_create_task_ext (
          &connection->session, opts, &global_slave_task_uuid);
        g_free (comment);
        g_free (max_checks);
        g_free (max_hosts);
        g_free (source_iface);
        g_free (hosts_ordering);
        if (ret)
          goto fail_config;
      }

      /* Start the task on the slave. */

      if (gmp_start_task_report (&connection->session,
                                 global_slave_task_uuid,
                                 &global_slave_report_uuid))
        goto fail_task;
      if (global_slave_report_uuid == NULL)
        goto fail_stop_task;

      set_report_slave_task_uuid (global_current_report,
                                  global_slave_task_uuid);
    }

  /* Setup the current task for functions like set_task_run_status. */

  current_scanner_task = task;

  /* Poll the slave until the task is finished. */

  next_result = 1;
  while (1)
    {
      entity_t get_tasks, report, get_report;
      const char *status;
      task_status_t run_status;
      int ret, status_done;

      /* Check if some other process changed the task status. */

      run_status = task_run_status (task);
      switch (run_status)
        {
        case TASK_STATUS_DELETE_REQUESTED:
        case TASK_STATUS_DELETE_ULTIMATE_REQUESTED:
        case TASK_STATUS_STOP_REQUESTED:
          switch (gmp_stop_task (&connection->session, global_slave_task_uuid))
            {
            case 0:
              break;
            case 404:
              /* Resource Missing. */
              set_task_interrupted (task,
                                    "Failed to find task on slave."
                                    "  Interrupting scan.");
              goto giveup;
            default:
              goto fail_stop_task;
            }
          if (run_status == TASK_STATUS_DELETE_REQUESTED)
            set_task_run_status (current_scanner_task,
                                 TASK_STATUS_DELETE_WAITING);
          else if (run_status == TASK_STATUS_DELETE_ULTIMATE_REQUESTED)
            set_task_run_status (current_scanner_task,
                                 TASK_STATUS_DELETE_ULTIMATE_WAITING);
          else
            set_task_run_status (current_scanner_task,
                                 TASK_STATUS_STOP_WAITING);
          break;
        case TASK_STATUS_STOP_REQUESTED_GIVEUP:
          g_debug ("   %s: task stopped for giveup", __FUNCTION__);
          set_task_run_status (current_scanner_task, TASK_STATUS_STOPPED);
          goto giveup;
          break;
        case TASK_STATUS_STOPPED:
          assert (0);
          goto fail_stop_task;
          break;
        case TASK_STATUS_DELETE_WAITING:
        case TASK_STATUS_DELETE_ULTIMATE_WAITING:
        case TASK_STATUS_DONE:
        case TASK_STATUS_NEW:
        case TASK_STATUS_REQUESTED:
        case TASK_STATUS_RUNNING:
        case TASK_STATUS_STOP_WAITING:
        case TASK_STATUS_INTERRUPTED:
          break;
        }

      ret = gmp_get_tasks (
        &connection->session, global_slave_task_uuid, 0, 0, &get_tasks);
      if (ret == 404)
        {
          /* Resource Missing. */
          set_task_interrupted (task,
                                "Task missing on slave."
                                "  Interrupting scan.");
          goto giveup;
        }
      else if (ret)
        {
          gvm_connection_close (connection);
          ret = slave_sleep_connect (connection, task);
          if (ret == 3)
            goto giveup;
          continue;
        }

      status = gmp_task_status (get_tasks);
      if (status == NULL)
        {
          set_task_interrupted (task,
                                "Error in slave task status."
                                "  Interrupting scan.");
          goto giveup;
        }
      status_done = (strcmp (status, "Done") == 0);
      if ((strcmp (status, "Running") == 0) || status_done)
        {
          int ret2 = 0;
          gmp_get_report_opts_t opts;

          if (run_status == TASK_STATUS_REQUESTED)
            set_task_run_status (task, TASK_STATUS_RUNNING);

          if ((strcmp (status, "Running") == 0)
              && update_slave_progress (get_tasks))
            {
              free_entity (get_tasks);
              goto fail_stop_task;
            }

          opts = gmp_get_report_opts_defaults;
          opts.report_id = global_slave_report_uuid;
          opts.format_id = "a994b278-1f62-11e1-96ac-406186ea4fc5";
          opts.filter = g_strdup_printf (
            "first=%i rows=-1 levels=hmlgd apply_overrides=0"
            " min_qod=0 autofp=0 result_hosts_only=%i"
            " sort=created",
            next_result,
            status_done
              /* Request all the hosts to get their end times. */
              ? 0
              : 1);

          ret = gmp_get_report_ext (&connection->session, opts, &get_report);
          if (ret)
            {
              opts.format_id = "d5da9f67-8551-4e51-807b-b6a873d70e34";
              ret2 =
                gmp_get_report_ext (&connection->session, opts, &get_report);
            }
          g_free (opts.filter);
          if ((ret == 404) && (ret2 == 404))
            {
              /* Resource Missing. */
              set_task_interrupted (task,
                                    "Task report missing on slave."
                                    "  Interrupting scan.");
              goto giveup;
            }
          if (ret && ret2)
            {
              free_entity (get_tasks);
              gvm_connection_close (connection);
              ret = slave_sleep_connect (connection, task);
              if (ret == 3)
                goto giveup;
              continue;
            }

          if (update_from_slave (task, get_report, &report, &next_result))
            {
              free_entity (get_tasks);
              free_entity (get_report);
              goto fail_stop_task;
            }

          if (strcmp (status, "Running") == 0)
            {
              if (update_end_times (report))
                goto fail_stop_task;
              free_entity (get_report);
            }
        }
      else if (strcmp (status, "Stopped") == 0)
        {
          set_task_run_status (task, TASK_STATUS_STOPPED);
          goto succeed_stopped;
        }
      else if (strcmp (status, "Stop Requested") == 0)
        set_task_run_status (task, TASK_STATUS_STOP_WAITING);
      else if ((strcmp (status, "Interrupted") == 0)
               /* Keeping this in case the slave is older. */
               || (strcmp (status, "Internal Error") == 0)
               || (strcmp (status, "Delete Requested") == 0))
        {
          free_entity (get_tasks);
          goto fail_stop_task;
        }

      if (status_done)
        {
          if (update_end_times (report))
            {
              free_entity (get_tasks);
              free_entity (get_report);
              goto fail_stop_task;
            }
          free_entity (get_report);
          if (update_slave_progress (get_tasks))
            {
              free_entity (get_report);
              free_entity (get_tasks);
              goto fail_stop_task;
            }
          free_entity (get_tasks);

          /* Add results to assets. */
          if (global_current_report)
            {
              hosts_set_identifiers (global_current_report);
              hosts_set_max_severity (global_current_report, NULL, NULL);
              hosts_set_details (global_current_report);
            }

          set_task_run_status (task, TASK_STATUS_DONE);
          break;
        }

      free_entity (get_tasks);

      gvm_sleep (RUN_SLAVE_TASK_SLEEP_SECONDS);
    }

  /* Cleanup. */

  current_scanner_task = (task_t) 0;

  gmp_delete_task_ext (&connection->session, global_slave_task_uuid, del_opts);
  set_report_slave_task_uuid (global_current_report, "");
  gmp_delete_config_ext (
    &connection->session, global_slave_config_uuid, del_opts);
  gmp_delete_target_ext (
    &connection->session, global_slave_target_uuid, del_opts);
  gmp_delete_port_list_ext (
    &connection->session, global_slave_port_list_uuid, del_opts);
  if (global_slave_ssh_credential_uuid)
    gmp_delete_lsc_credential_ext (
      &connection->session, global_slave_ssh_credential_uuid, del_opts);
  if (global_slave_smb_credential_uuid)
    gmp_delete_lsc_credential_ext (
      &connection->session, global_slave_smb_credential_uuid, del_opts);
  if (global_slave_esxi_credential_uuid)
    gmp_delete_lsc_credential_ext (
      &connection->session, global_slave_esxi_credential_uuid, del_opts);
  if (global_slave_snmp_credential_uuid)
    gmp_delete_lsc_credential_ext (
      &connection->session, global_slave_snmp_credential_uuid, del_opts);
succeed_stopped:
  free (global_slave_task_uuid);
  global_slave_task_uuid = NULL;
  free (global_slave_report_uuid);
  global_slave_report_uuid = NULL;
  free (global_slave_config_uuid);
  global_slave_config_uuid = NULL;
  free (global_slave_target_uuid);
  global_slave_target_uuid = NULL;
  free (global_slave_port_list_uuid);
  global_slave_port_list_uuid = NULL;
  free (global_slave_snmp_credential_uuid);
  global_slave_snmp_credential_uuid = NULL;
  free (global_slave_esxi_credential_uuid);
  global_slave_esxi_credential_uuid = NULL;
  free (global_slave_smb_credential_uuid);
  global_slave_smb_credential_uuid = NULL;
  free (global_slave_ssh_credential_uuid);
  global_slave_ssh_credential_uuid = NULL;
  gvm_connection_close (connection);
  global_slave_connection = NULL;
  g_debug ("   %s: succeed", __FUNCTION__);
  return 0;

fail_stop_task:
  gmp_stop_task (&connection->session, global_slave_task_uuid);
  free (global_slave_report_uuid);
fail_task:
  gmp_delete_task_ext (&connection->session, global_slave_task_uuid, del_opts);
  set_report_slave_task_uuid (global_current_report, "");
  free (global_slave_task_uuid);
fail_config:
  gmp_delete_config_ext (
    &connection->session, global_slave_config_uuid, del_opts);
  free (global_slave_config_uuid);
fail_target:
  gmp_delete_target_ext (
    &connection->session, global_slave_target_uuid, del_opts);
  free (global_slave_target_uuid);
  gmp_delete_port_list_ext (
    &connection->session, global_slave_port_list_uuid, del_opts);
  free (global_slave_port_list_uuid);
fail_credentials:
  if (global_slave_snmp_credential_uuid)
    gmp_delete_lsc_credential_ext (
      &connection->session, global_slave_snmp_credential_uuid, del_opts);
  free (global_slave_snmp_credential_uuid);
  if (global_slave_esxi_credential_uuid)
    gmp_delete_lsc_credential_ext (
      &connection->session, global_slave_esxi_credential_uuid, del_opts);
  free (global_slave_esxi_credential_uuid);
  if (global_slave_smb_credential_uuid)
    gmp_delete_lsc_credential_ext (
      &connection->session, global_slave_smb_credential_uuid, del_opts);
  free (global_slave_smb_credential_uuid);
  if (global_slave_ssh_credential_uuid)
    gmp_delete_lsc_credential_ext (
      &connection->session, global_slave_ssh_credential_uuid, del_opts);
  free (global_slave_ssh_credential_uuid);
fail:
  g_debug ("   %s: fail (%i)", __FUNCTION__, ret_fail);
  gvm_connection_close (connection);
  global_slave_connection = NULL;
  return ret_fail;

giveup:
  g_debug ("   %s: giveup (%i)", __FUNCTION__, ret_giveup);
  gvm_connection_close (connection);
  global_slave_connection = NULL;
  return ret_giveup;
}

/**
 * @brief Start a task on a slave.
 *
 * @param[in]  task                     The task.
 * @param[in]  target                   Task target.
 * @param[in]  target_ssh_credential    Target SSH credential.
 * @param[in]  target_smb_credential    Target SMB credential.
 * @param[in]  target_esxi_credential   Target ESXi credential.
 * @param[in]  target_snmp_credential   Target SNMP credential.
 * @param[in]  last_stopped_report      Last stopped report if any, else 0.
 * @param[in]  connection               Connection, with slave info.
 * @param[in]  slave_id                 UUID of slave.
 * @param[in]  slave_name               Name of slave.
 *
 * @return 0 success, 1 login failed, -1 failed to make UUID, -2 Failed to get
 *         task name.
 */
static int
handle_slave_task (task_t task,
                   target_t target,
                   credential_t target_ssh_credential,
                   credential_t target_smb_credential,
                   credential_t target_esxi_credential,
                   credential_t target_snmp_credential,
                   report_t last_stopped_report,
                   gvm_connection_t *connection,
                   const gchar *slave_id,
                   const gchar *slave_name)
{
  char *name, *uuid;
  int ret;
  gchar *slave_task_name;

  /* Some of the cases in here must write to the session outside an open
   * statement.  For example, the gmp_create_lsc_credential must come after
   * cleaning up the credential iterator.  This is because the slave may be
   * the master, and the open statement would prevent the slave from getting
   * a lock on the database and fulfilling the request. */

  g_debug ("   Running slave task %llu", task);

  // FIX permission checks  may the user still access the slave, target, port
  // list etc?

  report_set_slave_uuid (global_current_report, slave_id);
  report_set_slave_name (global_current_report, slave_name);
  report_set_slave_port (global_current_report, connection->port);
  report_set_slave_host (global_current_report, connection->host_string);

  uuid = gvm_uuid_make ();
  if (uuid == NULL)
    {
      g_warning ("%s: Failed to make UUID", __FUNCTION__);
      return -1;
    }

  name = task_name (task);
  if (name == NULL)
    {
      free (uuid);
      g_warning ("%s: Failed to get task name", __FUNCTION__);
      return -2;
    }
  slave_task_name = g_strdup_printf ("%s for %s", uuid, name);
  free (name);
  free (uuid);

  while ((ret = slave_connect (connection)))
    if (ret == 1)
      {
        result_t result;
        gchar *port_string;

        /* Login failed. */

        port_string = g_strdup_printf ("%i", connection->port);
        result = make_result (task,
                              connection->host_string,
                              "",
                              port_string,
                              /* NVT: Global variable settings. */
                              "1.3.6.1.4.1.25623.1.0.12288",
                              "Error Message",
                              "Authentication with the slave failed.");
        g_free (port_string);
        if (global_current_report)
          report_add_result (global_current_report, result);

        g_free (slave_task_name);
        return 1;
      }
    else
      {
        int current_signal = get_termination_signal ();
        if ((task_run_status (task) == TASK_STATUS_STOP_REQUESTED_GIVEUP)
            || (task_run_status (task) == TASK_STATUS_STOP_REQUESTED)
            || current_signal)
          {
            if (current_signal)
              {
                g_debug ("%s: Received %s signal.",
                         __FUNCTION__,
                         strsignal (get_termination_signal ()));
              }
            if (global_current_report)
              {
                set_report_scan_run_status (global_current_report,
                                            TASK_STATUS_STOPPED);
              }
            set_task_run_status (task, TASK_STATUS_STOPPED);
            g_free (slave_task_name);
            return 0;
          }
        gvm_sleep (RUN_SLAVE_TASK_SLEEP_SECONDS);
      }

  while (1)
    {
      if (get_termination_signal ())
        {
          g_debug ("%s: Received %s signal.",
                   __FUNCTION__,
                   strsignal (get_termination_signal ()));
          if (global_current_report)
            {
              set_report_scan_run_status (global_current_report,
                                          TASK_STATUS_STOPPED);
            }
          set_task_run_status (task, TASK_STATUS_STOPPED);
          g_free (slave_task_name);
          return 0;
        }

      ret = slave_setup (connection,
                         slave_task_name,
                         task,
                         target,
                         target_ssh_credential,
                         target_smb_credential,
                         target_esxi_credential,
                         target_snmp_credential,
                         last_stopped_report);
      if (ret == 1)
        {
          ret = slave_sleep_connect (connection, task);
          if (ret == 3)
            /* User requested "giveup". */
            break;
        }
      else
        break;
    }

  current_scanner_task = (task_t) 0;
  g_free (slave_task_name);

  return 0;
}

/* OSP tasks. */

/**
 * @brief Give a task's OSP scan options in a hash table.
 *
 * @param[in]   task        The task.
 * @param[in]   target      The target.
 *
 * @return Hash table with options names and their values.
 */
static GHashTable *
task_scanner_options (task_t task, target_t target)
{
  GHashTable *table;
  config_t config;
  iterator_t prefs;

  config = task_config (task);
  init_preference_iterator (&prefs, config);
  table = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  while (next (&prefs))
    {
      char *name, *value = NULL;
      const char *type;

      name = g_strdup (preference_iterator_name (&prefs));
      type = preference_iterator_type (&prefs);

      if (g_str_has_prefix (type, "credential_"))
        {
          credential_t credential = 0;
          iterator_t iter;
          const char *uuid = preference_iterator_value (&prefs);

          if (!strcmp (preference_iterator_value (&prefs), "0"))
            credential = target_ssh_credential (target);
          else if (find_resource ("credential", uuid, &credential))
            {
              g_warning ("Error getting credential for osp parameter %s", name);
              g_free (name);
              continue;
            }
          if (credential == 0)
            {
              g_warning ("No credential for osp parameter %s", name);
              g_free (name);
              continue;
            }

          init_credential_iterator_one (&iter, credential);
          if (!next (&iter))
            {
              g_warning ("No credential for credential_id %llu", credential);
              g_free (name);
              continue;
            }
          if (!strcmp (type, "credential_up")
              && !strcmp (credential_iterator_type (&iter), "up"))
            value = g_strdup_printf ("%s:%s",
                                     credential_iterator_login (&iter),
                                     credential_iterator_password (&iter));
          else if (!strcmp (type, "credential_up"))
            {
              g_warning ("OSP Parameter %s requires credentials of type"
                         " username+password",
                         name);
              g_free (name);
              continue;
            }
          else
            abort ();
          cleanup_iterator (&iter);
          if (!value)
            {
              g_warning ("No adequate %s for parameter %s", type, name);
              g_free (name);
              continue;
            }
        }
      else if (!strcmp (name, "definitions_file"))
        {
          char *fname;

          if (!preference_iterator_value (&prefs))
            continue;
          fname = g_strdup_printf (
            "%s/%s", MAGENI_SCAP_DATA_DIR "/", preference_iterator_value (&prefs));
          value = gvm_file_as_base64 (fname);
          if (!value)
            continue;
        }
      else
        value = g_strdup (preference_iterator_value (&prefs));
      g_hash_table_insert (table, name, value);
    }
  cleanup_iterator (&prefs);
  return table;
}

/**
 * @brief Delete an OSP scan.
 *
 * @param[in]   report_id   Report ID.
 * @param[in]   host        Scanner host.
 * @param[in]   port        Scanner port.
 * @param[in]   ca_pub      CA Certificate.
 * @param[in]   key_pub     Certificate.
 * @param[in]   key_priv    Private key.
 */
static void
delete_osp_scan (const char *report_id,
                 const char *host,
                 int port,
                 const char *ca_pub,
                 const char *key_pub,
                 const char *key_priv)
{
  osp_connection_t *connection;

  connection = osp_connection_new (host, port, ca_pub, key_pub, key_priv);
  if (!connection)
    {
      g_warning ("Couldn't connect to OSP scanner on %s:%d", host, port);
      return;
    }
  osp_delete_scan (connection, report_id);
  osp_connection_close (connection);
}

/**
 * @brief Get an OSP scan's report.
 *
 * @param[in]   scan_id     Scan ID.
 * @param[in]   host        Scanner host.
 * @param[in]   port        Scanner port.
 * @param[in]   ca_pub      CA Certificate.
 * @param[in]   key_pub     Certificate.
 * @param[in]   key_priv    Private key.
 * @param[in]   details     1 for detailed report, 0 otherwise.
 * @param[out]  report_xml  Scan report.
 *
 * @return -1 on error, progress value between 0 and 100 on success.
 */
static int
get_osp_scan_report (const char *scan_id,
                     const char *host,
                     int port,
                     const char *ca_pub,
                     const char *key_pub,
                     const char *key_priv,
                     int details,
                     char **report_xml)
{
  osp_connection_t *connection;
  int progress;
  char *error = NULL;

  connection = osp_connection_new (host, port, ca_pub, key_pub, key_priv);
  if (!connection)
    {
      g_warning ("Couldn't connect to OSP scanner on %s:%d", host, port);
      return -1;
    }
  progress = osp_get_scan (connection, scan_id, report_xml, details, &error);
  if (progress > 100 || progress < 0)
    {
      g_warning ("OSP get_scan %s: %s", scan_id, error);
      g_free (error);
      progress = -1;
    }

  osp_connection_close (connection);
  return progress;
}

/**
 * @brief Handle an ongoing OSP scan, until success or failure.
 *
 * @param[in]   task      The task.
 * @param[in]   report    The report.
 * @param[in]   scan_id   The UUID of the scan on the scanner.
 *
 * @return 0 if success, -1 if error, -2 if scan was stopped.
 */
static int
handle_osp_scan (task_t task, report_t report, const char *scan_id)
{
  char *host, *ca_pub, *key_pub, *key_priv;
  int rc, port;
  scanner_t scanner;

  scanner = task_scanner (task);
  host = scanner_host (scanner);
  port = scanner_port (scanner);
  ca_pub = scanner_ca_pub (scanner);
  key_pub = scanner_key_pub (scanner);
  key_priv = scanner_key_priv (scanner);
  while (1)
    {
      char *report_xml = NULL;
      int run_status;

      run_status = task_run_status (task);
      if (run_status == TASK_STATUS_STOPPED
          || run_status == TASK_STATUS_STOP_REQUESTED)
        {
          rc = -2;
          break;
        }
      int progress = get_osp_scan_report (
        scan_id, host, port, ca_pub, key_pub, key_priv, 0, NULL);
      if (progress == -1)
        {
          result_t result = make_osp_result (task,
                                             "",
                                             "",
                                             threat_message_type ("Error"),
                                             "Erroneous scan progress value",
                                             "",
                                             "",
                                             QOD_DEFAULT);
          report_add_result (report, result);
          rc = -1;
          break;
        }
      else if (progress < 100)
        {
          set_report_slave_progress (report, progress);
          gvm_sleep (10);
        }
      else if (progress == 100)
        {
          /* Get the full OSP report. */
          progress = get_osp_scan_report (
            scan_id, host, port, ca_pub, key_pub, key_priv, 1, &report_xml);
          if (progress != 100)
            {
              result_t result =
                make_osp_result (task,
                                 "",
                                 "",
                                 threat_message_type ("Error"),
                                 "Erroneous scan progress value",
                                 "",
                                 "",
                                 QOD_DEFAULT);
              report_add_result (report, result);
              rc = -1;
              break;
            }
          parse_osp_report (task, report, report_xml);
          g_free (report_xml);
          delete_osp_scan (scan_id, host, port, ca_pub, key_pub, key_priv);
          rc = 0;
          break;
        }
    }

  g_free (host);
  g_free (ca_pub);
  g_free (key_pub);
  g_free (key_priv);
  return rc;
}

/**
 * @brief Get an OSP Task's scan options.
 *
 * @param[in]   task        The task.
 * @param[in]   target      The target.
 *
 * @return OSP Task options, NULL if failure.
 */
static GHashTable *
get_osp_task_options (task_t task, target_t target)
{
  char *ssh_port;
  const char *user, *pass;
  iterator_t iter;
  credential_t cred;
  GHashTable *options = task_scanner_options (task, target);

  if (!options)
    return NULL;

  cred = target_ssh_credential (target);
  if (cred)
    {
      ssh_port = target_ssh_port (target);
      g_hash_table_insert (options, g_strdup ("port"), ssh_port);

      init_credential_iterator_one (&iter, cred);
      if (!next (&iter))
        {
          g_warning ("%s: LSC Credential not found.", __FUNCTION__);
          g_hash_table_destroy (options);
          cleanup_iterator (&iter);
          return NULL;
        }
      if (credential_iterator_private_key (&iter))
        {
          g_warning ("%s: LSC Credential not a user/pass pair.", __FUNCTION__);
          g_hash_table_destroy (options);
          cleanup_iterator (&iter);
          return NULL;
        }
      user = credential_iterator_login (&iter);
      pass = credential_iterator_password (&iter);
      g_hash_table_insert (options, g_strdup ("username"), g_strdup (user));
      g_hash_table_insert (options, g_strdup ("password"), g_strdup (pass));
      cleanup_iterator (&iter);
    }
  return options;
}

/**
 * @brief Launch an OSP task.
 *
 * @param[in]   task        The task.
 * @param[in]   target      The target.
 * @param[out]  scan_id     The new scan uuid.
 * @param[out]  error       Error return.
 *
 * @return 0 success, -1 if scanner is down.
 */
static int
launch_osp_task (task_t task,
                 target_t target,
                 const char *scan_id,
                 char **error)
{
  osp_connection_t *connection;
  char *target_str, *ports_str;
  GHashTable *options;
  int ret;

  options = get_osp_task_options (task, target);
  if (!options)
    return -1;
  connection = osp_scanner_connect (task_scanner (task));
  if (!connection)
    {
      g_hash_table_destroy (options);
      return -1;
    }
  target_str = target_hosts (target);
  ports_str = target_port_range (target);
  ret =
    osp_start_scan (connection, target_str, ports_str, options, scan_id, error);

  g_hash_table_destroy (options);
  osp_connection_close (connection);
  g_free (target_str);
  g_free (ports_str);
  return ret;
}

/**
 * @brief Fork a child to handle an OSP scan's fetching and inserting.
 *
 * @param[in]   task        The task.
 * @param[in]   target      The target.
 *
 * @return Parent returns with 0 if success, -1 if failure. Child process
 *         doesn't return and simply exits.
 */
static int
fork_osp_scan_handler (task_t task, target_t target)
{
  char *report_id, title[128], *error = NULL;
  int rc;

  assert (task);
  assert (target);

  if (create_current_report (task, &report_id, TASK_STATUS_REQUESTED))
    {
      g_debug ("   %s: failed to create report", __FUNCTION__);
      return -1;
    }

  set_task_run_status (task, TASK_STATUS_REQUESTED);

  switch (fork ())
    {
    case 0:
      break;
    case -1:
      /* Parent, failed to fork. */
      g_warning ("%s: Failed to fork: %s", __FUNCTION__, strerror (errno));
      set_task_interrupted (task,
                            "Error forking scan handler."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report,
                                  TASK_STATUS_INTERRUPTED);
      global_current_report = (report_t) 0;
      return -9;
    default:
      /* Parent, successfully forked. */
      return 0;
    }

  /* Child: Re-open DB after fork and periodically check scan progress.
   * If progress == 100%: Parse the report results and other info then exit(0).
   * Else, exit(1) in error cases like connection to scanner failure.
   */
  reinit_manage_process ();
  manage_session_init (current_credentials.uuid);
  if (launch_osp_task (task, target, report_id, &error))
    {
      result_t result;

      g_warning ("OSP start_scan %s: %s", report_id, error);
      result = make_osp_result (task,
                                "",
                                "",
                                threat_message_type ("Error"),
                                error,
                                "",
                                "",
                                QOD_DEFAULT);
      report_add_result (global_current_report, result);
      set_task_run_status (task, TASK_STATUS_DONE);
      set_report_scan_run_status (global_current_report, TASK_STATUS_DONE);
      set_task_end_time_epoch (task, time (NULL));
      set_scan_end_time_epoch (global_current_report, time (NULL));

      g_free (error);
      g_free (report_id);
      exit (-1);
    }

  set_task_run_status (task, TASK_STATUS_RUNNING);
  set_report_scan_run_status (global_current_report, TASK_STATUS_RUNNING);

  snprintf (title, sizeof (title), "mageni-sqlite: OSP: Handling scan %s", report_id);
  proctitle_set (title);

  rc = handle_osp_scan (task, global_current_report, report_id);
  g_free (report_id);
  if (rc == 0)
    {
      set_task_run_status (task, TASK_STATUS_DONE);
      set_report_scan_run_status (global_current_report, TASK_STATUS_DONE);
    }
  else if (rc == -1 || rc == -2)
    {
      set_task_run_status (task, TASK_STATUS_STOPPED);
      set_report_scan_run_status (global_current_report, TASK_STATUS_STOPPED);
    }

  set_task_end_time_epoch (task, time (NULL));
  set_scan_end_time_epoch (global_current_report, time (NULL));
  global_current_report = 0;
  current_scanner_task = (task_t) 0;
  exit (rc);
}

/**
 * @brief Start a task on an OSP scanner.
 *
 * @param[in]   task       The task.
 *
 * @return 0 success, 99 permission denied, -1 error.
 */
static int
run_osp_task (task_t task)
{
  target_t target;

  target = task_target (task);
  if (target)
    {
      char *uuid;
      target_t found;

      uuid = target_uuid (target);
      if (find_target_with_permission (uuid, &found, "get_targets"))
        {
          g_free (uuid);
          return -1;
        }
      g_free (uuid);
      if (found == 0)
        return 99;
    }

  if (fork_osp_scan_handler (task, target))
    {
      g_warning ("Couldn't fork OSP scan handler");
      return -1;
    }
  return 0;
}

/* CVE tasks. */

/**
 * @brief Perform a CVE "scan" on a host.
 *
 * @param[in]  task      Task.
 * @param[in]  gvm_host  Host.
 *
 * @return 0 success, 1 failed to get nthlast report for a host.
 */
static int
cve_scan_host (task_t task, gvm_host_t *gvm_host)
{
  report_host_t report_host;
  gchar *ip, *host;

  host = gvm_host_value_str (gvm_host);

  ip = report_host_ip (host);
  if (ip == NULL)
    ip = g_strdup (host);

  g_debug ("%s: ip: %s", __FUNCTION__, ip);

  /* Get the last report that applies to the host. */

  if (host_nthlast_report_host (ip, &report_host, 1))
    {
      g_warning ("%s: Failed to get nthlast report", __FUNCTION__);
      g_free (ip);
      return 1;
    }

  g_debug ("%s: report_host: %llu", __FUNCTION__, report_host);

  if (report_host)
    {
      iterator_t report_hosts;

      /* Get the report_host for the host. */

      init_report_host_iterator (&report_hosts, 0, NULL, report_host);
      if (next (&report_hosts))
        {
          iterator_t prognosis;
          int prognosis_report_host, start_time;

          /* Add report_host with prognosis results and host details. */

          start_time = time (NULL);
          prognosis_report_host = 0;
          init_host_prognosis_iterator (
            &prognosis, report_host, 0, -1, NULL, NULL, 0, NULL);
          while (next (&prognosis))
            {
              const char *app, *cve;
              double severity;
              gchar *desc, *location;
              result_t result;

              if (global_current_report && (prognosis_report_host == 0))
                prognosis_report_host = manage_report_host_add (
                  global_current_report, ip, start_time, 0);

              severity = prognosis_iterator_cvss_double (&prognosis);

              app = prognosis_iterator_cpe (&prognosis);
              cve = prognosis_iterator_cve (&prognosis);
              location = app_location (report_host, app);

              desc =
                g_strdup_printf ("The host carries the product: %s\n"
                                 "It is vulnerable according to: %s.\n"
                                 "%s%s%s"
                                 "\n"
                                 "%s",
                                 app,
                                 cve,
                                 location ? "The product was found at: " : "",
                                 location ? location : "",
                                 location ? ".\n" : "",
                                 prognosis_iterator_description (&prognosis));

              g_debug ("%s: making result with severity %1.1f desc [%s]",
                       __FUNCTION__,
                       severity,
                       desc);

              result = make_cve_result (task, ip, cve, severity, desc);
              g_free (desc);
              if (global_current_report)
                {
                  report_add_result (global_current_report, result);

                  insert_report_host_detail (global_current_report,
                                             ip,
                                             "cve",
                                             cve,
                                             "CVE Scanner",
                                             "App",
                                             app);

                  if (location)
                    {
                      insert_report_host_detail (global_current_report,
                                                 ip,
                                                 "cve",
                                                 cve,
                                                 "CVE Scanner",
                                                 app,
                                                 location);

                      insert_report_host_detail (global_current_report,
                                                 ip,
                                                 "cve",
                                                 cve,
                                                 "CVE Scanner",
                                                 "detected_at",
                                                 location);
                      insert_report_host_detail (global_current_report,
                                                 ip,
                                                 "cve",
                                                 cve,
                                                 "CVE Scanner",
                                                 "detected_by",
                                                 /* Detected by itself. */
                                                 cve);
                    }
                }
              g_free (location);
            }
          cleanup_iterator (&prognosis);

          if (prognosis_report_host)
            {
              /* Complete the report_host. */

              report_host_set_end_time (prognosis_report_host, time (NULL));
              insert_report_host_detail (global_current_report,
                                         ip,
                                         "cve",
                                         "",
                                         "CVE Scanner",
                                         "CVE Scan",
                                         "1");
            }
        }
      cleanup_iterator (&report_hosts);
    }

  g_free (ip);
  return 0;
}

/**
 * @brief Fork a child to handle a CVE scan's calculating and inserting.
 *
 * @param[in]   task        The task.
 * @param[in]   target      The target.
 *
 * @return Parent returns with 0 if success, -1 if failure. Child process
 *         doesn't return and simply exits.
 */
static int
fork_cve_scan_handler (task_t task, target_t target)
{
  int pid;
  char *report_id, title[128], *hosts;
  gvm_hosts_t *gvm_hosts;
  gvm_host_t *gvm_host;

  assert (task);
  assert (target);

  if (create_current_report (task, &report_id, TASK_STATUS_REQUESTED))
    {
      g_debug ("   %s: failed to create report", __FUNCTION__);
      return -1;
    }

  set_task_run_status (task, TASK_STATUS_REQUESTED);

  pid = fork ();
  switch (pid)
    {
    case 0:
      break;
    case -1:
      /* Parent, failed to fork. */
      g_warning ("%s: Failed to fork: %s", __FUNCTION__, strerror (errno));
      set_task_interrupted (task,
                            "Error forking scan handler."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report,
                                  TASK_STATUS_INTERRUPTED);
      global_current_report = (report_t) 0;
      return -9;
    default:
      /* Parent, successfully forked. */
      g_debug ("%s: %i forked %i", __FUNCTION__, getpid (), pid);
      return 0;
    }

  /* Child.
   *
   * Re-open DB and do prognostic calculation.  On success exit(0), else
   * exit(1). */
  reinit_manage_process ();
  manage_session_init (current_credentials.uuid);

  /* Setup the task. */

  set_task_run_status (task, TASK_STATUS_RUNNING);

  snprintf (title, sizeof (title), "mageni-sqlite: CVE: Handling scan %s", report_id);
  g_free (report_id);
  proctitle_set (title);

  hosts = target_hosts (target);
  if (hosts == NULL)
    {
      set_task_interrupted (task,
                            "Error in target host list."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report,
                                  TASK_STATUS_INTERRUPTED);
      exit (1);
    }

  reset_task (task);
  set_task_start_time_epoch (task, time (NULL));
  set_scan_start_time_epoch (global_current_report, time (NULL));

  /* Add the results. */

  gvm_hosts = gvm_hosts_new (hosts);
  free (hosts);
  while ((gvm_host = gvm_hosts_next (gvm_hosts)))
    if (cve_scan_host (task, gvm_host))
      {
        set_task_interrupted (task,
                              "Failed to get nthlast report."
                              "  Interrupting scan.");
        set_report_scan_run_status (global_current_report,
                                    TASK_STATUS_INTERRUPTED);
        gvm_hosts_free (gvm_hosts);
        exit (1);
      }
  gvm_hosts_free (gvm_hosts);

  /* Set the end states. */

  set_scan_end_time_epoch (global_current_report, time (NULL));
  set_task_end_time_epoch (task, time (NULL));
  set_task_run_status (task, TASK_STATUS_DONE);
  set_report_scan_run_status (global_current_report, TASK_STATUS_DONE);
  global_current_report = 0;
  current_scanner_task = (task_t) 0;
  exit (0);
}

/**
 * @brief Start a CVE task.
 *
 * @param[in]   task    The task.
 *
 * @return 0 success, 99 permission denied, -1 error.
 */
static int
run_cve_task (task_t task)
{
  target_t target;

  target = task_target (task);
  if (target)
    {
      char *uuid;
      target_t found;

      uuid = target_uuid (target);
      if (find_target_with_permission (uuid, &found, "get_targets"))
        {
          g_free (uuid);
          return -1;
        }
      g_free (uuid);
      if (found == 0)
        return 99;
    }

  if (fork_cve_scan_handler (task, target))
    {
      g_warning ("Couldn't fork CVE scan handler");
      return -1;
    }
  return 0;
}

/* OTP tasks. */

/**
 * @brief Initialise OpenVAS scanner variables, checking for defaults.
 *
 * @param[in]  ca_pub       CA Certificate.
 * @param[in]  key_pub      Scanner Certificate.
 * @param[in]  key_priv     Scanner private key.
 *
 * @return 0 success, 1 both default CA cert setting and ca_pub were NULL.
 */
int
set_certs (const char *ca_pub, const char *key_pub, const char *key_priv)
{
  const char *fallback;

  if (ca_pub == NULL)
    fallback = manage_default_ca_cert ();
  else
    fallback = NULL;

  openvas_scanner_set_certs (fallback ? fallback : ca_pub, key_pub, key_priv);

  if (ca_pub || fallback)
    return 0;
  return 1;
}

/**
 * @brief Initialise some values of the OpenVAS scanner.
 *
 * @param[in]  scanner  Scanner.
 *
 * @return 0 success, -1 error, 1 no CA cert.
 */
static int
scanner_setup (scanner_t scanner)
{
  int ret, port;
  char *host, *ca_pub, *key_pub, *key_priv;

  assert (scanner);
  host = scanner_host (scanner);
  if (host && *host == '/')
    {
      /* XXX: Workaround for unix socket case. Should add a flag. */
      openvas_scanner_set_unix (host);
      return 0;
    }
  port = scanner_port (scanner);
  ret = openvas_scanner_set_address (host, port);
  g_free (host);
  if (ret)
    return ret;
  ca_pub = scanner_ca_pub (scanner);
  key_pub = scanner_key_pub (scanner);
  key_priv = scanner_key_priv (scanner);
  ret = 0;
  if (set_certs (ca_pub, key_pub, key_priv))
    ret = 1;
  g_free (ca_pub);
  g_free (key_pub);
  g_free (key_priv);
  return ret;
}

/**
 * @brief Initialise variables required for running a scan.
 *
 * @param[in]  task             Task.
 * @param[out] config           Config.
 * @param[out] target           Target.
 * @param[out] port_list        Port list.
 * @param[out] ssh_credential   SSH credential.
 * @param[out] smb_credential   SMB credential.
 * @param[out] esxi_credential  ESXI credential.
 * @param[out] snmp_credential  SNMP credential.
 *
 * @return 0 success, -1 error, 99 permission denied.
 */
static int
run_task_setup (task_t task,
                config_t *config,
                target_t *target,
                port_list_t *port_list,
                credential_t *ssh_credential,
                credential_t *smb_credential,
                credential_t *esxi_credential,
                credential_t *snmp_credential)
{
  int ret;

  *config = task_config (task);
  *target = task_target (task);
  *port_list = target_port_list (*target);
  *ssh_credential = target_ssh_credential (*target);
  *smb_credential = target_smb_credential (*target);
  *esxi_credential = target_esxi_credential (*target);
  *snmp_credential = target_credential (*target, "snmp");

  ret = check_available ("config", *config, "get_configs");
  if (ret)
    return ret;

  ret = check_available ("target", *target, "get_targets");
  if (ret)
    return ret;

  ret = check_available ("port_list", *port_list, "get_port_lists");
  if (ret)
    return ret;

  if (*ssh_credential
      && ((ret = check_available (
             "credential", *ssh_credential, "get_credentials"))))
    return ret;

  if (*smb_credential
      && ((ret = check_available (
             "credential", *smb_credential, "get_credentials"))))
    return ret;

  if (*esxi_credential
      && ((ret = check_available (
             "credential", *esxi_credential, "get_credentials"))))
    return ret;

  if (*snmp_credential
      && ((ret = check_available (
             "credential", *snmp_credential, "get_credentials"))))
    return ret;

  return 0;
}

/**
 * @brief Prepare report for running a task.
 *
 * @param[in]   task        The task.
 * @param[out]  report_id   The report ID.
 * @param[in]   from        0 start from beginning, 1 continue from stopped, 2
 *                          continue if stopped else start from beginning.
 * @param[in]   run_status  The task's run status.
 * @param[in]   last_stopped_report  Last stopped report of task.
 *
 * @return 0 success, -1 error, -3 creating the report failed.
 */
static int
run_task_prepare_report (task_t task,
                         char **report_id,
                         int from,
                         task_status_t run_status,
                         report_t *last_stopped_report)
{
  if ((from == 1)
      || ((from == 2)
          && ((run_status == TASK_STATUS_STOPPED)
              || (run_status == TASK_STATUS_INTERRUPTED))))
    {
      if (task_last_resumable_report (task, last_stopped_report))
        {
          g_debug ("   error getting last stopped report");
          return -1;
        }

      global_current_report = *last_stopped_report;
      if (report_id)
        *report_id = report_uuid (*last_stopped_report);

      /* Remove partial host information from the report. */

      trim_partial_report (*last_stopped_report);

      /* Ensure the report is marked as requested. */

      set_report_scan_run_status (global_current_report, TASK_STATUS_REQUESTED);

      /* Clear the end times of the task and partial report. */

      set_task_start_time_epoch (task,
                                 scan_start_time_epoch (global_current_report));
      set_task_end_time (task, NULL);
      set_scan_end_time (*last_stopped_report, NULL);
    }
  else if ((from == 0) || (from == 2))
    {
      *last_stopped_report = 0;

      /* Create the report. */

      if (create_current_report (task, report_id, TASK_STATUS_REQUESTED))
        return -3;

      reset_task (task);
    }
  else
    {
      /* "from" must be 0, 1 or 2. */
      assert (0);
      return -1;
    }

  return 0;
}

/**
 * @brief Start a slave/GMP task.
 *
 * @param[in]  task        The task.
 * @param[in]  from        0 start from beginning, 1 continue from stopped, 2
 *                         continue if stopped else start from beginning.
 * @param[out] report_id   The report ID.
 * @param[in]  connection  Connection, with slave info.
 * @param[in]  slave_id    UUID of slave.
 * @param[in]  slave_name  Name of slave.
 *
 * @return Before forking: 1 task is active already, 3 failed to find task,
 *         -1 error.
 */
static int
run_slave_or_gmp_task (task_t task,
                       int from,
                       char **report_id,
                       gvm_connection_t *connection,
                       const gchar *slave_id,
                       const gchar *slave_name)
{
  int ret, pid;
  task_status_t run_status;
  report_t last_stopped_report;
  char title[128], *uuid;
  target_t target;
  config_t config;
  credential_t ssh_credential, smb_credential, esxi_credential, snmp_credential;
  port_list_t port_list;

  ret = run_task_setup (task,
                        &config,
                        &target,
                        &port_list,
                        &ssh_credential,
                        &smb_credential,
                        &esxi_credential,
                        &snmp_credential);
  if (ret)
    return ret;

  /* When resuming, check that the scanner supports it. */

  if (from > 0 && config_type (config) > 0)
    return 4;

  /* Mark task "Requested".
   *
   * Every fail exit from here must reset the run status. */

  if (set_task_requested (task, &run_status))
    return 1;

  /* Prepare the report. */

  ret = run_task_prepare_report (
    task, report_id, from, run_status, &last_stopped_report);
  if (ret)
    {
      set_task_run_status (task, run_status);
      return ret;
    }

  /* Check target. */

  if (target_hosts (target) == NULL)
    {
      g_debug ("   target hosts is NULL");
      set_task_run_status (task, run_status);
      return -4;
    }

  set_report_scheduled (global_current_report);

  /* Every fail exit from here must reset to this run status, and must
   * clear global_current_report. */

  /** @todo On fail exits only, may need to honour request states that one of
   *        the other processes has set on the task (stop_task,
   *        request_delete_task). */

  /** @todo Also reset status on report, as current_scanner_task is 0 here. */

  run_status = TASK_STATUS_INTERRUPTED;

  /* Fork a child to start and handle the task while the parent responds to
   * the client. */

  pid = fork ();
  switch (pid)
    {
    case 0:
      /* Child.  Carry on starting the task, reopen the database (required
       * after fork). */
      reinit_manage_process ();
      manage_session_init (current_credentials.uuid);
      break;
    case -1:
      /* Parent when error. */
      set_task_interrupted (task,
                            "Failed to fork task child."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report, run_status);
      global_current_report = (report_t) 0;
      return -9;
      break;
    default:
      g_debug ("%s: forked %i to run slave/gmp task", __FUNCTION__, pid);
      /* Parent.  Return, in order to respond to client. */
      global_current_report = (report_t) 0;
      return 0;
      break;
    }

  /* Reset any running information. */

  {
    char *iface;
    iface = task_preference_value (task, "source_iface");
    if (iface)
      report_set_source_iface (global_current_report, iface);
    else
      report_set_source_iface (global_current_report, "");
    free (iface);
  }

  uuid = report_uuid (global_current_report);
  snprintf (title, sizeof (title), "mageni-sqlite: OTP: Handling sensor scan %s", uuid);
  free (uuid);
  proctitle_set (title);

  switch (handle_slave_task (task,
                             target,
                             ssh_credential,
                             smb_credential,
                             esxi_credential,
                             snmp_credential,
                             last_stopped_report,
                             connection,
                             slave_id,
                             slave_name))
    {
    case 0:
      break;
    default:
      assert (0);
    case 1:
      set_task_interrupted (task,
                            "Authentication with slave failed."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report, run_status);
      exit (EXIT_FAILURE);
    case -1:
      set_task_interrupted (task,
                            "Failed to make UUID."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report, run_status);
      exit (EXIT_FAILURE);
    case -2:
      set_task_interrupted (task,
                            "Failed to get slave task name."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report, run_status);
      exit (EXIT_FAILURE);
    }
  exit (EXIT_SUCCESS);
}

/**
 * @brief Start a task on a GMP scanner.
 *
 * @param[in]   task        The task.
 * @param[in]   scanner     Slave scanner to run task on.
 * @param[in]   from        0 start from beginning, 1 continue from stopped, 2
 *                          continue if stopped else start from beginning.
 * @param[out]  report_id   The report ID.
 *
 * @return Before forking: 1 task is active already, 3 failed to find task,
 *         -1 error.
 */
static int
run_gmp_task (task_t task, scanner_t scanner, int from, char **report_id)
{
  int ret;
  gvm_connection_t connection;
  char *scanner_id, *name;

  memset (&connection, 0, sizeof (connection));

  connection.host_string = scanner_host (scanner);
  if (connection.host_string == NULL)
    {
      g_warning ("%s: Scanner has no host", __FUNCTION__);
      return -1;
    }

  g_debug ("   %s: connection.host: %s", __FUNCTION__, connection.host_string);

  connection.port = scanner_port (scanner);
  if (connection.port == -1)
    {
      free (connection.host_string);
      g_warning ("%s: Scanner has no port", __FUNCTION__);
      return -1;
    }

  connection.username = scanner_login (scanner);
  if (connection.username == NULL)
    {
      free (connection.host_string);
      g_warning ("%s: Scanner has no login username", __FUNCTION__);
      return -1;
    }

  connection.password = scanner_password (scanner);
  if (connection.password == NULL)
    {
      free (connection.username);
      free (connection.host_string);
      g_warning ("%s: Scanner has no login password", __FUNCTION__);
      return -1;
    }

  connection.ca_cert = scanner_ca_pub (scanner);

  scanner_id = scanner_uuid (scanner);
  name = scanner_name (scanner);

  connection.tls = 1;

  ret = run_slave_or_gmp_task (
    task, from, report_id, &connection, scanner_id, name);

  free (connection.host_string);
  free (connection.username);
  free (connection.password);
  free (connection.ca_cert);
  free (scanner_id);
  free (name);

  return ret;
}

/**
 * @brief Start an OTP scanner task.
 *
 * @param[in]   task        The task.
 * @param[in]   scanner     Scanner to use.
 * @param[in]   from        0 start from beginning, 1 continue from stopped, 2
 *                          continue if stopped else start from beginning.
 * @param[out]  report_id   The report ID.
 *
 * @return Before forking: 1 task is active already, 3 failed to find task,
 */
static int
run_otp_task (task_t task, scanner_t scanner, int from, char **report_id)
{
  char title[128], *hosts, *port_range, *port, *uuid;
  gchar *plugins;
  int fail, pid, ret;
  GSList *files = NULL;
  GPtrArray *preference_files;
  task_status_t run_status;
  report_t last_stopped_report;
  target_t target;
  config_t config;
  credential_t ssh_credential, smb_credential, esxi_credential, snmp_credential;
  port_list_t port_list;

  /* Setup the task info required for the scan. */

  ret = run_task_setup (task,
                        &config,
                        &target,
                        &port_list,
                        &ssh_credential,
                        &smb_credential,
                        &esxi_credential,
                        &snmp_credential);
  if (ret)
    return ret;

  /* When resuming, check that the scanner supports it. */

  if (from > 0 && config_type (config) > 0)
    return 4;

  /* For local scans, setup the scanner. */

  switch (scanner_setup (scanner))
    {
    case 0:
      break;
    case 1:
      return -7;
    default:
      return -5;
    }

  if (!openvas_scanner_connected ()
      && (openvas_scanner_connect () || openvas_scanner_init (0)))
    return -5;

  if (openvas_scanner_is_loading ())
    {
      openvas_scanner_close ();
      return -5;
    }

  /* Mark task "Requested".
   *
   * Every fail exit from here must reset the run status. */

  if (set_task_requested (task, &run_status))
    return 1;

  /* Prepare the report. */

  ret = run_task_prepare_report (
    task, report_id, from, run_status, &last_stopped_report);
  if (ret)
    {
      set_task_run_status (task, run_status);
      return ret;
    }

  /* Check target. */

  if (target_hosts (target) == NULL)
    {
      g_debug ("   target hosts is NULL");
      set_task_run_status (task, run_status);
      return -4;
    }

  set_report_scheduled (global_current_report);

  /* Every fail exit from here must reset to this run status, and must
   * clear global_current_report. */

  /** @todo On fail exits only, may need to honour request states that one of
   *        the other processes has set on the task (stop_task,
   *        request_delete_task). */

  /** @todo Also reset status on report, as current_scanner_task is 0 here. */

  run_status = TASK_STATUS_INTERRUPTED;

  /* Fork a child to start and handle the task while the parent responds to
   * the client. */

  pid = fork ();
  switch (pid)
    {
    case 0:
      /* Child.  Carry on starting the task, reopen the database (required
       * after fork). */
      reinit_manage_process ();
      manage_session_init (current_credentials.uuid);
      break;
    case -1:
      /* Parent when error. */
      g_warning (
        "%s: Failed to fork task child: %s", __FUNCTION__, strerror (errno));
      set_task_interrupted (task,
                            "Failed to fork task child."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report, run_status);
      global_current_report = (report_t) 0;
      return -9;
      break;
    default:
      /* Parent.  Return, in order to respond to client. */
      global_current_report = (report_t) 0;
      return 0;
      break;
    }

  /* Reset any running information. */

  {
    char *iface;
    iface = task_preference_value (task, "source_iface");
    if (iface)
      report_set_source_iface (global_current_report, iface);
    else
      report_set_source_iface (global_current_report, "");
    free (iface);
  }

  uuid = report_uuid (global_current_report);
  snprintf (title, sizeof (title), "mageni-sqlite: OTP: Handling scan %s", uuid);
  free (uuid);
  proctitle_set (title);

  report_set_slave_uuid (global_current_report, "");
  report_set_slave_name (global_current_report, "");
  report_set_slave_port (global_current_report, 0);
  report_set_slave_host (global_current_report, "");

  /* Send the preferences header. */

  if (send_to_server ("CLIENT <|> PREFERENCES <|>\n"))
    {
      g_warning ("%s: Failed to send OTP PREFERENCES", __FUNCTION__);
      set_task_interrupted (task,
                            "Failed to send OTP PREFERENCES."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report, run_status);
      global_current_report = (report_t) 0;
      return -10;
    }

  /* Send the plugin list. */

  plugins = nvt_selector_plugins (config);
  if (plugins)
    {
      if (ssh_credential == 0 && smb_credential == 0 && esxi_credential == 0)
        fail = sendf_to_server ("plugin_set <|> %s\n", plugins);
      else
        {
          GString *auth_plugins = g_string_new ("");
          if (ssh_credential)
            g_string_append (auth_plugins, "1.3.6.1.4.1.25623.1.0.90022;");
          if (smb_credential)
            g_string_append (auth_plugins, "1.3.6.1.4.1.25623.1.0.90023;");
          if (esxi_credential)
            g_string_append (auth_plugins, "1.3.6.1.4.1.25623.1.0.105058;");
          if (snmp_credential)
            g_string_append (auth_plugins, "1.3.6.1.4.1.25623.1.0.105076;");

          fail = sendf_to_server (
            "plugin_set <|> %s%s\n", auth_plugins->str, plugins);
          g_string_free (auth_plugins, TRUE);
        }
    }
  else
    fail = send_to_server ("plugin_set <|> 0\n");
  free (plugins);
  if (fail)
    {
      set_task_interrupted (task,
                            "Failed to send OTP plugin set."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report, run_status);
      global_current_report = (report_t) 0;
      return -10;
    }

  /* Send the scanner and task preferences. */

  if (send_config_preferences (config, "SERVER_PREFS", NULL, NULL))
    {
      set_task_interrupted (task,
                            "Failed to send OTP SERVER PREFS."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report, run_status);
      global_current_report = (report_t) 0;
      return -10;
    }

  if (send_task_preferences (task))
    {
      set_task_interrupted (task,
                            "Failed to send OTP task preferences."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report, run_status);
      global_current_report = (report_t) 0;
      return -10;
    }

  /* Send the port range. */

  port_range = target_port_range (target);
  if (sendf_to_server ("port_range <|> %s\n",
                       port_range ? port_range : "default"))
    {
      free (port_range);
      set_task_interrupted (task,
                            "Failed to send OTP port_range."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report, run_status);
      global_current_report = (report_t) 0;
      return -10;
    }
  free (port_range);

  /* Send the SSH LSC port. */

  port = target_ssh_port (target);
  if (port && sendf_to_server ("auth_port_ssh <|> %s\n", port))
    {
      free (port);
      set_task_interrupted (task,
                            "Failed to send OTP auth_port_ssh."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report, run_status);
      global_current_report = (report_t) 0;
      return -10;
    }
  free (port);

  /* Collect task files to send. */

  files = get_files_to_send (task);

  /* Send the plugins preferences. */

  preference_files = g_ptr_array_new ();
  if (send_config_preferences (
        config, "PLUGINS_PREFS", files, preference_files))
    {
      g_ptr_array_free (preference_files, TRUE);
      slist_free (files);
      set_task_interrupted (task,
                            "Failed to send OTP PLUGINS_PREFS."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report, run_status);
      global_current_report = (report_t) 0;
      return -10;
    }

  /* Send other scanner preferences. */

  if (send_scanner_preferences (task, target, last_stopped_report))
    {
      g_ptr_array_add (preference_files, NULL);
      array_free (preference_files);
      slist_free (files);
      set_task_interrupted (task,
                            "Failed to send OTP scanner preferences."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report, run_status);
      global_current_report = (report_t) 0;
      return -10;
    }

  /* Send credential preferences if there are credentials linked to target. */

  if (ssh_credential)
    {
      iterator_t credentials;

      init_credential_iterator_one (&credentials, ssh_credential);
      if (next (&credentials))
        {
          const char *user = credential_iterator_login (&credentials);
          const char *password = credential_iterator_password (&credentials);

          if (sendf_to_server ("SSH Authorization[entry]:SSH login name:"
                               " <|> %s\n",
                               user ? user : "")
              || (credential_iterator_private_key (&credentials)
                    ? sendf_to_server ("SSH Authorization[password]:"
                                       "SSH key passphrase:"
                                       " <|> %s\n",
                                       password ? password : "")
                    : sendf_to_server ("SSH Authorization[password]:"
                                       "SSH password (unsafe!):"
                                       " <|> %s\n",
                                       password ? password : "")))

            {
            fail:
              cleanup_iterator (&credentials);
              g_ptr_array_add (preference_files, NULL);
              array_free (preference_files);
              slist_free (files);
              set_task_interrupted (task,
                                    "Failed to send OTP SSH preferences."
                                    "  Interrupting scan.");
              set_report_scan_run_status (global_current_report, run_status);
              global_current_report = (report_t) 0;
              return -10;
            }

          if (credential_iterator_private_key (&credentials))
            {
              char *file_uuid = gvm_uuid_make ();
              if (file_uuid == NULL)
                goto fail;

              g_ptr_array_add (preference_files, (gpointer) file_uuid);
              g_ptr_array_add (
                preference_files,
                (gpointer) g_strdup (
                  credential_iterator_private_key (&credentials)));

              if (sendf_to_server ("SSH Authorization[file]:"
                                   "SSH private key:"
                                   " <|> %s\n",
                                   file_uuid))
                goto fail;
            }
        }
      cleanup_iterator (&credentials);
    }

  if (smb_credential)
    {
      iterator_t credentials;

      init_credential_iterator_one (&credentials, smb_credential);
      if (next (&credentials))
        {
          const char *user = credential_iterator_login (&credentials);
          const char *password = credential_iterator_password (&credentials);

          if (sendf_to_server ("SMB Authorization[entry]:SMB login: <|> %s\n",
                               user ? user : "")
              || sendf_to_server ("SMB Authorization[password]:SMB password:"
                                  " <|> %s\n",
                                  password ? password : ""))
            {
              cleanup_iterator (&credentials);
              g_ptr_array_add (preference_files, NULL);
              array_free (preference_files);
              slist_free (files);
              set_task_interrupted (task,
                                    "Failed to send OTP SMB preferences."
                                    "  Interrupting scan.");
              set_report_scan_run_status (global_current_report, run_status);
              global_current_report = (report_t) 0;
              return -10;
            }
        }
      cleanup_iterator (&credentials);
    }

  if (esxi_credential)
    {
      iterator_t credentials;

      init_credential_iterator_one (&credentials, esxi_credential);
      if (next (&credentials))
        {
          const char *user = credential_iterator_login (&credentials);
          const char *password = credential_iterator_password (&credentials);

          if (sendf_to_server ("ESXi Authorization[entry]:ESXi login name:"
                               " <|> %s\n",
                               user ? user : "")
              || sendf_to_server (
                   "ESXi Authorization[password]:ESXi login password:"
                   " <|> %s\n",
                   password ? password : ""))
            {
              cleanup_iterator (&credentials);
              g_ptr_array_add (preference_files, NULL);
              array_free (preference_files);
              slist_free (files);
              set_task_interrupted (task,
                                    "Failed to send OTP EXSi preferences."
                                    "  Interrupting scan.");
              set_report_scan_run_status (global_current_report, run_status);
              global_current_report = (report_t) 0;
              return -10;
            }
        }
      cleanup_iterator (&credentials);
    }

  if (snmp_credential)
    {
      iterator_t credentials;

      init_credential_iterator_one (&credentials, snmp_credential);
      if (next (&credentials))
        {
          const char *community = credential_iterator_community (&credentials);
          const char *user = credential_iterator_login (&credentials);
          const char *password = credential_iterator_password (&credentials);
          const char *auth_algorithm =
            credential_iterator_auth_algorithm (&credentials);
          const char *privacy_password =
            credential_iterator_privacy_password (&credentials);
          const char *privacy_algorithm =
            credential_iterator_privacy_algorithm (&credentials);

          if (sendf_to_server ("SNMP Authorization[password]:SNMP Community:"
                               " <|> %s\n",
                               community ? community : "")
              || sendf_to_server ("SNMP Authorization[entry]:SNMPv3 Username:"
                                  " <|> %s\n",
                                  user ? user : "")
              || sendf_to_server ("SNMP Authorization[password]:"
                                  "SNMPv3 Password:"
                                  " <|> %s\n",
                                  password ? password : "")
              || sendf_to_server ("SNMP Authorization[radio]:"
                                  "SNMPv3 Authentication Algorithm:"
                                  " <|> %s\n",
                                  auth_algorithm ? auth_algorithm : "")
              || sendf_to_server ("SNMP Authorization[password]:"
                                  "SNMPv3 Privacy Password:"
                                  " <|> %s\n",
                                  privacy_password ? privacy_password : "")
              || sendf_to_server ("SNMP Authorization[radio]:"
                                  "SNMPv3 Privacy Algorithm:"
                                  " <|> %s\n",
                                  privacy_algorithm ? privacy_algorithm : ""))
            {
              cleanup_iterator (&credentials);
              g_ptr_array_add (preference_files, NULL);
              array_free (preference_files);
              slist_free (files);
              set_task_interrupted (task,
                                    "Failed to send OTP SNMP preferences."
                                    "  Interrupting scan.");
              set_report_scan_run_status (global_current_report, run_status);
              global_current_report = (report_t) 0;
              return -10;
            }
        }
      cleanup_iterator (&credentials);
    }

  g_ptr_array_add (preference_files, NULL);

  /* Send preferences for target "Alive Test", overriding config values. */

  if (send_alive_test_preferences (target))
    {
      array_free (preference_files);
      slist_free (files);
      set_task_interrupted (task,
                            "Failed to send OTP alive test preferences."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report, run_status);
      global_current_report = (report_t) 0;
      return -10;
    }

  /* Send network_targets preference. */

  hosts = target_hosts (target);
  if (!hosts || sendf_to_server ("network_targets <|> %s\n", hosts))
    {
      g_free (hosts);
      g_ptr_array_add (preference_files, NULL);
      array_free (preference_files);
      slist_free (files);
      set_task_interrupted (task,
                            "Failed to send OTP network_targets."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report, run_status);
      global_current_report = (report_t) 0;
      return -10;
    }

  /* End off preferences. */

  if (send_to_server ("<|> CLIENT\n"))
    {
      free (hosts);
      array_free (preference_files);
      slist_free (files);
      set_task_interrupted (task,
                            "Failed to send OTP CLIENT."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report, run_status);
      global_current_report = (report_t) 0;
      return -10;
    }

  /* Send any files stored in the config preferences. */

  {
    gchar *file;
    int index = 0;
    while ((file = g_ptr_array_index (preference_files, index)))
      {
        GSList *head;
        gchar *value;

        index++;

        /* Skip the file if the value of the preference is the name of a
         * file associated with the task. */
        value = g_ptr_array_index (preference_files, index);
        head = files;
        while (head)
          {
            if (strcmp (head->data, value) == 0)
              break;
            head = g_slist_next (head);
          }

        if (head == NULL && send_file (file, value))
          {
            free (hosts);
            array_free (preference_files);
            slist_free (files);
            g_warning ("%s: Failed to send an OTP file", __FUNCTION__);
            set_task_interrupted (task,
                                  "Failed to send OTP file."
                                  "  Interrupting scan.");
            set_report_scan_run_status (global_current_report, run_status);
            global_current_report = (report_t) 0;
            return -10;
          }
        index++;
      }

    array_free (preference_files);
  }

  /* Send any files. */

  while (files)
    {
      GSList *last = files;
      if (send_task_file (task, files->data))
        {
          free (hosts);
          slist_free (files);
          set_task_interrupted (task,
                                "Failed to send an OTP task file."
                                "  Interrupting scan.");
          set_report_scan_run_status (global_current_report, run_status);
          global_current_report = (report_t) 0;
          return -10;
        }
      files = g_slist_next (files);
      g_free (last->data);
      g_slist_free_1 (last);
    }

  /* Send the attack command. */

  /* Send all the hosts to the Scanner.  When resuming a stopped task,
   * the hosts that have been completely scanned are excluded by being
   * included in exclude_hosts preference. */
  fail = sendf_to_server (
    "CLIENT <|> LONG_ATTACK <|>\n%d\n%s\n", strlen (hosts), hosts);
  free (hosts);
  if (fail)
    {
      set_task_interrupted (task,
                            "Failed to send OTP LONG_ATTACK."
                            "  Interrupting scan.");
      set_report_scan_run_status (global_current_report, run_status);
      global_current_report = (report_t) 0;
      return -10;
    }

  current_scanner_task = task;

  return 2;
}

/**
 * @brief Start or resume a task.
 *
 * Use \ref send_to_server to queue the task start sequence in the scanner
 * output buffer.
 *
 * Only one task can run at a time in a process.
 *
 * @param[in]   task_id     The task ID.
 * @param[out]  report_id   The report ID.
 * @param[in]   from        0 start from beginning, 1 continue from stopped, 2
 *                          continue if stopped else start from beginning.
 *
 * @return Before forking: 1 task is active already, 3 failed to find task,
 *         4 resuming task not supported, 99 permission denied, -1 error,
 *         -2 task is missing a target,
 *         -3 creating the report failed, -4 target missing hosts, -5 scanner is
 *         down or still loading, -6 already a task running in this process,
 *         -7 no CA cert, -9 fork failed.  After forking: 0 success (parent),
 *         2 success (child), -10 error (child).
 */
static int
run_task (const char *task_id, char **report_id, int from)
{
  task_t task;
  scanner_t scanner;
  int ret;
  const char *permission;

  if (current_scanner_task)
    return -6;

  if (from == 0)
    permission = "start_task";
  else if (from == 1)
    permission = "resume_task";
  else
    {
      assert (0);
      permission = "internal_error";
    }

  task = 0;
  if (find_task_with_permission (task_id, &task, permission))
    return -1;
  if (task == 0)
    return 3;

  scanner = task_scanner (task);
  assert (scanner);
  ret = check_available ("scanner", scanner, "get_scanners");
  if (ret)
    return ret;

  if (scanner_type (scanner) == SCANNER_TYPE_CVE)
    return run_cve_task (task);

  if (scanner_type (scanner) == SCANNER_TYPE_GMP)
    return run_gmp_task (task, scanner, from, report_id);

  if (scanner_type (scanner) != SCANNER_TYPE_OPENVAS)
    return run_osp_task (task);

  return run_otp_task (task, scanner, from, report_id);
}

/**
 * @brief Start a task.
 *
 * Use \ref send_to_server to queue the task start sequence in the scanner
 * output buffer.
 *
 * Only one task can run at a time in a process.
 *
 * @param[in]   task_id    The task ID.
 * @param[out]  report_id  The report ID.
 *
 * @return Before forking: 1 task is active already, 3 failed to find task,
 *         99 permission denied, -1 internal error,
 *         -2 task is missing a target, -3 creating the report failed,
 *         -4 target missing hosts, -6 already a task running in this process,
 *         -7 no CA cert, -9 fork failed.
 *         After forking: 0 success (parent), 2 success (child),
 *         -10 error (child).
 */
int
start_task (const char *task_id, char **report_id)
{
  if (acl_user_may ("start_task") == 0)
    return 99;

  return run_task (task_id, report_id, 0);
}

/**
 * @brief Stop an OSP task.
 *
 * @param[in]   task  The task.
 *
 * @return 0 on success, else -1.
 */
static int
stop_osp_task (task_t task)
{
  osp_connection_t *connection;
  int ret = -1;
  char *scan_id;

  connection = osp_scanner_connect (task_scanner (task));
  if (!connection)
    goto end_stop_osp;
  scan_id = report_uuid (task_running_report (task));
  if (!scan_id)
    goto end_stop_osp;
  set_task_run_status (task, TASK_STATUS_STOP_REQUESTED);
  ret = osp_stop_scan (connection, scan_id, NULL);
  osp_connection_close (connection);
  g_free (scan_id);

end_stop_osp:
  set_task_end_time_epoch (task, time (NULL));
  set_scan_end_time_epoch (global_current_report, time (NULL));
  set_task_run_status (task, TASK_STATUS_STOPPED);
  set_report_scan_run_status (global_current_report, TASK_STATUS_STOPPED);
  if (ret)
    return -1;
  return 0;
}

/**
 * @brief Initiate stopping a task.
 *
 * Use \ref send_to_server to queue the task stop sequence in the
 * scanner output buffer.
 *
 * @param[in]  task  Task.
 *
 * @return 0 on success, 1 if stop requested, -1 if out of space in scanner
 *         output buffer, -5 scanner down, -7 no CA cert.
 */
int
stop_task_internal (task_t task)
{
  task_status_t run_status;

  run_status = task_run_status (task);
  if (run_status == TASK_STATUS_REQUESTED || run_status == TASK_STATUS_RUNNING)
    {
      if (current_scanner_task == task)
        {
          scanner_t scanner = task_scanner (task);

          assert (scanner);
          switch (scanner_setup (scanner))
            {
            case 0:
              break;
            case 1:
              return -7;
            default:
              return -5;
            }
          if (!openvas_scanner_connected ()
              && (openvas_scanner_connect () || openvas_scanner_init (0)))
            return -5;
          if (send_to_server ("CLIENT <|> STOP_WHOLE_TEST <|> CLIENT\n"))
            return -1;
        }
      set_task_run_status (task, TASK_STATUS_STOP_REQUESTED);
      return 1;
    }
  else if (run_status == TASK_STATUS_DELETE_REQUESTED
           || run_status == TASK_STATUS_DELETE_WAITING
           || run_status == TASK_STATUS_DELETE_ULTIMATE_REQUESTED
           || run_status == TASK_STATUS_DELETE_ULTIMATE_WAITING
           || run_status == TASK_STATUS_STOP_REQUESTED
           || run_status == TASK_STATUS_STOP_WAITING)
    {
      scanner_t scanner;

      scanner = task_scanner (task);
      assert (scanner);
      if (scanner_type (scanner) == SCANNER_TYPE_GMP)
        {
          /* A special request from the user to get the task out of a requested
           * state when contact with the slave is lost. */
          set_task_run_status (task, TASK_STATUS_STOP_REQUESTED_GIVEUP);
          return 1;
        }
    }

  return 0;
}

/**
 * @brief Initiate stopping a task.
 *
 * Use \ref send_to_server to queue the task stop sequence in the
 * scanner output buffer.
 *
 * @param[in]  task_id  Task UUID.
 *
 * @return 0 on success, 1 if stop requested, 3 failed to find task,
 *         99 permission denied, -1 if out of space in scanner output buffer,
 *         -5 scanner down.
 */
int
stop_task (const char *task_id)
{
  task_t task;

  if (acl_user_may ("stop_task") == 0)
    return 99;

  task = 0;
  if (find_task_with_permission (task_id, &task, "stop_task"))
    return -1;
  if (task == 0)
    return 3;

  if (config_type (task_config (task)) != 0)
    return stop_osp_task (task);

  return stop_task_internal (task);
}

/**
 * @brief Resume a task.
 *
 * @param[in]   task_id    Task UUID.
 * @param[out]  report_id  If successful, ID of the resultant report.
 *
 * @return 22 caller error (task must be in "stopped" or "interrupted" state),
 *         or any start_task error.
 */
int
resume_task (const char *task_id, char **report_id)
{
  task_t task;
  task_status_t run_status;

  if (acl_user_may ("resume_task") == 0)
    return 99;

  task = 0;
  if (find_task_with_permission (task_id, &task, "resume_task"))
    return -1;
  if (task == 0)
    return 3;

  run_status = task_run_status (task);
  if ((run_status == TASK_STATUS_STOPPED)
      || (run_status == TASK_STATUS_INTERRUPTED))
    return run_task (task_id, report_id, 1);
  return 22;
}

/**
 * @brief Reassign a task to another slave.
 *
 * @param[in]  task_id    UUID of task.
 * @param[in]  slave_id   UUID of slave.
 *
 * @return 0 success, 1 success, process forked, 2 task not found,
 *         3 slave not found, 4 slaves not supported by scanner, 5 task cannot
 *         be stopped currently, 6 scanner does not allow stopping, 7 new
 *         scanner does not support slaves, 98 stop and resume permission
 *         denied, 99 permission denied, -1 error.
 */
int
move_task (const char *task_id, const char *slave_id)
{
  task_t task;
  int task_scanner_type, slave_scanner_type;
  scanner_t slave, scanner;
  task_status_t status;
  int should_resume_task = 0;

  if (task_id == NULL)
    return -1;
  if (slave_id == NULL)
    return -1;

  if (acl_user_may ("modify_task") == 0)
    return 99;

  /* Find the task. */

  if (find_task_with_permission (task_id, &task, "get_tasks"))
    return -1;
  if (task == 0)
    return 2;

  /* Make sure destination scanner supports slavery. */

  if (strcmp (slave_id, "") == 0)
    slave_id = SCANNER_UUID_DEFAULT;

  if (find_scanner_with_permission (slave_id, &slave, "get_scanners"))
    return -1;
  if (slave == 0)
    return 3;

  slave_scanner_type = scanner_type (slave);
  if (slave_scanner_type != SCANNER_TYPE_OPENVAS
      && slave_scanner_type != SCANNER_TYPE_GMP)
    return 7;

  /* Make sure current scanner supports slavery. */

  scanner = task_scanner (task);
  if (scanner == 0)
    return -1;

  task_scanner_type = scanner_type (scanner);
  if (task_scanner_type != SCANNER_TYPE_OPENVAS
      && task_scanner_type != SCANNER_TYPE_GMP)
    return 4;

  /* Stop task if required. */

  status = task_run_status (task);

  switch (status)
    {
    case TASK_STATUS_DELETE_REQUESTED:
    case TASK_STATUS_DELETE_ULTIMATE_REQUESTED:
    case TASK_STATUS_DELETE_WAITING:
    case TASK_STATUS_DELETE_ULTIMATE_WAITING:
    case TASK_STATUS_REQUESTED:
      // Task cannot be stopped now
      return 5;
      break;
    case TASK_STATUS_RUNNING:
      if (task_scanner_type == SCANNER_TYPE_CVE)
        return 6;
      // Check permissions to stop and resume task
      if (acl_user_has_access_uuid ("task", task_id, "stop_task", 0)
          && acl_user_has_access_uuid ("task", task_id, "resume_task", 0))
        {
          // Stop the task, wait and resume after changes
          stop_task_internal (task);
          should_resume_task = 1;

          status = task_run_status (task);
          while (status == TASK_STATUS_STOP_REQUESTED
                 || status == TASK_STATUS_STOP_REQUESTED_GIVEUP
                 || status == TASK_STATUS_STOP_WAITING)
            {
              sleep (5);
              status = task_run_status (task);
            }
        }
      else
        return 98;
      break;
    case TASK_STATUS_STOP_REQUESTED:
    case TASK_STATUS_STOP_REQUESTED_GIVEUP:
    case TASK_STATUS_STOP_WAITING:
      while (status == TASK_STATUS_STOP_REQUESTED
             || status == TASK_STATUS_STOP_REQUESTED_GIVEUP
             || status == TASK_STATUS_STOP_WAITING)
        {
          sleep (5);
          status = task_run_status (task);
        }
      break;
    default:
      break;
    }

  /* Update scanner. */

  set_task_scanner (task, slave);

  /* Resume task if required. */

  if (should_resume_task)
    {
      pid_t pid = getpid ();

      resume_task (task_id, NULL);

      if (getpid () != pid)
        return 1;
    }

  return 0;
}

/* OTP Scanner messaging. */

/**
 * @brief Acknowledge a scanner BYE.
 *
 * @return 0 on success, -1 if out of space in scanner output buffer.
 */
int
acknowledge_bye ()
{
  if (send_to_server ("CLIENT <|> BYE <|> ACK\n"))
    return -1;
  return 0;
}

/**
 * @brief Acknowledge scanner PLUGINS_FEED_VERSION message,
 * @brief requesting all plugin info.
 *
 * @return 0 on success, -1 if out of space in scanner output buffer.
 */
int
acknowledge_feed_version_info ()
{
  if (send_to_server ("CLIENT <|> COMPLETE_LIST <|> CLIENT\n"))
    return -1;
  return 0;
}

/**
 * @brief Handle state changes to current task made by other processes.
 *
 * @return 0 on success, -1 if out of space in scanner output buffer, 1 if
 *         queued to scanner.
 */
int
manage_check_current_task ()
{
  if (current_scanner_task)
    {
      task_status_t run_status;

      /* Commit pending transaction if needed. */
     // manage_transaction_stop (FALSE);

      /* Check if some other process changed the status. */

      run_status = task_run_status (current_scanner_task);
      switch (run_status)
        {
        case TASK_STATUS_STOP_REQUESTED_GIVEUP:
          /* This should only happen for slave tasks. */
          assert (0);
        case TASK_STATUS_STOP_REQUESTED:
          if (send_to_server ("CLIENT <|> STOP_WHOLE_TEST <|> CLIENT\n"))
            return -1;
          set_task_run_status (current_scanner_task, TASK_STATUS_STOP_WAITING);
          return 1;
          break;
        case TASK_STATUS_DELETE_REQUESTED:
          if (send_to_server ("CLIENT <|> STOP_WHOLE_TEST <|> CLIENT\n"))
            return -1;
          set_task_run_status (current_scanner_task,
                               TASK_STATUS_DELETE_WAITING);
          return 1;
          break;
        case TASK_STATUS_DELETE_ULTIMATE_REQUESTED:
          if (send_to_server ("CLIENT <|> STOP_WHOLE_TEST <|> CLIENT\n"))
            return -1;
          set_task_run_status (current_scanner_task,
                               TASK_STATUS_DELETE_ULTIMATE_WAITING);
          return 1;
          break;
        case TASK_STATUS_DELETE_WAITING:
        case TASK_STATUS_DELETE_ULTIMATE_WAITING:
        case TASK_STATUS_DONE:
        case TASK_STATUS_NEW:
        case TASK_STATUS_REQUESTED:
        case TASK_STATUS_RUNNING:
        case TASK_STATUS_STOP_WAITING:
        case TASK_STATUS_STOPPED:
        case TASK_STATUS_INTERRUPTED:
          break;
        }
    }
  return 0;
}

/* Credentials. */

/**
 * @brief Get the written-out name of an LSC Credential type.
 *
 * @param[in]  abbreviation  The type abbreviation.
 *
 * @return The written-out type name.
 */
const char *
credential_full_type (const char *abbreviation)
{
  if (abbreviation == NULL)
    return NULL;
  else if (strcasecmp (abbreviation, "cc") == 0)
    return "client certificate";
  else if (strcasecmp (abbreviation, "pw") == 0)
    return "password only";
  else if (strcasecmp (abbreviation, "snmp") == 0)
    return "SNMP";
  else if (strcasecmp (abbreviation, "up") == 0)
    return "username + password";
  else if (strcasecmp (abbreviation, "usk") == 0)
    return "username + SSH key";
  else
    return abbreviation;
}

/* System reports. */

/**
 * @brief Get system report types from a slave.
 *
 * @param[in]   required_type  Single type to limit types to.
 * @param[out]  types          Types on success.
 * @param[out]  start          Actual start of types, which caller must free.
 * @param[out]  slave_id       ID of GMP slave.
 *
 * @return 0 if successful, 2 failed to find slave, 3 unused, 4 could not
 * connect to slave, 5 authentication failed, 6 failed to get system report,
 * -1 otherwise.
 */
static int
get_slave_system_report_types (const char *required_type,
                               gchar ***start,
                               gchar ***types,
                               const char *slave_id)
{
  scanner_t slave = 0;
  char *host, **end;
  int port, socket;
  gnutls_session_t session;
  entity_t get, report;
  entities_t reports;
  int ret;

  if (find_scanner_with_permission (slave_id, &slave, "get_scanners"))
    return -1;
  if (slave == 0)
    return 2;

  host = scanner_host (slave);
  if (host == NULL)
    return -1;

  g_debug ("   %s: host: %s", __FUNCTION__, host);

  port = scanner_port (slave);
  if (port == -1)
    {
      free (host);
      return -1;
    }

  socket = gvm_server_open (&session, host, port);
  free (host);
  if (socket == -1)
    return 4;

  g_debug ("   %s: connected", __FUNCTION__);

  /* Authenticate using the slave login. */

  if (slave_authenticate (&session, slave))
    {
      ret = 5;
      goto fail;
    }

  g_debug ("   %s: authenticated", __FUNCTION__);

  if (gmp_get_system_reports (&session, required_type, 1, &get))
    {
      ret = 6;
      goto fail;
    }

  gvm_server_close (socket, session);

  reports = get->entities;
  end = *types = *start =
    g_malloc ((xml_count_entities (reports) + 1) * sizeof (gchar *));
  while ((report = first_entity (reports)))
    {
      if (strcmp (entity_name (report), "system_report") == 0)
        {
          entity_t name, title;
          gchar *pair;
          char *name_text, *title_text;
          name = entity_child (report, "name");
          title = entity_child (report, "title");
          if (name == NULL || title == NULL)
            {
              *end = NULL;
              g_strfreev (*start);
              free_entity (get);
              return -1;
            }
          name_text = entity_text (name);
          title_text = entity_text (title);
          *end = pair = g_malloc (strlen (name_text) + strlen (title_text) + 2);
          strcpy (pair, name_text);
          pair += strlen (name_text) + 1;
          strcpy (pair, title_text);
          end++;
        }
      reports = next_entities (reports);
    }
  *end = NULL;

  free_entity (get);

  return 0;

fail:
  gvm_server_close (socket, session);
  return ret;
}

/**
 * @brief Command called by get_system_report_types.
 *        gvmcg stands for gvm-create-graphs.
 */
#define COMMAND "gvmcg 0 titles"

/**
 * @brief Get system report types.
 *
 * @param[in]   required_type  Single type to limit types to.
 * @param[out]  types          Types on success.
 * @param[out]  start          Actual start of types, which caller must free.
 * @param[out]  slave_id       ID of slave.
 *
 * @return 0 if successful, 1 failed to find report type, 2 failed to find
 *         slave, 3 serving the fallback, 4 could not connect to slave,
 *         5 authentication failed, 6 failed to get system report,
 *         -1 otherwise.
 */
static int
get_system_report_types (const char *required_type,
                         gchar ***start,
                         gchar ***types,
                         const char *slave_id)
{
  gchar *astdout = NULL;
  gchar *astderr = NULL;
  GError *err = NULL;
  gint exit_status;

  if (slave_id && strcmp (slave_id, "0"))
    return get_slave_system_report_types (
      required_type, start, types, slave_id);

  g_debug ("   command: " COMMAND);

  if ((g_spawn_command_line_sync (
         COMMAND, &astdout, &astderr, &exit_status, &err)
       == FALSE)
      || (WIFEXITED (exit_status) == 0) || WEXITSTATUS (exit_status))
    {
      g_debug ("%s: gvmcg failed with %d", __FUNCTION__, exit_status);
      g_debug ("%s: stdout: %s", __FUNCTION__, astdout);
      g_debug ("%s: stderr: %s", __FUNCTION__, astderr);
      g_free (astdout);
      g_free (astderr);
      *start = *types = g_malloc0 (sizeof (gchar *) * 2);
      (*start)[0] = g_strdup ("fallback Fallback Report");
      (*start)[0][strlen ("fallback")] = '\0';
      return 3;
    }
  if (astdout)
    {
      char **type;
      *start = *types = type = g_strsplit (g_strchomp (astdout), "\n", 0);
      while (*type)
        {
          char *space;
          space = strchr (*type, ' ');
          if (space == NULL)
            {
              g_strfreev (*types);
              *types = NULL;
              g_free (astdout);
              g_free (astderr);
              return -1;
            }
          *space = '\0';
          if (required_type && (strcmp (*type, required_type) == 0))
            {
              char **next;
              /* Found the single given type. */
              next = type + 1;
              while (*next)
                {
                  free (*next);
                  next++;
                }
              next = type + 1;
              *next = NULL;
              *types = type;
              g_free (astdout);
              g_free (astderr);
              return 0;
            }
          type++;
        }
      if (required_type)
        {
          /* Failed to find the single given type. */
          g_free (astdout);
          g_free (astderr);
          g_strfreev (*types);
          return 1;
        }
    }
  else
    *start = *types = g_malloc0 (sizeof (gchar *));

  g_free (astdout);
  g_free (astderr);
  return 0;
}

#undef COMMAND

/**
 * @brief Initialise a system report type iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  type        Single report type to iterate over, NULL for all.
 * @param[in]  slave_id    ID of slave to get reports from.  0 for local.
 *
 * @return 0 on success, 1 failed to find report type, 2 failed to find slave,
 *         3 used the fallback report,  4 could not connect to slave,
 *         5 authentication failed, 6 failed to get system report,
 *         99 permission denied, -1 on error.
 */
int
init_system_report_type_iterator (report_type_iterator_t *iterator,
                                  const char *type,
                                  const char *slave_id)
{
  int ret;

  if (acl_user_may ("get_system_reports") == 0)
    return 99;

  ret = get_system_report_types (
    type, &iterator->start, &iterator->current, slave_id);
  if (ret == 0 || ret == 3)
    {
      iterator->current--;
      return ret;
    }
  return ret;
}

/**
 * @brief Cleanup a report type iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
cleanup_report_type_iterator (report_type_iterator_t *iterator)
{
  g_strfreev (iterator->start);
}

/**
 * @brief Increment a report type iterator.
 *
 * The caller must stop using this after it returns FALSE.
 *
 * @param[in]  iterator  Task iterator.
 *
 * @return TRUE if there was a next item, else FALSE.
 */
gboolean
next_report_type (report_type_iterator_t *iterator)
{
  iterator->current++;
  if (*iterator->current == NULL)
    return FALSE;
  return TRUE;
}

/**
 * @brief Return the name from a report type iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Name.
 */
const char *
report_type_iterator_name (report_type_iterator_t *iterator)
{
  return (const char *) *iterator->current;
}

/**
 * @brief Return the title from a report type iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Title.
 */
const char *
report_type_iterator_title (report_type_iterator_t *iterator)
{
  const char *name = *iterator->current;
  return name + strlen (name) + 1;
}

/**
 * @brief Get a system report from a slave.
 *
 * @param[in]  name       Name of report.
 * @param[in]  duration   Time range of report, in seconds.
 * @param[in]  start_time Time of first data point in report.
 * @param[in]  end_time   Time of last data point in report.
 * @param[in]  slave_id   ID of GMP scanner slave to get report from.
 *                        0 for local.
 * @param[out] report     On success, report in base64 if such a report exists
 *                        else NULL.  Arbitrary on error.
 *
 * @return 0 if successful, 2 failed to find slave, 3 unused, 4 could not
 * connect to slave, 5 authentication failed, 6 failed to get system report,
 * -1 otherwise.
 */
static int
slave_system_report (const char *name,
                     const char *duration,
                     const char *start_time,
                     const char *end_time,
                     const char *slave_id,
                     char **report)
{
  scanner_t slave = 0;
  char *host;
  int port, socket;
  gnutls_session_t session;
  entity_t get, entity;
  entities_t reports;
  gmp_get_system_reports_opts_t opts;
  int ret;

  if (find_scanner_with_permission (slave_id, &slave, "get_slaves"))
    return -1;
  if (slave == 0)
    return 2;

  host = scanner_host (slave);
  if (host == NULL)
    return -1;

  g_debug ("   %s: host: %s", __FUNCTION__, host);

  port = scanner_port (slave);
  if (port == -1)
    {
      free (host);
      return -1;
    }

  socket = gvm_server_open (&session, host, port);
  free (host);
  if (socket == -1)
    return 4;

  g_debug ("   %s: connected", __FUNCTION__);

  /* Authenticate using the slave login. */

  if (slave_authenticate (&session, slave))
    {
      ret = 5;
      goto fail;
    }

  g_debug ("   %s: authenticated", __FUNCTION__);

  opts = gmp_get_system_reports_opts_defaults;
  opts.name = name;
  opts.duration = duration;
  opts.start_time = start_time;
  opts.end_time = end_time;
  opts.brief = 0;

  if (gmp_get_system_reports_ext (&session, opts, &get))
    {
      ret = 6;
      goto fail;
    }

  gvm_server_close (socket, session);

  reports = get->entities;
  if ((entity = first_entity (reports))
      && (strcmp (entity_name (entity), "system_report") == 0))
    {
      entity = entity_child (entity, "report");
      if (entity)
        {
          *report = g_strdup (entity_text (entity));
          return 0;
        }
    }

  free_entity (get);
  g_warning ("   %s: error getting entity", __FUNCTION__);
  return 6;

fail:
  gvm_server_close (socket, session);
  return ret;
}

/**
 * @brief Header for fallback system report.
 */
#define FALLBACK_SYSTEM_REPORT_HEADER                                          \
  "This is the most basic, fallback report.  The system can be configured "    \
  "to\n"                                                                       \
  "produce more powerful reports.  Please contact your system administrator\n" \
  "for more information.\n\n"

/**
 * @brief Default duration for system reports.
 */
#define DEFAULT_DURATION 86400L

/**
 * @brief Get a system report.
 *
 * @param[in]  name       Name of report.
 * @param[in]  duration   Time range of report, in seconds.
 * @param[in]  start_time Time of first data point in report.
 * @param[in]  end_time   Time of last data point in report.
 * @param[in]  slave_id   ID of slave to get report from.  0 for local.
 * @param[out] report     On success, report in base64 if such a report exists
 *                        else NULL.  Arbitrary on error.
 *
 * @return 0 if successful (including failure to find report), -1 on error,
 *         3 if used the fallback report,  4 could not connect to slave,
 *         5 authentication failed, 6 failed to get system report.
 */
int
manage_system_report (const char *name,
                      const char *duration,
                      const char *start_time,
                      const char *end_time,
                      const char *slave_id,
                      char **report)
{
  gchar *astdout = NULL;
  gchar *astderr = NULL;
  GError *err = NULL;
  gint exit_status;
  gchar *command;
  time_t start_time_num, end_time_num, duration_num;
  start_time_num = 0;
  end_time_num = 0;
  duration_num = 0;

  assert (name);

  if (duration && strcmp (duration, ""))
    {
      duration_num = atol (duration);
      if (duration_num == 0)
        return manage_system_report ("blank", NULL, NULL, NULL, NULL, report);
    }
  if (start_time && strcmp (start_time, ""))
    {
      start_time_num = parse_iso_time (start_time);
      if (start_time_num == 0)
        return manage_system_report ("blank", NULL, NULL, NULL, NULL, report);
    }
  if (end_time && strcmp (end_time, ""))
    {
      end_time_num = parse_iso_time (end_time);
      if (end_time_num == 0)
        return manage_system_report ("blank", NULL, NULL, NULL, NULL, report);
    }

  if (slave_id && strcmp (slave_id, "0"))
    return slave_system_report (
      name, duration, start_time, end_time, slave_id, report);

  /* For simplicity, it's up to the command to do the base64 encoding. */
  if (start_time && strcmp (start_time, ""))
    {
      if (end_time && strcmp (end_time, ""))
        {
          command = g_strdup_printf (
            "gvmcg %ld %ld %s", start_time_num, end_time_num, name);
        }
      else if (duration && strcmp (duration, ""))
        {
          command = g_strdup_printf ("gvmcg %ld %ld %s",
                                     start_time_num,
                                     start_time_num + duration_num,
                                     name);
        }
      else
        {
          command = g_strdup_printf ("gvmcg %ld %ld %s",
                                     start_time_num,
                                     start_time_num + DEFAULT_DURATION,
                                     name);
        }
    }
  else if (end_time && strcmp (end_time, ""))
    {
      if (duration && strcmp (duration, ""))
        {
          command = g_strdup_printf ("gvmcg %ld %ld %s",
                                     end_time_num - duration_num,
                                     end_time_num,
                                     name);
        }
      else
        {
          command = g_strdup_printf ("gvmcg %ld %ld %s",
                                     end_time_num - DEFAULT_DURATION,
                                     end_time_num,
                                     name);
        }
    }
  else
    {
      if (duration && strcmp (duration, ""))
        {
          command = g_strdup_printf ("gvmcg %ld %s", duration_num, name);
        }
      else
        {
          command = g_strdup_printf ("gvmcg %ld %s", DEFAULT_DURATION, name);
        }
    }

  g_debug ("   command: %s", command);

  if ((g_spawn_command_line_sync (
         command, &astdout, &astderr, &exit_status, &err)
       == FALSE)
      || (WIFEXITED (exit_status) == 0) || WEXITSTATUS (exit_status))
    {
      int ret;
      double load[3];
      GError *get_error;
      gchar *output;
      gsize output_len;
      GString *buffer;

      g_debug ("%s: gvmcg failed with %d", __FUNCTION__, exit_status);
      g_debug ("%s: stdout: %s", __FUNCTION__, astdout);
      g_debug ("%s: stderr: %s", __FUNCTION__, astderr);
      g_free (astdout);
      g_free (astderr);
      g_free (command);

      buffer = g_string_new (FALLBACK_SYSTEM_REPORT_HEADER);

      ret = getloadavg (load, 3);
      if (ret == 3)
        {
          g_string_append_printf (
            buffer, "Load average for past minute:     %.1f\n", load[0]);
          g_string_append_printf (
            buffer, "Load average for past 5 minutes:  %.1f\n", load[1]);
          g_string_append_printf (
            buffer, "Load average for past 15 minutes: %.1f\n", load[2]);
        }
      else
        g_string_append (buffer, "Error getting load averages.\n");

      get_error = NULL;
      g_file_get_contents ("/proc/meminfo", &output, &output_len, &get_error);
      if (get_error)
        g_error_free (get_error);
      else
        {
          gchar *safe;
          g_string_append (buffer, "\n/proc/meminfo:\n\n");
          safe = g_markup_escape_text (output, strlen (output));
          g_free (output);
          g_string_append (buffer, safe);
          g_free (safe);
        }

      *report = g_string_free (buffer, FALSE);
      return 3;
    }
  g_free (astderr);
  g_free (command);
  if (astdout == NULL || strlen (astdout) == 0)
    {
      g_free (astdout);
      if (strcmp (name, "blank") == 0)
        return -1;
      return manage_system_report ("blank", NULL, NULL, NULL, NULL, report);
    }
  else
    *report = astdout;
  return 0;
}

/* Scheduling. */

/**
 * @brief Flag for manage_auth_allow_all.
 *
 * 1 if set via scheduler, 2 if set via event, else 0.
 */
int authenticate_allow_all = 0;

/**
 * @brief UUID of user whose scheduled task is to be started (in connection
 *        with authenticate_allow_all).
 */
static gchar *schedule_user_uuid = NULL;

/**
 * @brief Ensure that any subsequent authentications succeed.
 *
 * @param[in]  scheduled  Whether this is happening from the scheduler.
 */
void
manage_auth_allow_all (int scheduled)
{
  authenticate_allow_all = scheduled ? 1 : 2;
}

/**
 * @brief Access UUID of user that scheduled the current task.
 *
 * @return UUID of user that scheduled the current task.
 */
const gchar *
get_scheduled_user_uuid ()
{
  return schedule_user_uuid;
}

/**
 * @brief Set UUID of user that scheduled the current task.
 * The previous value is freed and a copy of the UUID is created.
 *
 * @param user_uuid UUID of user that scheduled the current task.
 */
void
set_scheduled_user_uuid (const gchar *user_uuid)
{
  gchar *user_uuid_copy = user_uuid ? g_strdup (user_uuid) : NULL;
  g_free (schedule_user_uuid);
  schedule_user_uuid = user_uuid_copy;
}

/**
 * @brief Task info, for scheduler.
 */
typedef struct
{
  gchar *owner_uuid; ///< UUID of owner.
  gchar *owner_name; ///< Name of owner.
  gchar *task_uuid;  ///< UUID of task.
} scheduled_task_t;

/**
 * @brief Create a schedule task structure.
 *
 * @param[in] task_uuid   UUID of task.
 * @param[in] owner_uuid  UUID of owner.
 * @param[in] owner_name  Name of owner.
 *
 * @return Scheduled task structure.
 */
static scheduled_task_t *
scheduled_task_new (const gchar *task_uuid,
                    const gchar *owner_uuid,
                    const gchar *owner_name)
{
  scheduled_task_t *scheduled_task;

  scheduled_task = g_malloc (sizeof (*scheduled_task));
  scheduled_task->task_uuid = g_strdup (task_uuid);
  scheduled_task->owner_uuid = g_strdup (owner_uuid);
  scheduled_task->owner_name = g_strdup (owner_name);

  return scheduled_task;
}

/**
 * @brief Set UUID of user that scheduled the current task.
 *
 * @param[in] scheduled_task  Scheduled task.
 */
static void
scheduled_task_free (scheduled_task_t *scheduled_task)
{
  g_free (scheduled_task->task_uuid);
  g_free (scheduled_task->owner_uuid);
  g_free (scheduled_task->owner_name);
  g_free (scheduled_task);
}

/**
 * @brief Start a task, for the scheduler.
 *
 * @param[in]  scheduled_task   Scheduled task.
 * @param[in]  fork_connection  Function that forks a child which is connected
 *                              to the Manager.  Must return PID in parent, 0
 *                              in child, or -1 on error.
 * @param[in]  sigmask_current  Sigmask to restore in child.
 *
 * @return 0 success, -1 error.  Child does not return.
 */
static int
scheduled_task_start (scheduled_task_t *scheduled_task,
                      manage_connection_forker_t fork_connection,
                      sigset_t *sigmask_current)
{
  char title[128];
  int pid;
  gvm_connection_t connection;
  gmp_authenticate_info_opts_t auth_opts;

  /* Fork a child to start the task and wait for the response, so that the
   * parent can return to the main loop.  Only the parent returns. */

  pid = fork ();
  switch (pid)
    {
    case 0:
      /* Child.  Carry on to start the task, reopen the database (required
       * after fork). */

      /* Restore the sigmask that was blanked for pselect. */
      pthread_sigmask (SIG_SETMASK, sigmask_current, NULL);

      reinit_manage_process ();
      manage_session_init (current_credentials.uuid);
      break;

    case -1:
      /* Parent on error. */
      g_warning ("%s: fork failed", __FUNCTION__);
      return -1;

    default:
      /* Parent.  Continue to next task. */
      g_debug ("%s: %i forked %i", __FUNCTION__, getpid (), pid);
      return 0;
    }

  /* Run the callback to fork a child connected to the Manager. */

  pid = fork_connection (&connection, scheduled_task->owner_uuid);
  switch (pid)
    {
    case 0:
      /* Child.  Break, start task, exit. */
      break;

    case -1:
      /* Parent on error. */
      g_warning ("%s: fork_connection failed", __FUNCTION__);
      reschedule_task (scheduled_task->task_uuid);
      scheduled_task_free (scheduled_task);
      exit (EXIT_FAILURE);
      break;

    default:
      {
        int status;

        /* Parent.  Wait for child, to check return. */

        snprintf (
          title, sizeof (title), "mageni-sqlite: scheduler: waiting for %i", pid);
        proctitle_set (title);

        g_debug ("%s: %i fork_connectioned %i", __FUNCTION__, getpid (), pid);

        if (signal (SIGCHLD, SIG_DFL) == SIG_ERR)
          g_warning ("%s: failed to set SIGCHLD", __FUNCTION__);
        while (waitpid (pid, &status, 0) < 0)
          {
            if (errno == ECHILD)
              {
                g_warning ("%s: Failed to get child exit,"
                           " so task '%s' may not have been scheduled",
                           __FUNCTION__,
                           scheduled_task->task_uuid);
                scheduled_task_free (scheduled_task);
                exit (EXIT_FAILURE);
              }
            if (errno == EINTR)
              continue;
            g_warning ("%s: waitpid: %s", __FUNCTION__, strerror (errno));
            g_warning ("%s: As a result, task '%s' may not have been"
                       " scheduled",
                       __FUNCTION__,
                       scheduled_task->task_uuid);
            scheduled_task_free (scheduled_task);
            exit (EXIT_FAILURE);
          }
        if (WIFEXITED (status))
          switch (WEXITSTATUS (status))
            {
            case EXIT_SUCCESS:
              {
                schedule_t schedule;
                int periods;
                const gchar *task_uuid;

                /* Child succeeded, so task successfully started. */

                task_uuid = scheduled_task->task_uuid;
                schedule = task_schedule_uuid (task_uuid);
                if (schedule && schedule_period (schedule) == 0
                    && schedule_duration (schedule) == 0
                    /* Check next time too, in case the user changed
                     * the schedule after this task was added to the
                     * "starts" list. */
                    && task_schedule_next_time_uuid (task_uuid) == 0)
                  /* A once-off schedule without a duration, remove
                   * it from the task.  If it has a duration it
                   * will be removed by manage_schedule via
                   * clear_duration_schedules, after the duration. */
                  set_task_schedule_uuid (task_uuid, 0, 0);
                else if ((periods = task_schedule_periods_uuid (task_uuid)))
                  {
                    /* A task restricted to a certain number of
                     * scheduled runs. */
                    if (periods > 1)
                      {
                        set_task_schedule_periods (task_uuid, periods - 1);
                      }
                    else if (periods == 1 && schedule_duration (schedule) == 0)
                      {
                        /* Last run of a task restricted to a certain
                         * number of scheduled runs. */
                        set_task_schedule_uuid (task_uuid, 0, 1);
                      }
                    else if (periods == 1)
                      /* Flag that the task has started, for
                       * update_duration_schedule_periods. */
                      set_task_schedule_next_time_uuid (task_uuid, 0);
                  }
              }
              scheduled_task_free (scheduled_task);
              exit (EXIT_SUCCESS);

            case EXIT_FAILURE:
            default:
              break;
            }

        /* Child failed, reset task schedule time and exit. */

        g_warning ("%s: child failed", __FUNCTION__);
        reschedule_task (scheduled_task->task_uuid);
        scheduled_task_free (scheduled_task);
        exit (EXIT_FAILURE);
      }
    }

  /* Start the task. */

  snprintf (title,
            sizeof (title),
            "mageni-sqlite: scheduler: starting %s",
            scheduled_task->task_uuid);
  proctitle_set (title);

  auth_opts = gmp_authenticate_info_opts_defaults;
  auth_opts.username = scheduled_task->owner_name;
  if (gmp_authenticate_info_ext_c (&connection, auth_opts))
    {
      g_warning ("%s: gmp_authenticate failed", __FUNCTION__);
      scheduled_task_free (scheduled_task);
      gvm_connection_free (&connection);
      exit (EXIT_FAILURE);
    }

  if (gmp_resume_task_report_c (&connection, scheduled_task->task_uuid, NULL))
    {
      if (gmp_start_task_report_c (
            &connection, scheduled_task->task_uuid, NULL))
        {
          g_warning ("%s: gmp_start_task and gmp_resume_task failed",
                     __FUNCTION__);
          scheduled_task_free (scheduled_task);
          gvm_connection_free (&connection);
          exit (EXIT_FAILURE);
        }
    }

  scheduled_task_free (scheduled_task);
  gvm_connection_free (&connection);
  exit (EXIT_SUCCESS);
}

/**
 * @brief Stop a task, for the scheduler.
 *
 * @param[in]  scheduled_task   Scheduled task.
 * @param[in]  fork_connection  Function that forks a child which is connected
 *                              to the Manager.  Must return PID in parent, 0
 *                              in child, or -1 on error.
 * @param[in]  sigmask_current  Sigmask to restore in child.
 *
 * @return 0 success, -1 error.  Child does not return.
 */
static int
scheduled_task_stop (scheduled_task_t *scheduled_task,
                     manage_connection_forker_t fork_connection,
                     sigset_t *sigmask_current)
{
  char title[128];
  gvm_connection_t connection;
  gmp_authenticate_info_opts_t auth_opts;

  /* TODO As with starts above, this should retry if the stop failed. */

  /* Run the callback to fork a child connected to the Manager. */

  switch (fork_connection (&connection, scheduled_task->owner_uuid))
    {
    case 0:
      /* Child.  Break, stop task, exit. */
      break;

    case -1:
      /* Parent on error. */
      g_warning ("%s: stop fork failed", __FUNCTION__);
      return -1;

    default:
      /* Parent.  Continue to next task. */
      return 0;
    }

  /* Stop the task. */

  snprintf (title,
            sizeof (title),
            "mageni-sqlite: scheduler: stopping %s",
            scheduled_task->task_uuid);
  proctitle_set (title);

  auth_opts = gmp_authenticate_info_opts_defaults;
  auth_opts.username = scheduled_task->owner_name;
  if (gmp_authenticate_info_ext_c (&connection, auth_opts))
    {
      scheduled_task_free (scheduled_task);
      gvm_connection_free (&connection);
      exit (EXIT_FAILURE);
    }

  if (gmp_stop_task_c (&connection, scheduled_task->task_uuid))
    {
      scheduled_task_free (scheduled_task);
      gvm_connection_free (&connection);
      exit (EXIT_FAILURE);
    }

  scheduled_task_free (scheduled_task);
  gvm_connection_free (&connection);
  exit (EXIT_SUCCESS);
}

/**
 * @brief Perform any syncing that is due.
 *
 * In gvmd, periodically called from the main daemon loop.
 *
 * @param[in]  sigmask_current  Sigmask to restore in child.
 * @param[in]  fork_update_nvt_cache  Function that forks a child that syncs
 *                                    the NVTS.  Child does not return.
 */
void
manage_sync (sigset_t *sigmask_current, int (*fork_update_nvt_cache) ())
{
  manage_sync_nvts (fork_update_nvt_cache);
//  manage_sync_scap (sigmask_current);
//  manage_sync_cert (sigmask_current);
}

/**
 * @brief Schedule any actions that are due.
 *
 * In gvmd, periodically called from the main daemon loop.
 *
 * @param[in]  fork_connection  Function that forks a child which is connected
 *                              to the Manager.  Must return PID in parent, 0
 *                              in child, or -1 on error.
 * @param[in]  run_tasks        Whether to run scheduled tasks.
 * @param[in]  sigmask_current  Sigmask to restore in child.
 *
 * @return 0 success, 1 failed to get lock, -1 error.
 */
int
manage_schedule (manage_connection_forker_t fork_connection,
                 gboolean run_tasks,
                 sigset_t *sigmask_current)
{
  iterator_t schedules;
  GSList *starts, *stops;
  int ret;
  task_t previous_start_task, previous_stop_task;

  starts = NULL;
  stops = NULL;
  previous_start_task = 0;
  previous_stop_task = 0;

  ret = manage_update_nvti_cache ();
  if (ret)
    {
      if (ret == -1)
        {
          g_warning ("%s: manage_update_nvti_cache error"
                     " (Perhaps the db went down?)",
                     __FUNCTION__);
          /* Just ignore, in case the db went down temporarily. */
          return 0;
        }

      return ret;
    }

  if (run_tasks == 0)
    return 0;

  /* Assemble "starts" and "stops" list containing task uuid, owner name and
   * owner UUID for each (scheduled) task to start or stop. */

  ret = init_task_schedule_iterator (&schedules);
  if (ret)
    {
      if (ret == -1)
        {
          g_warning ("%s: iterator init error"
                     " (Perhaps the db went down?)",
                     __FUNCTION__);
          /* Just ignore, in case the db went down temporarily. */
          return 0;
        }

      return ret;
    }
  /* This iterator runs in a transaction. */
  while (next (&schedules))
    if (task_schedule_iterator_start_due (&schedules))
      {
        const char *icalendar, *zone;
        int timed_out;

        /* Check if task schedule is timed out before updating next due time */
        timed_out = task_schedule_iterator_timed_out (&schedules);

        /* Update the task schedule info to prevent multiple schedules. */

        icalendar = task_schedule_iterator_icalendar (&schedules);
        zone = task_schedule_iterator_timezone (&schedules);

        g_debug ("%s: start due for %llu, setting next_time",
                 __FUNCTION__,
                 task_schedule_iterator_task (&schedules));
        set_task_schedule_next_time (
          task_schedule_iterator_task (&schedules),
          icalendar_next_time_from_string (icalendar, zone, 0));

        /* Skip this task if it was already added to the starts list
         * to avoid conflicts between multiple users with permissions. */

        if (previous_start_task == task_schedule_iterator_task (&schedules))
          continue;

        if (timed_out)
          {
            g_message (" %s: Task timed out: %s",
                       __FUNCTION__,
                       task_schedule_iterator_task_uuid (&schedules));
            continue;
          }

        previous_start_task = task_schedule_iterator_task (&schedules);

        /* Add task UUID and owner name and UUID to the list. */

        starts = g_slist_prepend (
          starts,
          scheduled_task_new (task_schedule_iterator_task_uuid (&schedules),
                              task_schedule_iterator_owner_uuid (&schedules),
                              task_schedule_iterator_owner_name (&schedules)));
      }
    else if (task_schedule_iterator_stop_due (&schedules))
      {
        /* Skip this task if it was already added to the stops list
         * to avoid conflicts between multiple users with permissions. */

        if (previous_stop_task == task_schedule_iterator_task (&schedules))
          continue;
        previous_stop_task = task_schedule_iterator_task (&schedules);

        /* Add task UUID and owner name and UUID to the list. */

        stops = g_slist_prepend (
          stops,
          scheduled_task_new (task_schedule_iterator_task_uuid (&schedules),
                              task_schedule_iterator_owner_uuid (&schedules),
                              task_schedule_iterator_owner_name (&schedules)));
      }
  cleanup_task_schedule_iterator (&schedules);

  /* Start tasks in forked processes, now that the SQL statement is closed. */

  while (starts)
    {
      scheduled_task_t *scheduled_task;
      GSList *head;

      scheduled_task = starts->data;

      head = starts;
      starts = starts->next;
      g_slist_free_1 (head);

      if (scheduled_task_start (
            scheduled_task, fork_connection, sigmask_current))
        /* Error.  Reschedule and continue to next task. */
        reschedule_task (scheduled_task->task_uuid);
      scheduled_task_free (scheduled_task);
    }

  /* Stop tasks in forked processes, now that the SQL statement is closed. */

  while (stops)
    {
      scheduled_task_t *scheduled_task;
      GSList *head;

      scheduled_task = stops->data;
      head = stops;
      stops = stops->next;
      g_slist_free_1 (head);

      if (scheduled_task_stop (
            scheduled_task, fork_connection, sigmask_current))
        {
          /* Error.  Exit. */
          scheduled_task_free (scheduled_task);
          while (stops)
            {
              scheduled_task_free (stops->data);
              stops = g_slist_delete_link (stops, stops);
            }
          return -1;
        }
      scheduled_task_free (scheduled_task);
    }

  clear_duration_schedules (0);
  update_duration_schedule_periods (0);

  auto_delete_reports ();

  return 0;
}

/**
 * @brief Get the current schedule timeout.
 *
 * @return The schedule timeout in minutes.
 */
int
get_schedule_timeout ()
{
  return schedule_timeout;
}

/**
 * @brief Set the schedule timeout.
 *
 * @param new_timeout The new schedule timeout in minutes.
 */
void
set_schedule_timeout (int new_timeout)
{
  if (new_timeout < 0)
    schedule_timeout = -1;
  else
    schedule_timeout = new_timeout;
}

/* Report formats. */

/**
 * @brief Get the name of a report format param type.
 *
 * @param[in]  type  Param type.
 *
 * @return The name of the param type.
 */
const char *
report_format_param_type_name (report_format_param_type_t type)
{
  switch (type)
    {
    case REPORT_FORMAT_PARAM_TYPE_BOOLEAN:
      return "boolean";
    case REPORT_FORMAT_PARAM_TYPE_INTEGER:
      return "integer";
    case REPORT_FORMAT_PARAM_TYPE_SELECTION:
      return "selection";
    case REPORT_FORMAT_PARAM_TYPE_STRING:
      return "string";
    case REPORT_FORMAT_PARAM_TYPE_TEXT:
      return "text";
    case REPORT_FORMAT_PARAM_TYPE_REPORT_FORMAT_LIST:
      return "report_format_list";
    default:
      assert (0);
    case REPORT_FORMAT_PARAM_TYPE_ERROR:
      return "ERROR";
    }
}

/**
 * @brief Get a report format param type from a name.
 *
 * @param[in]  name  Param type name.
 *
 * @return The param type.
 */
report_format_param_type_t
report_format_param_type_from_name (const char *name)
{
  if (strcmp (name, "boolean") == 0)
    return REPORT_FORMAT_PARAM_TYPE_BOOLEAN;
  if (strcmp (name, "integer") == 0)
    return REPORT_FORMAT_PARAM_TYPE_INTEGER;
  if (strcmp (name, "selection") == 0)
    return REPORT_FORMAT_PARAM_TYPE_SELECTION;
  if (strcmp (name, "string") == 0)
    return REPORT_FORMAT_PARAM_TYPE_STRING;
  if (strcmp (name, "text") == 0)
    return REPORT_FORMAT_PARAM_TYPE_TEXT;
  if (strcmp (name, "report_format_list") == 0)
    return REPORT_FORMAT_PARAM_TYPE_REPORT_FORMAT_LIST;
  return REPORT_FORMAT_PARAM_TYPE_ERROR;
}

/**
 * @brief Return whether a name is a backup file name.
 *
 * @param[in]  name  Name.
 *
 * @return 0 if normal file name, 1 if backup file name.
 */
static int
backup_file_name (const char *name)
{
  int length = strlen (name);

  if (length && (name[length - 1] == '~'))
    return 1;

  if ((length > 3) && (name[length - 4] == '.'))
    return ((name[length - 3] == 'b') && (name[length - 2] == 'a')
            && (name[length - 1] == 'k'))
           || ((name[length - 3] == 'B') && (name[length - 2] == 'A')
               && (name[length - 1] == 'K'))
           || ((name[length - 3] == 'C') && (name[length - 2] == 'K')
               && (name[length - 1] == 'P'));

  return 0;
}

/**
 * @brief Get files associated with a report format.
 *
 * @param[in]   dir_name  Location of files.
 * @param[out]  start     Files on success.
 *
 * @return 0 if successful, -1 otherwise.
 */
static int
get_report_format_files (const char *dir_name, GPtrArray **start)
{
  GPtrArray *files;
  struct dirent **names;
  int n, index;
  char *locale;

  files = g_ptr_array_new ();

  locale = setlocale (LC_ALL, "C");
  n = scandir (dir_name, &names, NULL, alphasort);
  setlocale (LC_ALL, locale);
  if (n < 0)
    {
      g_warning ("%s: failed to open dir %s: %s",
                 __FUNCTION__,
                 dir_name,
                 strerror (errno));
      return -1;
    }

  for (index = 0; index < n; index++)
    {
      if (strcmp (names[index]->d_name, ".")
          && strcmp (names[index]->d_name, "..")
          && (backup_file_name (names[index]->d_name) == 0))
        g_ptr_array_add (files, g_strdup (names[index]->d_name));
      free (names[index]);
    }
  free (names);

  g_ptr_array_add (files, NULL);

  *start = files;
  return 0;
}

/**
 * @brief Get the directory of a report format.
 *
 * @param[in]  uuid  Report format UUID.  NULL to get parent dir.
 *
 * @return Freshly allocated dir name.
 */
gchar *
predefined_report_format_dir (const gchar *uuid)
{
  return g_build_filename (MAGENI_DATA_DIR, "report_formats", uuid, NULL);
}

/**
 * @brief Initialise a report format file iterator.
 *
 * @param[in]  iterator       Iterator.
 * @param[in]  report_format  Single report format to iterate over, NULL for
 *                            all.
 *
 * @return 0 on success, -1 on error.
 */
int
init_report_format_file_iterator (file_iterator_t *iterator,
                                  report_format_t report_format)
{
  gchar *dir_name, *uuid;

  uuid = report_format_uuid (report_format);
  if (uuid == NULL)
    return -1;

  if (report_format_predefined (report_format))
    dir_name = predefined_report_format_dir (uuid);
  else
    {
      gchar *owner_uuid;

      owner_uuid = report_format_owner_uuid (report_format);
      if (owner_uuid == NULL)
        return -1;
      dir_name = g_build_filename (
        MAGENI_STATE_DIR, "report_formats", owner_uuid, uuid, NULL);
      g_free (owner_uuid);
    }

  g_free (uuid);

  if (get_report_format_files (dir_name, &iterator->start))
    {
      g_free (dir_name);
      return -1;
    }

  iterator->current = iterator->start->pdata;
  iterator->current--;
  iterator->dir_name = dir_name;
  return 0;
}

/**
 * @brief Cleanup a report type iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
cleanup_file_iterator (file_iterator_t *iterator)
{
  array_free (iterator->start);
  g_free (iterator->dir_name);
}

/**
 * @brief Increment a report type iterator.
 *
 * The caller must stop using this after it returns FALSE.
 *
 * @param[in]  iterator  Task iterator.
 *
 * @return TRUE if there was a next item, else FALSE.
 */
gboolean
next_file (file_iterator_t *iterator)
{
  iterator->current++;
  if (*iterator->current == NULL)
    return FALSE;
  return TRUE;
}

/**
 * @brief Return the name from a file iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return File name.
 */
const char *
file_iterator_name (file_iterator_t *iterator)
{
  return (const char *) *iterator->current;
}

/**
 * @brief Return the file contents from a file iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Freshly allocated file contents, in base64.
 */
gchar *
file_iterator_content_64 (file_iterator_t *iterator)
{
  gchar *path_name, *content;
  GError *error;
  gsize content_size;

  path_name =
    g_build_filename (iterator->dir_name, (gchar *) *iterator->current, NULL);

  /* Read in the contents. */

  error = NULL;
  if (g_file_get_contents (path_name, &content, &content_size, &error) == FALSE)
    {
      if (error)
        {
          g_debug ("%s: failed to read %s: %s",
                   __FUNCTION__,
                   path_name,
                   error->message);
          g_error_free (error);
        }
      g_free (path_name);
      return NULL;
    }

  g_free (path_name);

  /* Base64 encode the contents. */

  if (content && (content_size > 0))
    {
      gchar *base64 = g_base64_encode ((guchar *) content, content_size);
      g_free (content);
      return base64;
    }

  return content;
}

/* Scanner Tags. */

/**
 * @brief Split up the tags received from the scanner.
 *
 * @param[in]  scanner_tags  The tags sent by the scanner.
 * @param[out] tags          Tags.
 * @param[out] cvss_base     CVSS base.
 */
void
parse_tags (const char *scanner_tags, gchar **tags, gchar **cvss_base)
{
  gchar **split, **point;
  GString *tags_buffer;
  gboolean first;

  tags_buffer = g_string_new ("");
  split = g_strsplit (scanner_tags, "|", 0);
  point = split;
  *cvss_base = NULL;
  first = TRUE;

  while (*point)
    {
      if (strncmp (*point, "cvss_base=", strlen ("cvss_base=")) == 0)
        {
          /* Skip this tag. */
        }
      else if (strncmp (
                 *point, "cvss_base_vector=", strlen ("cvss_base_vector="))
               == 0)
        {
          if (*cvss_base == NULL)
            *cvss_base =
              g_strdup_printf ("%.1f",
                               get_cvss_score_from_base_metrics (
                                 *point + strlen ("cvss_base_vector=")));
          if (first)
            first = FALSE;
          else
            g_string_append_c (tags_buffer, '|');
          g_string_append (tags_buffer, *point);
        }
      else
        {
          if (first)
            first = FALSE;
          else
            g_string_append_c (tags_buffer, '|');
          g_string_append (tags_buffer, *point);
        }
      point++;
    }

  if (tags_buffer->len == 0)
    {
      g_string_free (tags_buffer, TRUE);
      *tags = g_strdup ("NOTAG");
    }
  else
    *tags = g_string_free (tags_buffer, FALSE);
  g_strfreev (split);
}

/* Slaves. */

/**
 * @brief Delete a task on a slave.
 *
 * @param[in]  host             Slave host.
 * @param[in]  port             Slave port.
 * @param[in]  username         Slave username.
 * @param[in]  password         Slave password.
 * @param[in]  slave_task_uuid  UUID of task on slave.
 *
 * @return 0 success, -1 error.
 */
int
delete_slave_task (const gchar *host,
                   int port,
                   const gchar *username,
                   const gchar *password,
                   const char *slave_task_uuid)
{
  int socket;
  gnutls_session_t session;
  entity_t get_tasks, get_targets, entity, task, credential, port_list;
  const char *slave_config_uuid, *slave_target_uuid, *slave_port_list_uuid;
  const char *slave_ssh_credential_uuid, *slave_smb_credential_uuid;

  gmp_delete_opts_t del_opts = gmp_delete_opts_ultimate_defaults;

  /* Connect to the slave. */

  g_debug ("   %s: host: %s", __FUNCTION__, host);

  socket = gvm_server_open (&session, host, port);
  if (socket == -1)
    return -1;

  g_debug ("   %s: connected", __FUNCTION__);

  /* Authenticate using the slave login. */

  if (gmp_authenticate (&session, username, password))
    return -1;

  g_debug ("   %s: authenticated", __FUNCTION__);

  /* Get the UUIDs of the slave resources. */

  if (gmp_get_tasks (&session, slave_task_uuid, 0, 0, &get_tasks))
    goto fail;

  task = entity_child (get_tasks, "task");
  if (task == NULL)
    goto fail_free_task;

  entity = entity_child (task, "config");
  if (entity == NULL)
    goto fail_free_task;
  slave_config_uuid = entity_attribute (entity, "id");

  entity = entity_child (task, "target");
  if (entity == NULL)
    goto fail_free_task;
  slave_target_uuid = entity_attribute (entity, "id");

  if (gmp_get_targets (&session, slave_target_uuid, 0, 0, &get_targets))
    goto fail_free_task;

  entity = entity_child (get_targets, "target");
  if (entity == NULL)
    goto fail_free;

  port_list = entity_child (entity, "port_list");
  if (port_list == NULL)
    goto fail_free;
  slave_port_list_uuid = entity_attribute (port_list, "id");

  credential = entity_child (entity, "ssh_credential");
  if (credential == NULL)
    goto fail_free;
  slave_ssh_credential_uuid = entity_attribute (credential, "id");

  credential = entity_child (entity, "smb_credential");
  if (credential == NULL)
    goto fail_free;
  slave_smb_credential_uuid = entity_attribute (credential, "id");

  /* Remove the slave resources. */

  gmp_stop_task (&session, slave_task_uuid);
  if (gmp_delete_task_ext (&session, slave_task_uuid, del_opts))
    goto fail_config;
  if (gmp_delete_config_ext (&session, slave_config_uuid, del_opts))
    goto fail_target;
  if (gmp_delete_target_ext (&session, slave_target_uuid, del_opts))
    goto fail_credential;
  if (gmp_delete_port_list_ext (&session, slave_port_list_uuid, del_opts))
    goto fail_credential;
  if (gmp_delete_lsc_credential_ext (
        &session, slave_smb_credential_uuid, del_opts))
    goto fail;
  if (gmp_delete_lsc_credential_ext (
        &session, slave_ssh_credential_uuid, del_opts))
    goto fail;

  /* Cleanup. */

  free_entity (get_targets);
  free_entity (get_tasks);
  gvm_server_close (socket, session);
  return 0;

fail_config:
  gmp_delete_config_ext (&session, slave_config_uuid, del_opts);
fail_target:
  gmp_delete_target_ext (&session, slave_target_uuid, del_opts);
  gmp_delete_port_list_ext (&session, slave_port_list_uuid, del_opts);
fail_credential:
  gmp_delete_lsc_credential_ext (&session, slave_smb_credential_uuid, del_opts);
  gmp_delete_lsc_credential_ext (&session, slave_ssh_credential_uuid, del_opts);
fail_free:
  free_entity (get_targets);
fail_free_task:
  free_entity (get_tasks);
fail:
  gvm_server_close (socket, session);
  return -1;
}

/**
 * @brief Return the path to the CPE dictionary.
 *
 * @return A dynamically allocated string (to be g_free'd) containing the
 *         path to the desired file.
 */
static char *
get_cpe_filename ()
{
  return g_strdup (CPE_DICT_FILENAME);
}

/**
 * @brief Compute the filename where a given CVE can be found.
 *
 * @param[in] item_id   Full CVE identifier ("CVE-YYYY-ZZZZ").
 *
 * @return A dynamically allocated string (to be g_free'd) containing the
 *         path to the desired file or NULL on error.
 */
static char *
get_cve_filename (char *item_id)
{
  int year;

  if (sscanf (item_id, "%*3s-%d-%*d", &year) == 1)
    {
      /* CVEs before 2002 are stored in the 2002 file. */
      if (year <= 2002)
        year = 2002;
      return g_strdup_printf (CVE_FILENAME_FMT, year);
    }
  return NULL;
}

/**
 * @brief Get the filename where a given OVAL definition can be found.
 *
 * @param[in] item_id   Full OVAL identifier with file suffix.
 *
 * @return A dynamically allocated string (to be g_free'd) containing the
 *         path to the desired file or NULL on error.
 */
static char *
get_ovaldef_filename (char *item_id)
{
  char *result, *short_filename;

  result = NULL;
  short_filename = get_ovaldef_short_filename (item_id);

  if (*short_filename)
    {
      result = g_strdup_printf ("%s/%s", MAGENI_SCAP_DATA_DIR, short_filename);
    }
  free (short_filename);

  return result;
}

/**
 * @brief Compute the filename where a given CERT-Bund Advisory can be found.
 *
 * @param[in] item_id   CERT-Bund identifier without version ("CB-K??/????").
 *
 * @return A dynamically allocated string (to be g_free'd) containing the
 *         path to the desired file or NULL on error.
 */
static char *
get_cert_bund_adv_filename (char *item_id)
{
  int year;

  if (sscanf (item_id, "CB-K%d-%*s", &year) == 1)
    {
      return g_strdup_printf (CERT_BUND_ADV_FILENAME_FMT, year);
    }
  return NULL;
}

/**
 * @brief Compute the filename where a given DFN-CERT Advisory can be found.
 *
 * @param[in] item_id   Full DFN-CERT identifier ("DFN-CERT-YYYY-ZZZZ").
 *
 * @return A dynamically allocated string (to be g_free'd) containing the
 *         path to the desired file or NULL on error.
 */
static char *
get_dfn_cert_adv_filename (char *item_id)
{
  int year;

  if (sscanf (item_id, "DFN-CERT-%d-%*s", &year) == 1)
    {
      return g_strdup_printf (DFN_CERT_ADV_FILENAME_FMT, year);
    }
  return NULL;
}

/**
 * @brief Run xsltproc in an external process.
 *
 * @param[in] stylesheet    XSL stylesheet to use.
 * @param[in] xmlfile       XML file to process.
 * @param[in] param_names   NULL terminated array of stringparam names (can
 *                          be NULL).
 * @param[in] param_values  NULL terminated array of stringparam values (can
 *                          be NULL).
 *
 * @return A dynamically allocated (to be g_free'd) string containing the
 *         result of the operation of NULL on failure.
 */
static gchar *
xsl_transform (gchar *stylesheet,
               gchar *xmlfile,
               gchar **param_names,
               gchar **param_values)
{
  int i, param_idx;
  gchar **cmd, *cmd_full;
  gint exit_status;
  gboolean success;
  gchar *standard_out = NULL, *standard_err = NULL;

  param_idx = 0;
  if (param_names && param_values)
    while (param_names[param_idx] && param_values[param_idx])
      param_idx++;

  cmd = (gchar **) g_malloc ((4 + param_idx * 3) * sizeof (gchar *));

  i = 0;
  cmd[i++] = "xsltproc";
  if (param_idx)
    {
      int j;

      for (j = 0; j < param_idx; j++)
        {
          cmd[i++] = "--stringparam";
          cmd[i++] = param_names[j];
          cmd[i++] = param_values[j];
        }
    }
  cmd[i++] = stylesheet;
  cmd[i++] = xmlfile;
  cmd[i] = NULL;

  /* DEBUG: display the final command line. */
  cmd_full = g_strjoinv (" ", cmd);
  g_debug ("%s: Spawning in parent dir: %s", __FUNCTION__, cmd_full);
  g_free (cmd_full);
  /* --- */

  if ((g_spawn_sync (NULL,
                     cmd,
                     NULL, /* Environment. */
                     G_SPAWN_SEARCH_PATH,
                     NULL, /* Setup function. */
                     NULL,
                     &standard_out,
                     &standard_err,
                     &exit_status,
                     NULL)
       == FALSE)
      || (WIFEXITED (exit_status) == 0) || WEXITSTATUS (exit_status))
    {
      g_debug ("%s: failed to transform the xml: %d (WIF %i, WEX %i)",
               __FUNCTION__,
               exit_status,
               WIFEXITED (exit_status),
               WEXITSTATUS (exit_status));
      g_debug ("%s: stderr: %s", __FUNCTION__, standard_err);
      g_debug ("%s: stdout: %s", __FUNCTION__, standard_out);
      success = FALSE;
    }
  else if (strlen (standard_out) == 0)
    success = FALSE; /* execution succeeded but nothing was found */
  else
    success = TRUE; /* execution succeeded and we have a result */

  /* Cleanup. */
  g_free (cmd);
  g_free (standard_err);

  if (success)
    return standard_out;

  g_free (standard_out);
  return NULL;
}

/**
 * @brief Define a code snippet for get_nvti_xml.
 *
 * @param  x  Prefix for names in snippet.
 */
#define DEF(x)                             \
  const char *x = nvt_iterator_##x (nvts); \
  gchar *x##_text = x ? g_markup_escape_text (x, -1) : g_strdup ("");

/**
 * @brief Create and return XML description for an NVT.
 *
 * @param[in]  nvts        The NVT.
 * @param[in]  details     If true, detailed XML, else simple XML.
 * @param[in]  pref_count  Preference count.  Used if details is true.
 * @param[in]  preferences If true, included preferences.
 * @param[in]  timeout     Timeout.  Used if details is true.
 * @param[in]  config      Config, used if preferences is true.
 * @param[in]  close_tag   Whether to close the NVT tag or not.
 *
 * @return A dynamically allocated string containing the XML description.
 */
gchar *
get_nvti_xml (iterator_t *nvts,
              int details,
              int pref_count,
              int preferences,
              const char *timeout,
              config_t config,
              int close_tag)
{
  const char *oid = nvt_iterator_oid (nvts);
  const char *name = nvt_iterator_name (nvts);
  gchar *msg, *name_text;

  name_text = name ? g_markup_escape_text (name, strlen (name)) : g_strdup ("");
  if (details)
    {
      int tag_count;
      GString *cert_refs_str, *tags_str, *buffer;
      iterator_t cert_refs_iterator, tags;
      gchar *tag_name_esc, *tag_value_esc, *tag_comment_esc;
      char *default_timeout = nvt_default_timeout (oid);

      DEF (family);
      DEF (xref);
      DEF (tag);

#undef DEF

      cert_refs_str = g_string_new ("");
      if (manage_cert_loaded ())
        {
          init_nvt_cert_bund_adv_iterator (&cert_refs_iterator, oid, 0, 0);
          while (next (&cert_refs_iterator))
            {
              g_string_append_printf (
                cert_refs_str,
                "<cert_ref type=\"CERT-Bund\" id=\"%s\"/>",
                get_iterator_name (&cert_refs_iterator));
            }
          cleanup_iterator (&cert_refs_iterator);

          init_nvt_dfn_cert_adv_iterator (&cert_refs_iterator, oid, 0, 0);
          while (next (&cert_refs_iterator))
            {
              g_string_append_printf (cert_refs_str,
                                      "<cert_ref type=\"DFN-CERT\" id=\"%s\"/>",
                                      get_iterator_name (&cert_refs_iterator));
            }
          cleanup_iterator (&cert_refs_iterator);
        }
      else
        {
          g_string_append (cert_refs_str,
                           "<warning>database not available</warning>");
        }

      tags_str = g_string_new ("");
      tag_count = resource_tag_count ("nvt", get_iterator_resource (nvts), 1);

      if (tag_count)
        {
          g_string_append_printf (tags_str,
                                  "<user_tags>"
                                  "<count>%i</count>",
                                  tag_count);

          init_resource_tag_iterator (
            &tags, "nvt", get_iterator_resource (nvts), 1, NULL, 1);
          while (next (&tags))
            {
              tag_name_esc =
                g_markup_escape_text (resource_tag_iterator_name (&tags), -1);
              tag_value_esc =
                g_markup_escape_text (resource_tag_iterator_value (&tags), -1);
              tag_comment_esc = g_markup_escape_text (
                resource_tag_iterator_comment (&tags), -1);
              g_string_append_printf (tags_str,
                                      "<tag id=\"%s\">"
                                      "<name>%s</name>"
                                      "<value>%s</value>"
                                      "<comment>%s</comment>"
                                      "</tag>",
                                      resource_tag_iterator_uuid (&tags),
                                      tag_name_esc,
                                      tag_value_esc,
                                      tag_comment_esc);
              g_free (tag_name_esc);
              g_free (tag_value_esc);
              g_free (tag_comment_esc);
            }
          cleanup_iterator (&tags);
          g_string_append_printf (tags_str, "</user_tags>");
        }

      buffer = g_string_new ("");

      g_string_append_printf (
        buffer,
        "<nvt oid=\"%s\">"
        "<name>%s</name>"
        "<creation_time>%s</creation_time>"
        "<modification_time>%s</modification_time>"
        "%s" // user_tags
        "<category>%d</category>"
        "<family>%s</family>"
        "<cvss_base>%s</cvss_base>"
        "<qod>"
        "<value>%s</value>"
        "<type>%s</type>"
        "</qod>"
        "<cve_id>%s</cve_id>"
        "<bugtraq_id>%s</bugtraq_id>"
        "<cert_refs>%s</cert_refs>"
        "<xrefs>%s</xrefs>"
        "<tags>%s</tags>"
        "<preference_count>%i</preference_count>"
        "<timeout>%s</timeout>"
        "<default_timeout>%s</default_timeout>",
        oid,
        name_text,
        get_iterator_creation_time (nvts) ? get_iterator_creation_time (nvts)
                                          : "",
        get_iterator_modification_time (nvts)
          ? get_iterator_modification_time (nvts)
          : "",
        tags_str->str,
        nvt_iterator_category (nvts),
        family_text,
        nvt_iterator_cvss_base (nvts) ? nvt_iterator_cvss_base (nvts) : "",
        nvt_iterator_qod (nvts),
        nvt_iterator_qod_type (nvts),
        nvt_iterator_cve (nvts),
        nvt_iterator_bid (nvts),
        cert_refs_str->str,
        xref_text,
        tag_text,
        pref_count,
        timeout ? timeout : "",
        default_timeout ? default_timeout : "");
      g_free (family_text);
      g_free (xref_text);
      g_free (tag_text);
      g_string_free (cert_refs_str, 1);
      g_string_free (tags_str, 1);

      if (preferences)
        {
          iterator_t prefs;
          const char *nvt_name = nvt_iterator_name (nvts);

          /* Send the preferences for the NVT. */

          xml_string_append (buffer,
                             "<preferences>"
                             "<timeout>%s</timeout>"
                             "<default_timeout>%s</default_timeout>",
                             timeout ? timeout : "",
                             default_timeout ? default_timeout : "");

          init_nvt_preference_iterator (&prefs, nvt_name);
          while (next (&prefs))
            buffer_config_preference_xml (buffer, &prefs, config, 1);
          cleanup_iterator (&prefs);

          xml_string_append (buffer, "</preferences>");
        }

      xml_string_append (buffer, close_tag ? "</nvt>" : "");
      msg = g_string_free (buffer, FALSE);
      free (default_timeout);
    }
  else
    {
      int tag_count;
      tag_count = resource_tag_count ("nvt", get_iterator_resource (nvts), 1);

      if (tag_count)
        {
          msg = g_strdup_printf ("<nvt oid=\"%s\"><name>%s</name>"
                                 "<user_tags><count>%i</count></user_tags>%s",
                                 oid,
                                 name_text,
                                 tag_count,
                                 close_tag ? "</nvt>" : "");
        }
      else
        {
          msg = g_strdup_printf ("<nvt oid=\"%s\"><name>%s</name>%s",
                                 oid,
                                 name_text,
                                 close_tag ? "</nvt>" : "");
        }
    }
  g_free (name_text);
  return msg;
}

/**
 * @brief GET SCAP update time, as a string.
 *
 * @return Last update time as a static string, or "" on error.
 */
const char *
manage_scap_update_time ()
{
  gchar *content;
  GError *error;
  gsize content_size;
  struct tm update_time;

  /* Read in the contents. */

  error = NULL;
  if (g_file_get_contents (
        SCAP_TIMESTAMP_FILENAME, &content, &content_size, &error)
      == FALSE)
    {
      if (error)
        {
          g_debug ("%s: failed to read %s: %s",
                   __FUNCTION__,
                   SCAP_TIMESTAMP_FILENAME,
                   error->message);
          g_error_free (error);
        }
      return "";
    }

  memset (&update_time, 0, sizeof (struct tm));
  if (strptime (content, "%Y%m%d%H%M", &update_time))
    {
      static char time_string[100];
      strftime (time_string, 99, "%FT%T.000%z", &update_time);
      return time_string;
    }
  return "";
}

/**
 * @brief Read raw information.
 *
 * @param[in]   type    Type of the requested information.
 * @param[in]   uid     Unique identifier of the requested information
 * @param[in]   name    Name or identifier of the requested information.
 * @param[out]  result  Pointer to the read information location. Will point
 *                      to NULL on error.
 *
 * @return 1 success, -1 error.
 */
int
manage_read_info (gchar *type, gchar *uid, gchar *name, gchar **result)
{
  gchar *fname;
  gchar *pnames[2] = {"refname", NULL};
  gchar *pvalues[2] = {name, NULL};

  assert (result != NULL);
  *result = NULL;

  if (g_ascii_strcasecmp ("CPE", type) == 0)
    {
      fname = get_cpe_filename ();
      if (fname)
        {
          gchar *cpe;
          cpe = xsl_transform (CPE_GETBYNAME_XSL, fname, pnames, pvalues);
          g_free (fname);
          if (cpe)
            *result = cpe;
        }
    }
  else if (g_ascii_strcasecmp ("CVE", type) == 0)
    {
      fname = get_cve_filename (uid);
      if (fname)
        {
          gchar *cve;
          cve = xsl_transform (CVE_GETBYNAME_XSL, fname, pnames, pvalues);
          g_free (fname);
          if (cve)
            *result = cve;
        }
    }
  else if (g_ascii_strcasecmp ("NVT", type) == 0)
    {
      iterator_t nvts;
      nvt_t nvt;

      if (!find_nvt (name ? name : uid, &nvt) && nvt)
        {
          init_nvt_iterator (&nvts, nvt, 0, NULL, NULL, 0, NULL);

          if (next (&nvts))
            *result = get_nvti_xml (&nvts,
                                    1,    /* Include details. */
                                    0,    /* Preference count. */
                                    1,    /* Include preferences. */
                                    NULL, /* Timeout. */
                                    0,    /* Config. */
                                    1);   /* Close tag. */

          cleanup_iterator (&nvts);
        }
    }
  else if (g_ascii_strcasecmp ("OVALDEF", type) == 0)
    {
      fname = get_ovaldef_filename (uid);
      if (fname)
        {
          gchar *ovaldef;
          ovaldef =
            xsl_transform (OVALDEF_GETBYNAME_XSL, fname, pnames, pvalues);
          g_free (fname);
          if (ovaldef)
            *result = ovaldef;
        }
    }
  else if (g_ascii_strcasecmp ("CERT_BUND_ADV", type) == 0)
    {
      fname = get_cert_bund_adv_filename (uid);
      if (fname)
        {
          gchar *adv;
          adv =
            xsl_transform (CERT_BUND_ADV_GETBYNAME_XSL, fname, pnames, pvalues);
          g_free (fname);
          if (adv)
            *result = adv;
        }
    }
  else if (g_ascii_strcasecmp ("DFN_CERT_ADV", type) == 0)
    {
      fname = get_dfn_cert_adv_filename (uid);
      if (fname)
        {
          gchar *adv;
          adv =
            xsl_transform (DFN_CERT_ADV_GETBYNAME_XSL, fname, pnames, pvalues);
          g_free (fname);
          if (adv)
            *result = adv;
        }
    }

  if (*result == NULL)
    return -1;

  return 1;
}

/* Users. */

/**
 *
 * @brief Validates a username.
 *
 * @param[in]  name  The name.
 *
 * @return 0 if the username is valid, 1 if not.
 */
int
validate_username (const gchar *name)
{
  if (g_regex_match_simple ("^[[:alnum:]-_.]+$", name, 0, 0))
    return 0;
  else
    return 1;
}

/* Resource aggregates. */

/**
 * @brief Free a sort_data_t struct and its related resources.
 *
 * @param[in] sort_data  The sort_data struct to free.
 */
void
sort_data_free (sort_data_t *sort_data)
{
  g_free (sort_data->field);
  g_free (sort_data->stat);
  g_free (sort_data);
}

/* Feeds. */

/**
 * @brief Request a feed synchronization script selftest.
 *
 * Ask a feed synchronization script to perform a selftest and report
 * the results.
 *
 * @param[in]   sync_script  The file name of the synchronization script.
 * @param[out]  result       Return location for selftest errors, or NULL.
 *
 * @return TRUE if the selftest was successful, or FALSE if an error occurred.
 */
gboolean
gvm_sync_script_perform_selftest (const gchar *sync_script, gchar **result)
{
  g_assert (sync_script);
  g_assert_cmpstr (*result, ==, NULL);

  gchar *script_working_dir = g_path_get_dirname (sync_script);

  gchar **argv = (gchar **) g_malloc (3 * sizeof (gchar *));
  argv[0] = g_strdup (sync_script);
  argv[1] = g_strdup ("--selftest");
  argv[2] = NULL;

  gchar *script_out;
  gchar *script_err;
  gint script_exit;
  GError *error = NULL;

  if (!g_spawn_sync (script_working_dir,
                     argv,
                     NULL,
                     0,
                     NULL,
                     NULL,
                     &script_out,
                     &script_err,
                     &script_exit,
                     &error))
    {
      if (*result != NULL)
        {
          *result = g_strdup_printf ("Failed to execute synchronization "
                                     "script: %s",
                                     error->message);
        }

      g_free (script_working_dir);
      g_strfreev (argv);
      g_free (script_out);
      g_free (script_err);
      g_error_free (error);

      return FALSE;
    }

  if (script_exit != 0)
    {
      if (script_err != NULL)
        {
          *result = g_strdup_printf ("%s", script_err);
        }

      g_free (script_working_dir);
      g_strfreev (argv);
      g_free (script_out);
      g_free (script_err);

      return FALSE;
    }

  g_free (script_working_dir);
  g_strfreev (argv);
  g_free (script_out);
  g_free (script_err);

  return TRUE;
}

/**
 * @brief Retrieves the ID string of a feed sync script, with basic validation.
 *
 * @param[in]   sync_script     The file name of the synchronization script.
 * @param[out]  identification  Return location of the identification string.
 * @param[in]   feed_type       Could be NVT_FEED, SCAP_FEED or CERT_FEED.
 *
 * @return TRUE if the identification string was retrieved, or FALSE if an
 *         error occurred.
 */
gboolean
gvm_get_sync_script_identification (const gchar *sync_script,
                                    gchar **identification,
                                    int feed_type)
{
  g_assert (sync_script);
  if (identification)
    g_assert_cmpstr (*identification, ==, NULL);

  gchar *script_working_dir = g_path_get_dirname (sync_script);

  gchar **argv = (gchar **) g_malloc (3 * sizeof (gchar *));
  argv[0] = g_strdup (sync_script);
  argv[1] = g_strdup ("--identify");
  argv[2] = NULL;

  gchar *script_out;
  gchar *script_err;
  gint script_exit;
  GError *error = NULL;

  gchar **script_identification;

  if (!g_spawn_sync (script_working_dir,
                     argv,
                     NULL,
                     0,
                     NULL,
                     NULL,
                     &script_out,
                     &script_err,
                     &script_exit,
                     &error))
    {
      g_warning ("Failed to execute %s: %s", sync_script, error->message);

      g_free (script_working_dir);
      g_strfreev (argv);
      g_free (script_out);
      g_free (script_err);
      g_error_free (error);

      return FALSE;
    }

  if (script_exit != 0)
    {
      g_warning ("%s returned a non-zero exit code.", sync_script);

      g_free (script_working_dir);
      g_strfreev (argv);
      g_free (script_out);
      g_free (script_err);

      return FALSE;
    }

  script_identification = g_strsplit (script_out, "|", 6);

  if ((script_identification[0] == NULL)
      || (feed_type == NVT_FEED
          && g_ascii_strncasecmp (script_identification[0], "NVTSYNC", 7))
      || (feed_type == SCAP_FEED
          && g_ascii_strncasecmp (script_identification[0], "SCAPSYNC", 7))
      || (feed_type == CERT_FEED
          && g_ascii_strncasecmp (script_identification[0], "CERTSYNC", 7))
      || g_ascii_strncasecmp (
           script_identification[0], script_identification[5], 7))
    {
      g_warning ("%s is not a feed synchronization script", sync_script);

      g_free (script_working_dir);
      g_strfreev (argv);
      g_free (script_out);
      g_free (script_err);

      g_strfreev (script_identification);

      return FALSE;
    }

  if (identification)
    *identification = g_strdup (script_out);

  g_free (script_working_dir);
  g_strfreev (argv);
  g_free (script_out);
  g_free (script_err);

  g_strfreev (script_identification);

  return TRUE;
}

/**
 * @brief Retrieves description of a feed sync script, with basic validation.
 *
 * @param[in]   sync_script  The file name of the synchronization script.
 * @param[out]  description  Return location of the description string.
 *
 * @return TRUE if the description was retrieved, or FALSE if an error
 *         occurred.
 */
gboolean
gvm_get_sync_script_description (const gchar *sync_script, gchar **description)
{
  g_assert (sync_script);
  g_assert_cmpstr (*description, ==, NULL);

  gchar *script_working_dir = g_path_get_dirname (sync_script);

  gchar **argv = (gchar **) g_malloc (3 * sizeof (gchar *));
  argv[0] = g_strdup (sync_script);
  argv[1] = g_strdup ("--describe");
  argv[2] = NULL;

  gchar *script_out;
  gchar *script_err;
  gint script_exit;
  GError *error = NULL;

  if (!g_spawn_sync (script_working_dir,
                     argv,
                     NULL,
                     0,
                     NULL,
                     NULL,
                     &script_out,
                     &script_err,
                     &script_exit,
                     &error))
    {
      g_warning ("Failed to execute %s: %s", sync_script, error->message);

      g_free (script_working_dir);
      g_strfreev (argv);
      g_free (script_out);
      g_free (script_err);
      g_error_free (error);

      return FALSE;
    }

  if (script_exit != 0)
    {
      g_warning ("%s returned a non-zero exit code.", sync_script);

      g_free (script_working_dir);
      g_strfreev (argv);
      g_free (script_out);
      g_free (script_err);

      return FALSE;
    }

  *description = g_strdup (script_out);

  g_free (script_working_dir);
  g_strfreev (argv);
  g_free (script_out);
  g_free (script_err);

  return TRUE;
}

/**
 * @brief Retrieves the version of a feed handled by the sync, with basic
 * validation.
 *
 * @param[in]   sync_script  The file name of the synchronization script.
 * @param[out]  feed_version  Return location of the feed version string.
 *
 * @return TRUE if the feed version was retrieved, or FALSE if an error
 *         occurred.
 */
gboolean
gvm_get_sync_script_feed_version (const gchar *sync_script,
                                  gchar **feed_version)
{
  g_assert (sync_script);
  g_assert_cmpstr (*feed_version, ==, NULL);

  gchar *script_working_dir = g_path_get_dirname (sync_script);

  gchar **argv = (gchar **) g_malloc (3 * sizeof (gchar *));
  argv[0] = g_strdup (sync_script);
  argv[1] = g_strdup ("--feedversion");
  argv[2] = NULL;

  gchar *script_out;
  gchar *script_err;
  gint script_exit;
  GError *error = NULL;

  if (!g_spawn_sync (script_working_dir,
                     argv,
                     NULL,
                     0,
                     NULL,
                     NULL,
                     &script_out,
                     &script_err,
                     &script_exit,
                     &error))
    {
      g_warning ("Failed to execute %s: %s", sync_script, error->message);

      g_free (script_working_dir);
      g_strfreev (argv);
      g_free (script_out);
      g_free (script_err);
      g_error_free (error);

      return FALSE;
    }

  if (script_exit != 0)
    {
      g_warning ("%s returned a non-zero exit code.", sync_script);

      g_free (script_working_dir);
      g_strfreev (argv);
      g_free (script_out);
      g_free (script_err);

      return FALSE;
    }

  *feed_version = g_strdup (script_out);

  g_free (script_working_dir);
  g_strfreev (argv);
  g_free (script_out);
  g_free (script_err);

  return TRUE;
}

/**
 * @brief Migrates SCAP or CERT database, waiting until migration terminates.
 *
 * Calls a sync script to migrate the SCAP or CERT database.
 *
 * @param[in]  feed_type     Could be SCAP_FEED or CERT_FEED.
 *
 * @return 0 sync complete, 1 sync already in progress, -1 error
 */
int
gvm_migrate_secinfo (int feed_type)
{
  int lockfile, ret;
  gchar *lockfile_name;
  const gchar *lockfile_basename;

  if (feed_type == SCAP_FEED)
    lockfile_basename = "mageni-sync-scap";
  else if (feed_type == CERT_FEED)
    lockfile_basename = "mageni-sync-cert";
  else
    {
      g_warning ("%s: unsupported feed_type", __FUNCTION__);
      return -1;
    }

  /* Open the lock file. */

  lockfile_name = g_build_filename (g_get_tmp_dir (), lockfile_basename, NULL);

  lockfile = open (lockfile_name,
                   O_RDWR | O_CREAT | O_APPEND,
                   /* "-rw-r--r--" */
                   S_IWUSR | S_IRUSR | S_IROTH | S_IRGRP);
  if (lockfile == -1)
    {
      g_warning (
        "Failed to open lock file '%s': %s", lockfile_name, strerror (errno));
      g_free (lockfile_name);
      return -1;
    }

  if (flock (lockfile, LOCK_EX | LOCK_NB)) /* Exclusive, Non blocking. */
    {
      if (errno == EWOULDBLOCK)
        {
          if (close (lockfile))
            g_warning ("%s: failed to close lockfile: %s",
                       __FUNCTION__,
                       strerror (errno));
          g_free (lockfile_name);
          return 1;
        }
      g_debug ("%s: flock: %s", __FUNCTION__, strerror (errno));
      if (close (lockfile))
        g_warning (
          "%s: failed to close lockfile: %s", __FUNCTION__, strerror (errno));
      g_free (lockfile_name);
      return -1;
    }

  if (feed_type == SCAP_FEED)
    ret = check_scap_db_version ();
  else
    ret = check_cert_db_version ();

  /* Close the lock file. */

  if (close (lockfile))
    {
      g_free (lockfile_name);
      g_warning ("Failed to close lock file: %s", strerror (errno));
      return -1;
    }

  g_free (lockfile_name);

  return ret;
}

/* Wizards. */

/**
 * @brief Run a wizard.
 *
 * @param[in]  wizard_name       Wizard name.
 * @param[in]  run_command       Function to run GMP command.
 * @param[in]  run_command_data  Argument for run_command.
 * @param[in]  params            Wizard params.  Array of name_value_t.
 * @param[in]  read_only         Whether to only allow wizards marked as
 *                               read only.
 * @param[in]  mode              Name of the mode to run the wizard in.
 * @param[out] command_error     Address for error message from failed command
 *                               when return is 4, or NULL.
 * @param[out] command_error_code Address for status code from failed command
 *                                when return is 4, or NULL.
 * @param[out] ret_response      Address for response string of last command.
 *
 * @return 0 success, 1 name error, 2 process forked to run task, -10 process
 *         forked to run task where task start failed, -2 to_scanner buffer
 *         full, 4 command in wizard failed, 5 wizard not read only,
 *         6 Parameter validation failed, -1 internal error,
 *         99 permission denied.
 */
int
manage_run_wizard (const gchar *wizard_name,
                   int (*run_command) (void *, gchar *, gchar **),
                   void *run_command_data,
                   array_t *params,
                   int read_only,
                   const char *mode,
                   gchar **command_error,
                   gchar **command_error_code,
                   gchar **ret_response)
{
  GString *params_xml;
  gchar *file, *file_name, *response, *extra, *extra_wrapped, *wizard;
  gsize wizard_len;
  GError *get_error;
  entity_t entity, mode_entity, params_entity, read_only_entity;
  entity_t param_def, step;
  entities_t modes, steps, param_defs;
  int ret, forked;
  const gchar *point;

  forked = 0;

  if (acl_user_may ("run_wizard") == 0)
    return 99;

  if (command_error)
    *command_error = NULL;

  if (command_error_code)
    *command_error_code = NULL;

  if (ret_response)
    *ret_response = NULL;

  point = wizard_name;
  while (*point && (isalnum (*point) || *point == '_'))
    point++;
  if (*point)
    return 1;

  /* Read wizard from file. */

  file_name = g_strdup_printf ("%s.xml", wizard_name);
  file = g_build_filename (MAGENI_DATA_DIR, "wizards", file_name, NULL);
  g_free (file_name);

  get_error = NULL;
  g_file_get_contents (file, &wizard, &wizard_len, &get_error);
  g_free (file);
  if (get_error)
    {
      g_warning (
        "%s: Failed to read wizard: %s", __FUNCTION__, get_error->message);
      g_error_free (get_error);
      return -1;
    }

  /* Parse wizard. */

  entity = NULL;
  if (parse_entity (wizard, &entity))
    {
      g_warning ("%s: Failed to parse wizard", __FUNCTION__);
      g_free (wizard);
      return -1;
    }
  g_free (wizard);

  /* Select mode */
  if (mode && strcmp (mode, ""))
    {
      modes = entity->entities;
      int mode_found = 0;
      while (mode_found == 0 && (mode_entity = first_entity (modes)))
        {
          if (strcasecmp (entity_name (mode_entity), "mode") == 0)
            {
              entity_t name_entity;
              name_entity = entity_child (mode_entity, "name");

              if (strcmp (entity_text (name_entity), mode) == 0)
                mode_found = 1;
            }
          modes = next_entities (modes);
        }

      if (mode_found == 0)
        {
          free_entity (entity);
          if (ret_response)
            *ret_response = g_strdup ("");

          if (forked)
            return 3;
          else
            return 0;
        }
    }
  else
    {
      mode_entity = entity;
    }

  /* If needed, check if wizard is marked as read only.
   * This does not check the actual commands.
   */
  if (read_only)
    {
      read_only_entity = entity_child (mode_entity, "read_only");
      if (read_only_entity == NULL)
        {
          free_entity (entity);
          return 5;
        }
    }

  /* Check params */
  params_xml = g_string_new ("");
  params_entity = entity_child (mode_entity, "params");
  if (params_entity)
    param_defs = params_entity->entities;

  while (params_entity && (param_def = first_entity (param_defs)))
    {
      if (strcasecmp (entity_name (param_def), "param") == 0)
        {
          entity_t name_entity, regex_entity, optional_entity;
          const char *name, *regex;
          int optional;
          int param_found = 0;

          name_entity = entity_child (param_def, "name");
          if ((name_entity == NULL)
              || (strcmp (entity_text (name_entity), "") == 0))
            {
              g_warning ("%s: Wizard PARAM missing NAME", __FUNCTION__);
              free_entity (entity);
              return -1;
            }
          else
            name = entity_text (name_entity);

          regex_entity = entity_child (param_def, "regex");
          if ((regex_entity == NULL)
              || (strcmp (entity_text (regex_entity), "") == 0))
            {
              g_warning ("%s: Wizard PARAM missing REGEX", __FUNCTION__);
              free_entity (entity);
              return -1;
            }
          else
            regex = entity_text (regex_entity);

          optional_entity = entity_child (param_def, "optional");
          optional =
            (optional_entity && strcmp (entity_text (optional_entity), "")
             && strcmp (entity_text (optional_entity), "0"));

          if (params)
            {
              guint index = params->len;
              while (index--)
                {
                  name_value_t *pair;

                  pair = (name_value_t *) g_ptr_array_index (params, index);

                  if (pair == NULL)
                    continue;

                  if ((pair->name) && (pair->value)
                      && (strcmp (pair->name, name) == 0))
                    {
                      index = 0; // end loop;
                      param_found = 1;

                      if (g_regex_match_simple (regex, pair->value, 0, 0) == 0)
                        {
                          *command_error =
                            g_strdup_printf ("Value '%s' is not valid for"
                                             " parameter '%s'.",
                                             pair->value,
                                             name);
                          free_entity (entity);
                          g_string_free (params_xml, TRUE);
                          return 6;
                        }
                    }
                }
            }

          if (optional == 0 && param_found == 0)
            {
              *command_error = g_strdup_printf ("Mandatory wizard param '%s'"
                                                " missing",
                                                name);
              free_entity (entity);
              return 6;
            }
        }
      param_defs = next_entities (param_defs);
    }

  /* Buffer params */
  if (params)
    {
      guint index = params->len;
      while (index--)
        {
          name_value_t *pair;

          pair = (name_value_t *) g_ptr_array_index (params, index);
          xml_string_append (params_xml,
                             "<param>"
                             "<name>%s</name>"
                             "<value>%s</value>"
                             "</param>",
                             pair->name ? pair->name : "",
                             pair->value ? pair->value : "");
        }
    }

  /* Run each step of the wizard. */

  response = NULL;
  extra = NULL;
  steps = mode_entity->entities;
  while ((step = first_entity (steps)))
    {
      if (strcasecmp (entity_name (step), "step") == 0)
        {
          entity_t command, extra_xsl;
          gchar *gmp;
          int xsl_fd, xml_fd;
          char xsl_file_name[] = "/tmp/mageni-xsl-XXXXXX";
          FILE *xsl_file, *xml_file;
          char xml_file_name[] = "/tmp/mageni-xml-XXXXXX";
          char extra_xsl_file_name[] = "/tmp/mageni-extra-xsl-XXXXXX";
          char extra_xml_file_name[] = "/tmp/mageni-extra-xml-XXXXXX";

          /* Get the command element. */

          command = entity_child (step, "command");
          if (command == NULL)
            {
              g_warning ("%s: Wizard STEP missing COMMAND", __FUNCTION__);
              free_entity (entity);
              g_free (response);
              g_free (extra);
              g_string_free (params_xml, TRUE);
              return -1;
            }

          /* Save the command XSL from the element to a file. */

          xsl_fd = mkstemp (xsl_file_name);
          if (xsl_fd == -1)
            {
              g_warning ("%s: Wizard XSL file create failed", __FUNCTION__);
              free_entity (entity);
              g_free (response);
              g_free (extra);
              g_string_free (params_xml, TRUE);
              return -1;
            }

          xsl_file = fdopen (xsl_fd, "w");
          if (xsl_file == NULL)
            {
              g_warning ("%s: Wizard XSL file open failed", __FUNCTION__);
              close (xsl_fd);
              free_entity (entity);
              g_free (response);
              g_free (extra);
              g_string_free (params_xml, TRUE);
              return -1;
            }

          if (first_entity (command->entities))
            print_entity (xsl_file, first_entity (command->entities));

          /* Write the params as XML to a file. */

          xml_fd = mkstemp (xml_file_name);
          if (xml_fd == -1)
            {
              g_warning ("%s: Wizard XML file create failed", __FUNCTION__);
              fclose (xsl_file);
              unlink (xsl_file_name);
              free_entity (entity);
              g_free (response);
              g_free (extra);
              g_string_free (params_xml, TRUE);
              return -1;
            }

          xml_file = fdopen (xml_fd, "w");
          if (xml_file == NULL)
            {
              g_warning ("%s: Wizard XML file open failed", __FUNCTION__);
              fclose (xsl_file);
              unlink (xsl_file_name);
              close (xml_fd);
              free_entity (entity);
              g_free (response);
              g_free (extra);
              g_string_free (params_xml, TRUE);
              return -1;
            }

          if (fprintf (xml_file,
                       "<wizard>"
                       "<params>%s</params>"
                       "<previous>"
                       "<response>%s</response>"
                       "<extra_data>%s</extra_data>"
                       "</previous>"
                       "</wizard>\n",
                       params_xml->str ? params_xml->str : "",
                       response ? response : "",
                       extra ? extra : "")
              < 0)
            {
              fclose (xsl_file);
              unlink (xsl_file_name);
              fclose (xml_file);
              unlink (xml_file_name);
              free_entity (entity);
              g_warning ("%s: Wizard failed to write XML", __FUNCTION__);
              g_free (response);
              g_free (extra);
              g_string_free (params_xml, TRUE);
              return -1;
            }

          fflush (xml_file);

          /* Combine XSL and XML to get the GMP command. */

          gmp = xsl_transform (xsl_file_name, xml_file_name, NULL, NULL);
          fclose (xsl_file);
          unlink (xsl_file_name);
          fclose (xml_file);
          unlink (xml_file_name);
          if (gmp == NULL)
            {
              g_warning ("%s: Wizard XSL transform failed", __FUNCTION__);
              free_entity (entity);
              g_free (response);
              g_free (extra);
              g_string_free (params_xml, TRUE);
              return -1;
            }

          /* Run the GMP command. */

          g_free (response);
          response = NULL;
          ret = run_command (run_command_data, gmp, &response);
          if (ret == 3)
            {
              /* Parent after a start_task fork. */
              forked = 1;
            }
          else if (ret == 0)
            {
              /* Command succeeded. */
            }
          else if (ret == 2)
            {
              /* Process forked to run a task. */
              free_entity (entity);
              g_free (response);
              g_free (extra);
              g_string_free (params_xml, TRUE);
              return 2;
            }
          else if (ret == -10)
            {
              /* Process forked to run a task.  Task start failed. */
              free_entity (entity);
              g_free (response);
              g_free (extra);
              g_string_free (params_xml, TRUE);
              return -10;
            }
          else if (ret == -2)
            {
              /* to_scanner buffer full. */
              free_entity (entity);
              g_free (response);
              g_free (extra);
              g_string_free (params_xml, TRUE);
              return -2;
            }
          else
            {
              free_entity (entity);
              g_free (response);
              g_free (extra);
              g_string_free (params_xml, TRUE);
              return -1;
            }

          /* Exit if the command failed. */

          if (response)
            {
              const char *status;
              entity_t response_entity;

              response_entity = NULL;
              if (parse_entity (response, &response_entity))
                {
                  g_warning ("%s: Wizard failed to parse response",
                             __FUNCTION__);
                  free_entity (entity);
                  g_free (response);
                  g_free (extra);
                  g_string_free (params_xml, TRUE);
                  return -1;
                }

              status = entity_attribute (response_entity, "status");
              if ((status == NULL) || (strlen (status) == 0)
                  || (status[0] != '2'))
                {
                  g_debug ("response was %s", response);
                  if (command_error)
                    {
                      const char *text;
                      text = entity_attribute (response_entity, "status_text");
                      if (text)
                        *command_error = g_strdup (text);
                    }
                  if (command_error_code)
                    {
                      *command_error_code = g_strdup (status);
                    }
                  free_entity (response_entity);
                  free_entity (entity);
                  g_free (response);
                  g_free (extra);
                  g_string_free (params_xml, TRUE);
                  return 4;
                }

              free_entity (response_entity);
            }

          /* Get the extra_data element. */

          extra_xsl = entity_child (step, "extra_data");
          if (extra_xsl)
            {
              /* Save the extra_data XSL from the element to a file. */

              xsl_fd = mkstemp (extra_xsl_file_name);
              if (xsl_fd == -1)
                {
                  g_warning ("%s: Wizard extra_data XSL file create failed",
                             __FUNCTION__);
                  free_entity (entity);
                  g_free (response);
                  g_free (extra);
                  g_string_free (params_xml, TRUE);
                  return -1;
                }

              xsl_file = fdopen (xsl_fd, "w");
              if (xsl_file == NULL)
                {
                  g_warning ("%s: Wizard extra_data XSL file open failed",
                             __FUNCTION__);
                  close (xsl_fd);
                  free_entity (entity);
                  g_free (response);
                  g_free (extra);
                  g_string_free (params_xml, TRUE);
                  return -1;
                }

              if (first_entity (extra_xsl->entities))
                print_entity (xsl_file, first_entity (extra_xsl->entities));

              /* Write the params as XML to a file. */

              xml_fd = mkstemp (extra_xml_file_name);
              if (xml_fd == -1)
                {
                  g_warning ("%s: Wizard XML file create failed", __FUNCTION__);
                  fclose (xsl_file);
                  unlink (xsl_file_name);
                  free_entity (entity);
                  g_free (response);
                  g_free (extra);
                  g_string_free (params_xml, TRUE);
                  return -1;
                }

              xml_file = fdopen (xml_fd, "w");
              if (xml_file == NULL)
                {
                  g_warning ("%s: Wizard XML file open failed", __FUNCTION__);
                  fclose (xsl_file);
                  unlink (xsl_file_name);
                  close (xml_fd);
                  free_entity (entity);
                  g_free (response);
                  g_free (extra);
                  g_string_free (params_xml, TRUE);
                  return -1;
                }

              if (fprintf (xml_file,
                           "<wizard>"
                           "<params>%s</params>"
                           "<current>"
                           "<response>%s</response>"
                           "</current>"
                           "<previous>"
                           "<extra_data>%s</extra_data>"
                           "</previous>"
                           "</wizard>\n",
                           params_xml->str ? params_xml->str : "",
                           response ? response : "",
                           extra ? extra : "")
                  < 0)
                {
                  fclose (xsl_file);
                  unlink (extra_xsl_file_name);
                  fclose (xml_file);
                  unlink (extra_xml_file_name);
                  free_entity (entity);
                  g_warning ("%s: Wizard failed to write XML", __FUNCTION__);
                  g_free (response);
                  g_free (extra);
                  g_string_free (params_xml, TRUE);
                  return -1;
                }

              fflush (xml_file);

              g_free (extra);
              extra = xsl_transform (
                extra_xsl_file_name, extra_xml_file_name, NULL, NULL);
              fclose (xsl_file);
              unlink (extra_xsl_file_name);
              fclose (xml_file);
              unlink (extra_xml_file_name);
            }
        }
      steps = next_entities (steps);
    }

  if (extra)
    extra_wrapped = g_strdup_printf ("<extra_data>%s</extra_data>", extra);
  else
    extra_wrapped = NULL;
  g_free (extra);

  if (ret_response)
    *ret_response = response;

  if (extra_wrapped && (forked == 0))
    {
      entity_t extra_entity, status_entity, status_text_entity;
      ret = parse_entity (extra_wrapped, &extra_entity);
      if (ret == 0)
        {
          status_entity = entity_child (extra_entity, "status");
          status_text_entity = entity_child (extra_entity, "status_text");

          if (status_text_entity && command_error)
            {
              *command_error = g_strdup (entity_text (status_text_entity));
            }

          if (status_entity && command_error_code)
            {
              *command_error_code = g_strdup (entity_text (status_entity));
            }
          free_entity (extra_entity);
        }
      else
        {
          g_warning ("%s: failed to parse extra data", __FUNCTION__);
          free_entity (entity);
          g_string_free (params_xml, TRUE);
          return -1;
        }
    }

  free_entity (entity);
  g_string_free (params_xml, TRUE);

  /* All the steps succeeded. */

  if (forked)
    return 3;
  return 0;
}

/**
 * @brief Gets the last termination signal or 0.
 *
 * @return The last termination signal or 0 if there was none.
 */
int
get_termination_signal ()
{
  return termination_signal;
}

/* Resources. */

/**
 * @brief Delete a resource.
 *
 * @param[in]  type         Type of resource.
 * @param[in]  resource_id  UUID of resource.
 * @param[in]  ultimate     Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 1 resource in use, 2 failed to find resource,
 *         3 predefined resource, 99 permission denied, -1 error.
 */
int
delete_resource (const char *type, const char *resource_id, int ultimate)
{
  if (strcasecmp (type, "ticket") == 0)
    return delete_ticket (resource_id, ultimate);
  assert (0);
  return -1;
}
