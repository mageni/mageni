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
 * @brief GPGME utilities.
 */

#include "gpgmeutils.h"

#include "fileutils.h"

#include <errno.h>     /* for ENOENT, errno */
#include <gpg-error.h> /* for gpg_err_source, gpg_strerror, gpg_error_from... */
#include <locale.h>    /* for setlocale, LC_MESSAGES, LC_CTYPE */
#include <stdlib.h>    /* for mkdtemp */
#include <string.h>    /* for strlen */
#include <sys/stat.h>  /* for mkdir */
#include <unistd.h>    /* for access, F_OK */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "util gpgme"

/**
 * @brief Log function with extra gpg-error style output
 *
 * If \p err is not 0, the appropriate error string is appended to
 * the output.  It takes care to only add the error source string if
 * it makes sense.
 *
 * @param level  The GLib style log level
 * @param err    An gpg-error value or 0
 * @param fmt    The printf style format string, followed by its
 *                arguments.
 *
 */
void
log_gpgme (GLogLevelFlags level, gpg_error_t err, const char *fmt, ...)
{
  va_list arg_ptr;
  char *msg;

  va_start (arg_ptr, fmt);
  msg = g_strdup_vprintf (fmt, arg_ptr);
  va_end (arg_ptr);
  if (err && gpg_err_source (err) != GPG_ERR_SOURCE_ANY && gpg_err_source (err))
    g_log (G_LOG_DOMAIN, level, "%s: %s <%s>", msg, gpg_strerror (err),
           gpg_strsource (err));
  else if (err)
    g_log (G_LOG_DOMAIN, level, "%s: %s", msg, gpg_strerror (err));
  else
    g_log (G_LOG_DOMAIN, level, "%s", msg);
  g_free (msg);
}

/**
 * @brief Returns a new gpgme context.
 *
 * Inits a gpgme context with the custom gpg directory, protocol
 * version etc. Returns the context or NULL if an error occurred.
 * This function also does an gpgme initialization the first time it
 * is called.
 *
 * @param dir  Directory to use for gpg
 *
 * @return The gpgme_ctx_t to the context or NULL if an error occurred.
 */
gpgme_ctx_t
gvm_init_gpgme_ctx_from_dir (const gchar *dir)
{
  static int initialized;
  gpgme_error_t err;
  gpgme_ctx_t ctx;

  /* Initialize GPGME the first time we are called.  This is a
     failsafe mode; it would be better to initialize GPGME early at
     process startup instead of this on-the-fly method; however in
     this non-threaded system; this is an easier way for a library.
     We allow to initialize until a valid gpgme or a gpg backend has
     been found.  */
  if (!initialized)
    {
      gpgme_engine_info_t info;

      if (!gpgme_check_version (NULL))
        {
          g_critical ("gpgme library could not be initialized.");
          return NULL;
        }
      gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifdef LC_MESSAGES
      gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif

#ifndef NDEBUG
      g_debug ("Setting GnuPG dir to '%s'", dir);
#endif
      err = 0;
      if (access (dir, F_OK))
        {
          err = gpg_error_from_syserror ();

          if (errno == ENOENT)
            /* directory does not exists. try to create it */
            if (mkdir (dir, 0700) == 0)
              {
#ifndef NDEBUG
                g_debug ("Created GnuPG dir '%s'", dir);
#endif
                err = 0;
              }
        }

      if (!err)
        err = gpgme_set_engine_info (GPGME_PROTOCOL_OpenPGP, NULL, dir);

      if (err)
        {
          log_gpgme (G_LOG_LEVEL_WARNING, err, "Setting GnuPG dir failed");
          return NULL;
        }

      /* Show the OpenPGP engine version.  */
      if (!gpgme_get_engine_info (&info))
        {
          while (info && info->protocol != GPGME_PROTOCOL_OpenPGP)
            info = info->next;
        }
      else
        info = NULL;
#ifndef NDEBUG
      g_debug ("Using OpenPGP engine version '%s'",
                 info && info->version ? info->version : "[?]");
#endif

      /* Everything is fine.  */
      initialized = 1;
    }

  /* Allocate the context.  */
  ctx = NULL;
  err = gpgme_new (&ctx);
  if (err)
    log_gpgme (G_LOG_LEVEL_WARNING, err, "Creating GPGME context failed");

  return ctx;
}

/**
 * @brief Import a key or certificate given by a string.
 *
 * @param[in]  ctx      The GPGME context to import the key / certificate into.
 * @param[in]  key_str  Key or certificate string.
 * @param[in]  key_len  Length of key/certificate string or -1 to use strlen.
 * @param[in]  key_type The expected key type.
 *
 * @return 0 success, 1 invalid key data, 2 unexpected key data,
 *  3 error importing key/certificate, -1 error.
 */
int
gvm_gpg_import_from_string (gpgme_ctx_t ctx, const char *key_str,
                            ssize_t key_len, gpgme_data_type_t key_type)
{
  gpgme_data_t key_data;
  gpgme_error_t err;
  gpgme_data_type_t given_key_type;
  gpgme_import_result_t import_result;

  gpgme_data_new_from_mem (
    &key_data, key_str, (key_len >= 0 ? key_len : (ssize_t) strlen (key_str)),
    0);

  given_key_type = gpgme_data_identify (key_data, 0);
  if (given_key_type != key_type)
    {
      int ret;
      if (given_key_type == GPGME_DATA_TYPE_INVALID)
        {
          ret = 1;
          g_warning ("%s: key_str is invalid", __FUNCTION__);
        }
      else
        {
          ret = 2;
          g_warning ("%s: key_str is not the expected type: "
                     " expected: %d, got %d",
                     __FUNCTION__, key_type, given_key_type);
        }
      gpgme_data_release (key_data);
      return ret;
    }

  err = gpgme_op_import (ctx, key_data);
  gpgme_data_release (key_data);
  if (err)
    {
      g_warning ("%s: Import failed: %s", __FUNCTION__, gpgme_strerror (err));
      return 3;
    }

  import_result = gpgme_op_import_result (ctx);
  g_debug ("%s: %d imported, %d not imported", __FUNCTION__,
           import_result->imported, import_result->not_imported);

  gpgme_import_status_t status;
  status = import_result->imports;
  while (status)
    {
      if (status->result != GPG_ERR_NO_ERROR)
        g_warning ("%s: '%s' could not be imported: %s", __FUNCTION__,
                   status->fpr, gpgme_strerror (status->result));
      else
        g_debug ("%s: Imported '%s'", __FUNCTION__, status->fpr);

      status = status->next;
    };

  if (import_result->not_imported)
    return 3;

  return 0;
}

/**
 * @brief Find a key that can be used to encrypt for an email recipient.
 *
 * @param[in]  ctx        The GPGME context.
 * @param[in]  uid_email  The recipient email address to look for.
 *
 * @return  The key as a gpgme_key_t.
 */
static gpgme_key_t
find_email_encryption_key (gpgme_ctx_t ctx, const char *uid_email)
{
  gchar *bracket_email;
  gpgme_key_t key;
  gboolean recipient_found = FALSE;

  if (uid_email == NULL)
    return NULL;

  bracket_email = g_strdup_printf ("<%s>", uid_email);

  gpgme_op_keylist_start (ctx, NULL, 0);
  gpgme_op_keylist_next (ctx, &key);
  while (key && recipient_found == FALSE)
    {
      if (key->can_encrypt)
        {
          g_debug ("%s: key '%s' OK for encryption", __FUNCTION__,
                   key->subkeys->fpr);

          gpgme_user_id_t uid;
          uid = key->uids;
          while (uid && recipient_found == FALSE)
            {
              g_debug ("%s: UID email: %s", __FUNCTION__, uid->email);

              if (strcmp (uid->email, uid_email) == 0
                  || strstr (uid->email, bracket_email))
                {
                  g_message ("%s: Found matching UID for %s", __FUNCTION__,
                             uid_email);
                  recipient_found = TRUE;
                }
              uid = uid->next;
            }
        }
      else
        {
          g_debug ("%s: key '%s' cannot be used for encryption", __FUNCTION__,
                   key->subkeys->fpr);
        }

      if (recipient_found == FALSE)
        gpgme_op_keylist_next (ctx, &key);
    }

  if (recipient_found)
    return key;
  else
    {
      g_warning ("%s: No suitable key found for %s", __FUNCTION__, uid_email);
      return NULL;
    }
}

/**
 * @brief Encrypt a stream for a PGP public key, writing to another stream.
 *
 * The output will use ASCII armor mode and no compression.
 *
 * @param[in]  plain_file     Stream / FILE* providing the plain text.
 * @param[in]  encrypted_file Stream to write the encrypted text to.
 * @param[in]  key_str        String containing the public key or certificate.
 * @param[in]  key_len        Length of key / certificate, -1 to use strlen.
 * @param[in]  uid_email      Email address of key / certificate to use.
 * @param[in]  protocol       The protocol to use, e.g. OpenPGP or CMS.
 * @param[in]  data_type      The expected GPGME buffered data type.
 *
 * @return 0 success, -1 error.
 */
static int
encrypt_stream_internal (FILE *plain_file, FILE *encrypted_file,
                         const char *key_str, ssize_t key_len,
                         const char *uid_email, gpgme_protocol_t protocol,
                         gpgme_data_type_t data_type)
{
  char gpg_temp_dir[] = "/tmp/gvmd-gpg-XXXXXX";
  gpgme_ctx_t ctx;
  gpgme_data_t plain_data, encrypted_data;
  gpgme_key_t key;
  gpgme_key_t keys[2] = {NULL, NULL};
  gpgme_error_t err;
  gpgme_encrypt_flags_t encrypt_flags;
  const char *key_type_str;

  if (uid_email == NULL || strcmp (uid_email, "") == 0)
    {
      g_warning ("%s: No email address for user identification given",
                 __FUNCTION__);
      return -1;
    }

  if (protocol == GPGME_PROTOCOL_CMS)
    key_type_str = "certificate";
  else
    key_type_str = "public key";

  // Create temporary GPG home directory, set up context and encryption flags
  if (mkdtemp (gpg_temp_dir) == NULL)
    {
      g_warning ("%s: mkdtemp failed\n", __FUNCTION__);
      return -1;
    }

  gpgme_new (&ctx);

  if (protocol == GPGME_PROTOCOL_CMS)
    gpgme_set_armor (ctx, 0);
  else
    gpgme_set_armor (ctx, 1);

  gpgme_ctx_set_engine_info (ctx, protocol, NULL, gpg_temp_dir);
  gpgme_set_protocol (ctx, protocol);
  encrypt_flags = GPGME_ENCRYPT_ALWAYS_TRUST | GPGME_ENCRYPT_NO_COMPRESS;

  // Import public key into context
  if (gvm_gpg_import_from_string (ctx, key_str, key_len, data_type))
    {
      g_warning ("%s: Import of %s failed", __FUNCTION__, key_type_str);
      gpgme_release (ctx);
      gvm_file_remove_recurse (gpg_temp_dir);
      return -1;
    }

  // Get imported public key
  key = find_email_encryption_key (ctx, uid_email);
  if (key == NULL)
    {
      g_warning ("%s: Could not find %s for encryption", __FUNCTION__,
                 key_type_str);
      gpgme_release (ctx);
      gvm_file_remove_recurse (gpg_temp_dir);
      return -1;
    }
  keys[0] = key;

  // Set up data objects for input and output streams
  gpgme_data_new_from_stream (&plain_data, plain_file);
  gpgme_data_new_from_stream (&encrypted_data, encrypted_file);

  if (protocol == GPGME_PROTOCOL_CMS)
    gpgme_data_set_encoding (encrypted_data, GPGME_DATA_ENCODING_BASE64);

  // Encrypt data
  err = gpgme_op_encrypt (ctx, keys, encrypt_flags, plain_data, encrypted_data);

  if (err)
    {
      g_warning ("%s: Encryption failed: %s", __FUNCTION__,
                 gpgme_strerror (err));
      gpgme_data_release (plain_data);
      gpgme_data_release (encrypted_data);
      gpgme_release (ctx);
      gvm_file_remove_recurse (gpg_temp_dir);
      return -1;
    }

  gpgme_data_release (plain_data);
  gpgme_data_release (encrypted_data);
  gpgme_release (ctx);
  gvm_file_remove_recurse (gpg_temp_dir);

  return 0;
}

/**
 * @brief Encrypt a stream for a PGP public key, writing to another stream.
 *
 * The output will use ASCII armor mode and no compression.
 *
 * @param[in]  plain_file       Stream / FILE* providing the plain text.
 * @param[in]  encrypted_file   Stream to write the encrypted text to.
 * @param[in]  uid_email        Email address of public key to use.
 * @param[in]  public_key_str   String containing the public key.
 * @param[in]  public_key_len   Length of public key or -1 to use strlen.
 *
 * @return 0 success, -1 error.
 */
int
gvm_pgp_pubkey_encrypt_stream (FILE *plain_file, FILE *encrypted_file,
                               const char *uid_email,
                               const char *public_key_str,
                               ssize_t public_key_len)
{
  return encrypt_stream_internal (
    plain_file, encrypted_file, public_key_str, public_key_len, uid_email,
    GPGME_PROTOCOL_OpenPGP, GPGME_DATA_TYPE_PGP_KEY);
}

/**
 * @brief Encrypt a stream for a S/MIME certificate, writing to another stream.
 *
 * The output will use ASCII armor mode and no compression.
 *
 * @param[in]  plain_file       Stream / FILE* providing the plain text.
 * @param[in]  encrypted_file   Stream to write the encrypted text to.
 * @param[in]  uid_email        Email address of certificate to use.
 * @param[in]  certificate_str  String containing the public key.
 * @param[in]  certificate_len  Length of public key or -1 to use strlen.
 *
 * @return 0 success, -1 error.
 */
int
gvm_smime_encrypt_stream (FILE *plain_file, FILE *encrypted_file,
                          const char *uid_email, const char *certificate_str,
                          ssize_t certificate_len)
{
  return encrypt_stream_internal (
    plain_file, encrypted_file, certificate_str, certificate_len, uid_email,
    GPGME_PROTOCOL_CMS, GPGME_DATA_TYPE_CMS_OTHER);
}
