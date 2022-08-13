// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Name: lsc_crypt.c
 * Brief: Utilities for LSC credential encryption. This file provides support for encrypting LSC credentials.
 * 
 * Copyright:
 * Copyright (C) 2013-2018 Greenbone Networks GmbH
 * Copyright (C) 2022, Mageni Security LLC
 *
 */

#include "lsc_crypt.h"

#include <glib.h>
#include <glib/gstdio.h>
#include "../../libraries/util/gpgmeutils.h"
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md  crypt"

/**
 * @brief The name of the encryption key.
 *
 * Note that the code will use the "=" prefix flag to indicate an
 * exact search.  Thus when creating the key it should not have a
 * comment or email address part.
 */
#define ENCRYPTION_KEY_UID "Mageni Credential Encryption"

/**
 * @brief The maximum size of an encrypted value
 *
 * To avoid excessive memory allocations we put a limit on the size of
 * values stored in a name/value pair.
 */
#define MAX_VALUE_LENGTH (128 * 1024)

#ifndef GPG_ERR_AMBIGUOUS
/**
 * @brief Replacement for an error code in libgpg-error > 1.10.
 */
#define GPG_ERR_AMBIGUOUS GPG_ERR_AMBIGUOUS_NAME
#endif

/**
 * @brief  A linked list to help caching results.
 */
struct namelist_s
{
  struct namelist_s *next; ///< Next element in list
  size_t valoff;           /**< Offset to the value in the plaintext buffer
                              or 0 if VALUE below is used instead.  Note
                              that a value will never be at the begin of
                              the plaintext buffer.  VALOFF and VALUE
                              0/NULL indicates a NULL value. */
  char *value;             ///< The value.
  char name[1];            ///< The name.
};

/**
 * @brief The context object for encryption operations
 *
 * This context is used to track the underlying gpgme conectec and to
 * provide a decryption cache.
 */
struct lsc_crypt_ctx_s
{
  gpgme_ctx_t encctx;          ///< Encryption context.
  gpgme_key_t enckey;          ///< The key to be used for encryption.
  char *plaintext;             ///< Text to be encrypted.
  size_t plaintextlen;         ///< Length of text.
  struct namelist_s *namelist; ///< Info describing PLAINTEXT.
};

/* Simple helper functions  */

/**
 * @brief Return a fixed string instead of NULL
 *
 * This is a convenience functions to return a descriptive string for
 * a NULL pointer.  Some printf implementations already do that for
 * the "s" format but it is not a standard.  Thus we use this little
 * helper.
 *
 * @param s  String.
 *
 * @return "[none]" if \p s is NULL, else \p s.
 */
static G_GNUC_CONST const char *
nonnull (const char *s)
{
  return s ? s : "[none]";
}

/**
 * @brief Append a 32 bit unsigned integer to a GString.
 *
 * This function is used to append a 32 bit unsigned value to a
 * GString in network byte order (big endian).
 *
 * @param buffer  GString as destination
 * @param value   The 32 bit unsigned value
 */
static void
put32 (GString *buffer, uint32_t value)
{
  unsigned char tmp[4];
  tmp[0] = value >> 24;
  tmp[1] = value >> 16;
  tmp[2] = value >> 8;
  tmp[3] = value;
  g_string_append_len (buffer, (char *) tmp, 4);
}

/**
 * @brief Extract a 32 bit unsigned integer from a buffer
 *
 * @param buffer   Pointer to an arbitrary buffer with a length of at
 *                 least 4 bytes.

 * @return An unsigned 32 bit integer value taken from the first 4
 *         bytes of the buffer which is assumed to be in big-endian
 *         encoding.
 */
static G_GNUC_PURE uint32_t
get32 (const void *buffer)
{
  const unsigned char *s = buffer;
  uint32_t value;

  value = s[0] << 24;
  value |= s[1] << 16;
  value |= s[2] << 8;
  value |= s[3];

  return value;
}

/* Local functions. */

/**
 * @brief Create the credential encryption key
 *
 * This should only be called if the key does not yet exist.
 *
 * @param ctx  The initialized encryption context
 *
 * @return On success 0 is returned; any other value indicates an error.
 */
static int
create_the_key (lsc_crypt_ctx_t ctx)
{
  const char parms[] = "<GnupgKeyParms format=\"internal\">\n"
                       "Key-Type: RSA\n"
                       "Key-Length: 2048\n"
                       "Key-Usage: encrypt\n"
                       "Name-Real: " ENCRYPTION_KEY_UID "\n"
                       "Expire-Date: 0\n"
                       "%no-protection\n"
                       "%no-ask-passphrase\n"
                       "</GnupgKeyParms>\n";
  gpg_error_t err;

  log_gpgme (G_LOG_LEVEL_INFO, 0, "starting key generation ...");
  err = gpgme_op_genkey (ctx->encctx, parms, NULL, NULL);
  if (err)
    {
      log_gpgme (G_LOG_LEVEL_WARNING,
                 err,
                 "error creating OpenPGP key '%s'",
                 ENCRYPTION_KEY_UID);
      return -1;
    }
  log_gpgme (G_LOG_LEVEL_INFO,
             0,
             "OpenPGP key '%s' has been generated",
             ENCRYPTION_KEY_UID);
  return 0;
}

/**
 * @brief Locate the encryption key
 *
 * This function is used to find and return the standard encryption
 * key.
 *
 * @param ctx        An initialized encryption context
 * @param no_create  If TRUE, do not try to create a missing encryption key.
 *
 * @return A gpgme key object or NULL on error.
 */
static gpgme_key_t
find_the_key (lsc_crypt_ctx_t ctx, gboolean no_create)
{
  gpg_error_t err;
  int nfound, any_skipped;
  gpgme_key_t found, key;

again:
  /* Search for the public key.  Note that the "=" prefix flag enables
     an exact search.  */
  err = gpgme_op_keylist_start (ctx->encctx, "=" ENCRYPTION_KEY_UID, 0);
  if (err)
    {
      log_gpgme (G_LOG_LEVEL_WARNING,
                 err,
                 "error starting search for OpenPGP key '%s'",
                 ENCRYPTION_KEY_UID);
      return NULL;
    }

  nfound = any_skipped = 0;
  found = NULL;
  while (!(err = gpgme_op_keylist_next (ctx->encctx, &key)))
    {
      if (!key->can_encrypt || key->revoked || key->expired || key->disabled
          || key->invalid)
        {
          log_gpgme (G_LOG_LEVEL_MESSAGE,
                     0,
                     "skipping unusable OpenPGP key %s",
                     key->subkeys ? nonnull (key->subkeys->keyid) : "?");
          any_skipped = 1;
          continue;
        }
      nfound++;
      if (!found)
        {
          gpgme_key_ref (key);
          found = key;
        }
      gpgme_key_unref (key);
    }
  if (gpgme_err_code (err) == GPG_ERR_EOF)
    err = 0;
  gpgme_op_keylist_end (ctx->encctx);

  if (err)
    {
      char *path = g_build_filename (MAGENI_STATE_DIR, "gnupg", NULL);

      /* We better reset the gpgme context after an error.  */
      gpgme_release (ctx->encctx);
      ctx->encctx = gvm_init_gpgme_ctx_from_dir (path);
      g_free (path);
      if (!ctx->encctx)
        {
          g_critical ("%s: can't continue w/o a gpgme context", G_STRFUNC);
          exit (EXIT_FAILURE);
        }
    }
  else if (!found)
    {
      static int genkey_tried;

      /* Try to create the key if we have not seen any matching key at
         all and if this is the first time in this process' lifetime.  */
      if (!any_skipped && !genkey_tried && !no_create)
        {
          genkey_tried = 1;
          if (!create_the_key (ctx))
            goto again; /* Created - search again.  */
        }

      err = gpg_err_make (GPG_ERR_SOURCE_ANY, GPG_ERR_NOT_FOUND);
    }
  else if (nfound > 1)
    err = gpg_err_make (GPG_ERR_SOURCE_ANY, GPG_ERR_AMBIGUOUS);

  if (err)
    {
      log_gpgme (G_LOG_LEVEL_MESSAGE,
                 err,
                 "error searching for OpenPGP key '%s'",
                 ENCRYPTION_KEY_UID);
      gpgme_key_unref (found);
      found = NULL;
    }

  return found;
}

/**
 * @brief Encrypt data using the standard key
 *
 * Encrypt the given plaintext using the standard credential key and
 * return a base 64 encoded ciphertext.
 *
 * @param[in] ctx          An initialized encryption context
 * @param[in] plaintext    The data to be encrypted
 * @param[in] plaintextlen The length in bytes of \p plaintext
 *
 * @return A base64 encoded ciphertext to be released by the caller.
 *         NULL is returned on error.
 */
static char *
do_encrypt (lsc_crypt_ctx_t ctx, const void *plaintext, size_t plaintextlen)
{
  gpg_error_t err;
  gpgme_data_t in, out;
  gpgme_key_t keyarray[2];
  char *ciphertext;
  size_t ciphertextlen;
  char *result;

  if (!ctx->enckey)
    {
      ctx->enckey = find_the_key (ctx, 0);
      if (!ctx->enckey)
        return NULL;
    }

  err = gpgme_data_new_from_mem (&in, plaintext, plaintextlen, 0);
  if (err)
    {
      log_gpgme (G_LOG_LEVEL_WARNING,
                 err,
                 "%s: error creating data object from plaintext",
                 G_STRFUNC);
      return NULL;
    }

  err = gpgme_data_new (&out);
  if (err)
    {
      log_gpgme (G_LOG_LEVEL_WARNING,
                 err,
                 "%s: error creating data object for ciphertext",
                 G_STRFUNC);
      gpgme_data_release (in);
      return NULL;
    }

  gpgme_set_armor (ctx->encctx, 0);
  keyarray[0] = ctx->enckey;
  keyarray[1] = NULL;
  err = gpgme_op_encrypt (
    ctx->encctx, keyarray, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
  gpgme_data_release (in);
  if (err)
    {
      log_gpgme (
        G_LOG_LEVEL_WARNING, err, "%s: error encrypting credential", G_STRFUNC);
      gpgme_data_release (out);
      return NULL;
    }
  ciphertext = gpgme_data_release_and_get_mem (out, &ciphertextlen);
  if (!ciphertext)
    {
      g_critical ("%s: error snatching memory", G_STRFUNC);
      exit (EXIT_FAILURE);
    }

  result = g_base64_encode ((unsigned char *) ciphertext, ciphertextlen);
  gpgme_free (ciphertext);

  return result;
}

/**
 * @brief Decrypt data encrypted to the standard key
 *
 * Decrypt the base64 encoded ciphersting.  On success store the size
 * of the plaintext at R_PLAINTEXTSIZE and return an allocated buffer
 * with the PLAINTEXT.  The caller must release the result.  Returns
 * NULL on error.
 *
 * @param ctx                 An initialized encryption context
 * @param[in] cipherstring    The base64 encoded input
 * @param[out] r_plaintextlen The address of variable to receive the length
 *                            in bytes of the decrypted plaintext.  On error
 *                            that value is not defined.
 *
 * @return An allocated buffer it the decrypten result (ie. the
 *         plaintext).  The caller must release this buffer. NULL is
 *         returned on error.
 */
static char *
do_decrypt (lsc_crypt_ctx_t ctx,
            const char *cipherstring,
            size_t *r_plaintextlen)
{
  gpg_error_t err;
  gpgme_data_t in, out;
  char *ciphertext;
  size_t ciphertextlen;
  char *result;

  /* Unfortunately GPGME does not yet support plain base64 encoding.  */
  ciphertext = (char *) g_base64_decode (cipherstring, &ciphertextlen);
  if (!ciphertext || !ciphertextlen)
    return NULL; /* Empty or bad encoding.  */

  err = gpgme_data_new_from_mem (&in, ciphertext, ciphertextlen, 0);
  if (err)
    {
      log_gpgme (G_LOG_LEVEL_WARNING,
                 err,
                 "%s: error creating data object from ciphertext",
                 G_STRFUNC);
      g_free (ciphertext);
      return NULL;
    }
  /* (We must release CIPHERTEXT only after IN.) */

  err = gpgme_data_new (&out);
  if (err)
    {
      log_gpgme (G_LOG_LEVEL_WARNING,
                 err,
                 "%s: error creating data object for plaintext",
                 G_STRFUNC);
      gpgme_data_release (in);
      g_free (ciphertext);
      return NULL;
    }

  err = gpgme_op_decrypt (ctx->encctx, in, out);
  gpgme_data_release (in);
  g_free (ciphertext);
  if (err)
    {
      gpgme_decrypt_result_t decres;
      gpgme_recipient_t recp;

      gpgme_data_release (out);
      log_gpgme (G_LOG_LEVEL_WARNING, err, "error decrypting credential");
      decres = gpgme_op_decrypt_result (ctx->encctx);
      if (decres->unsupported_algorithm)
        log_gpgme (G_LOG_LEVEL_INFO,
                   0,
                   "   unsupported algorithm (%s)",
                   decres->unsupported_algorithm);
      if (decres->wrong_key_usage)
        log_gpgme (G_LOG_LEVEL_INFO, 0, "   wrong key usage");
      for (recp = decres->recipients; recp; recp = recp->next)
        log_gpgme (G_LOG_LEVEL_INFO,
                   recp->status,
                   "   encrypted to keyid %s, algo=%d",
                   recp->keyid,
                   recp->pubkey_algo);
      return NULL;
    }
  result = gpgme_data_release_and_get_mem (out, r_plaintextlen);
  if (!result)
    {
      g_critical ("%s: error snatching memory", G_STRFUNC);
      exit (EXIT_FAILURE);
    }

  return result;
}

/* API */

/**
 * @brief Return a new context for LSC encryption
 *
 * @return A new context object to be released with \ref
 *         lsc_crypt_release.
 */
lsc_crypt_ctx_t
lsc_crypt_new ()
{
  char *path = g_build_filename (MAGENI_STATE_DIR, "gnupg", NULL);
  lsc_crypt_ctx_t ctx;

  ctx = g_malloc0 (sizeof *ctx);
  ctx->encctx = gvm_init_gpgme_ctx_from_dir (path);
  g_free (path);
  if (!ctx->encctx)
    {
      g_critical ("%s: can't continue w/o a gpgme context", G_STRFUNC);
      exit (EXIT_FAILURE);
    }

  return ctx;
}

/**
 * @brief Release an LSC encryption context
 *
 * @param[in]  ctx  The context or NULL
 */
void
lsc_crypt_release (lsc_crypt_ctx_t ctx)
{
  if (!ctx)
    return;
  lsc_crypt_flush (ctx);
  if (ctx->encctx) /* Check required for gpgme < 1.3.1 */
    gpgme_release (ctx->encctx);
  g_free (ctx);
}

/**
 * @brief Flush an LSC encryption context
 *
 * This function is used to flush the context.  The flushing
 * invalidates returned strings and internal caches.  Basically this
 * is the same as releasing and creating the context but it is
 * optimized to keep some internal state.
 *
 * @param[in]  ctx  The context or NULL
 */
void
lsc_crypt_flush (lsc_crypt_ctx_t ctx)
{
  if (!ctx)
    return;
  while (ctx->namelist)
    {
      struct namelist_s *nl = ctx->namelist->next;
      g_free (ctx->namelist->value);
      g_free (ctx->namelist);
      ctx->namelist = nl;
    }
  g_free (ctx->plaintext);
  ctx->plaintext = NULL;
}

/**
 * @brief Encrypt a list of name/value pairs
 *
 * @param[in] ctx        The context
 * @param[in] first_name The name of the first name/value pair.  This
 *                       must be followed by a string value and
 *                       optionally followed by more name and value
 *                       pairs.  This list is terminated by a single
 *                       NULL instead of a name.
 *
 * @return A pointer to a freshly allocated string in base64 encoding.
 *         Caller must free.  On error NULL is returned.
 */
char *
lsc_crypt_encrypt (lsc_crypt_ctx_t ctx, const char *first_name, ...)
{
  va_list arg_ptr;
  GString *stringbuf;
  char *plaintext;
  size_t plaintextlen;
  char *ciphertext;
  const char *name, *value;
  size_t len;

  if (!ctx || !first_name)
    return NULL;

  /* Assuming a 2048 bit RSA ssh private key in PEM encoding, a buffer
     with an initial size of 2k should be large enough.  */
  stringbuf = g_string_sized_new (2048);

  name = first_name;
  va_start (arg_ptr, first_name);
  do
    {
      value = va_arg (arg_ptr, const char *);
      if (!value)
        value = "";
      len = strlen (name);
      if (len) /* We skip pairs with an empty name. */
        {
          put32 (stringbuf, len);
          g_string_append (stringbuf, name);
          len = strlen (value);
          if (len > MAX_VALUE_LENGTH)
            {
              g_warning ("%s: value for '%s' larger than our limit (%d)",
                         G_STRFUNC,
                         name,
                         MAX_VALUE_LENGTH);
              g_string_free (stringbuf, TRUE);
              va_end (arg_ptr);
              return NULL;
            }
          put32 (stringbuf, len);
          g_string_append (stringbuf, value);
        }
    }
  while ((name = va_arg (arg_ptr, const char *)));
  va_end (arg_ptr);
  plaintext = stringbuf->str;
  plaintextlen = stringbuf->len;
  g_string_free (stringbuf, FALSE);
  g_assert (plaintextlen);

  ciphertext = do_encrypt (ctx, plaintext, plaintextlen);
  g_free (plaintext);

  return ciphertext;
}

/**
 * @brief Return an encrypted value in the clear.
 *
 * This function returns the encrypted value in the clear.  The
 * clear value may also be NULL , if no value is available.  If a
 * decryption has not yet been done, the passed \a ciphertext value is
 * first decrypted.  Thus a changed value of ciphertext may not have
 * an effect.  To force a decryption a call to \ref lsc_crypt_flush is
 * required.
 *
 * @param[in]  ctx  The context
 * @param[in]  ciphertext  The base64 encoded ciphertext.
 * @param[in]  name  Name of the value to get.
 *
 * @return A const pointer to a string object.  This pointer is valid
 *         as long as the context is valid and \ref lsc_crypt_flush
 *         has not been called.  If no value is available NULL is
 *         returned.
 */
const char *
lsc_crypt_decrypt (lsc_crypt_ctx_t ctx,
                   const char *ciphertext,
                   const char *name)
{
  size_t namelen;
  const char *p;
  size_t len;
  uint32_t n;
  int found;
  struct namelist_s *nl;

  if (!ctx || !name || !*name)
    return NULL;
  if (disable_encrypted_credentials)
    {
      static gboolean shown;
      if (!shown)
        {
          shown = 1;
          g_warning ("note that decryption of credentials has been disabled");
        }
      return NULL;
    }

  if (!ctx->plaintext)
    {
      if (!ciphertext)
        return NULL;
      ctx->plaintext = do_decrypt (ctx, ciphertext, &ctx->plaintextlen);
      if (!ctx->plaintext)
        return NULL;
    }

  /* Try to return it from the cache.  */
  for (nl = ctx->namelist; nl; nl = nl->next)
    if (!strcmp (nl->name, name))
      {
        return (nl->value
                  ? nl->value
                  : (nl->valoff ? (ctx->plaintext + nl->valoff) : NULL));
      }

  /* Cache miss: Parse the data, cache the result, and return it.  */
  /* Fixme: Cache a not found status.  */
  namelen = strlen (name);
  p = ctx->plaintext;
  len = ctx->plaintextlen;
  found = 0;
  while (len)
    {
      if (len < 4)
        goto failed;
      n = get32 (p);
      p += 4;
      len -= 4;
      if (n > len)
        goto failed;
      if (n == namelen && !memcmp (p, name, namelen))
        found = 1;
      p += n;
      len -= n;
      if (len < 4)
        goto failed;
      n = get32 (p);
      p += 4;
      len -= 4;
      if (n > len)
        goto failed;
      if (found)
        {
          if (n > MAX_VALUE_LENGTH)
            {
              g_warning ("%s: value for '%s' larger than our limit (%d)",
                         G_STRFUNC,
                         name,
                         MAX_VALUE_LENGTH);
              return NULL;
            }
          nl = g_malloc (sizeof *nl + namelen);
#if 0
          strcpy (nl->name, name);
#else
          /* The pointer arithmetic helps Clang see that nl is allocated
           * bigger than the size of *nl. */
          strcpy (((char *) nl) + (nl->name - (char *) nl), name);
#endif

          if (n + 1 < len && p[n] == 0)
            {
              /* The values is followed by another name and the first
                 byte of that name's length is 0.  Thus we don't need
                 to take a copy because that length byte acts as the
                 string terminator.  */
              nl->valoff = (p - ctx->plaintext);
              nl->value = NULL;
            }
          else
            {
              /* We need to take a copy of the value, so that we can
                 add the string terminator.  */
              nl->valoff = 0;
              nl->value = g_malloc (n + 1);
              memcpy (nl->value, p, n);
              nl->value[n] = 0;
            }
          nl->next = ctx->namelist;
          ctx->namelist = nl;
          return nl->value ? nl->value : (ctx->plaintext + nl->valoff);
        }
      p += n;
      len -= n;
    }
  if (!len)
    goto not_found;

failed:
  g_warning ("%s: decrypted credential data block is inconsistent;"
             " %zu bytes remaining at offset %zu",
             G_STRFUNC,
             len,
             (size_t) (p - ctx->plaintext));
not_found:
  /* Cache a NULL value.  */
  nl = g_malloc (sizeof *nl + namelen);
#if 0
  strcpy (nl->name, name);
#else
  /* The pointer arithmetic helps Clang see that nl is allocated
   * bigger than the size of *nl. */
  strcpy (((char *) nl) + (nl->name - (char *) nl), name);
#endif
  nl->valoff = 0;
  nl->value = NULL;
  nl->next = ctx->namelist;
  ctx->namelist = nl;
  return NULL;
}

/**
 * @brief Return an encrypted password in the clear.
 *
 * This function returns the encrypted password in the clear.  The
 * clear value may also be NULL , if no password is available.  If a
 * decryption has not yet been done, the passed \a ciphertext value is
 * first decrypted.  Thus a changed value of ciphertext may not have
 * an effect.  To force a decryption a call to \ref lsc_crypt_flush is
 * required.
 *
 * @param[in]  ctx  The context
 * @param[in]  ciphertext  The base64 encoded ciphertext.
 *
 * @return A const pointer to a string object.  This pointer is valid
 *         as long as the context is valid and \ref lsc_crypt_flush
 *         has not been called.  If no password is available NULL is
 *         returned.
 */
const char *
lsc_crypt_get_password (lsc_crypt_ctx_t ctx, const char *ciphertext)
{
  return lsc_crypt_decrypt (ctx, ciphertext, "password");
}

/**
 * @brief Return an encrypted private key in the clear.
 *
 * This function returns the encrypted private key in the clear.  The
 * clear value may also be NULL , if no private key is available.  If a
 * decryption has not yet been done, the passed \a ciphertext value is
 * first decrypted.  Thus a changed value of ciphertext may not have
 * an effect.  To force a decryption a call to \ref lsc_crypt_flush is
 * required.
 *
 * @param[in]  ctx  The context
 * @param[in]  ciphertext  The base64 encoded ciphertext.
 *
 * @return A const pointer to a string object.  This pointer is valid
 *         as long as the context is valid and \ref lsc_crypt_flush
 *         has not been called.  If no private key is available NULL is
 *         returned.
 */
const char *
lsc_crypt_get_private_key (lsc_crypt_ctx_t ctx, const char *ciphertext)
{
  return lsc_crypt_decrypt (ctx, ciphertext, "private_key");
}
