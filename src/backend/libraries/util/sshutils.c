/* Copyright (C) 2015-2019 Greenbone Networks GmbH
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
 * @brief Implementation of SSH related API.
 */

#include "sshutils.h"

#include <glib.h>          /* for g_free, g_strdup, g_strdup_printf */
#include <gnutls/gnutls.h> /* for gnutls_datum_t */
#include <gnutls/x509.h> /* for gnutls_x509_privkey_deinit, gnutls_x509_p... */
#include <libssh/libssh.h> /* for ssh_key_free, ssh_key_type, ssh_key_type_... */
#include <string.h>        /* for strcmp, strlen */

/**
 * @brief Decrypts a base64 encrypted ssh private key.
 *
 * @param[in]   pkcs8_key       PKCS#8 encrypted private key.
 * @param[in]   passphrase      Passphrase for the private key.
 *
 * @return Decrypted private key if success, NULL otherwise.
 */
char *
gvm_ssh_pkcs8_decrypt (const char *pkcs8_key, const char *passphrase)
{
  gnutls_datum_t data;
  gnutls_x509_privkey_t key;
  char buffer[16 * 2048];
  int rc;
  size_t size = sizeof (buffer);

  rc = gnutls_x509_privkey_init (&key);
  if (rc)
    return NULL;
  data.size = strlen (pkcs8_key);
  data.data = (void *) g_strdup (pkcs8_key);
  rc = gnutls_x509_privkey_import_pkcs8 (key, &data, GNUTLS_X509_FMT_PEM,
                                         passphrase ? passphrase : "", 0);
  if (rc)
    {
      gnutls_x509_privkey_deinit (key);
      return NULL;
    }
  g_free (data.data);
  rc = gnutls_x509_privkey_export (key, GNUTLS_X509_FMT_PEM, buffer, &size);
  gnutls_x509_privkey_deinit (key);
  if (rc)
    return NULL;
  return g_strdup (buffer);
}

/**
 * @brief Exports a base64 encoded public key from a private key and its
 *        passphrase.
 *
 * @param[in]   private_key     Private key to export.
 * @param[in]   passphrase      Passphrase for the private key.
 *
 * @return Allocated base64 encoded public key if success, NULL otherwise.
 */
char *
gvm_ssh_public_from_private (const char *private_key, const char *passphrase)
{
  ssh_key priv;
  char *pub_key, *decrypted_priv, *pub_str = NULL;
  const char *type;
  int ret;

  decrypted_priv = gvm_ssh_pkcs8_decrypt (private_key, passphrase);
  ret = ssh_pki_import_privkey_base64 (decrypted_priv ? decrypted_priv
                                                      : private_key,
                                       passphrase, NULL, NULL, &priv);
  g_free (decrypted_priv);
  if (ret)
    return NULL;
  ret = ssh_pki_export_pubkey_base64 (priv, &pub_key);
  type = ssh_key_type_to_char (ssh_key_type (priv));
#if LIBSSH_VERSION_INT >= SSH_VERSION_INT(0, 6, 4)
  if (!strcmp (type, "ssh-ecdsa"))
    type = ssh_pki_key_ecdsa_name (priv);
#endif
  ssh_key_free (priv);
  if (ret)
    return NULL;
  pub_str = g_strdup_printf ("%s %s", type, pub_key);
  g_free (pub_key);
  return pub_str;
}
