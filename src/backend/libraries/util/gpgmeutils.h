/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2013-2019 Greenbone Networks GmbH
 * SPDX-FileComment: GPGME Utils
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef MAGENI_GPGMEUTILS_H
#define MAGENI_GPGMEUTILS_H

#include <glib.h>  /* for gchar */
#include <gpgme.h> /* for gpgme_ctx_t */

void log_gpgme (GLogLevelFlags, gpg_error_t, const char *, ...);

gpgme_ctx_t gvm_init_gpgme_ctx_from_dir (const gchar *);

int mgn_gpg_import_from_string (gpgme_ctx_t, const char *, ssize_t,
                            gpgme_data_type_t);

int mgn_pgp_pubkey_encrypt_stream (FILE *, FILE *, const char *, const char *,
                               ssize_t);

int mgn_smime_encrypt_stream (FILE *, FILE *, const char *, const char *, ssize_t);

#endif /*MAGENI_GPGMEUTILS_H*/
