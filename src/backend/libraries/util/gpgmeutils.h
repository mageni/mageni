// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Name: gpgmeutils.h
 * Brief: GPGME Utils
 *  
 * Copyright:
 * Copyright (C) 2013-2019 Greenbone Networks GmbH
 * Copyright (C) 2022, Mageni Security LLC
 * 
 */

#ifndef _GVM_GPGMEUTILS_H
#define _GVM_GPGMEUTILS_H

#include <glib.h>  /* for gchar */
#include <gpgme.h> /* for gpgme_ctx_t */

void
log_gpgme (GLogLevelFlags, gpg_error_t, const char *, ...);

gpgme_ctx_t
gvm_init_gpgme_ctx_from_dir (const gchar *);

int
gvm_gpg_import_from_string (gpgme_ctx_t, const char *, ssize_t,
                            gpgme_data_type_t);

int
gvm_pgp_pubkey_encrypt_stream (FILE *, FILE *, const char *, const char *,
                               ssize_t);

int
gvm_smime_encrypt_stream (FILE *, FILE *, const char *, const char *, ssize_t);

#endif /*_GVM_GPGMEUTILS_H*/
