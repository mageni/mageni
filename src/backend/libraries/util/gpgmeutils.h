/* Copyright (C) 2013-2019 Greenbone Networks GmbH
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
 * @brief Protos and data structures for GPGME utilities.
 *
 * This file contains the protos for \ref gpgmeutils.c
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
