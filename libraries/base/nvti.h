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
 * @brief Protos and data structures for NVT Information data sets.
 *
 * This file contains the protos for \ref nvti.c
 */

#ifndef _NVTI_H
#define _NVTI_H

#include <glib.h>

/**
 * @brief The structure for a preference of a NVT.
 *
 * The elements of this structure should never be accessed directly.
 * Only the functions corresponding to this module should be used.
 */
typedef struct nvtpref
{
  gchar *type; ///< Preference type
  gchar *name; ///< Name of the preference
  gchar *dflt; ///< Default value of the preference
} nvtpref_t;

nvtpref_t *
nvtpref_new (gchar *, gchar *, gchar *);
void
nvtpref_free (nvtpref_t *);
gchar *
nvtpref_name (const nvtpref_t *);
gchar *
nvtpref_type (const nvtpref_t *);
gchar *
nvtpref_default (const nvtpref_t *);

/**
 * @brief The structure of a information record that corresponds to a NVT.
 *
 * The elements of this structure should never be accessed directly.
 * Only the functions corresponding to this module should be used.
 */
typedef struct nvti
{
  gchar *oid;  /**< @brief Object ID */
  gchar *name; /**< @brief The name */

  gchar *cve;       /**< @brief List of CVEs, this NVT corresponds to */
  gchar *bid;       /**< @brief List of Bugtraq IDs, this NVT
                                corresponds to */
  gchar *xref;      /**< @brief List of Cross-references, this NVT
                                corresponds to */
  gchar *tag;       /**< @brief List of tags attached to this NVT */
  gchar *cvss_base; /**< @brief CVSS base score for this NVT. */

  gchar *dependencies;   /**< @brief List of dependencies of this NVT */
  gchar *required_keys;  /**< @brief List of required KB keys of this NVT */
  gchar *mandatory_keys; /**< @brief List of mandatory KB keys of this NVT */
  gchar *excluded_keys;  /**< @brief List of excluded KB keys of this NVT */
  gchar *required_ports; /**< @brief List of required ports of this NVT */
  gchar
    *required_udp_ports; /**< @brief List of required UDP ports of this NVT*/

  GSList *prefs; /**< @brief Collection of NVT preferences */

  // The following are not settled yet.
  gint timeout;  /**< @brief Default timeout time for this NVT */
  gint category; /**< @brief The category, this NVT belongs to */
  gchar *family; /**< @brief Family the NVT belongs to */
} nvti_t;

nvti_t *
nvti_new (void);
void
nvti_free (nvti_t *);

gchar *
nvti_oid (const nvti_t *);
gchar *
nvti_name (const nvti_t *);
gchar *
nvti_cve (const nvti_t *);
gchar *
nvti_bid (const nvti_t *);
gchar *
nvti_xref (const nvti_t *);
gchar *
nvti_tag (const nvti_t *);
gchar *
nvti_cvss_base (const nvti_t *);
gchar *
nvti_dependencies (const nvti_t *);
gchar *
nvti_required_keys (const nvti_t *);
gchar *
nvti_mandatory_keys (const nvti_t *);
gchar *
nvti_excluded_keys (const nvti_t *);
gchar *
nvti_required_ports (const nvti_t *);
gchar *
nvti_required_udp_ports (const nvti_t *);
gint
nvti_timeout (const nvti_t *);
gint
nvti_category (const nvti_t *);
gchar *
nvti_family (const nvti_t *);
guint
nvti_pref_len (const nvti_t *);
const nvtpref_t *
nvti_pref (const nvti_t *, guint);

int
nvti_set_oid (nvti_t *, const gchar *);
int
nvti_set_name (nvti_t *, const gchar *);
int
nvti_set_cve (nvti_t *, const gchar *);
int
nvti_set_bid (nvti_t *, const gchar *);
int
nvti_set_xref (nvti_t *, const gchar *);
int
nvti_set_tag (nvti_t *, const gchar *);
int
nvti_set_cvss_base (nvti_t *, const gchar *);
int
nvti_set_dependencies (nvti_t *, const gchar *);
int
nvti_set_required_keys (nvti_t *, const gchar *);
int
nvti_set_mandatory_keys (nvti_t *, const gchar *);
int
nvti_set_excluded_keys (nvti_t *, const gchar *);
int
nvti_set_required_ports (nvti_t *, const gchar *);
int
nvti_set_required_udp_ports (nvti_t *, const gchar *);
int
nvti_set_timeout (nvti_t *, const gint);
int
nvti_set_category (nvti_t *, const gint);
int
nvti_set_family (nvti_t *, const gchar *);

int
nvti_add_cve (nvti_t *, const gchar *);
int
nvti_add_bid (nvti_t *, const gchar *);
int
nvti_add_required_keys (nvti_t *, const gchar *);
int
nvti_add_mandatory_keys (nvti_t *, const gchar *);
int
nvti_add_excluded_keys (nvti_t *, const gchar *);
int
nvti_add_required_ports (nvti_t *, const gchar *);
int
nvti_add_required_udp_ports (nvti_t *, const gchar *);
int
nvti_add_pref (nvti_t *, nvtpref_t *);

/* Collections of NVT Infos. */

/**
 * @brief A collection of information records corresponding to NVTs.
 */
typedef GHashTable nvtis_t;

nvtis_t *
nvtis_new (void);

void
nvtis_free (nvtis_t *);

void
nvtis_add (nvtis_t *, nvti_t *);

nvti_t *
nvtis_lookup (nvtis_t *, const char *);

#endif /* not _NVTI_H */
