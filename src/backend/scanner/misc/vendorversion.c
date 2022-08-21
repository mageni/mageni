/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: 2009-2019 Greenbone Networks GmbH
 * SPDX-FileComment: Functions to set and get the vendor version.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#include "vendorversion.h"

#include <glib.h>

/**
 * @brief Vendor version, or NULL.
 */
gchar *vendor_version = NULL;

/**
 * @brief Set vendor version
 *
 * @param[in]  version  Vendor version.
 */
void
vendor_version_set (const gchar *version)
{
  g_free (vendor_version);
  vendor_version = g_strdup (version);
}

/**
 * @brief Get vendor version.
 *
 * @return Set vendor version or empty string.
 */
const gchar *
vendor_version_get ()
{
  return vendor_version ? vendor_version : "";
}
