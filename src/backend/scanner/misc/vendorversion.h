/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: 2009-2019 Greenbone Networks GmbH
 * SPDX-FileComment: Functions to set and get the vendor version.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef _OPENVAS_VENDORVERSION_H
#define _OPENVAS_VENDORVERSION_H

#include <glib.h>

const gchar *
vendor_version_get (void);

void
vendor_version_set (const gchar *);

#endif /* not _OPENVAS_VENDORVERSION_H */
