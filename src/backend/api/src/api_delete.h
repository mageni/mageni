/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2018 Greenbone Networks GmbH
 * SPDX-FileComment: Base facilities.
 * SPDX-FileContributor: Matthew Mundell <matthew.mundell@greenbone.net>
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef _GVMD_GMP_DELETE_H
#define _GVMD_GMP_DELETE_H

#include "api_base.h"

#include <glib.h>

void
delete_start (const gchar *, const gchar *, const gchar **, const gchar **);

void
delete_run (gmp_parser_t *, GError **);

#endif /* not _GVMD_GMP_DELETE_H */
