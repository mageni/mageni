/* GVM
 * $Id$
 * Description: GVM GMP layer: Common DELETE command headers.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2018 Greenbone Networks GmbH
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

#ifndef _GVMD_GMP_DELETE_H
#define _GVMD_GMP_DELETE_H

#include "gmp_base.h"

#include <glib.h>

void
delete_start (const gchar *, const gchar *, const gchar **, const gchar **);

void
delete_run (gmp_parser_t *, GError **);

#endif /* not _GVMD_GMP_DELETE_H */
