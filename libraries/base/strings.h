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
 * @brief String utilities.
 */

#ifndef _GVM_STRINGS_H
#define _GVM_STRINGS_H

#include <glib.h>

void
gvm_append_string (gchar **, const gchar *);
void
gvm_append_text (gchar **, const gchar *, gsize);
void
gvm_free_string_var (gchar **);

char *
gvm_strip_space (char *, char *);

#endif /* not _GVM_STRINGS_H */
