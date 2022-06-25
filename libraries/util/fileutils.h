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
 * @brief Protos for file utility functions.
 *
 * This file contains the protos for \ref fileutils.c
 */

#ifndef _GVM_FILEUTILS_H
#define _GVM_FILEUTILS_H

#include <glib.h>

int
gvm_file_check_is_dir (const char *name);

int
gvm_file_remove_recurse (const gchar *pathname);

gboolean
gvm_file_copy (const gchar *, const gchar *);

gboolean
gvm_file_move (const gchar *, const gchar *);

char *
gvm_file_as_base64 (const char *);

gchar *
gvm_export_file_name (const char *, const char *, const char *, const char *,
                      const char *, const char *, const char *, const char *);

#endif /* not _GVM_FILEUTILS_H */
