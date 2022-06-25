/* Copyright (C) 2010-2019 Greenbone Networks GmbH
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
 * @brief Privilege dropping header file.
 */

#ifndef _GVM_DROP_PRIVILEGES_H
#define _GVM_DROP_PRIVILEGES_H

#include <glib.h>

/**
 * @brief The GQuark for privilege dropping errors.
 */
#define GVM_DROP_PRIVILEGES \
  g_quark_from_static_string ("gvm-drop-privileges-error-quark")

/**
 * @brief Definition of the return code ERROR_ALREADY_SET.
 */
#define GVM_DROP_PRIVILEGES_ERROR_ALREADY_SET -1

/**
 * @brief Definition of the return code OK.
 */
#define GVM_DROP_PRIVILEGES_OK 0

/**
 * @brief Definition of the return code FAIL_NOT_ROOT.
 */
#define GVM_DROP_PRIVILEGES_FAIL_NOT_ROOT 1

/**
 * @brief Definition of the return code FAIL_UNKNOWN_USER.
 */
#define GVM_DROP_PRIVILEGES_FAIL_UNKNOWN_USER 2

/**
 * @brief Definition of the return code FAIL_DROP_GID.
 */
#define GVM_DROP_PRIVILEGES_FAIL_DROP_GID 3

/**
 * @brief Definition of the return code FAIL_DROP_UID.
 */
#define GVM_DROP_PRIVILEGES_FAIL_DROP_UID 4

/**
 * @brief Definition of the return code FAIL_SUPPLEMENTARY.
 */
#define GVM_DROP_PRIVILEGES_FAIL_SUPPLEMENTARY 5

int
drop_privileges (gchar *username, GError **error);

#endif
