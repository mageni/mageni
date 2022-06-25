/* Copyright (C) 2014-2019 Greenbone Networks GmbH
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
 * @brief API for Open Scanner Protocol communication.
 */

#ifndef _GVM_OSP_H
#define _GVM_OSP_H

#include <glib.h> /* for GHashTable, GSList */

typedef struct osp_connection osp_connection_t;

/**
 * @brief OSP parameter types.
 */
typedef enum
{
  OSP_PARAM_TYPE_INT = 0,      /**< Integer type. */
  OSP_PARAM_TYPE_STR,          /**< String type. */
  OSP_PARAM_TYPE_PASSWORD,     /**< Password type. */
  OSP_PARAM_TYPE_FILE,         /**< File type. */
  OSP_PARAM_TYPE_BOOLEAN,      /**< Boolean type. */
  OSP_PARAM_TYPE_OVALDEF_FILE, /**< Oval definition type. */
  OSP_PARAM_TYPE_SELECTION,    /**< Selection type. */
  OSP_PARAM_TYPE_CRD_UP,       /**< Credential user/pass type. */
} osp_param_type_t;

typedef struct osp_param osp_param_t;

osp_connection_t *
osp_connection_new (const char *, int, const char *, const char *,
                    const char *);

int
osp_get_version (osp_connection_t *, char **, char **, char **, char **,
                 char **, char **);

int
osp_start_scan (osp_connection_t *, const char *, const char *, GHashTable *,
                const char *, char **);

int
osp_get_scan (osp_connection_t *, const char *, char **, int, char **);

int
osp_delete_scan (osp_connection_t *, const char *);

int
osp_stop_scan (osp_connection_t *, const char *, char **);

int
osp_get_scanner_details (osp_connection_t *, char **, GSList **);

osp_param_t *
osp_param_new (void);

const char *
osp_param_id (const osp_param_t *);

const char *
osp_param_name (const osp_param_t *);

const char *
osp_param_desc (const osp_param_t *);

const char *
osp_param_default (const osp_param_t *);

const char *
osp_param_type_str (const osp_param_t *);

int
osp_param_mandatory (const osp_param_t *);

void
osp_param_free (osp_param_t *);

void
osp_connection_close (osp_connection_t *);

#endif
