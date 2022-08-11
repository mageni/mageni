/* Copyright (C) 2016-2018 Greenbone Networks GmbH
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
 * @file iterator.h
 * @brief Headers for Iterators.
 *
 * The interface here is for "external" use.  The SQL parts of the interface
 * are in sql.h.  Both are defined in sql.c.
 */

#ifndef _GVMD_ITERATOR_H
#define _GVMD_ITERATOR_H

#include "lsc_crypt.h"

#include <glib.h>

/* Types. */

/**
 * @brief A resource, like a task or target.
 */
typedef long long int resource_t;

/**
 * @brief A prepared SQL statement.
 */
typedef struct sql_stmt sql_stmt_t;

/**
 * @brief A generic SQL iterator structure.
 */
struct iterator
{
  sql_stmt_t *stmt;          ///< SQL statement.
  gboolean done;             ///< End flag.
  int prepared;              ///< Prepared flag.
  lsc_crypt_ctx_t crypt_ctx; ///< Encryption context.
};

/**
 * @brief A generic SQL iterator type.
 */
typedef struct iterator iterator_t;

/* Functions. */

void
cleanup_iterator (iterator_t *);

gboolean
next (iterator_t *);

#endif /* not _GVMD_ITERATOR_H */
