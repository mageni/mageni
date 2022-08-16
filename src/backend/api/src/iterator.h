/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2016-2018 Greenbone Networks GmbH
 * SPDX-FileComment: Headers for Iterators. 
 * SPDX-FileContributor: Mageni Security LLC
 * 
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
