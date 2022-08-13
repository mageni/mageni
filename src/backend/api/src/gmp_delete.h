// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Name: gmp_delete.c
 * Brief: Headers used internally.
 * 
 * Common DELETE command code for the GVM GMP layer.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 * 
 * Copyright:
 * Copyright (C) 2018 Greenbone Networks GmbH
 * Copyright (C) 2022, Mageni Security LLC
 * 
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
