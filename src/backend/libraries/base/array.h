/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2009-2019 Greenbone Networks GmbH
 * SPDX-FileComment: Array utilities
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef _GVM_ARRAY_H
#define _GVM_ARRAY_H

#include <glib.h>

typedef GPtrArray array_t;

GPtrArray *
make_array ();

void array_reset (array_t **array);

void array_free (GPtrArray *array);

void array_add (array_t *array, gpointer pointer);

void array_terminate (array_t *array);

#endif /* not _GVM_ARRAY_H */
