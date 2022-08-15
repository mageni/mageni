// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * strings.c
 *
 * String utilities.
 *  
 * Copyright:
 * Copyright (C) 2009-2019 Greenbone Networks GmbH
 * Copyright (C) 2022 Mageni Security LLC
 * 
 */

#ifndef MAGENI_STRINGS_H
#define MAGENI_STRINGS_H

#include <glib.h>

void mgn_append_string (gchar **, const gchar *);

void mgn_append_text (gchar **, const gchar *, gsize);

void mgn_free_string_var (gchar **);

char * mgn_strip_space (char *, char *);

#endif /* not MAGENI_STRINGS_H */