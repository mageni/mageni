/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2014-2019 Greenbone Networks GmbH
 * SPDX-FileComment: Implementation of API to handle globally stored preferences.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */


#ifndef MAGENI_PREFS_H
#define MAGENI_PREFS_H

#include <glib.h>

void prefs_config (const char *);

const gchar * prefs_get (const gchar *key);

int prefs_get_bool (const gchar *key);

void prefs_set (const gchar *, const gchar *);

void prefs_dump (void);

int prefs_nvt_timeout (const char *);

GHashTable * preferences_get (void);

#endif /* not MAGENI_PREFS_H */
