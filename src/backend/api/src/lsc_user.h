// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Name: lsc_user.h
 * Brief: Utilities for LSC credential package generation. 
 * This file provides support for generating packages for LSC credentials.
 * 
 * Copyright:
 * Copyright (C) 2009-2018 Greenbone Networks GmbH
 * Copyright (C) 2022, Mageni Security LLC
 *
 */

#ifndef _GVMD_LSC_USER_H
#define _GVMD_LSC_USER_H

#include <glib.h>

int
lsc_user_keys_create (const gchar *, gchar **);

int
lsc_user_rpm_recreate (const gchar *, const gchar *, void **, gsize *);

int
lsc_user_deb_recreate (const gchar *,
                       const char *,
                       const char *,
                       void **,
                       gsize *);

int
lsc_user_exe_recreate (const gchar *, const gchar *, void **, gsize *);

#endif /* not _GVMD_LSC_USER_H */
