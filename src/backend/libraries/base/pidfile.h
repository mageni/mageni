/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2009-2019 Greenbone Networks GmbH
 * SPDX-FileComment: PID-file management.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */


#ifndef MAGENI_PIDFILE_H
#define MAGENI_PIDFILE_H

#include <glib.h>

int pidfile_create (gchar *);

void pidfile_remove (gchar *);

#endif /* not MAGENI_PIDFILE_H */
