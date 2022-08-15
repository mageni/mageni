// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Name: pidfile.h
 * Brief: PID-file management.
 *  
 * Copyright:
 * Copyright (C) 2009-2019 Greenbone Networks GmbH
 * Copyright (C) 2022 Mageni Security LLC
 * 
 */

#ifndef _GVM_PIDFILE_H
#define _GVM_PIDFILE_H

#include <glib.h>

int
pidfile_create (gchar *);
void
pidfile_remove (gchar *);

#endif /* not _GVM_PIDFILE_H */
