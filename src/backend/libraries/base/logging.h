// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Name: logging.h
 * Brief: Implementation of logging methods.
 *  
 * Copyright:
 * Copyright (C) 2017-2019 Greenbone Networks GmbH
 * Copyright (C) 2022 Mageni Security LLC
 * 
 */

#ifndef _GVM_LOGGING_H
#define _GVM_LOGGING_H

#include <glib.h> /* for GSList, gchar, GLogLevelFlags, gpointer */

GSList *
load_log_configuration (gchar *);

void
free_log_configuration (GSList *);

gchar *
get_time (gchar *);

void
gvm_log_silent (const char *, GLogLevelFlags, const char *, gpointer);
void
gvm_log_func (const char *, GLogLevelFlags, const char *, gpointer);

void
log_func_for_gnutls (int, const char *);

void
setup_log_handlers (GSList *);

#endif /* not _GVM_LOGGING_H */
