/**
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileCopyrightText: Portions Copyright (C) 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
 * SPDX-FileComment: Header of file that creates new threads.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef MAGENI_THREADS_H
#define MAGENI_THREADS_H

#include <sys/types.h>

typedef void (*process_func_t) (void *);
pid_t
create_process (process_func_t, void *);
int terminate_process (pid_t);

#endif
