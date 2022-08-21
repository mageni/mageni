/**
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileCopyrightText: Portions Copyright (C) 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef MAGENI_SIGHAND_H
#define MAGENI_SIGHAND_H

void (*openvas_signal (int signum, void (*handler) (int))) (int);
void
sighand_chld ();
void
sighand_segv ();

void
let_em_die (int pid);
void
make_em_die (int sig);
#endif
