/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2014-2019 Greenbone Networks GmbH
 * SPDX-FileComment: Implementation of an API to set process title.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef MAGENI_PROCTITLE_H
#define MAGENI_PROCTITLE_H

void proctitle_init (int, char **);

void proctitle_set (const char *, ...);

#endif /* not MAGENI_PROCTITLE_H */
