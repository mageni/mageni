// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * proctitle.h
 *
 * Implementation of an API to set process title.
 *  
 * Copyright:
 * Copyright (C) 2014-2019 Greenbone Networks GmbH
 * Copyright (C) 2022 Mageni Security LLC
 * 
 */

#ifndef MAGENI_PROCTITLE_H
#define MAGENI_PROCTITLE_H

void proctitle_init (int, char **);

void proctitle_set (const char *, ...);

#endif /* not MAGENI_PROCTITLE_H */
