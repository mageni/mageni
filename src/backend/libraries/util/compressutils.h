// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Name: compressutils.h
 * Brief: Functions related to data compression (gzip format.)
 *  
 * Copyright:
 * Copyright (C) 2013-2019 Greenbone Networks GmbH
 * Copyright (C) 2022, Mageni Security LLC
 * 
 */

#ifndef _GVM_COMPRESSUTILS_H
#define _GVM_COMPRESSUTILS_H

void *
gvm_compress (const void *, unsigned long, unsigned long *);

void *
gvm_compress_gzipheader (const void *, unsigned long, unsigned long *);

void *
gvm_uncompress (const void *, unsigned long, unsigned long *);

#endif /* not _GVM_COMPRESSUTILS_H */
