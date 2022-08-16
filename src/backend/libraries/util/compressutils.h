/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2013-2019 Greenbone Networks GmbH
 * SPDX-FileComment: Functions related to data compression (gzip format.)
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef MAGENI_COMPRESSUTILS_H
#define MAGENI_COMPRESSUTILS_H

void * mgn_compress (const void *, unsigned long, unsigned long *);

void * mgn_compress_gzipheader (const void *, unsigned long, unsigned long *);

void * mgn_uncompress (const void *, unsigned long, unsigned long *);

#endif /* not MAGENI_COMPRESSUTILS_H */
