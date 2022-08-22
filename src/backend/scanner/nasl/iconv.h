/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright (C) Andrew Tridgell 2004
 * SPDX-FileComment: Unix SMB/CIFS implementation. minimal iconv implementation
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef _system_iconv_h
#define _system_iconv_h

#if !defined(HAVE_ICONV) && defined(HAVE_ICONV_H)
#define HAVE_ICONV
#endif

#if !defined(HAVE_GICONV) && defined(HAVE_GICONV_H)
#define HAVE_GICONV
#endif

#if !defined(HAVE_BICONV) && defined(HAVE_BICONV_H)
#define HAVE_BICONV
#endif

#ifdef HAVE_NATIVE_ICONV
#if defined(HAVE_ICONV)
#include <iconv.h>
#elif defined(HAVE_GICONV)
#include <giconv.h>
#elif defined(HAVE_BICONV)
#include <biconv.h>
#endif
#endif /* HAVE_NATIVE_ICONV */

/* needed for some systems without iconv. Doesn't really matter
   what error code we use */
#ifndef EILSEQ
#define EILSEQ EIO
#endif

#endif
