/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright (C) Andrew Tridgell 2001
 * SPDX-FileCopyrightText: Copyright (C) Jelmer Vernooij 2002
 * SPDX-FileComment: Unix SMB/CIFS implementation: Character set conversion Extensions
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef __CHARSET_H__
#define __CHARSET_H__

#include "smb.h"

#include <string.h>

/* this defines the charset types used in samba */
typedef enum
{
  CH_UTF16LE = 0,
  CH_UTF16 = 0,
  CH_UNIX = 1,
  CH_DISPLAY = 2,
  CH_DOS = 3,
  CH_UTF8 = 4,
  CH_UTF16BE = 5
} charset_t;

#define NUM_CHARSETS 6
/*
 *   for each charset we have a function that pushes from that charset to a ucs2
 *   buffer, and a function that pulls from ucs2 buffer to that  charset.
 */

struct charset_functions_ntlmssp
{
  const char *name;
  size_t (*pull) (void *, const char **inbuf, size_t *inbytesleft,
                  char **outbuf, size_t *outbytesleft);
  size_t (*push) (void *, const char **inbuf, size_t *inbytesleft,
                  char **outbuf, size_t *outbytesleft);
  struct charset_functions_ntlmssp *prev, *next;
};
#endif
