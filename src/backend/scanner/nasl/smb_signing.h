/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright (C) Jeremy Allison 2003.
 * SPDX-FileCopyrightText: Copyright (C) Andrew Bartlett <abartlet@samba.org> 2002-2003
 * SPDX-FileComment: This file will be deleted as SMBClient/RPCClient will take this function.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

/*
   Modified by Preeti Subramanian <spreeti@secpod.com> for OpenVAS:
      simple packet signature function argument struct smb_basic_signing_context
      *data to uint8_t* mac_key and henceforth used mac_key in the
   implementation
*/

#ifndef _SMB_SIGNING_H
#define _SMB_SIGNING_H

#include "byteorder.h"
#include "md5.h"
#include "smb.h"

#ifndef uchar
#define uchar unsigned char
#endif

#ifndef uint8
#define uint8 uint8_t
#endif

void
simple_packet_signature_ntlmssp (uint8_t *mac_key, const uchar *buf,
                                 uint32 seq_number,
                                 unsigned char *calc_md5_mac);

#endif
