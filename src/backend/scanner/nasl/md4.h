/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright (C) Andrew Tridgell 1997-1998
 * SPDX-FileComment: Unix SMB/CIFS implementation. A implementation of MD4 designed for use in the SMB authentication protocol
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

void
mdfour_ntlmssp (unsigned char *out, const unsigned char *in, int n);
