/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileComment: This file will be deleted as SMBClient/RPCClient will take this function.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef _NASL_OPENVAS_SMB_INTERFACE_H
#define _NASL_OPENVAS_SMB_INTERFACE_H

typedef long int SMB_HANDLE;

char *
smb_versioninfo (void);
int
smb_connect (const char *, const char *, const char *, const char *,
             SMB_HANDLE *);
int smb_close (SMB_HANDLE);
char *
smb_file_SDDL (SMB_HANDLE, const char *);
char *
smb_file_OwnerSID (SMB_HANDLE, const char *);
char *
smb_file_GroupSID (SMB_HANDLE, const char *);
char *
smb_file_TrusteeRights (SMB_HANDLE, const char *);
int
wincmd (int argc, char *argv[], char **res);

#endif
