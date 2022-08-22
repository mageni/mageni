/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileComment: This file will be deleted as SMBClient/RPCClient will take this function.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

/* for NULL */
#include "openvas_smb_interface.h"

#include <string.h>

/**
 * @brief Return version info for SMB implementation.
 *
 * @return NULL if this the implementation is a non-functional stub,
 *         else a arbitrary string that explains the version of the
 *         implementation.
 */
char *
smb_versioninfo ()
{
  return NULL;
}

/**
 * @brief Establish connection to a SMB service.
 *
 * @param[in] server - The host system to connect to
 *
 * @param[in] share - The file system share.
 *
 * @param[in] username - The username for getting access to SMB service
 *
 * @param[in] password - The password that corresponds to username
 *
 * @param[out] con - A connection handle in case of success.
 *
 * @return, 0 on success, -1 on failure
 */
int
smb_connect (const char *server, const char *share, const char *username,
             const char *password, SMB_HANDLE *con)
{
  (void) server;
  (void) share;
  (void) username;
  (void) password;
  (void) con;
  return -1;
}

/**
 * @brief Close the connection handle for SMB service.
 *
 * @param[in] handle - SMB connection handle
 *
 * @return, 0 on success, -1 on failure
 */
int
smb_close (SMB_HANDLE handle)
{
  (void) handle;
  return -1;
}

/**
 * @brief Obtain Windows file rights in SDDL format
 *
 * @param[in] handle - SMB connection handle
 *
 * @param[in] filename - File system path
 *
 * @return, Security Descriptor in SDDL format on success, NULL on failure.
 */
char *
smb_file_SDDL (SMB_HANDLE handle, const char *filename)
{
  (void) handle;
  (void) filename;
  return NULL;
}

/**
 * @brief Obtain the SID of the Owner for a given file/path
 *
 * @param[in] handle - SMB connection handle
 *
 * @param[in] filename - File system path
 *
 * @return, Owner SID string on success, NULL on failure.
 */
char *
smb_file_OwnerSID (SMB_HANDLE handle, const char *filename)
{
  (void) handle;
  (void) filename;
  return NULL;
}

/**
 * @brief Obtain the SID of the Group for a given file/path
 *
 * @param[in] handle - SMB connection handle
 *
 * @param[in] filename - File system path
 *
 * @return, Group SID string on success, NULL on failure.
 */
char *
smb_file_GroupSID (SMB_HANDLE handle, const char *filename)
{
  (void) handle;
  (void) filename;
  return NULL;
}

/**
 * @brief Obtain the Trustee SID and their rights for a given file/path
 *
 * @param[in] handle - SMB connection handle
 *
 * @param[in] filename - File system path
 *
 * @return, Trustee SID:Access_Mask string on success, NULL on failure.
 */
char *
smb_file_TrusteeRights (SMB_HANDLE handle, const char *filename)
{
  (void) handle;
  (void) filename;
  return NULL;
}

/**
 * @brief Command Execution in Windows
 *
 * @param[in] argc - Connection strings
 *
 * @param[in] argv - Number of arguments
 *
 * @return, 0 on success, -1 on failure
 */
int
wincmd (int argc, char *argv[], char **res)
{
  (void) argc;
  (void) argv;
  (void) res;
  return -1;
}
