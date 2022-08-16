/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2015-2019 Greenbone Networks GmbH
 * SPDX-FileComment: Implementation of SSH related API.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef _GVM_SSHUTILS_H
#define _GVM_SSHUTILS_H

char * mgn_ssh_pkcs8_decrypt (const char *, const char *);

char * mgn_ssh_public_from_private (const char *, const char *);

#endif /* not _GVM_SSHUTILS_H */
