// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Name: sshutils.h
 * Brief: Implementation of SSH related API.
 *  
 * Copyright:
 * Copyright (C) 2015-2019 Greenbone Networks GmbH
 * Copyright (C) 2022, Mageni Security LLC
 * 
 */

#ifndef _GVM_SSHUTILS_H
#define _GVM_SSHUTILS_H

char *
gvm_ssh_pkcs8_decrypt (const char *, const char *);

char *
gvm_ssh_public_from_private (const char *, const char *);

#endif /* not _GVM_SSHUTILS_H */
