/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2013-2019 Greenbone Networks GmbH
 * SPDX-FileComment: Check passwords against a list of pattern
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef MAGENI_PWPOLICY_H
#define MAGENI_PWPOLICY_H

char * mgn_validate_password (const char *, const char *);

void mgn_disable_password_policy (void);

#endif /* MAGENI_PWPOLICY_H */
