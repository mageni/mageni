// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * pwpolicy.h
 *
 * Check passwords against a list of pattern
 *  
 * Copyright:
 * Copyright (C) 2013-2019 Greenbone Networks GmbH
 * Copyright (C) 2022 Mageni Security LLC
 * 
 */

#ifndef MAGENI_PWPOLICY_H
#define MAGENI_PWPOLICY_H

char * mgn_validate_password (const char *, const char *);

void mgn_disable_password_policy (void);

#endif /* MAGENI_PWPOLICY_H */
