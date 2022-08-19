/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: 2009-2019 Greenbone Networks GmbH
 * SPDX-FileComment: Support macros for special platforms.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef _OPENVAS_MISC_SUPPORT_H
#define _OPENVAS_MISC_SUPPORT_H

// This structure does not exist on MacOS or FreeBSD systems
#ifndef s6_addr32
#if defined(__APPLE__) || defined(__FreeBSD__)
#define s6_addr32 __u6_addr.__u6_addr32
#endif // __APPLE__ || __FreeBSD__
#endif // !s6_addr32

#endif /* not _OPENVAS_MISC_SUPPORT_H */
