/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2012-2019 Greenbone Networks GmbH
 * SPDX-FileComment: CVSS utility functions
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef _GVM_CVSS_H
#define _GVM_CVSS_H

#include <glib.h>

double
get_cvss_score_from_base_metrics (const char *);

#endif /* not _GVM_CVSS_H */
