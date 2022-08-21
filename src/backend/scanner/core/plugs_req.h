/**
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileCopyrightText: Portions Copyright (C) 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
 * SPDX-FileComment: Header of file that performs various checks for requirements set in a given plugin.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef PLUGINS_REQUIREMENTS_H
#define PLUGINS_REQUIREMENTS_H

#include "../../libraries/util/kb.h" /* for struct kb_item */

char * requirements_plugin (kb_t, nvti_t *);

int mandatory_requirements_met (kb_t, nvti_t *);

#endif
