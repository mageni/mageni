/**
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileCopyrightText: Portions Copyright (C) 2006 Software in the Public Interest, Inc.
 * SPDX-FileCopyrightText: Based on work Copyright (C) 1998 - 2006 Tenable Network Security, Inc.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef MAGENI_ATTACK_H
#define MAGENI_ATTACK_H

#include "../misc/scanneraux.h"

#include "../../libraries/util/kb.h"

void attack_network (struct scan_globals *, kb_t *network_kb);

#endif
