/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileCopyrightText: Based on work Copyright (C) 1998 - 2007 Tenable Network Security, Inc.
 * SPDX-FileComment: This file contains defines for the categories of VIPER. Categories influence the execution order of VIPERs (e.g. VIPERs with category ACT_SCANNER are in principle executed first).
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef _NVT_CATEGORIES_H
#define _NVT_CATEGORIES_H

/**
 * @brief NVT 'Categories', influence execution order of NVTs.
 */
typedef enum
{
  ACT_INIT = 0,
  ACT_SCANNER,
  ACT_SETTINGS,
  ACT_GATHER_INFO,
  ACT_ATTACK,
  ACT_MIXED_ATTACK,
  ACT_DESTRUCTIVE_ATTACK,
  ACT_DENIAL,
  ACT_KILL_HOST,
  ACT_FLOOD,
  ACT_END,
} nvt_category;

#endif /* _NVT_CATEGORIES_H */
