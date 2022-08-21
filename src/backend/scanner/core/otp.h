/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileComment: Implements Mageni Transfer Protocol.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#ifndef MTP_H
#define MTP_H

typedef enum
{
  CREQ_UNKNOWN,
  CREQ_ATTACHED_FILE,
  CREQ_LONG_ATTACK,
  CREQ_PREFERENCES,
  CREQ_STOP_WHOLE_TEST,
  CREQ_NVT_INFO,
} client_request_t;

client_request_t otp_get_client_request (char *);

#endif
