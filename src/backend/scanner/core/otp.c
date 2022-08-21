/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Portions Copyright (C) 2009-2019 Greenbone Networks GmbH
 * SPDX-FileComment: Implements Mageni Transfer Protocol.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#include "otp.h"

#include "../misc/network.h"

#include <glib.h>
#include <string.h>

/**
 * @brief Find the enum identifier for the client request which is given
 * @brief as string.
 *
 * @param str Enum identifier of OTP command (a client_request_t).
 * @see client_request_t
 */
client_request_t otp_get_client_request (char *str)
{
  if (!strcmp (str, "ATTACHED_FILE"))
    return (CREQ_ATTACHED_FILE);
  if (!strcmp (str, "LONG_ATTACK"))
    return (CREQ_LONG_ATTACK);
  if (!strcmp (str, "PREFERENCES"))
    return (CREQ_PREFERENCES);
  if (!strcmp (str, "STOP_WHOLE_TEST"))
    return (CREQ_STOP_WHOLE_TEST);
  if (!strcmp (str, "NVT_INFO"))
    return (CREQ_NVT_INFO);

  return (CREQ_UNKNOWN);
}
