// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Name: otp.h
 * Brief: OTP library headers
 * 
 * Copyright:
 * Copyright (C) 2009-2018 Greenbone Networks GmbH
 * Copyright (C) 2022, Mageni Security LLC
 *
 */

#ifndef _GVMD_OTP_H
#define _GVMD_OTP_H

#include "manage.h"

#include <glib.h>

void
init_otp_data ();

int
process_otp_scanner_input ();

/** @todo Exported for following functions. */
/**
 * @brief Possible initialisation states of the scanner.
 */
typedef enum
{
  SCANNER_INIT_CONNECTED,
  SCANNER_INIT_DONE,
  SCANNER_INIT_DONE_CACHE_MODE,        /* Done, when in NVT cache rebuild. */
  SCANNER_INIT_DONE_CACHE_MODE_UPDATE, /* Done, when in NVT cache update. */
  SCANNER_INIT_GOT_FEED_VERSION,
  SCANNER_INIT_GOT_PLUGINS,
  SCANNER_INIT_SENT_COMPLETE_LIST,
  SCANNER_INIT_SENT_COMPLETE_LIST_UPDATE,
  SCANNER_INIT_SENT_VERSION,
  SCANNER_INIT_TOP
} scanner_init_state_t;

/** @todo Exported for gmpd.c. */
extern scanner_init_state_t scanner_init_state;

extern int scanner_current_loading;
extern int scanner_total_loading;

/** @todo Exported for gmpd.c and scanner.c. */
void
set_scanner_init_state (scanner_init_state_t state);

/** @todo Exported for scanner.c. */
void
reset_scanner_states ();

/** @todo Exported for gmpd.c. */
extern int scanner_init_offset;

#endif /* not _GVMD_OTP_H */
