// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Name: utils.h
 * Brief: Generic helper utilities.
 * 
 * Copyright:
 * Copyright (C) 2012-2018 Greenbone Networks GmbH
 * Copyright (C) 2022, Mageni Security LLC
 *
 */

#ifndef _GVMD_UTILS_H
#define _GVMD_UTILS_H

#include <glib.h>
#include <time.h>

int
gvm_usleep (unsigned int);

int
gvm_sleep (unsigned int);

int
parse_otp_time (const char *);

int
parse_feed_timestamp (const char *);

int
parse_ctime (const char *);

int
days_from_now (time_t *);

char *
iso_time (time_t *);

char *
iso_time_tz (time_t *, const char *, const char **);

/**
 * @brief Lockfile.
 */
typedef struct
{
  int fd;      ///< File descriptor.
  gchar *name; ///< Name.
} lockfile_t;

int
lockfile_lock (lockfile_t *, const gchar *);

int
lockfile_lock_nb (lockfile_t *, const gchar *);

int
lockfile_lock_shared_nb (lockfile_t *, const gchar *);

int
lockfile_unlock (lockfile_t *);

int
lockfile_locked (const gchar *);

#endif /* not _GVMD_UTILS_H */
