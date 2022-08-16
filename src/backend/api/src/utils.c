/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2016-2018 Greenbone Networks GmbH
 * SPDX-FileComment: Generic helper utilities.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#define _XOPEN_SOURCE

#define _POSIX_C_SOURCE 199309L

#include "utils.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/* Sleep. */

/**
 * @brief Sleep for some number of microseconds, handling interrupts.
 *
 * @param[in] microseconds  Number of microseconds.
 *
 * @return 0 success, -1 error (with errno set).
 */
int
gvm_usleep (unsigned int microseconds)
{
  struct timespec a, b, *requested, *remaining;
  int ret;

  requested = &a;
  remaining = &b;

  requested->tv_sec = microseconds / 1000000;
  requested->tv_nsec = (microseconds % 1000000) * 1000;

  while ((ret = nanosleep (requested, remaining)) && (errno == EINTR))
    {
      struct timespec *temp;
      temp = requested;
      requested = remaining;
      remaining = temp;
    }
  if (ret)
    return -1;
  return 0;
}

/**
 * @brief Sleep for some number of seconds, handling interrupts.
 *
 * @param[in] seconds  Number of seconds.
 *
 * @return 0 success, -1 error (with errno set).
 */
int
gvm_sleep (unsigned int seconds)
{
  return gvm_usleep (seconds * 1000000);
}

/* Time. */

/**
 * @brief Convert a UTC time into seconds since epoch.
 *
 * @param[in]  format     Format of time.
 * @param[in]  text_time  Time as text.
 *
 * @return Time since epoch.  0 on error.
 */
static int
parse_utc_time (const char *format, const char *text_time)
{
  int epoch_time;
  struct tm tm;
  gchar *tz;

  /* Scanner sends UTC in ctime format: "Wed Jun 30 21:49:08 1993". */

  /* Store current TZ. */
  tz = getenv ("TZ") ? g_strdup (getenv ("TZ")) : NULL;

  if (setenv ("TZ", "UTC", 1) == -1)
    {
      g_warning ("%s: Failed to switch to UTC", __FUNCTION__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }

  memset (&tm, 0, sizeof (struct tm));
  if (strptime ((char *) text_time, format, &tm) == NULL)
    {
      g_warning ("%s: Failed to parse time", __FUNCTION__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }
  epoch_time = mktime (&tm);
  if (epoch_time == -1)
    {
      g_warning ("%s: Failed to make time", __FUNCTION__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }

  /* Revert to stored TZ. */
  if (tz)
    {
      if (setenv ("TZ", tz, 1) == -1)
        {
          g_warning ("%s: Failed to switch to original TZ", __FUNCTION__);
          g_free (tz);
          return 0;
        }
    }
  else
    unsetenv ("TZ");

  g_free (tz);
  return epoch_time;
}

/**
 * @brief Convert an OTP time into seconds since epoch.
 *
 * Use UTC as timezone.
 *
 * @param[in]  text_time  Time as text in ctime format.
 *
 * @return Time since epoch.  0 on error.
 */
int
parse_otp_time (const char *text_time)
{
  return parse_utc_time ("%a %b %d %H:%M:%S %Y", text_time);
}

/**
 * @brief Convert a feed timestamp into seconds since epoch.
 *
 * @param[in]  text_time  Time as text in ctime format.
 *
 * @return Time since epoch.  0 on error.
 */
int
parse_feed_timestamp (const char *text_time)
{
  return parse_utc_time ("%Y%m%d", text_time);
}

/**
 * @brief Convert a ctime into seconds since epoch.
 *
 * Use the current timezone.
 *
 * @param[in]  text_time  Time as text in ctime format.
 *
 * @return Time since epoch.
 */
int
parse_ctime (const char *text_time)
{
  int epoch_time;
  struct tm tm;

  /* ctime format: "Wed Jun 30 21:49:08 1993". */

  memset (&tm, 0, sizeof (struct tm));
  if (strptime ((char *) text_time, "%a %b %d %H:%M:%S %Y", &tm) == NULL)
    {
      g_warning ("%s: Failed to parse time '%s'", __FUNCTION__, text_time);
      return 0;
    }
  epoch_time = mktime (&tm);
  if (epoch_time == -1)
    {
      g_warning ("%s: Failed to make time '%s'", __FUNCTION__, text_time);
      return 0;
    }

  return epoch_time;
}

/**
 * @brief Calculate difference between now and epoch_time in days
 *
 * @param[in]  epoch_time  Time in seconds from epoch.
 *
 * @return Int days bettween now and epoch_time or -1 if epoch_time is in the
 * past
 */
int
days_from_now (time_t *epoch_time)
{
  time_t now = time (NULL);
  int diff = *epoch_time - now;

  if (diff < 0)
    return -1;
  return diff / 86400; /* 60 sec * 60 min * 24 h */
}

/**
 * @brief Create an ISO time from seconds since epoch.
 *
 * @param[in]  epoch_time  Time in seconds from epoch.
 * @param[out] abbrev      Abbreviation for current timezone.
 *
 * @return Pointer to ISO time in static memory, or NULL on error.
 */
static char *
iso_time_internal (time_t *epoch_time, const char **abbrev)
{
  struct tm *tm;
  static char time_string[100];

  tm = localtime (epoch_time);
  if (tm == NULL)
    return NULL;
#ifdef __FreeBSD__
  if (tm->tm_gmtoff == 0)
#else
  if (timezone == 0)
#endif
    {
      if (strftime (time_string, 98, "%FT%TZ", tm) == 0)
        return NULL;

      if (abbrev)
        *abbrev = "UTC";
    }
  else
    {
      int len;

      if (strftime (time_string, 98, "%FT%T%z", tm) == 0)
        return NULL;

      /* Insert the ISO 8601 colon by hand. */
      len = strlen (time_string);
      time_string[len + 1] = '\0';
      time_string[len] = time_string[len - 1];
      time_string[len - 1] = time_string[len - 2];
      time_string[len - 2] = ':';

      if (abbrev)
        {
          static char abbrev_string[100];
          if (strftime (abbrev_string, 98, "%Z", tm) == 0)
            return NULL;
          *abbrev = abbrev_string;
        }
    }

  return time_string;
}

/**
 * @brief Create an ISO time from seconds since epoch.
 *
 * @param[in]  epoch_time  Time in seconds from epoch.
 *
 * @return Pointer to ISO time in static memory, or NULL on error.
 */
char *
iso_time (time_t *epoch_time)
{
  return iso_time_internal (epoch_time, NULL);
}

/**
 * @brief Create an ISO time from seconds since epoch, given a timezone.
 *
 * @param[in]  epoch_time  Time in seconds from epoch.
 * @param[in]  zone        Timezone.
 * @param[out] abbrev      Timezone abbreviation.
 *
 * @return Pointer to ISO time in static memory, or NULL on error.
 */
char *
iso_time_tz (time_t *epoch_time, const char *zone, const char **abbrev)
{
  gchar *tz;
  char *ret;

  if (zone == NULL)
    return iso_time (epoch_time);

  /* Store current TZ. */
  tz = getenv ("TZ") ? g_strdup (getenv ("TZ")) : NULL;

  if (setenv ("TZ", zone, 1) == -1)
    {
      g_warning ("%s: Failed to switch to zone", __FUNCTION__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return iso_time (epoch_time);
    }

  tzset ();
  ret = iso_time_internal (epoch_time, abbrev);

  /* Revert to stored TZ. */
  if (tz)
    {
      if (setenv ("TZ", tz, 1) == -1)
        {
          g_warning ("%s: Failed to switch to original TZ", __FUNCTION__);
          g_free (tz);
          return ret;
        }
    }
  else
    unsetenv ("TZ");

  g_free (tz);
  return ret;
}

/* Locks. */

/**
 * @brief Lock a file.
 *
 * @param[in]  lockfile           Lockfile.
 * @param[in]  lockfile_basename  Basename of lock file.
 * @param[in]  operation          LOCK_EX (exclusive) or LOCK_SH (shared).
 *                                Maybe ORd with LOCK_NB to prevent blocking.
 *
 * @return 0 success, 1 already locked, -1 error
 */
static int
lock_internal (lockfile_t *lockfile,
               const gchar *lockfile_basename,
               int operation)
{
  int fd;
  gchar *lockfile_name;

  /* Open the lock file. */

  lockfile_name = g_build_filename (MAGENI_RUN_DIR, lockfile_basename, NULL);

  fd = open (lockfile_name,
             O_RDWR | O_CREAT | O_APPEND,
             /* "-rw-r--r--" */
             S_IWUSR | S_IRUSR | S_IROTH | S_IRGRP);
  if (fd == -1)
    {
      g_warning (
        "Failed to open lock file '%s': %s", lockfile_name, strerror (errno));
      lockfile->name = NULL;
      g_free (lockfile_name);
      return -1;
    }

  /* Lock the lockfile. */

  if (flock (fd, operation)) /* Blocks, unless operation includes LOCK_NB. */
    {
      int flock_errno;

      flock_errno = errno;
      lockfile->name = NULL;
      g_free (lockfile_name);
      if (close (fd))
        g_warning ("%s: failed to close lock file fd: %s",
                   __FUNCTION__,
                   strerror (errno));
      if (flock_errno == EWOULDBLOCK)
        return 1;
      g_warning ("%s: flock: %s", __FUNCTION__, strerror (flock_errno));
      return -1;
    }

  lockfile->fd = fd;
  lockfile->name = lockfile_name;

  return 0;
}

/**
 * @brief Lock a file exclusively.
 *
 * Block until file is locked.
 *
 * @param[in]  lockfile           Lockfile.
 * @param[in]  lockfile_basename  Basename of lock file.
 *
 * @return 0 success, 1 already locked, -1 error
 */
int
lockfile_lock (lockfile_t *lockfile, const gchar *lockfile_basename)
{
  g_debug ("%s: lock '%s'", __FUNCTION__, lockfile_basename);
  return lock_internal (lockfile, lockfile_basename, LOCK_EX);
}

/**
 * @brief Lock a file exclusively, without blocking.
 *
 * @param[in]  lockfile           Lockfile.
 * @param[in]  lockfile_basename  Basename of lock file.
 *
 * @return 0 success, 1 already locked, -1 error
 */
int
lockfile_lock_nb (lockfile_t *lockfile, const gchar *lockfile_basename)
{
  g_debug ("%s: lock '%s'", __FUNCTION__, lockfile_basename);
  return lock_internal (lockfile, lockfile_basename, LOCK_EX | LOCK_NB);
}

/**
 * @brief Lock a file with a shared lock.
 *
 * @param[in]  lockfile           Lockfile.
 * @param[in]  lockfile_basename  Basename of lock file.
 *
 * @return 0 success, 1 already locked, -1 error
 */
int
lockfile_lock_shared_nb (lockfile_t *lockfile, const gchar *lockfile_basename)
{
  g_debug ("%s: lock '%s'", __FUNCTION__, lockfile_basename);
  return lock_internal (lockfile, lockfile_basename, LOCK_SH | LOCK_NB);
}

/**
 * @brief Unlock a file.
 *
 * @param[in]  lockfile  Lockfile.
 *
 * @return 0 success, -1 error
 */
int
lockfile_unlock (lockfile_t *lockfile)
{
  if (lockfile->name == NULL)
    return 0;

  assert (lockfile->fd);

  g_debug ("%s: unlock '%s'", __FUNCTION__, lockfile->name);

  /* Close the lock file. */

  if (close (lockfile->fd))
    {
      g_free (lockfile->name);
      lockfile->name = NULL;
      g_warning ("Failed to close lock file: %s", strerror (errno));
      return -1;
    }

  /* Clear the lock file data. */

  g_free (lockfile->name);
  lockfile->name = NULL;

  return 0;
}

/**
 * @brief Check if a file is locked.
 *
 * @param[in]  lockfile_basename  Basename of lock file.
 *
 * @return 0 free, 1 locked, -1 error
 */
int
lockfile_locked (const gchar *lockfile_basename)
{
  int ret;
  lockfile_t lockfile;

  g_debug ("%s: check '%s'", __FUNCTION__, lockfile_basename);

  ret = lockfile_lock_nb (&lockfile, lockfile_basename);
  if ((ret == 0) && lockfile_unlock (&lockfile))
    return -1;
  return ret;
}
