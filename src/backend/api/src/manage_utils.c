/* 
 * Most new code since 2022 by Mageni Security LLC
 * Copyright (C) 2014-2018 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file manage_utils.c
 * @brief Module for Greenbone Vulnerability Manager: Manage library utilities.
 */

#include "manage_utils.h"

#include <assert.h> /* for assert */
#include "../../libraries/base/hosts.h"
#include "../../libraries/util/uuidutils.h"
#include <stdio.h>  /* for sscanf */
#include <stdlib.h> /* for getenv */
#include <string.h> /* for strcmp */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md  utils"

/**
 * @brief Number of seconds in a day.
 */
#define SECS_PER_DAY 86400

/**
 * @file  manage_utils.c
 * @brief The Greenbone Vulnerability Manager management library.
 *
 * Utilities used by the manage library that do not depend on anything.
 */

/**
 * @brief Get the offset from UTC of a timezone at a particular time.
 *
 * @param[in]  zone  Timezone, or NULL for UTC.
 * @param[in]  time  Time.
 *
 * @return Seconds east of UTC.
 */
static long
time_offset (const char *zone, time_t time)
{
  gchar *tz;
  struct tm *time_broken;
  int mins;
  char buf[100];

  if (zone == NULL || strcmp (zone, "UTC") == 0)
    return 0;

  /* Store current TZ. */
  tz = getenv ("TZ") ? g_strdup (getenv ("TZ")) : NULL;

  if (setenv ("TZ", zone, 1) == -1)
    {
      g_warning ("%s: Failed to switch to timezone", __FUNCTION__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }

  tzset ();

  time_broken = localtime (&time);
  if (time_broken == NULL)
    {
      g_warning ("%s: localtime failed", __FUNCTION__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }
  if (strftime (buf, 100, "%z", time_broken) == 0)
    {
      g_warning ("%s: Failed to format timezone", __FUNCTION__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }

  if (strlen (buf) >= 3)
    {
      mins = atoi (buf);
      mins /= 100;
      mins *= 60;
      mins += atoi (buf + 3);
    }
  else
    mins = 0;

  /* Revert to stored TZ. */
  if (tz)
    {
      if (setenv ("TZ", tz, 1) == -1)
        {
          g_warning ("%s: Failed to switch to original TZ", __FUNCTION__);
          g_free (tz);
          return mins * 60;
        }
    }
  else
    unsetenv ("TZ");

  g_free (tz);
  return mins * 60;
}

/**
 * @brief Get the current offset from UTC of a timezone.
 *
 * @param[in]  zone  Timezone, or NULL for UTC.
 *
 * @return Seconds east of UTC.
 */
long
current_offset (const char *zone)
{
  gchar *tz;
  long offset;
  time_t now;
  struct tm *now_broken;

  if (zone == NULL)
    return 0;

  /* Store current TZ. */
  tz = getenv ("TZ") ? g_strdup (getenv ("TZ")) : NULL;

  if (setenv ("TZ", zone, 1) == -1)
    {
      g_warning ("%s: Failed to switch to timezone", __FUNCTION__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }

  tzset ();

  time (&now);
  now_broken = localtime (&now);
  if (now_broken == NULL)
    {
      g_warning ("%s: localtime failed", __FUNCTION__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }
  if (setenv ("TZ", "UTC", 1) == -1)
    {
      g_warning ("%s: Failed to switch to UTC", __FUNCTION__);
      if (tz != NULL)
        setenv ("TZ", tz, 1);
      g_free (tz);
      return 0;
    }
  tzset ();
  offset = -(now - mktime (now_broken));

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
  return offset;
}

/**
 * @brief Code fragment for months_between.
 */
#define MONTHS_WITHIN_YEAR()                                                   \
  (same_month                                                                  \
     ? 0                                                                       \
     : ((broken2->tm_mon - broken1.tm_mon)                                     \
        - (same_day                                                            \
             ? (same_hour ? (same_minute ? (same_second ? 0                    \
                                                        : (broken2->tm_sec     \
                                                           < broken1.tm_sec))  \
                                         : (broken2->tm_min < broken1.tm_min)) \
                          : (broken2->tm_hour < broken1.tm_hour))              \
             : (broken2->tm_mday < broken1.tm_mday))))

/**
 * @brief Count number of full months between two times.
 *
 * There are two full months between 0h00.00 1 February 2010 and 0h00.00 1
 * April 2010.  There is one full month between 0h00.00 1 February 2010 and
 * 23h59.59 31 March 2010.
 *
 * @param[in]  time1  Earlier time.
 * @param[in]  time2  Later time.
 *
 * @return Number of full months between time1 and time2.
 */
static time_t
months_between (time_t time1, time_t time2)
{
  struct tm broken1, *broken2;
  int same_year, same_month, same_day, same_hour, same_minute, same_second;
  int month1_less, day1_less, hour1_less, minute1_less;
  int second1_less;

  assert (time1 <= time2);

  broken2 = localtime (&time2);
  if ((localtime_r (&time1, &broken1) == NULL) || (broken2 == NULL))
    {
      g_warning ("%s: localtime failed", __FUNCTION__);
      return 0;
    }

  same_year = (broken1.tm_year == broken2->tm_year);
  same_month = (broken1.tm_mon == broken2->tm_mon);
  same_day = (broken1.tm_mday == broken2->tm_mday);
  same_hour = (broken1.tm_hour == broken2->tm_hour);
  same_minute = (broken1.tm_min == broken2->tm_min);
  same_second = (broken1.tm_sec == broken2->tm_sec);

  month1_less = (broken1.tm_mon < broken2->tm_mon);
  day1_less = (broken1.tm_mday < broken2->tm_mday);
  hour1_less = (broken1.tm_hour < broken2->tm_hour);
  minute1_less = (broken1.tm_min < broken2->tm_min);
  second1_less = (broken1.tm_sec < broken2->tm_sec);

  return (
    same_year
      ? MONTHS_WITHIN_YEAR ()
      : ((month1_less
          || (same_month
              && (day1_less
                  || (same_day
                      && (hour1_less
                          || (same_hour
                              && (minute1_less
                                  || (same_minute && second1_less))))))))
           ? (/* time1 is earlier in the year than time2. */
              ((broken2->tm_year - broken1.tm_year) * 12)
              + MONTHS_WITHIN_YEAR ())
           : (/* time1 is later in the year than time2. */
              ((broken2->tm_year - broken1.tm_year - 1) * 12)
              /* Months left in year of time1. */
              + (11 - broken1.tm_mon)
              /* Months past in year of time2. */
              + broken2->tm_mon
              /* Possible extra month due to position in month of each time. */
              + (day1_less
                 || (same_day
                     && (hour1_less
                         || (same_hour
                             && (minute1_less
                                 || (same_minute && second1_less)))))))));
}

/**
 * @brief Add months to a time.
 *
 * @param[in]  time    Time.
 * @param[in]  months  Months.
 *
 * @return Time plus given number of months.
 */
time_t
add_months (time_t time, int months)
{
  struct tm *broken = localtime (&time);
  if (broken == NULL)
    {
      g_warning ("%s: localtime failed", __FUNCTION__);
      return 0;
    }
  broken->tm_mon += months;
  return mktime (broken);
}

/**
 * @brief Calculate day of week corresponding to a time.
 *
 * @param[in]  time  Time.
 *
 * @return Day of week mask: 1 Monday, 2 Tuesday, 4 Wednesday...
 */
static int
day_of_week (time_t time)
{
  struct tm *tm;
  int sunday_first;

  tm = gmtime (&time);
  if (tm == NULL)
    {
      g_warning ("%s: gmtime failed", __FUNCTION__);
      return 0;
    }

  sunday_first = tm->tm_wday; /* Sunday 0, Monday 1, ... */
  return 1 << ((sunday_first + 6) % 7);
}

/**
 * @brief Get days till next occurrence.
 *
 * @param[in] day_of_week  Day of week flag: 1 Monday, 2 Tuesday, 4 Wednesday...
 * @param[in] byday        Byday mask.
 *
 * @return Number of days to next day flagged in byday.  -1 if no next day.
 */
static int
next_day (int day_of_week, int byday)
{
  int days;

  days = 0;
  while (days < 7)
    {
      if (byday & day_of_week)
        return days;
      if (day_of_week == (1 << 6))
        /* Roll around to Monday. */
        day_of_week = 1;
      else
        day_of_week = day_of_week << 1;
      days++;
    }
  return -1;
}

/**
 * @brief Number of seconds in a day.
 */
#define SECONDS_PER_DAY 86400

/**
 * @brief Calculate the next time from now given a start time and a period.
 *
 * @param[in] first           The first time.
 * @param[in] period          The period in seconds.
 * @param[in] period_months   The period in months.
 * @param[in] byday           Days of week to run schedule.
 * @param[in] zone            The timezone to use.
 * @param[in] periods_offset  Number of periods to offset.
 *                            e.g. 0 = next time, -1 current/last time
 *
 * @return  the next time a schedule with the given times is due.
 */
time_t
next_time (time_t first,
           int period,
           int period_months,
           int byday,
           const char *zone,
           int periods_offset)
{
  int periods_diff;
  time_t now;
  long offset_diff;

  if (zone)
    {
      long first_offset_val, current_offset_val;

      first_offset_val = time_offset (zone, first);
      current_offset_val = current_offset (zone);
      offset_diff = current_offset_val - first_offset_val;
    }
  else
    {
      offset_diff = 0;
    }

  now = time (NULL);

  if (first >= now)
    return first;

  if (byday)
    {
      time_t next_day_multiple;

      assert (now > first);

      g_debug ("%s: byday: %i", __FUNCTION__, byday);

      /* TODO does this need timezone offsetting? */

      /* The next multiple of a day after the first time, but "now" at the
       * earliest.  So if now is at the same time as the first time, this will
       * be now.  If now is an hour after the first time, this will be one
       * day after the first time.  If now is 7 days and 3 seconds after the
       * first time, this will be 8 days after the first time.
       *
       * Simply: the next possible time on a daily schedule. */
      next_day_multiple = now + (SECS_PER_DAY - ((now - first) % SECS_PER_DAY));

      g_debug ("%s: next_day_multiple: %lli",
               __FUNCTION__,
               (long long) next_day_multiple);
      g_debug ("%s: day_of_week (next_day_multiple): %i",
               __FUNCTION__,
               day_of_week (next_day_multiple));
      g_debug ("%s: next_day (^, byday): %i",
               __FUNCTION__,
               next_day (day_of_week (next_day_multiple), byday));

      /* Return the next possible daily time, offset according the next day of
       * the week that the schedule must run on. */
      return next_day_multiple
             + next_day (day_of_week (next_day_multiple), byday)
                 * SECONDS_PER_DAY;
    }

  if (period > 0)
    {
      return first
             + ((((now - first + offset_diff) / period) + 1 + periods_offset)
                * period)
             - offset_diff;
    }
  else if (period_months > 0)
    {
      time_t ret;
      gchar *tz;

      /* Store current TZ. */
      tz = getenv ("TZ") ? g_strdup (getenv ("TZ")) : NULL;

      if (setenv ("TZ", zone ? zone : "UTC", 1) == -1)
        {
          g_warning ("%s: Failed to switch to timezone", __FUNCTION__);
          if (tz != NULL)
            setenv ("TZ", tz, 1);
          g_free (tz);
          return 0;
        }

      tzset ();

      /* Calculate new time */
      periods_diff = months_between (first, now) / period_months;
      periods_diff += periods_offset;
      ret = add_months (first, (periods_diff + 1) * period_months);
      ret -= offset_diff;

      /* Revert to stored TZ. */
      if (tz)
        {
          if (setenv ("TZ", tz, 1) == -1)
            g_warning ("%s: Failed to switch to original TZ", __FUNCTION__);

          g_free (tz);
        }
      else
        unsetenv ("TZ");

      return ret;
    }
  else if (periods_offset == -1)
    {
      return first;
    }
  return 0;
}

/**
 * @brief Try convert an OTP NVT tag time string into epoch time.
 *
 * @param[in]   string   String.
 * @param[out]  seconds  Time as seconds since the epoch.
 *
 * @return -1 failed to parse time, -2 failed to make time, -3 failed to parse
 *         timezone offset, 0 success.
 */
int
parse_time (const gchar *string, int *seconds)
{
  int epoch_time, offset;
  struct tm tm;

  if ((strcmp ((char *) string, "") == 0)
      || (strcmp ((char *) string, "$Date: $") == 0)
      || (strcmp ((char *) string, "$Date$") == 0)
      || (strcmp ((char *) string, "$Date:$") == 0)
      || (strcmp ((char *) string, "$Date") == 0)
      || (strcmp ((char *) string, "$$") == 0))
    {
      if (seconds)
        *seconds = 0;
      return 0;
    }

  /* Parse the time. */

  /* 2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011) */
  /* $Date: 2012-02-17 16:05:26 +0100 (Fr, 17. Feb 2012) $ */
  /* $Date: Fri, 11 Nov 2011 14:42:28 +0100 $ */
  memset (&tm, 0, sizeof (struct tm));
  if (strptime ((char *) string, "%F %T %z", &tm) == NULL)
    {
      memset (&tm, 0, sizeof (struct tm));
      if (strptime ((char *) string, "$Date: %F %T %z", &tm) == NULL)
        {
          memset (&tm, 0, sizeof (struct tm));
          if (strptime ((char *) string, "%a %b %d %T %Y %z", &tm) == NULL)
            {
              memset (&tm, 0, sizeof (struct tm));
              if (strptime ((char *) string, "$Date: %a, %d %b %Y %T %z", &tm)
                  == NULL)
                {
                  memset (&tm, 0, sizeof (struct tm));
                  if (strptime (
                        (char *) string, "$Date: %a %b %d %T %Y %z", &tm)
                      == NULL)
                    {
                      g_debug (
                        "%s: Failed to parse time: %s", __FUNCTION__, string);
                      return -1;
                    }
                }
            }
        }
    }
  epoch_time = mktime (&tm);
  if (epoch_time == -1)
    {
      g_debug ("%s: Failed to make time: %s", __FUNCTION__, string);
      return -2;
    }

  /* Get the timezone offset from the string. */

  if ((sscanf ((char *) string, "%*u-%*u-%*u %*u:%*u:%*u %d%*[^]]", &offset)
       != 1)
      && (sscanf (
            (char *) string, "$Date: %*u-%*u-%*u %*u:%*u:%*u %d%*[^]]", &offset)
          != 1)
      && (sscanf (
            (char *) string, "%*s %*s %*s %*u:%*u:%*u %*u %d%*[^]]", &offset)
          != 1)
      && (sscanf ((char *) string,
                  "$Date: %*s %*s %*s %*u %*u:%*u:%*u %d%*[^]]",
                  &offset)
          != 1)
      && (sscanf ((char *) string,
                  "$Date: %*s %*s %*s %*u:%*u:%*u %*u %d%*[^]]",
                  &offset)
          != 1))
    {
      g_debug (
        "%s: Failed to parse timezone offset: %s", __FUNCTION__, string);
      return -3;
    }

  /* Use the offset to convert to UTC. */

  if (offset < 0)
    {
      epoch_time += ((-offset) / 100) * 60 * 60;
      epoch_time += ((-offset) % 100) * 60;
    }
  else if (offset > 0)
    {
      epoch_time -= (offset / 100) * 60 * 60;
      epoch_time -= (offset % 100) * 60;
    }

  if (seconds)
    *seconds = epoch_time;
  return 0;
}

/**
 * @brief Return number of hosts described by a hosts string.
 *
 * @param[in]  given_hosts      String describing hosts.
 * @param[in]  exclude_hosts    String describing hosts excluded from given set.
 * @param[in]  max_hosts        Max hosts.
 *
 * @return Number of hosts, or -1 on error.
 */
int
manage_count_hosts_max (const char *given_hosts,
                        const char *exclude_hosts,
                        int max_hosts)
{
  int count;
  gvm_hosts_t *hosts;

  hosts = gvm_hosts_new_with_max (given_hosts, max_hosts);
  if (hosts == NULL)
    return -1;

  if (exclude_hosts)
    {
      if (gvm_hosts_exclude_with_max (hosts, exclude_hosts, max_hosts) < 0)
        return -1;
    }

  count = gvm_hosts_count (hosts);
  gvm_hosts_free (hosts);

  return count;
}

/**
 * @brief Get the minimum severity for a severity level and class.
 *
 * @param[in] level  The name of the severity level.
 * @param[in] class  The severity class, NULL to get from current user setting.
 *
 * @return The minimum severity.
 */
double
level_min_severity (const char *level, const char *class)
{
  if (strcasecmp (level, "Log") == 0)
    return SEVERITY_LOG;
  else if (strcasecmp (level, "False Positive") == 0)
    return SEVERITY_FP;
  else if (strcasecmp (level, "Debug") == 0)
    return SEVERITY_DEBUG;
  else if (strcasecmp (level, "Error") == 0)
    return SEVERITY_ERROR;
  else if (strcasecmp (class, "pci-dss") == 0)
    {
      if (strcasecmp (level, "high") == 0)
        return 4.0;
      else
        return SEVERITY_UNDEFINED;
    }
  else
    {
      /* NIST/BSI. */
      if (strcasecmp (level, "high") == 0)
        return 7.0;
      else if (strcasecmp (level, "medium") == 0)
        return 4.0;
      else if (strcasecmp (level, "low") == 0)
        return 0.1;
      else
        return SEVERITY_UNDEFINED;
    }
}

/**
 * @brief Get the minimum severity for a severity level and class.
 *
 * @param[in] level  The name of the severity level.
 * @param[in] class  The severity class.
 *
 * @return The minimum severity.
 */
double
level_max_severity (const char *level, const char *class)
{
  if (strcasecmp (level, "Log") == 0)
    return SEVERITY_LOG;
  else if (strcasecmp (level, "False Positive") == 0)
    return SEVERITY_FP;
  else if (strcasecmp (level, "Debug") == 0)
    return SEVERITY_DEBUG;
  else if (strcasecmp (level, "Error") == 0)
    return SEVERITY_ERROR;
  else if (strcasecmp (class, "pci-dss") == 0)
    {
      if (strcasecmp (level, "high") == 0)
        return 10.0;
      else
        return SEVERITY_UNDEFINED;
    }
  else
    {
      /* NIST/BSI. */
      if (strcasecmp (level, "high") == 0)
        return 10.0;
      else if (strcasecmp (level, "medium") == 0)
        return 6.9;
      else if (strcasecmp (level, "low") == 0)
        return 3.9;
      else
        return SEVERITY_UNDEFINED;
    }
}

/**
 * @brief Returns whether a host has an equal host in a hosts string.
 *
 * For example, 192.168.10.1 has an equal in a hosts string
 * "192.168.10.1-5, 192.168.10.10-20" string while 192.168.10.7 doesn't.
 *
 * @param[in] hosts_str      Hosts string to check.
 * @param[in] find_host_str  The host to find.
 * @param[in] max_hosts      Maximum number of hosts allowed in hosts_str.
 *
 * @return 1 if host has equal in hosts_str, 0 otherwise.
 */
int
hosts_str_contains (const char *hosts_str,
                    const char *find_host_str,
                    int max_hosts)
{
  gvm_hosts_t *hosts, *find_hosts;

  hosts = gvm_hosts_new_with_max (hosts_str, max_hosts);
  find_hosts = gvm_hosts_new_with_max (find_host_str, 1);

  if (hosts == NULL || find_hosts == NULL || find_hosts->count != 1)
    {
      gvm_hosts_free (hosts);
      gvm_hosts_free (find_hosts);
      return 0;
    }

  int ret = gvm_host_in_hosts (find_hosts->hosts[0], NULL, hosts);
  gvm_hosts_free (hosts);
  gvm_hosts_free (find_hosts);
  return ret;
}

/**
 * @brief Check whether a resource type table name is valid.
 *
 * @param[in]  type  Type of resource.
 *
 * @return 1 yes, 0 no.
 */
int
valid_db_resource_type (const char *type)
{
  if (type == NULL)
    return 0;

  return (strcasecmp (type, "agent") == 0) || (strcasecmp (type, "alert") == 0)
         || (strcasecmp (type, "config") == 0)
         || (strcasecmp (type, "cpe") == 0)
         || (strcasecmp (type, "credential") == 0)
         || (strcasecmp (type, "cve") == 0)
         || (strcasecmp (type, "cert_bund_adv") == 0)
         || (strcasecmp (type, "dfn_cert_adv") == 0)
         || (strcasecmp (type, "filter") == 0)
         || (strcasecmp (type, "group") == 0)
         || (strcasecmp (type, "host") == 0) || (strcasecmp (type, "os") == 0)
         || (strcasecmp (type, "note") == 0) || (strcasecmp (type, "nvt") == 0)
         || (strcasecmp (type, "ovaldef") == 0)
         || (strcasecmp (type, "override") == 0)
         || (strcasecmp (type, "port_list") == 0)
         || (strcasecmp (type, "permission") == 0)
         || (strcasecmp (type, "report") == 0)
         || (strcasecmp (type, "report_format") == 0)
         || (strcasecmp (type, "result") == 0)
         || (strcasecmp (type, "role") == 0)
         || (strcasecmp (type, "scanner") == 0)
         || (strcasecmp (type, "schedule") == 0)
         || (strcasecmp (type, "slave") == 0) || (strcasecmp (type, "tag") == 0)
         || (strcasecmp (type, "target") == 0)
         || (strcasecmp (type, "task") == 0)
         || (strcasecmp (type, "ticket") == 0)
         || (strcasecmp (type, "user") == 0);
}

/**
 * @brief GVM product ID.
 */
#define GVM_PRODID \
  "-//Mageni.net//NONSGML Mageni Security " APID_VERSION "//EN"

/**
 * @brief Try to get a built-in libical timezone from a tzid or city name.
 *
 * @param[in]  tzid  The tzid or Olson city name.
 *
 * @return The built-in timezone if found or UTC otherwise.
 */
static icaltimezone *
icalendar_timezone_from_tzid (const char *tzid)
{
  icaltimezone *tz;

  if (tzid)
    {
      /* tzid is not NULL, try to get a libical built-in. */
      tz = icaltimezone_get_builtin_timezone_from_tzid (tzid);
      if (tz == NULL)
        {
          tz = icaltimezone_get_builtin_timezone (tzid);
          if (tz == NULL)
            /* tzid is not a built-in timezone, fall back to UTC. */
            tz = icaltimezone_get_utc_timezone ();
        }
    }
  else
    /* tzid is NULL, fall back to UTC. */
    tz = icaltimezone_get_utc_timezone ();

  return tz;
}

/**
 * @brief Create an iCalendar component from old schedule data.
 *
 * @param[in]  first_time     The first run time.
 * @param[in]  period         The period in seconds.
 * @param[in]  period_months  The period in months.
 * @param[in]  duration       The duration in seconds.
 * @param[in]  byday_mask     The byday mask.
 * @param[in]  zone           The timezone id / city name.
 *
 * @return  The generated iCalendar component.
 */
icalcomponent *
icalendar_from_old_schedule_data (time_t first_time,
                                  time_t period,
                                  time_t period_months,
                                  time_t duration,
                                  int byday_mask,
                                  const char *zone)
{
  gchar *uid;
  icalcomponent *ical_new, *vevent;
  icaltimezone *ical_timezone;
  icaltimetype dtstart, dtstamp;
  int has_recurrence;
  struct icalrecurrencetype recurrence;
  struct icaldurationtype ical_duration;

  // Setup base calendar component
  ical_new = icalcomponent_new_vcalendar ();
  icalcomponent_add_property (ical_new, icalproperty_new_version ("2.0"));
  icalcomponent_add_property (ical_new, icalproperty_new_prodid (GVM_PRODID));

  // Create event component
  vevent = icalcomponent_new_vevent ();
  icalcomponent_add_component (ical_new, vevent);

  // Generate UID for event
  uid = gvm_uuid_make ();
  icalcomponent_set_uid (vevent, uid);
  g_free (uid);
  uid = NULL;

  // Set timestamp
  dtstamp = icaltime_current_time_with_zone (icaltimezone_get_utc_timezone ());
  icalcomponent_set_dtstamp (vevent, dtstamp);

  // Get timezone and set first start time
  if (zone)
    {
      ical_timezone = icalendar_timezone_from_tzid (zone);
    }
  else
    {
      ical_timezone = NULL;
    }
  dtstart = icaltime_from_timet_with_zone (first_time, 0, ical_timezone);
  icalcomponent_set_dtstart (vevent, dtstart);

  // Get recurrence rule if applicable
  icalrecurrencetype_clear (&recurrence);
  if (period_months)
    {
      if (period_months % 12 == 0)
        {
          recurrence.freq = ICAL_YEARLY_RECURRENCE;
          recurrence.interval = period_months / 12;
        }
      else
        {
          recurrence.freq = ICAL_MONTHLY_RECURRENCE;
          recurrence.interval = period_months;
        }
      has_recurrence = 1;
    }
  else if (period)
    {
      if (period % 604800 == 0)
        {
          recurrence.freq = ICAL_WEEKLY_RECURRENCE;
          recurrence.interval = period / 604800;
        }
      else if (period % 86400 == 0)
        {
          recurrence.freq = ICAL_DAILY_RECURRENCE;
          recurrence.interval = period / 86400;
        }
      else if (period % 3600 == 0)
        {
          recurrence.freq = ICAL_HOURLY_RECURRENCE;
          recurrence.interval = period / 3600;
        }
      else if (period % 60 == 0)
        {
          recurrence.freq = ICAL_MINUTELY_RECURRENCE;
          recurrence.interval = period / 60;
        }
      else
        {
          recurrence.freq = ICAL_SECONDLY_RECURRENCE;
          recurrence.interval = period;
        }

      has_recurrence = 1;
    }
  else
    has_recurrence = 0;

  // Add set by_day and add the RRULE if applicable
  if (has_recurrence)
    {
      if (byday_mask)
        {
          int ical_day, array_pos;

          // iterate over libical days starting at 1 for Sunday.
          array_pos = 0;
          for (ical_day = 1; ical_day <= 7; ical_day++)
            {
              int mask_bit;
              // Convert to GVM byday mask bit index starting at 0 for Monday.
              mask_bit = (ical_day == 1) ? 1 : (ical_day - 2);
              if (byday_mask & (1 << mask_bit))
                {
                  recurrence.by_day[array_pos] = ical_day;
                  array_pos++;
                }
            }
        }

      icalcomponent_add_property (vevent, icalproperty_new_rrule (recurrence));
    }

  // Add duration
  if (duration)
    {
      ical_duration = icaldurationtype_from_int (duration);
      icalcomponent_set_duration (vevent, ical_duration);
    }

  return ical_new;
}

/**
 * @brief Simplify an VEVENT iCal component.
 *
 * @param[in]  vevent          The VEVENT component to simplify.
 * @param[in]  used_tzids      GHashTable to collect ids of the used timezones.
 * @param[out] error           Output of iCal errors or warnings.
 * @param[out] warnings_buffer GString buffer to write warnings to.
 *
 * @return  A newly allocated, simplified VEVENT component.
 */
static icalcomponent *
icalendar_simplify_vevent (icalcomponent *vevent,
                           GHashTable *used_tzids,
                           gchar **error,
                           GString *warnings_buffer)
{
  icalproperty *error_prop;
  gchar *uid;
  icalcomponent *vevent_simplified;
  icaltimetype dtstart, dtstamp;
  const char *start_tzid;
  struct icaldurationtype duration;
  icalproperty *rrule_prop, *rdate_prop, *exdate_prop, *exrule_prop;

  // Only handle VEVENT components
  assert (icalcomponent_isa (vevent) == ICAL_VEVENT_COMPONENT);

  // Check for errors
  icalrestriction_check (vevent);
  error_prop =
    icalcomponent_get_first_property (vevent, ICAL_XLICERROR_PROPERTY);
  if (error_prop)
    {
      if (error)
        *error = g_strdup_printf ("Error in VEVENT: %s",
                                  icalproperty_get_xlicerror (error_prop));
      return NULL;
    }

  // Get mandatory first start time
  dtstart = icalcomponent_get_dtstart (vevent);
  if (icaltime_is_null_time (dtstart))
    {
      if (error)
        *error = g_strdup_printf ("VEVENT must have a dtstart property");
      return NULL;
    }

  // Get timezone id used in start time
  start_tzid = icaltime_get_tzid (dtstart);
  if (start_tzid && used_tzids)
    g_hash_table_add (used_tzids, g_strdup (start_tzid));

  // Get duration or try to calculate it from end time
  duration = icalcomponent_get_duration (vevent);
  if (icaldurationtype_is_null_duration (duration))
    {
      icaltimetype dtend;
      dtend = icalcomponent_get_dtend (vevent);

      if (icaltime_is_null_time (dtend))
        {
          duration = icaldurationtype_null_duration ();
        }
      else
        {
          duration = icaltime_subtract (dtend, dtstart);
        }
    }

  /*
   * Try to get only the first recurrence rule and ignore any others.
   * Technically there can be multiple ones but behavior is undefined in
   *  the iCalendar specification.
   */
  rrule_prop = icalcomponent_get_first_property (vevent, ICAL_RRULE_PROPERTY);

  // Warn about EXRULE being deprecated
  exrule_prop = icalcomponent_get_first_property (vevent, ICAL_EXRULE_PROPERTY);
  if (exrule_prop)
    {
      g_string_append_printf (warnings_buffer,
                              "<warning>"
                              "VEVENT contains the deprecated EXRULE property,"
                              " which will be ignored."
                              "</warning>");
    }

  // Create new, simplified VEVENT from collected data.
  vevent_simplified = icalcomponent_new_vevent ();
  icalcomponent_set_dtstart (vevent_simplified, dtstart);
  icalcomponent_set_duration (vevent_simplified, duration);
  if (rrule_prop)
    {
      icalproperty *prop_clone = icalproperty_new_clone (rrule_prop);
      icalcomponent_add_property (vevent_simplified, prop_clone);
    }

  // Simplify and copy RDATE properties
  rdate_prop = icalcomponent_get_first_property (vevent, ICAL_RDATE_PROPERTY);
  while (rdate_prop)
    {
      struct icaldatetimeperiodtype old_datetimeperiod, new_datetimeperiod;
      icalproperty *new_rdate;

      old_datetimeperiod = icalproperty_get_rdate (rdate_prop);

      // Reduce period to a simple date or datetime.
      new_datetimeperiod.period = icalperiodtype_null_period ();
      if (icalperiodtype_is_null_period (old_datetimeperiod.period))
        {
          new_datetimeperiod.time = old_datetimeperiod.time;
        }
      else
        {
          new_datetimeperiod.time = old_datetimeperiod.period.start;
        }
      new_rdate = icalproperty_new_rdate (new_datetimeperiod);
      icalcomponent_add_property (vevent_simplified, new_rdate);

      rdate_prop =
        icalcomponent_get_next_property (vevent, ICAL_RDATE_PROPERTY);
    }

  // Copy EXDATE properties
  exdate_prop = icalcomponent_get_first_property (vevent, ICAL_EXDATE_PROPERTY);
  while (exdate_prop)
    {
      icalproperty *prop_clone;

      prop_clone = icalproperty_new_clone (exdate_prop);
      icalcomponent_add_property (vevent_simplified, prop_clone);

      exdate_prop =
        icalcomponent_get_next_property (vevent, ICAL_EXDATE_PROPERTY);
    }

  // Generate UID for event
  uid = gvm_uuid_make ();
  icalcomponent_set_uid (vevent_simplified, uid);
  g_free (uid);
  uid = NULL;

  // Set timestamp
  dtstamp = icaltime_current_time_with_zone (icaltimezone_get_utc_timezone ());
  icalcomponent_set_dtstamp (vevent_simplified, dtstamp);

  return vevent_simplified;
}

/**
 * @brief Error return for icalendar_from_string.
 */
#define ICAL_RETURN_ERROR(message)           \
  do                                         \
    {                                        \
      if (error)                             \
        *error = message;                    \
      icalcomponent_free (ical_parsed);      \
      icalcomponent_free (ical_new);         \
      g_string_free (warnings_buffer, TRUE); \
      g_hash_table_destroy (tzids);          \
      return NULL;                           \
    }                                        \
  while (0)

/**
 * @brief Creates a new, simplified VCALENDAR component from a string.
 *
 * @param[in]  ical_string  The ical_string to create the component from.
 * @param[out] error        Output of iCal errors or warnings.
 *
 * @return  A newly allocated, simplified VCALENDAR component.
 */
icalcomponent *
icalendar_from_string (const char *ical_string, gchar **error)
{
  icalcomponent *ical_new, *ical_parsed;
  icalproperty *error_prop;
  GHashTable *tzids;
  GString *warnings_buffer;
  int vevent_count = 0;
  int other_component_count = 0;
  icalcompiter ical_iter;
  GHashTableIter tzids_iter;
  gchar *tzid;

  // Parse the iCalendar string
  ical_parsed = icalcomponent_new_from_string (ical_string);
  if (ical_parsed == NULL)
    {
      if (error)
        *error = g_strdup_printf ("Could not parse iCalendar string");
      return NULL;
    }

  // Check for errors
  icalrestriction_check (ical_parsed);
  error_prop =
    icalcomponent_get_first_property (ical_parsed, ICAL_XLICERROR_PROPERTY);
  if (error_prop)
    {
      if (error)
        *error = g_strdup_printf ("Error in root component: %s",
                                  icalproperty_get_xlicerror (error_prop));
      icalcomponent_free (ical_parsed);
      return NULL;
    }

  // Create buffers and new VCALENDAR
  warnings_buffer = g_string_new ("");
  tzids = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  ical_new = icalcomponent_new_vcalendar ();
  icalcomponent_add_property (ical_new, icalproperty_new_version ("2.0"));
  icalcomponent_add_property (ical_new, icalproperty_new_prodid (GVM_PRODID));

  switch (icalcomponent_isa (ical_parsed))
    {
    case ICAL_NO_COMPONENT:
      // The text must contain valid iCalendar component
      ICAL_RETURN_ERROR (
        g_strdup_printf ("String contains no iCalendar component"));
      break;
    case ICAL_XROOT_COMPONENT:
    case ICAL_VCALENDAR_COMPONENT:
      // Check multiple components
      ical_iter =
        icalcomponent_begin_component (ical_parsed, ICAL_ANY_COMPONENT);
      icalcomponent *subcomp;
      while ((subcomp = icalcompiter_deref (&ical_iter)))
        {
          icalcomponent *new_vevent;
          switch (icalcomponent_isa (subcomp))
            {
            case ICAL_VEVENT_COMPONENT:
              // Copy and simplify only the first VEVENT, ignoring all
              //  following ones.
              if (vevent_count == 0)
                {
                  new_vevent = icalendar_simplify_vevent (
                    subcomp, tzids, error, warnings_buffer);
                  if (new_vevent == NULL)
                    ICAL_RETURN_ERROR (*error);
                  icalcomponent_add_component (ical_new, new_vevent);
                }
              vevent_count++;
              break;
            case ICAL_VTIMEZONE_COMPONENT:
              // Timezones are collected separately
              break;
            case ICAL_VJOURNAL_COMPONENT:
            case ICAL_VTODO_COMPONENT:
              // VJOURNAL and VTODO components are ignored
              other_component_count++;
              break;
            default:
              // Unexpected components
              ICAL_RETURN_ERROR (g_strdup_printf (
                "Unexpected component type: %s",
                icalcomponent_kind_to_string (icalcomponent_isa (subcomp))));
            }
          icalcompiter_next (&ical_iter);
        }

      if (vevent_count == 0)
        {
          ICAL_RETURN_ERROR (
            g_strdup_printf ("iCalendar string must contain a VEVENT"));
        }
      else if (vevent_count > 1)
        {
          g_string_append_printf (warnings_buffer,
                                  "<warning>"
                                  "iCalendar contains %d VEVENT components"
                                  " but only the first one will be used"
                                  "</warning>",
                                  vevent_count);
        }

      if (other_component_count)
        {
          g_string_append_printf (warnings_buffer,
                                  "<warning>"
                                  "iCalendar contains %d VTODO and/or"
                                  " VJOURNAL component(s) which will be"
                                  " ignored"
                                  "</warning>",
                                  other_component_count);
        }
      break;
    case ICAL_VEVENT_COMPONENT:
      {
        icalcomponent *new_vevent;

        new_vevent = icalendar_simplify_vevent (
          ical_parsed, tzids, error, warnings_buffer);
        if (new_vevent == NULL)
          ICAL_RETURN_ERROR (*error);
        icalcomponent_add_component (ical_new, new_vevent);
      }
      break;
    default:
      ICAL_RETURN_ERROR (
        g_strdup_printf ("iCalendar string must be a VCALENDAR or VEVENT"
                         " component or consist of multiple elements."));
      break;
    }

  g_hash_table_iter_init (&tzids_iter, tzids);
  while (g_hash_table_iter_next (&tzids_iter, (gpointer *) (&tzid), NULL))
    {
      icaltimezone *tz;
      tz = icalcomponent_get_timezone (ical_parsed, tzid);
      if (tz)
        {
          icalcomponent *tz_component;

          tz_component = icaltimezone_get_component (tz);
          if (tz_component)
            {
              icalcomponent *tz_component_copy;
              tz_component_copy = icalcomponent_new_clone (tz_component);
              icalcomponent_add_component (ical_new, tz_component_copy);
            }
        }
    }

  g_hash_table_destroy (tzids);
  icalcomponent_free (ical_parsed);

  if (error)
    *error = g_string_free (warnings_buffer, FALSE);
  else
    g_string_free (warnings_buffer, TRUE);

  return ical_new;
}

/**
 * @brief Approximate the recurrence of a VCALENDAR as classic schedule data.
 * The VCALENDAR must have simplified with icalendar_from_string for this to
 *  work reliably.
 *
 * @param[in]  vcalendar       The VCALENDAR component to get the data from.
 * @param[out] period          Output of the period in seconds.
 * @param[out] period_months   Output of the period in months.
 * @param[out] byday_mask      Output of the GVM byday mask.
 *
 * @return 0 success, 1 invalid vcalendar.
 */
int
icalendar_approximate_rrule_from_vcalendar (icalcomponent *vcalendar,
                                            time_t *period,
                                            time_t *period_months,
                                            int *byday_mask)
{
  icalcomponent *vevent;
  icalproperty *rrule_prop;

  assert (period);
  assert (period_months);
  assert (byday_mask);

  *period = 0;
  *period_months = 0;
  *byday_mask = 0;

  // Component must be a VCALENDAR
  if (vcalendar == NULL
      || icalcomponent_isa (vcalendar) != ICAL_VCALENDAR_COMPONENT)
    return 1;

  // Process only the first VEVENT
  // Others should be removed by icalendar_from_string
  vevent = icalcomponent_get_first_component (vcalendar, ICAL_VEVENT_COMPONENT);
  if (vevent == NULL)
    return -1;

  // Process only first RRULE.
  rrule_prop = icalcomponent_get_first_property (vevent, ICAL_RRULE_PROPERTY);
  if (rrule_prop)
    {
      struct icalrecurrencetype recurrence;
      recurrence = icalproperty_get_rrule (rrule_prop);
      int array_pos;

      // Get period or period_months
      switch (recurrence.freq)
        {
        case ICAL_YEARLY_RECURRENCE:
          *period_months = recurrence.interval * 12;
          break;
        case ICAL_MONTHLY_RECURRENCE:
          *period_months = recurrence.interval;
          break;
        case ICAL_WEEKLY_RECURRENCE:
          *period = recurrence.interval * 604800;
          break;
        case ICAL_DAILY_RECURRENCE:
          *period = recurrence.interval * 86400;
          break;
        case ICAL_HOURLY_RECURRENCE:
          *period = recurrence.interval * 3600;
          break;
        case ICAL_MINUTELY_RECURRENCE:
          *period = recurrence.interval * 60;
          break;
        case ICAL_SECONDLY_RECURRENCE:
          *period = recurrence.interval;
        case ICAL_NO_RECURRENCE:
          break;
        default:
          return -1;
        }

      /*
       * Try to approximate byday mask
       * - libical days start at 1 for Sunday.
       * - GVM byday mask bit index starts at 0 for Monday -> Sunday = 6
       */
      array_pos = 0;
      while (recurrence.by_day[array_pos] != ICAL_RECURRENCE_ARRAY_MAX)
        {
          int ical_day =
            icalrecurrencetype_day_day_of_week (recurrence.by_day[array_pos]);
          int mask_bit = -1;

          if (ical_day == 1)
            mask_bit = 6;
          else if (ical_day)
            mask_bit = ical_day - 2;

          if (mask_bit != -1)
            {
              *byday_mask |= (1 << mask_bit);
            }
          array_pos++;
        }
    }

  return 0;
}

/**
 * @brief Collect the times of EXDATE or RDATE properties from an VEVENT.
 * The returned GPtrArray will contain pointers to icaltimetype structs, which
 *  will be freed with g_ptr_array_free.
 *
 * @param[in]  vevent  The VEVENT component to collect times.
 * @param[in]  type    The property to get the times from.
 *
 * @return  GPtrArray with pointers to collected times or NULL on error.
 */
static GPtrArray *
icalendar_times_from_vevent (icalcomponent *vevent, icalproperty_kind type)
{
  GPtrArray *times;
  icalproperty *date_prop;

  if (icalcomponent_isa (vevent) != ICAL_VEVENT_COMPONENT
      || (type != ICAL_EXDATE_PROPERTY && type != ICAL_RDATE_PROPERTY))
    return NULL;

  times = g_ptr_array_new_with_free_func (g_free);

  date_prop = icalcomponent_get_first_property (vevent, type);
  while (date_prop)
    {
      icaltimetype *time;
      time = g_malloc0 (sizeof (icaltimetype));
      if (type == ICAL_EXDATE_PROPERTY)
        {
          *time = icalproperty_get_exdate (date_prop);
        }
      else if (type == ICAL_RDATE_PROPERTY)
        {
          struct icaldatetimeperiodtype datetimeperiod;
          datetimeperiod = icalproperty_get_rdate (date_prop);
          // Assume periods have been converted to date or datetime
          *time = datetimeperiod.time;
        }
      g_ptr_array_insert (times, -1, time);
      date_prop = icalcomponent_get_next_property (vevent, type);
    }

  return times;
}

/**
 * @brief  Tests if an icaltimetype matches one in a GPtrArray.
 * When an icaltimetype is a date, only the date must match, otherwise both
 *  date and time must match.
 *
 * @param[in]  time         The icaltimetype to try to find a match of.
 * @param[in]  times_array  Array of pointers to check for a matching time.
 *
 * @return  Whether a match was found.
 */
static gboolean
icalendar_time_matches_array (icaltimetype time, GPtrArray *times_array)
{
  gboolean found = FALSE;
  int index;

  if (times_array == NULL)
    return FALSE;

  for (index = 0; found == FALSE && index < times_array->len; index++)
    {
      int compare_result;
      icaltimetype *array_time = g_ptr_array_index (times_array, index);

      if (array_time->is_date)
        compare_result = icaltime_compare_date_only (time, *array_time);
      else
        compare_result = icaltime_compare (time, *array_time);

      if (compare_result == 0)
        found = TRUE;
    }
  return found;
}

/**
 * @brief  Get the next or previous time from a list of RDATEs.
 *
 * @param[in]  rdates         The list of RDATEs.
 * @param[in]  tz             The icaltimezone to use.
 * @param[in]  ref_time_ical  The reference time (usually the current time).
 * @param[in]  periods_offset 0 for next, -1 for previous from/before reference.
 *
 * @return  The next or previous time as time_t.
 */
static time_t
icalendar_next_time_from_rdates (GPtrArray *rdates,
                                 icaltimetype ref_time_ical,
                                 icaltimezone *tz,
                                 int periods_offset)
{
  int index;
  time_t ref_time, closest_time;
  int old_diff;

  closest_time = 0;
  ref_time = icaltime_as_timet_with_zone (ref_time_ical, tz);
  if (periods_offset < 0)
    old_diff = INT_MIN;
  else
    old_diff = INT_MAX;

  for (index = 0; index < rdates->len; index++)
    {
      icaltimetype *iter_time_ical;
      time_t iter_time;
      int time_diff;

      iter_time_ical = g_ptr_array_index (rdates, index);
      iter_time = icaltime_as_timet_with_zone (*iter_time_ical, tz);
      time_diff = iter_time - ref_time;

      // Cases: previous (offset -1): lastest before reference
      //        next     (offset  0): earliest after reference
      if ((periods_offset == -1 && time_diff < 0 && time_diff > old_diff)
          || (periods_offset == 0 && time_diff > 0 && time_diff < old_diff))
        {
          closest_time = iter_time;
          old_diff = time_diff;
        }
    }

  return closest_time;
}

/**
 * @brief Calculate the next time of a recurrence
 *
 * @param[in]  recurrence     The recurrence rule to evaluate.
 * @param[in]  dtstart        The start time of the recurrence.
 * @param[in]  reference_time The reference time (usually the current time).
 * @param[in]  tz             The icaltimezone to use.
 * @param[in]  exdates        GList of EXDATE dates or datetimes to skip.
 * @param[in]  rdates         GList of RDATE datetimes to include.
 * @param[in]  periods_offset 0 for next, -1 for previous from/before reference.
 *
 * @return  The next time.
 */
static time_t
icalendar_next_time_from_recurrence (struct icalrecurrencetype recurrence,
                                     icaltimetype dtstart,
                                     icaltimetype reference_time,
                                     icaltimezone *tz,
                                     GPtrArray *exdates,
                                     GPtrArray *rdates,
                                     int periods_offset)
{
  icalrecur_iterator *recur_iter;
  icaltimetype recur_time, prev_time, next_time;
  time_t rrule_time, rdates_time;

  recur_iter = icalrecur_iterator_new (recurrence, dtstart);

  /* Get the first rule-based recurrence time, skipping ahead in case DTSTART
   *  is excluded by EXDATEs.  */
  recur_time = icalrecur_iterator_next (recur_iter);
  while (icaltime_is_null_time (recur_time) == FALSE
         && icalendar_time_matches_array (recur_time, exdates))
    {
      recur_time = icalrecur_iterator_next (recur_iter);
    }

  // Set the first recur_time as either the previous or next time.
  if (icaltime_compare (recur_time, reference_time) < 0)
    {
      prev_time = recur_time;
    }
  else
    {
      prev_time = icaltime_null_time ();
    }

  // Iterate over rule-based recurrences up to first time after reference time
  while (icaltime_is_null_time (recur_time) == FALSE
         && icaltime_compare (recur_time, reference_time) < 0)
    {
      if (icalendar_time_matches_array (recur_time, exdates) == FALSE)
        prev_time = recur_time;

      recur_time = icalrecur_iterator_next (recur_iter);
    }

  // Skip further ahead if last recurrence time is in EXDATEs
  while (icaltime_is_null_time (recur_time) == FALSE
         && icalendar_time_matches_array (recur_time, exdates))
    {
      recur_time = icalrecur_iterator_next (recur_iter);
    }

  // Select last recur_time as the next_time
  next_time = recur_time;

  // Get time from RDATEs
  rdates_time = icalendar_next_time_from_rdates (
    rdates, reference_time, tz, periods_offset);

  // Select appropriate time as the RRULE time, compare it to the RDATEs time
  //  and return the appropriate time.
  if (periods_offset == -1)
    {
      rrule_time = icaltime_as_timet_with_zone (prev_time, tz);
      if (rdates_time == 0 || rrule_time - rdates_time > 0)
        return rrule_time;
      else
        return rdates_time;
    }
  else
    {
      rrule_time = icaltime_as_timet_with_zone (next_time, tz);
      if (rdates_time == 0 || rrule_time - rdates_time < 0)
        return rrule_time;
      else
        return rdates_time;
    }
}

/**
 * @brief  Get the next or previous due time from a VCALENDAR component.
 * The VCALENDAR must have simplified with icalendar_from_string for this to
 *  work reliably.
 *
 * @param[in]  vcalendar       The VCALENDAR component to get the time from.
 * @param[in]  default_tzid    Timezone id to use if none is set in the iCal.
 * @param[in]  periods_offset  0 for next, -1 for previous from/before now.
 *
 * @return The next or previous time as a time_t.
 */
time_t
icalendar_next_time_from_vcalendar (icalcomponent *vcalendar,
                                    const char *default_tzid,
                                    int periods_offset)
{
  icalcomponent *vevent;
  icaltimetype dtstart, ical_now;
  icaltimezone *tz;
  icalproperty *rrule_prop;
  struct icalrecurrencetype recurrence;
  GPtrArray *exdates, *rdates;
  time_t next_time = 0;

  // Only offsets -1 and 0 will work properly
  if (periods_offset < -1 || periods_offset > 0)
    return 0;

  // Component must be a VCALENDAR
  if (vcalendar == NULL
      || icalcomponent_isa (vcalendar) != ICAL_VCALENDAR_COMPONENT)
    return 0;

  // Process only the first VEVENT
  // Others should be removed by icalendar_from_string
  vevent = icalcomponent_get_first_component (vcalendar, ICAL_VEVENT_COMPONENT);
  if (vevent == NULL)
    return 0;

  // Get start time and timezone
  dtstart = icalcomponent_get_dtstart (vevent);
  if (icaltime_is_null_time (dtstart))
    return 0;

  tz = (icaltimezone *) (icaltime_get_timezone (dtstart));
  if (tz == NULL)
    tz = icalendar_timezone_from_tzid (default_tzid);

  // Get current time
  ical_now = icaltime_current_time_with_zone (tz);
  // Set timezone explicitly because icaltime_current_time_with_zone doesn't.
  if (ical_now.zone == NULL)
    {
      ical_now.zone = tz;
    }

  // Get EXDATEs and RDATEs
  exdates = icalendar_times_from_vevent (vevent, ICAL_EXDATE_PROPERTY);
  rdates = icalendar_times_from_vevent (vevent, ICAL_RDATE_PROPERTY);

  // Try to get the recurrence from the RRULE property
  rrule_prop = icalcomponent_get_first_property (vevent, ICAL_RRULE_PROPERTY);
  if (rrule_prop)
    recurrence = icalproperty_get_rrule (rrule_prop);
  else
    icalrecurrencetype_clear (&recurrence);

  // Calculate next time.
  next_time = icalendar_next_time_from_recurrence (
    recurrence, dtstart, ical_now, tz, exdates, rdates, periods_offset);

  // Cleanup
  g_ptr_array_free (exdates, TRUE);
  g_ptr_array_free (rdates, TRUE);

  return next_time;
}

/**
 * @brief  Get the next or previous due time from a VCALENDAR string.
 * The string must be a VCALENDAR simplified with icalendar_from_string for
 *  this to work reliably.
 *
 * @param[in]  ical_string     The VCALENDAR string to get the time from.
 * @param[in]  default_tzid    Timezone id to use if none is set in the iCal.
 * @param[in]  periods_offset  0 for next, -1 for previous from/before now.
 *
 * @return The next or previous time as a time_t.
 */
time_t
icalendar_next_time_from_string (const char *ical_string,
                                 const char *default_tzid,
                                 int periods_offset)
{
  time_t next_time;
  icalcomponent *ical_parsed;

  ical_parsed = icalcomponent_new_from_string (ical_string);
  next_time = icalendar_next_time_from_vcalendar (
    ical_parsed, default_tzid, periods_offset);
  icalcomponent_free (ical_parsed);
  return next_time;
}

/**
 * @brief  Get the duration VCALENDAR component.
 * The VCALENDAR must have simplified with icalendar_from_string for this to
 *  work reliably.
 *
 * @param[in]  vcalendar       The VCALENDAR component to get the time from.
 *
 * @return The duration in seconds.
 */
int
icalendar_duration_from_vcalendar (icalcomponent *vcalendar)
{
  icalcomponent *vevent;
  struct icaldurationtype duration;

  // Component must be a VCALENDAR
  if (vcalendar == NULL
      || icalcomponent_isa (vcalendar) != ICAL_VCALENDAR_COMPONENT)
    return 0;

  // Process only the first VEVENT
  // Others should be removed by icalendar_from_string
  vevent = icalcomponent_get_first_component (vcalendar, ICAL_VEVENT_COMPONENT);
  if (vevent == NULL)
    return 0;

  // Get the duration
  duration = icalcomponent_get_duration (vevent);

  // Convert to time_t
  return icaldurationtype_as_int (duration);
}

/**
 * @brief  Get the first time from a VCALENDAR component.
 * The VCALENDAR must have simplified with icalendar_from_string for this to
 *  work reliably.
 *
 * @param[in]  vcalendar       The VCALENDAR component to get the time from.
 * @param[in]  default_tzid    Timezone id to use if none is set in the iCal.
 *
 * @return The first time as a time_t.
 */
time_t
icalendar_first_time_from_vcalendar (icalcomponent *vcalendar,
                                     const char *default_tzid)
{
  icalcomponent *vevent;
  icaltimetype dtstart;
  icaltimezone *tz;

  // Component must be a VCALENDAR
  if (vcalendar == NULL
      || icalcomponent_isa (vcalendar) != ICAL_VCALENDAR_COMPONENT)
    return 0;

  // Process only the first VEVENT
  // Others should be removed by icalendar_from_string
  vevent = icalcomponent_get_first_component (vcalendar, ICAL_VEVENT_COMPONENT);
  if (vevent == NULL)
    return 0;

  // Get start time and timezone
  dtstart = icalcomponent_get_dtstart (vevent);
  if (icaltime_is_null_time (dtstart))
    return 0;

  tz = (icaltimezone *) (icaltime_get_timezone (dtstart));
  if (tz == NULL)
    tz = icalendar_timezone_from_tzid (default_tzid);

  // Convert to time_t
  return icaltime_as_timet_with_zone (dtstart, tz);
}
