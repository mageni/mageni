/* Copyright (C) 2009-2019 Greenbone Networks GmbH
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
 * @file
 * @brief Implementation of API to handle NVT Info Cache
 *
 * This file contains all methods to handle NVT Information Cache
 * (nvticache_t).
 *
 * The module consequently uses glib datatypes and api for memory
 * management etc.
 */

#include "nvticache.h"

#include "kb.h" /* for kb_del_items, kb_item_get_str, kb_item_add_int */

#include <assert.h> /* for assert */
#include <errno.h>
#include <stdio.h>    /* for fopen */
#include <stdlib.h>   /* for atoi */
#include <string.h>   /* for strcmp */
#include <sys/stat.h> /* for stat, st_mtime */
#include <time.h>     /* for time, time_t */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "lib  nvticache"

char *src_path = NULL; /**< The directory of the source files. */
kb_t cache_kb = NULL;  /**< Cache KB handler. */
int cache_saved = 1;   /**< If cache was saved. */

/**
 * @brief Return whether the nvt cache is initialized.
 *
 * @return 1 if cache is initialized, 0 otherwise.
 */
int
nvticache_initialized (void)
{
  return !!cache_kb;
}

/**
 * @brief Initializes the nvti cache.
 *
 * @param src           The directory that contains the nvt files.
 * @param kb_path       Path to kb socket.
 *
 * @return 0 in case of success, anything else indicates an error.
 */
int
nvticache_init (const char *src, const char *kb_path)
{
  assert (src);

  if (src_path)
    g_free (src_path);
  src_path = g_strdup (src);
  if (cache_kb)
    kb_lnk_reset (cache_kb);
  cache_kb = kb_find (kb_path, NVTICACHE_STR);
  if (cache_kb)
    return 0;

  if (kb_new (&cache_kb, kb_path)
      || kb_item_set_str (cache_kb, NVTICACHE_STR, "1", 0))
    return -1;
  return 0;
}

/**
 * @brief Return the nvticache kb.
 *
 * @return Cache kb.
 */
kb_t
nvticache_get_kb (void)
{
  assert (cache_kb);
  return cache_kb;
}

/**
 * @brief Check if the nvt for the given filename exists in cache.
 *
 * @param filename The name of the original NVT without the path
 *                 to the base location of NVTs (e.g.
 *                 "scriptname1.nasl" or even
 *                 "subdir1/subdir2/scriptname2.nasl" )
 *
 * @return 1 if nvt is in cache and up to date, 0 otherwise.
 */
int
nvticache_check (const gchar *filename)
{
  assert (cache_kb);
  char *src_file, *time_s;
  struct stat src_stat;
  int ret = 0;

  src_file = g_build_filename (src_path, filename, NULL);
  time_s = kb_nvt_get (cache_kb, filename, NVT_TIMESTAMP_POS);
  if (time_s && src_file && stat (src_file, &src_stat) >= 0
      && atoi (time_s) > src_stat.st_mtime)
    ret = 1;
  g_free (time_s);
  g_free (src_file);
  return ret;
}

/**
 * @brief Reset connection to KB. To be called after a fork().
 */
void
nvticache_reset ()
{
  if (cache_kb)
    kb_lnk_reset (cache_kb);
}

/**
 * @brief Determine the version of the NVT feed.
 *
 * @return Feed version string if success, NULL otherwise.
 */
static char *
nvt_feed_version ()
{
  char filename[2048], *fcontent = NULL, *plugin_set;
  GError *error = NULL;
  static int msg_shown = 0;

  g_snprintf (filename, sizeof (filename), "%s/plugin_feed_info.inc", src_path);
  if (!g_file_get_contents (filename, &fcontent, NULL, &error))
    {
      if (error && msg_shown == 0)
	{
	  g_warning ("nvt_feed_version: %s", error->message);
	  msg_shown = 1;
	}
      g_error_free (error);
      return NULL;
    }
  plugin_set = g_strrstr (fcontent, "PLUGIN_SET = ");
  if (!plugin_set)
    {
      g_warning ("nvt_feed_version: Erroneous %s format", filename);
      g_free (fcontent);
      return NULL;
    }
  msg_shown = 0;
  plugin_set = g_strndup (plugin_set + 14, 12);
  g_free (fcontent);
  return plugin_set;
}

/**
 * @brief Save the nvticache to disk.
 */
void
nvticache_save ()
{
  char *feed_version;
  if (cache_kb && !cache_saved)
    {
      kb_save (cache_kb);
      cache_saved = 1;
    }
  if ((feed_version = nvt_feed_version ()))
    kb_item_set_str (cache_kb, NVTICACHE_STR, feed_version, 0);
  g_free (feed_version);
}

/**
 * @brief Add a NVT Information to the cache.
 *
 * @param nvti     The NVT Information to add
 *
 * @param filename The name of the original NVT without the path
 *                 to the base location of NVTs (e.g.
 *                 "scriptname1.nasl" or even
 *                 "subdir1/subdir2/scriptname2.nasl" )
 *
 * @return 0 in case of success, anything else indicates an error.
 */
int
nvticache_add (const nvti_t *nvti, const char *filename)
{
  char *oid, *dummy;

  assert (cache_kb);
  /* Check for duplicate OID. */
  oid = nvti_oid (nvti);
  dummy = nvticache_get_filename (oid);
  if (dummy && strcmp (filename, dummy))
    {
      struct stat src_stat;
      char *src_file = g_build_filename (src_path, dummy, NULL);

      /* If .nasl file was duplicated, not moved. */
      if (src_file && stat (src_file, &src_stat) >= 0)
        g_warning ("NVT %s with duplicate OID %s will be replaced with %s",
                   src_file, oid, filename);
      g_free (src_file);
    }
  if (dummy)
    nvticache_delete (oid);

  g_free (dummy);

  if (kb_nvt_add (cache_kb, nvti, filename))
    goto kb_fail;
  cache_saved = 0;

  return 0;
kb_fail:
  return -1;
}

/**
 * @brief Get the full source filename of an OID.
 *
 * @param oid      The OID to look up.
 *
 * @return Filename with full path matching OID if found, NULL otherwise.
 */
char *
nvticache_get_src (const char *oid)
{
  char *filename, *src;

  assert (cache_kb);

  filename = kb_nvt_get (cache_kb, oid, NVT_FILENAME_POS);
  if (!filename)
    return NULL;
  src = g_build_filename (src_path, filename, NULL);
  g_free (filename);
  return src;
}

/**
 * @brief Get the OID from a plugin filename.
 *
 * @param filename      Filename to lookup.
 *
 * @return OID matching filename if found, NULL otherwise.
 */
char *
nvticache_get_oid (const char *filename)
{
  assert (cache_kb);

  return kb_nvt_get (cache_kb, filename, NVT_OID_POS);
}

/**
 * @brief Get the filename from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Filanem matching OID, NULL otherwise.
 */
char *
nvticache_get_filename (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_FILENAME_POS);
}

/**
 * @brief Get the Required Keys from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Required Keys matching OID, NULL otherwise.
 */
char *
nvticache_get_required_keys (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_REQUIRED_KEYS_POS);
}

/**
 * @brief Get the Mandatory Keys from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Mandatory Keys matching OID, NULL otherwise.
 */
char *
nvticache_get_mandatory_keys (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_MANDATORY_KEYS_POS);
}

/**
 * @brief Get the Excluded Keys from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Excluded Keys matching OID, NULL otherwise.
 */
char *
nvticache_get_excluded_keys (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_EXCLUDED_KEYS_POS);
}

/**
 * @brief Get the Required udp ports from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Required udp ports matching OID, NULL otherwise.
 */
char *
nvticache_get_required_udp_ports (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_REQUIRED_UDP_PORTS_POS);
}

/**
 * @brief Get the Required ports from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Required ports matching OID, NULL otherwise.
 */
char *
nvticache_get_required_ports (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_REQUIRED_PORTS_POS);
}

/**
 * @brief Get the Dependencies from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Dependencies matching OID, NULL otherwise.
 */
char *
nvticache_get_dependencies (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_DEPENDENCIES_POS);
}

/**
 * @brief Get the Category from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Category matching OID, -1 otherwise.
 */
int
nvticache_get_category (const char *oid)
{
  int category;
  char *category_s;

  assert (cache_kb);
  category_s = kb_nvt_get (cache_kb, oid, NVT_CATEGORY_POS);
  category = atoi (category_s);
  g_free (category_s);
  return category;
}

/**
 * @brief Get the Timeout from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Timeout matching OID, -1 otherwise.
 */
int
nvticache_get_timeout (const char *oid)
{
  int timeout;
  char *timeout_s;

  assert (cache_kb);
  timeout_s = kb_nvt_get (cache_kb, oid, NVT_TIMEOUT_POS);
  timeout = atoi (timeout_s);
  g_free (timeout_s);
  return timeout;
}

/**
 * @brief Get the name from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Name matching OID, NULL otherwise.
 */
char *
nvticache_get_name (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_NAME_POS);
}

/**
 * @brief Get the cves from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return CVEs matching OID, NULL otherwise.
 */
char *
nvticache_get_cves (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_CVES_POS);
}

/**
 * @brief Get the bids from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return BIDs matching OID, NULL otherwise.
 */
char *
nvticache_get_bids (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_BIDS_POS);
}

/**
 * @brief Get the xrefs from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return XREFs matching OID, NULL otherwise.
 */
char *
nvticache_get_xrefs (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_XREFS_POS);
}

/**
 * @brief Get the family from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Family matching OID, NULL otherwise.
 */
char *
nvticache_get_family (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_FAMILY_POS);
}

/**
 * @brief Get the tags from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Tags matching OID, NULL otherwise.
 */
char *
nvticache_get_tags (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get (cache_kb, oid, NVT_TAGS_POS);
}

/**
 * @brief Get the nvti from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Full nvti matching OID, NULL otherwise.
 */
nvti_t *
nvticache_get_nvt (const char *oid)
{
  assert (cache_kb);
  return kb_nvt_get_all (cache_kb, oid);
}

/**
 * @brief Get the prefs from a plugin OID.
 *
 * @param[in]   oid     OID to match.
 *
 * @return Prefs matching OID, NULL otherwise.
 */
GSList *
nvticache_get_prefs (const char *oid)
{
  char pattern[4096];
  struct kb_item *prefs, *element;
  GSList *list = NULL;

  assert (cache_kb);

  g_snprintf (pattern, sizeof (pattern), "oid:%s:prefs", oid);
  prefs = element = kb_item_get_all (cache_kb, pattern);
  while (element)
    {
      nvtpref_t *np;
      char **array = g_strsplit (element->v_str, "|||", -1);

      assert (array[2]);
      assert (!array[3]);
      np = g_malloc0 (sizeof (nvtpref_t));
      np->name = array[0];
      np->type = array[1];
      np->dflt = array[2];
      g_free (array);
      list = g_slist_append (list, np);
      element = element->next;
    }
  kb_item_free (prefs);

  return list;
}

/**
 * @brief Get the list of nvti OIDs.
 *
 * @return OIDs list.
 */
GSList *
nvticache_get_oids ()
{
  assert (cache_kb);

  return kb_nvt_get_oids (cache_kb);
}

/**
 * @brief Get the number of nvt's in the cache.
 *
 * @return Number of nvt's.
 */
size_t
nvticache_count ()
{
  assert (cache_kb);

  return kb_item_count (cache_kb, "nvt:*");
}

/**
 * @brief Delete NVT from the cache.
 * @param[in] oid OID to match.
 */
void
nvticache_delete (const char *oid)
{
  char pattern[4096];
  char *filename;

  assert (cache_kb);
  assert (oid);

  filename = nvticache_get_filename (oid);
  g_snprintf (pattern, sizeof (pattern), "oid:%s:prefs", oid);
  kb_del_items (cache_kb, pattern);
  g_snprintf (pattern, sizeof (pattern), "nvt:%s", oid);
  kb_del_items (cache_kb, pattern);

  if (filename)
    {
      g_snprintf (pattern, sizeof (pattern), "filename:%s", filename);
      kb_del_items (cache_kb, pattern);
    }
  g_free (filename);
}

/**
 * @brief Get the NVT feed version.
 *
 * @return Feed version.
 */
char *
nvticache_feed_version (void)
{
  return kb_item_get_str (cache_kb, NVTICACHE_STR);
}

/**
 * @brief Check if the plugins feed was newer than cached feed.
 *
 * @return 1 if new feed, 0 if matching feeds or error.
 */
int
nvticache_check_feed (void)
{
  char *cached, *current;
  int ret;

  if (!(current = nvt_feed_version ()))
    return 0;
  cached = kb_item_get_str (cache_kb, NVTICACHE_STR);
  ret = strcmp (cached, current);
  g_free (cached);
  g_free (current);
  return ret;
}
