/* Copyright (C) 2014-2019 Greenbone Networks GmbH
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
 * @brief Knowledge base management API - Redis backend.
 */

#define _GNU_SOURCE

#include "kb.h"

#include <errno.h> /* for ENOMEM, EINVAL, EPROTO, EALREADY, ECONN... */
#include <glib.h>  /* for g_log, g_free */
#include <hiredis/hiredis.h> /* for redisReply, freeReplyObject, redisCommand */
#include <stdbool.h>         /* for bool, true, false */
#include <stdio.h>
#include <stdlib.h> /* for atoi */
#include <string.h> /* for strlen, strerror, strncpy, memset */
#include <unistd.h> /* for sleep */

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "lib  kb"

/**
 * @file kb.c
 *
 * @brief Contains specialized structures and functions to use redis as a KB
 *        server.
 */

/**
 * @brief Name of the namespace usage bitmap in redis.
 */
#define GLOBAL_DBINDEX_NAME "MGN.__GlobalDBIndex"

/**
 * @brief Number of seconds to wait for between two attempts to acquire a KB
 *        namespace.
 */
#define KB_RETRY_DELAY 60

static const struct kb_operations KBRedisOperations;

/**
 * @brief Subclass of struct kb, it contains the redis-specific fields, such as
 *        the redis context, current DB (namespace) id and the server socket
 *        path.
 */
struct kb_redis
{
  struct kb kb;        /**< Parent KB handle. */
  unsigned int max_db; /**< Max # of databases. */
  unsigned int db;     /**< Namespace ID number, 0 if uninitialized. */
  redisContext *rctx;  /**< Redis client context. */
  char path[0];        /**< Path to the server socket. */
};
#define redis_kb(__kb) ((struct kb_redis *) (__kb))

static int
redis_delete_all (struct kb_redis *);
static int redis_lnk_reset (kb_t);
static int
redis_flush_all (kb_t, const char *);
static redisReply *
redis_cmd (struct kb_redis *kbr, const char *fmt, ...);

/**
 * @brief Attempt to atomically acquire ownership of a database.
 * @return 0 on success, negative integer otherwise.
 */
static int
try_database_index (struct kb_redis *kbr, int index)
{
  redisContext *ctx = kbr->rctx;
  redisReply *rep;
  int rc = 0;

  rep = redisCommand (ctx, "HSETNX %s %d 1", GLOBAL_DBINDEX_NAME, index);
  if (rep == NULL)
    return -ENOMEM;

  if (rep->type != REDIS_REPLY_INTEGER)
    rc = -EPROTO;
  else if (rep->integer == 0)
    rc = -EALREADY;
  else
    kbr->db = index;

  freeReplyObject (rep);

  return rc;
}

/* Redis 2.4.* compatibility mode.
 *
 * Before 2.6.* redis won't tell its clients how many databases have been
 * configured. We can find it empirically by attempting to select a given
 * DB and seeing whether we get an error or not.
 */
/**
 * @brief Max number of configured DB.
 */
#define MAX_DB_INDEX__24 1000

/**
 * @brief Set the number of databases have been configured
 *        into kbr struct. (For Redis 2.4.* compatibility).
 * @param[in] kbr Subclass of struct kb where to save the max db index founded.
 * @return 0 on success, -1 on error.
 */
static int
fetch_max_db_index_compat (struct kb_redis *kbr)
{
  redisContext *ctx = kbr->rctx;
  redisReply *rep;
  int min, max;
  int rc = 0;

  min = 1;
  max = MAX_DB_INDEX__24;

  while (min < max)
    {
      int current;

      current = min + ((max - min) / 2);

      rep = redisCommand (ctx, "SELECT %d", current);
      if (rep == NULL)
        {
          g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
                 "%s: redis command failed with '%s'", __func__, ctx->errstr);
          return -1;
        }

      switch (rep->type)
        {
        case REDIS_REPLY_ERROR:
          max = current;
          break;

        case REDIS_REPLY_STATUS:
          min = current + 1;
          break;

        default:
          g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
                 "%s: unexpected reply of type %d", __func__, rep->type);
          freeReplyObject (rep);
          return -1;
        }
      freeReplyObject (rep);
    }

  kbr->max_db = min;

  /* Go back to DB #0 */
  rep = redisCommand (ctx, "SELECT 0");
  if (rep == NULL)
    {
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
             "%s: DB selection failed with '%s'", __func__, ctx->errstr);
      rc = -1;
    }

  if (rep)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Set the number of databases have been configured
 *        into kbr struct.
 * @param[in] kbr Subclass of struct kb where to save the max db index founded.
 * @return 0 on success, -1 on error.
 */
static int
fetch_max_db_index (struct kb_redis *kbr)
{
  int rc = 0;
  redisContext *ctx = kbr->rctx;
  redisReply *rep = NULL;

  rep = redisCommand (ctx, "CONFIG GET databases");
  if (rep == NULL)
    {
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
             "%s: redis command failed with '%s'", __func__, ctx->errstr);
      rc = -1;
      goto err_cleanup;
    }

  if (rep->type != REDIS_REPLY_ARRAY)
    {
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
             "%s: cannot retrieve max DB number: %s", __func__, rep->str);
      rc = -1;
      goto err_cleanup;
    }

  if (rep->elements == 0)
    {
      /* Redis 2.4 compatibility mode. Suboptimal... */
      rc = fetch_max_db_index_compat (kbr);
    }
  else if (rep->elements == 2)
    {
      kbr->max_db = (unsigned) atoi (rep->element[1]->str);
    }
  else
    {
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
             "%s: unexpected reply length (%zd)", __func__, rep->elements);
      rc = -1;
      goto err_cleanup;
    }

  g_debug ("%s: maximum DB number: %u", __func__, kbr->max_db);

err_cleanup:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Select DB.
 * @param[in] kbr Subclass of struct kb where to save the db index.
 * @return 0 on success, -1 on error.
 *
 * WARNING: do not call redis_cmd in here, since our context is not fully
 * acquired yet!
 */
static int
select_database (struct kb_redis *kbr)
{
  int rc;
  redisContext *ctx = kbr->rctx;
  redisReply *rep = NULL;

  if (kbr->db == 0)
    {
      unsigned i;

      if (kbr->max_db == 0)
        fetch_max_db_index (kbr);

      for (i = 1; i < kbr->max_db; i++)
        {
          rc = try_database_index (kbr, i);
          if (rc == 0)
            break;
        }
    }

  /* No DB available, give up. */
  if (kbr->db == 0)
    {
      rc = -1;
      goto err_cleanup;
    }

  rep = redisCommand (ctx, "SELECT %u", kbr->db);
  if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
    {
      rc = -1;
      goto err_cleanup;
    }

  rc = 0;

err_cleanup:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Release DB.
 * @param[in] kbr Subclass of struct kb.
 *
 * @return 0 on success, -1 on error.
 */
static int
redis_release_db (struct kb_redis *kbr)
{
  int rc;
  redisContext *ctx = kbr->rctx;
  redisReply *rep;

  if (ctx == NULL)
    return -EINVAL;

  rep = redisCommand (ctx, "SELECT 0"); /* Management database*/
  if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
    {
      rc = -1;
      goto err_cleanup;
    }
  freeReplyObject (rep);

  rep = redisCommand (ctx, "HDEL %s %d", GLOBAL_DBINDEX_NAME, kbr->db);
  if (rep == NULL || rep->type != REDIS_REPLY_INTEGER)
    {
      rc = -1;
      goto err_cleanup;
    }

  rc = 0;

err_cleanup:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Get redis context if it is already connected or do a
 *        a connection.
 * @param[in] kbr Subclass of struct kb where to fetch the context.
 *                or where it is saved in case of a new connection.
 * @return Redis context on success, NULL otherwise.
 */
static redisContext *
get_redis_ctx (struct kb_redis *kbr)
{
  int rc;

  if (kbr->rctx != NULL)
    return kbr->rctx;

  do
    {
      kbr->rctx = redisConnectUnix (kbr->path);
      if (kbr->rctx == NULL || kbr->rctx->err)
        {
          g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
                 "%s: redis connection error: %s", __func__,
                 kbr->rctx ? kbr->rctx->errstr : strerror (ENOMEM));
          redisFree (kbr->rctx);
          kbr->rctx = NULL;
          return NULL;
        }

      rc = select_database (kbr);
      if (rc)
        {
          g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
                 "%s: No redis DB available, retrying in %ds...", __func__,
                 KB_RETRY_DELAY);
          sleep (KB_RETRY_DELAY);
          redisFree (kbr->rctx);
          kbr->rctx = NULL;
        }
    }
  while (rc != 0);

  g_debug ("%s: connected to redis://%s/%d", __func__, kbr->path, kbr->db);
  return kbr->rctx;
}

/**
 * @brief Test redis connection.
 * @param[in] kbr Subclass of struct kb to test.
 * @return 0 on success, negative integer on error.
 */
static int
redis_test_connection (struct kb_redis *kbr)
{
  int rc = 0;
  redisReply *rep;

  rep = redis_cmd (kbr, "PING");
  if (rep == NULL)
    {
      /* not 100% relevant but hiredis doesn't provide us with proper error
       * codes. */
      rc = -ECONNREFUSED;
      goto out;
    }

  if (rep->type != REDIS_REPLY_STATUS)
    {
      rc = -EINVAL;
      goto out;
    }

  if (g_ascii_strcasecmp (rep->str, "PONG"))
    {
      rc = -EPROTO;
      goto out;
    }

out:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Delete all entries and release ownership on the namespace.
 * @param[in] kb KB handle to release.
 * @return 0 on success, non-null on error.
 */
static int
redis_delete (kb_t kb)
{
  struct kb_redis *kbr;

  kbr = redis_kb (kb);

  redis_delete_all (kbr);
  redis_release_db (kbr);

  if (kbr->rctx != NULL)
    {
      redisFree (kbr->rctx);
      kbr->rctx = NULL;
    }

  g_free (kb);
  return 0;
}

/**
 * @brief Return the kb index
 * @param[in] kb KB handle.
 * @return kb_index on success, null on error.
 */
static int
redis_get_kb_index (kb_t kb)
{
  int i;
  i = ((struct kb_redis *) kb)->db;
  if (i > 0)
    return i;
  return -1;
}

/**
 * @brief Initialize a new Knowledge Base object.
 * @param[in] kb  Reference to a kb_t to initialize.
 * @param[in] kb_path   Path to KB.
 * @return 0 on success, non-null on error.
 */
static int
redis_new (kb_t *kb, const char *kb_path)
{
  struct kb_redis *kbr;
  int rc = 0;

  kbr = g_malloc0 (sizeof (struct kb_redis) + strlen (kb_path) + 1);
  kbr->kb.kb_ops = &KBRedisOperations;
  strncpy (kbr->path, kb_path, strlen (kb_path));

  rc = redis_test_connection (kbr);
  if (rc)
    {
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
             "%s: cannot access redis at '%s'", __func__, kb_path);
      redis_delete ((kb_t) kbr);
      kbr = NULL;
    }

  *kb = (kb_t) kbr;

  return rc;
}

/**
 * @brief Connect to a Knowledge Base object with the given kb_index.
 * @param[in] kb_path   Path to KB.
 * @param[in] kb_index       DB index
 * @return Knowledge Base object, NULL otherwise.
 */
static kb_t
redis_direct_conn (const char *kb_path, const int kb_index)
{
  struct kb_redis *kbr;
  redisReply *rep;

  kbr = g_malloc0 (sizeof (struct kb_redis) + strlen (kb_path) + 1);
  kbr->kb.kb_ops = &KBRedisOperations;
  strncpy (kbr->path, kb_path, strlen (kb_path));

  kbr->rctx = redisConnectUnix (kbr->path);
  if (kbr->rctx == NULL || kbr->rctx->err)
    {
      g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
             "%s: redis connection error: %s", __func__,
             kbr->rctx ? kbr->rctx->errstr : strerror (ENOMEM));
      redisFree (kbr->rctx);
      g_free (kbr);
      return NULL;
    }
  kbr->db = kb_index;
  rep = redisCommand (kbr->rctx, "SELECT %d", kb_index);
  if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
    {
      if (rep != NULL)
        freeReplyObject (rep);
      redisFree (kbr->rctx);
      kbr->rctx = NULL;
      return NULL;
    }
  freeReplyObject (rep);
  return (kb_t) kbr;
}

/**
 * @brief Find an existing Knowledge Base object with key.
 * @param[in] kb_path   Path to KB.
 * @param[in] key       Marker key to search for in KB objects.
 * @return Knowledge Base object, NULL otherwise.
 */
static kb_t
redis_find (const char *kb_path, const char *key)
{
  struct kb_redis *kbr;
  unsigned int i = 1;

  kbr = g_malloc0 (sizeof (struct kb_redis) + strlen (kb_path) + 1);
  kbr->kb.kb_ops = &KBRedisOperations;
  strncpy (kbr->path, kb_path, strlen (kb_path));

  do
    {
      redisReply *rep;

      kbr->rctx = redisConnectUnix (kbr->path);
      if (kbr->rctx == NULL || kbr->rctx->err)
        {
          g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
                 "%s: redis connection error: %s", __func__,
                 kbr->rctx ? kbr->rctx->errstr : strerror (ENOMEM));
          redisFree (kbr->rctx);
          g_free (kbr);
          return NULL;
        }

      if (kbr->max_db == 0)
        fetch_max_db_index (kbr);

      kbr->db = i;
      rep = redisCommand (kbr->rctx, "HEXISTS %s %d", GLOBAL_DBINDEX_NAME, i);
      if (rep == NULL || rep->type != REDIS_REPLY_INTEGER || rep->integer != 1)
        {
          if (rep != NULL)
            freeReplyObject (rep);
          i++;
          redisFree (kbr->rctx);
          kbr->rctx = NULL;
          continue;
        }
      freeReplyObject (rep);
      rep = redisCommand (kbr->rctx, "SELECT %u", i);
      if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
        {
          sleep (KB_RETRY_DELAY);
          kbr->rctx = NULL;
        }
      else
        {
          freeReplyObject (rep);
          if (key)
            {
              char *tmp = kb_item_get_str (&kbr->kb, key);
              if (tmp)
                {
                  g_free (tmp);
                  return (kb_t) kbr;
                }
            }
        }
      redisFree (kbr->rctx);
      i++;
    }
  while (i < kbr->max_db);

  g_free (kbr);
  return NULL;
}

/**
 * @brief Release a KB item (or a list).
 * @param[in] item Item or list to be release
 */
void
kb_item_free (struct kb_item *item)
{
  while (item != NULL)
    {
      struct kb_item *next;

      next = item->next;
      if (item->type == KB_TYPE_STR && item->v_str != NULL)
        g_free (item->v_str);
      g_free (item);
      item = next;
    }
}

/**
 * @brief Give a single KB item.
 * @param[in] name Name of the item.
 * @param[in] elt A redisReply element where to fetch the item.
 * @param[in] force_int To force string to integer conversion.
 * @return Single retrieve kb_item on success, NULL otherwise.
 */
static struct kb_item *
redis2kbitem_single (const char *name, const redisReply *elt, int force_int)
{
  struct kb_item *item;
  size_t namelen;

  if (elt->type != REDIS_REPLY_STRING && elt->type != REDIS_REPLY_INTEGER)
    return NULL;

  namelen = strlen (name) + 1;

  item = g_malloc0 (sizeof (struct kb_item) + namelen);
  if (elt->type == REDIS_REPLY_INTEGER)
    {
      item->type = KB_TYPE_INT;
      item->v_int = elt->integer;
    }
  else if (force_int)
    {
      item->type = KB_TYPE_INT;
      item->v_int = atoi (elt->str);
    }
  else
    {
      item->type = KB_TYPE_STR;
      item->v_str = g_memdup (elt->str, elt->len + 1);
      item->len = elt->len;
    }

  item->next = NULL;
  item->namelen = namelen;
  strncpy (item->name, name, namelen);

  return item;
}

/**
 * @brief Fetch a KB item or list from a redis Reply.
 * @param[in] name Name of the item.
 * @param[in] rep A redisReply element where to fetch the item.
 * @return kb_item or list on success, NULL otherwise.
 */
static struct kb_item *
redis2kbitem (const char *name, const redisReply *rep)
{
  struct kb_item *kbi;

  kbi = NULL;

  switch (rep->type)
    {
      unsigned int i;

    case REDIS_REPLY_STRING:
    case REDIS_REPLY_INTEGER:
      kbi = redis2kbitem_single (name, rep, 0);
      break;

    case REDIS_REPLY_ARRAY:
      for (i = 0; i < rep->elements; i++)
        {
          struct kb_item *tmpitem;

          tmpitem = redis2kbitem_single (name, rep->element[i], 0);
          if (tmpitem == NULL)
            break;

          if (kbi != NULL)
            {
              tmpitem->next = kbi;
              kbi = tmpitem;
            }
          else
            kbi = tmpitem;
        }
      break;

    case REDIS_REPLY_NIL:
    case REDIS_REPLY_STATUS:
    case REDIS_REPLY_ERROR:
    default:
      break;
    }

  return kbi;
}

/**
 * @brief Execute a redis command and get a redis reply.
 * @param[in] kbr Subclass of struct kb to connect to.
 * @param[in] fmt Formatted variable argument list with the cmd to be executed.
 * @return Redis reply on success, NULL otherwise.
 */
static redisReply *
redis_cmd (struct kb_redis *kbr, const char *fmt, ...)
{
  redisReply *rep;
  va_list ap, aq;
  int retry = 0;

  va_start (ap, fmt);
  do
    {
      redisContext *ctx;

      rep = NULL;

      ctx = get_redis_ctx (kbr);
      if (ctx == NULL)
        {
          va_end (ap);
          return NULL;
        }

      va_copy (aq, ap);
      rep = redisvCommand (ctx, fmt, aq);
      va_end (aq);

      if (ctx->err)
        {
          if (rep != NULL)
            freeReplyObject (rep);

          redis_lnk_reset ((kb_t) kbr);
          retry = !retry;
        }
      else
        retry = 0;
    }
  while (retry);

  va_end (ap);

  return rep;
}

/**
 * @brief Get a single KB element.
 * @param[in] kb KB handle where to fetch the item.
 * @param[in] name  Name of the element to retrieve.
 * @param[in] type Desired element type.
 * @return A struct kb_item to be freed with kb_item_free() or NULL if no
 *         element was found or on error.
 */
static struct kb_item *
redis_get_single (kb_t kb, const char *name, enum kb_item_type type)
{
  struct kb_item *kbi;
  struct kb_redis *kbr;
  redisReply *rep;

  kbr = redis_kb (kb);
  kbi = NULL;

  rep = redis_cmd (kbr, "LINDEX %s -1", name);
  if (rep == NULL || rep->type != REDIS_REPLY_STRING)
    {
      kbi = NULL;
      goto out;
    }

  kbi = redis2kbitem_single (name, rep, type == KB_TYPE_INT);

out:
  if (rep != NULL)
    freeReplyObject (rep);

  return kbi;
}

/**
 * @brief Get a single KB string item.
 * @param[in] kb  KB handle where to fetch the item.
 * @param[in] name  Name of the element to retrieve.
 * @return A struct kb_item to be freed with kb_item_free() or NULL if no
 *         element was found or on error.
 */
static char *
redis_get_str (kb_t kb, const char *name)
{
  struct kb_item *kbi;

  kbi = redis_get_single (kb, name, KB_TYPE_STR);
  if (kbi != NULL)
    {
      char *res;

      res = kbi->v_str;
      kbi->v_str = NULL;
      kb_item_free (kbi);
      return res;
    }
  return NULL;
}

/**
 * @brief Push a new entry under a given key.
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Key to push to.
 * @param[in] value Value to push.
 * @return 0 on success, non-null on error.
 */
static int
redis_push_str (kb_t kb, const char *name, const char *value)
{
  struct kb_redis *kbr;
  redisReply *rep = NULL;
  int rc = 0;

  kbr = redis_kb (kb);
  rep = redis_cmd (kbr, "LPUSH %s %s", name, value);
  if (!rep || rep->type == REDIS_REPLY_ERROR)
    rc = -1;

  if (rep)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Pops a single KB string item.
 * @param[in] kb  KB handle where to fetch the item.
 * @param[in] name  Name of the key from where to retrieve.
 * @return A string to be freed or NULL if list is empty or on error.
 */
static char *
redis_pop_str (kb_t kb, const char *name)
{
  struct kb_redis *kbr;
  redisReply *rep;
  char *value = NULL;

  kbr = redis_kb (kb);
  rep = redis_cmd (kbr, "RPOP %s", name);
  if (!rep)
    return NULL;

  if (rep->type == REDIS_REPLY_STRING)
    value = g_strdup (rep->str);
  freeReplyObject (rep);

  return value;
}

/**
 * @brief Get a single KB integer item.
 * @param[in] kb  KB handle where to fetch the item.
 * @param[in] name  Name of the element to retrieve.
 * @return A struct kb_item to be freed with kb_item_free() or NULL if no
 *         element was found or on error.
 */
static int
redis_get_int (kb_t kb, const char *name)
{
  struct kb_item *kbi;

  kbi = redis_get_single (kb, name, KB_TYPE_INT);
  if (kbi != NULL)
    {
      int res;

      res = kbi->v_int;
      kb_item_free (kbi);
      return res;
    }
  return -1;
}

/**
 * @brief Get field of a NVT.
 * @param[in] kb        KB handle where to store the nvt.
 * @param[in] oid       OID of NVT to get from.
 * @param[in] position  Position of field to get.
 * @return Value of field, NULL otherwise.
 */
static char *
redis_get_nvt (kb_t kb, const char *oid, enum kb_nvt_pos position)
{
  struct kb_redis *kbr;
  redisReply *rep;
  char *res = NULL;

  kbr = redis_kb (kb);
  if (position >= NVT_TIMESTAMP_POS)
    rep = redis_cmd (kbr, "LINDEX filename:%s %d", oid,
                     position - NVT_TIMESTAMP_POS);
  else
    rep = redis_cmd (kbr, "LINDEX nvt:%s %d", oid, position);
  if (!rep)
    return NULL;
  if (rep->type == REDIS_REPLY_INTEGER)
    res = g_strdup_printf ("%lld", rep->integer);
  else if (rep->type == REDIS_REPLY_STRING)
    res = g_strdup (rep->str);
  freeReplyObject (rep);

  return res;
}

/**
 * @brief Get a full NVT.
 * @param[in] kb        KB handle where to store the nvt.
 * @param[in] oid       OID of NVT to get.
 * @return nvti_t of NVT, NULL otherwise.
 */
static nvti_t *
redis_get_nvt_all (kb_t kb, const char *oid)
{
  struct kb_redis *kbr;
  redisReply *rep;

  kbr = redis_kb (kb);
  rep =
    redis_cmd (kbr, "LRANGE nvt:%s %d %d", oid, NVT_FILENAME_POS, NVT_NAME_POS);
  if (!rep)
    return NULL;
  if (rep->type != REDIS_REPLY_ARRAY || rep->elements != NVT_NAME_POS + 1)
    {
      freeReplyObject (rep);
      return NULL;
    }
  else
    {
      nvti_t *nvti = nvti_new ();

      nvti_set_oid (nvti, oid);
      nvti_set_required_keys (nvti, rep->element[NVT_REQUIRED_KEYS_POS]->str);
      nvti_set_mandatory_keys (nvti, rep->element[NVT_MANDATORY_KEYS_POS]->str);
      nvti_set_excluded_keys (nvti, rep->element[NVT_EXCLUDED_KEYS_POS]->str);
      nvti_set_required_udp_ports (
        nvti, rep->element[NVT_REQUIRED_UDP_PORTS_POS]->str);
      nvti_set_required_ports (nvti, rep->element[NVT_REQUIRED_PORTS_POS]->str);
      nvti_set_dependencies (nvti, rep->element[NVT_DEPENDENCIES_POS]->str);
      nvti_set_tag (nvti, rep->element[NVT_TAGS_POS]->str);
      nvti_set_cve (nvti, rep->element[NVT_CVES_POS]->str);
      nvti_set_bid (nvti, rep->element[NVT_BIDS_POS]->str);
      nvti_set_xref (nvti, rep->element[NVT_XREFS_POS]->str);
      nvti_set_category (nvti, atoi (rep->element[NVT_CATEGORY_POS]->str));
      nvti_set_timeout (nvti, atoi (rep->element[NVT_TIMEOUT_POS]->str));
      nvti_set_family (nvti, rep->element[NVT_FAMILY_POS]->str);
      nvti_set_name (nvti, rep->element[NVT_NAME_POS]->str);

      freeReplyObject (rep);
      return nvti;
    }
}

/**
 * @brief Get all items stored under a given name.
 * @param[in] kb  KB handle where to fetch the items.
 * @param[in] name  Name of the elements to retrieve.
 * @return Linked struct kb_item instances to be freed with kb_item_free() or
 *         NULL if no element was found or on error.
 */
static struct kb_item *
redis_get_all (kb_t kb, const char *name)
{
  struct kb_redis *kbr;
  struct kb_item *kbi;
  redisReply *rep;

  kbr = redis_kb (kb);

  rep = redis_cmd (kbr, "LRANGE %s 0 -1", name);
  if (rep == NULL)
    return NULL;

  kbi = redis2kbitem (name, rep);

  freeReplyObject (rep);

  return kbi;
}

/**
 * @brief Get all items stored under a given pattern.
 * @param[in] kb  KB handle where to fetch the items.
 * @param[in] pattern  '*' pattern of the elements to retrieve.
 * @return Linked struct kb_item instances to be freed with kb_item_free() or
 *         NULL if no element was found or on error.
 */
static struct kb_item *
redis_get_pattern (kb_t kb, const char *pattern)
{
  struct kb_redis *kbr;
  struct kb_item *kbi = NULL;
  redisReply *rep;
  unsigned int i;
  redisContext *ctx;

  kbr = redis_kb (kb);
  rep = redis_cmd (kbr, "KEYS %s", pattern);
  if (!rep)
    return NULL;
  if (rep->type != REDIS_REPLY_ARRAY)
    {
      freeReplyObject (rep);
      return NULL;
    }

  ctx = get_redis_ctx (kbr);
  for (i = 0; i < rep->elements; i++)
    redisAppendCommand (ctx, "LRANGE %s 0 -1", rep->element[i]->str);

  for (i = 0; i < rep->elements; i++)
    {
      struct kb_item *tmp;
      redisReply *rep_range;

      redisGetReply (ctx, (void **) &rep_range);
      if (!rep)
        continue;
      tmp = redis2kbitem (rep->element[i]->str, rep_range);
      if (!tmp)
        {
          freeReplyObject (rep_range);
          continue;
        }

      if (kbi)
        {
          struct kb_item *tmp2;

          tmp2 = tmp;
          while (tmp->next)
            tmp = tmp->next;
          tmp->next = kbi;
          kbi = tmp2;
        }
      else
        kbi = tmp;
      freeReplyObject (rep_range);
    }

  freeReplyObject (rep);
  return kbi;
}

/**
 * @brief Get all NVT OIDs.
 * @param[in] kb  KB handle where to fetch the items.
 * @return Linked list of all OIDs or NULL.
 */
static GSList *
redis_get_oids (kb_t kb)
{
  struct kb_redis *kbr;
  redisReply *rep;
  GSList *list = NULL;
  size_t i;

  kbr = redis_kb (kb);
  rep = redis_cmd (kbr, "KEYS nvt:*");
  if (!rep)
    return NULL;

  if (rep->type != REDIS_REPLY_ARRAY)
    {
      freeReplyObject (rep);
      return NULL;
    }

  /* Fetch OID values from key names nvt:OID. */
  for (i = 0; i < rep->elements; i++)
    list = g_slist_prepend (list, g_strdup (rep->element[i]->str + 4));
  freeReplyObject (rep);

  return list;
}

/**
 * @brief Count all items stored under a given pattern.
 *
 * @param[in] kb  KB handle where to count the items.
 * @param[in] pattern  '*' pattern of the elements to count.
 *
 * @return Count of items.
 */
static size_t
redis_count (kb_t kb, const char *pattern)
{
  struct kb_redis *kbr;
  redisReply *rep;
  size_t count;

  kbr = redis_kb (kb);

  rep = redis_cmd (kbr, "KEYS %s", pattern);
  if (rep == NULL)
    return 0;

  if (rep->type != REDIS_REPLY_ARRAY)
    {
      freeReplyObject (rep);
      return 0;
    }

  count = rep->elements;
  freeReplyObject (rep);
  return count;
}

/**
 * @brief Delete all entries under a given name.
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @return 0 on success, non-null on error.
 */
static int
redis_del_items (kb_t kb, const char *name)
{
  struct kb_redis *kbr;
  redisReply *rep;
  int rc = 0;

  kbr = redis_kb (kb);

  rep = redis_cmd (kbr, "DEL %s", name);
  if (rep == NULL || rep->type == REDIS_REPLY_ERROR)
    rc = -1;

  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Insert (append) a new unique entry under a given name.
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @param[in] str  Item value.
 * @param[in] len  Value length. Used for blobs.
 * @return 0 on success, non-null on error.
 */
static int
redis_add_str_unique (kb_t kb, const char *name, const char *str, size_t len)
{
  struct kb_redis *kbr;
  redisReply *rep = NULL;
  int rc = 0;
  redisContext *ctx;

  kbr = redis_kb (kb);
  ctx = get_redis_ctx (kbr);

  /* Some VTs still rely on values being unique (ie. a value inserted multiple
   * times, will only be present once.)
   * Once these are fixed, the LREM becomes redundant and should be removed.
   */
  if (len == 0)
    {
      redisAppendCommand (ctx, "LREM %s 1 %s", name, str);
      redisAppendCommand (ctx, "RPUSH %s %s", name, str);
      redisGetReply (ctx, (void **) &rep);
      if (rep && rep->type == REDIS_REPLY_INTEGER && rep->integer == 1)
        g_debug ("Key '%s' already contained value '%s'", name, str);
      freeReplyObject (rep);
      redisGetReply (ctx, (void **) &rep);
    }
  else
    {
      redisAppendCommand (ctx, "LREM %s 1 %b", name, str, len);
      redisAppendCommand (ctx, "RPUSH %s %b", name, str, len);
      redisGetReply (ctx, (void **) &rep);
      if (rep && rep->type == REDIS_REPLY_INTEGER && rep->integer == 1)
        g_debug ("Key '%s' already contained string '%s'", name, str);
      freeReplyObject (rep);
      redisGetReply (ctx, (void **) &rep);
    }
  if (rep == NULL || rep->type == REDIS_REPLY_ERROR)
    rc = -1;

  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Insert (append) a new entry under a given name.
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @param[in] str  Item value.
 * @param[in] len  Value length. Used for blobs.
 * @return 0 on success, non-null on error.
 */
static int
redis_add_str (kb_t kb, const char *name, const char *str, size_t len)
{
  struct kb_redis *kbr;
  redisReply *rep;
  int rc = 0;

  kbr = redis_kb (kb);
  if (len == 0)
    rep = redis_cmd (kbr, "RPUSH %s %s", name, str);
  else
    rep = redis_cmd (kbr, "RPUSH %s %b", name, str, len);
  if (!rep || rep->type == REDIS_REPLY_ERROR)
    rc = -1;

  if (rep)
    freeReplyObject (rep);
  return rc;
}

/**
 * @brief Set (replace) a new entry under a given name.
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @param[in] val  Item value.
 * @param[in] len  Value length. Used for blobs.
 * @return 0 on success, non-null on error.
 */
static int
redis_set_str (kb_t kb, const char *name, const char *val, size_t len)
{
  struct kb_redis *kbr;
  redisReply *rep = NULL;
  redisContext *ctx;
  int rc = 0, i = 4;

  kbr = redis_kb (kb);
  ctx = get_redis_ctx (kbr);
  redisAppendCommand (ctx, "MULTI");
  redisAppendCommand (ctx, "DEL %s", name);
  if (len == 0)
    redisAppendCommand (ctx, "RPUSH %s %s", name, val);
  else
    redisAppendCommand (ctx, "RPUSH %s %b", name, val, len);
  redisAppendCommand (ctx, "EXEC");
  while (i--)
    {
      redisGetReply (ctx, (void **) &rep);
      if (!rep || rep->type == REDIS_REPLY_ERROR)
        rc = -1;
      if (rep)
        freeReplyObject (rep);
    }

  return rc;
}

/**
 * @brief Insert (append) a new unique entry under a given name.
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @param[in] val  Item value.
 * @return 0 on success, non-null on error.
 */
static int
redis_add_int_unique (kb_t kb, const char *name, int val)
{
  struct kb_redis *kbr;
  redisReply *rep;
  int rc = 0;
  redisContext *ctx;

  kbr = redis_kb (kb);
  ctx = get_redis_ctx (kbr);
  redisAppendCommand (ctx, "LREM %s 1 %d", name, val);
  redisAppendCommand (ctx, "RPUSH %s %d", name, val);
  redisGetReply (ctx, (void **) &rep);
  if (rep && rep->type == REDIS_REPLY_INTEGER && rep->integer == 1)
    g_debug ("Key '%s' already contained integer '%d'", name, val);
  freeReplyObject (rep);
  redisGetReply (ctx, (void **) &rep);
  if (rep == NULL || rep->type == REDIS_REPLY_ERROR)
    {
      rc = -1;
      goto out;
    }

out:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Insert (append) a new entry under a given name.
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @param[in] val  Item value.
 * @return 0 on success, non-null on error.
 */
static int
redis_add_int (kb_t kb, const char *name, int val)
{
  redisReply *rep;
  int rc = 0;

  rep = redis_cmd (redis_kb (kb), "RPUSH %s %d", name, val);
  if (!rep || rep->type == REDIS_REPLY_ERROR)
    rc = -1;
  if (rep)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Set (replace) a new entry under a given name.
 * @param[in] kb  KB handle where to store the item.
 * @param[in] name  Item name.
 * @param[in] val  Item value.
 * @return 0 on success, non-null on error.
 */
static int
redis_set_int (kb_t kb, const char *name, int val)
{
  redisReply *rep = NULL;
  redisContext *ctx;
  int rc = 0, i = 4;

  ctx = get_redis_ctx (redis_kb (kb));
  redisAppendCommand (ctx, "MULTI");
  redisAppendCommand (ctx, "DEL %s", name);
  redisAppendCommand (ctx, "RPUSH %s %d", name, val);
  redisAppendCommand (ctx, "EXEC");
  while (i--)
    {
      redisGetReply (ctx, (void **) &rep);
      if (!rep || rep->type == REDIS_REPLY_ERROR)
        rc = -1;
      if (rep)
        freeReplyObject (rep);
    }

  return rc;
}

/**
 * @brief Insert a new nvt.
 * @param[in] kb        KB handle where to store the nvt.
 * @param[in] nvt       nvt to store.
 * @param[in] filename  Path to nvt to store.
 * @return 0 on success, non-null on error.
 */
static int
redis_add_nvt (kb_t kb, const nvti_t *nvt, const char *filename)
{
  struct kb_redis *kbr;
  redisReply *rep = NULL;
  int rc = 0;
  GSList *element;

  if (!nvt || !filename)
    return -1;

  kbr = redis_kb (kb);
  rep = redis_cmd (
    kbr, "RPUSH nvt:%s %s %s %s %s %s %s %s %s %s %s %s %d %d %s %s",
    nvti_oid (nvt), filename, nvti_required_keys (nvt) ?: "",
    nvti_mandatory_keys (nvt) ?: "", nvti_excluded_keys (nvt) ?: "",
    nvti_required_udp_ports (nvt) ?: "", nvti_required_ports (nvt) ?: "",
    nvti_dependencies (nvt) ?: "", nvti_tag (nvt) ?: "", nvti_cve (nvt) ?: "",
    nvti_bid (nvt) ?: "", nvti_xref (nvt) ?: "", nvti_category (nvt),
    nvti_timeout (nvt), nvti_family (nvt), nvti_name (nvt));
  if (rep == NULL || rep->type == REDIS_REPLY_ERROR)
    rc = -1;
  if (rep != NULL)
    freeReplyObject (rep);

  element = nvt->prefs;
  if (g_slist_length (element))
    rep = redis_cmd (kbr, "DEL oid:%s:prefs", nvti_oid (nvt));
  while (element)
    {
      nvtpref_t *pref = element->data;

      rep = redis_cmd (kbr, "RPUSH oid:%s:prefs %s|||%s|||%s", nvti_oid (nvt),
                       pref->name, pref->type, pref->dflt);
      if (!rep || rep->type == REDIS_REPLY_ERROR)
        rc = -1;
      if (rep)
        freeReplyObject (rep);
      element = element->next;
    }
  rep = redis_cmd (kbr, "RPUSH filename:%s %lu %s", filename, time (NULL),
                   nvti_oid (nvt));
  if (!rep || rep->type == REDIS_REPLY_ERROR)
    rc = -1;
  if (rep)
    freeReplyObject (rep);
  return rc;
}

/**
 * @brief Reset connection to the KB. This is called after each fork() to make
 *        sure connections aren't shared between concurrent processes.
 * @param[in] kb KB handle.
 * @return 0 on success, non-null on error.
 */
static int
redis_lnk_reset (kb_t kb)
{
  struct kb_redis *kbr;

  kbr = redis_kb (kb);

  if (kbr->rctx != NULL)
    {
      redisFree (kbr->rctx);
      kbr->rctx = NULL;
    }

  return 0;
}

/**
 * @brief Flush all the KB's content. Delete all namespaces.
 * @param[in] kb        KB handle.
 * @param[in] except    Don't flush DB with except key.
 * @return 0 on success, non-null on error.
 */
static int
redis_flush_all (kb_t kb, const char *except)
{
  unsigned int i = 1;
  struct kb_redis *kbr;

  kbr = redis_kb (kb);
  if (kbr->rctx)
    redisFree (kbr->rctx);

  g_debug ("%s: deleting all DBs at %s except %s", __func__, kbr->path, except);
  do
    {
      redisReply *rep;

      kbr->rctx = redisConnectUnix (kbr->path);
      if (kbr->rctx == NULL || kbr->rctx->err)
        {
          g_log (G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
                 "%s: redis connection error: %s", __func__,
                 kbr->rctx ? kbr->rctx->errstr : strerror (ENOMEM));
          redisFree (kbr->rctx);
          kbr->rctx = NULL;
          return -1;
        }

      kbr->db = i;
      rep = redisCommand (kbr->rctx, "HEXISTS %s %d", GLOBAL_DBINDEX_NAME, i);
      if (rep == NULL || rep->type != REDIS_REPLY_INTEGER || rep->integer != 1)
        {
          freeReplyObject (rep);
          redisFree (kbr->rctx);
          i++;
          continue;
        }
      freeReplyObject (rep);
      rep = redisCommand (kbr->rctx, "SELECT %u", i);
      if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
        {
          freeReplyObject (rep);
          sleep (KB_RETRY_DELAY);
          redisFree (kbr->rctx);
          kbr->rctx = NULL;
        }
      else
        {
          freeReplyObject (rep);
          /* Don't remove DB if it has "except" key. */
          if (except)
            {
              char *tmp = kb_item_get_str (kb, except);
              if (tmp)
                {
                  g_free (tmp);
                  i++;
                  redisFree (kbr->rctx);
                  continue;
                }
            }
          redis_delete_all (kbr);
          redis_release_db (kbr);
          redisFree (kbr->rctx);
        }
      i++;
    }
  while (i < kbr->max_db);

  g_free (kb);
  return 0;
}

/**
 * @brief Save all the elements from the KB.
 * @param[in] kb        KB handle.
 * @return 0 on success, -1 on error.
 */
int
redis_save (kb_t kb)
{
  int rc;
  redisReply *rep;
  struct kb_redis *kbr;

  kbr = redis_kb (kb);
  g_debug ("%s: saving all elements from KB #%u", __func__, kbr->db);
  rep = redis_cmd (kbr, "SAVE");
  if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
    {
      rc = -1;
      goto err_cleanup;
    }

  rc = 0;

err_cleanup:
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Delete all the KB's content.
 * @param[in] kbr Subclass of struct kb.
 * @return 0 on success, non-null on error.
 */
int
redis_delete_all (struct kb_redis *kbr)
{
  int rc;
  redisReply *rep;
  struct sigaction new_action, original_action;

  /* Ignore SIGPIPE, in case of a lost connection. */
  new_action.sa_flags = 0;
  if (sigemptyset (&new_action.sa_mask))
    return -1;
  new_action.sa_handler = SIG_IGN;
  if (sigaction (SIGPIPE, &new_action, &original_action))
    return -1;

  g_debug ("%s: deleting all elements from KB #%u", __func__, kbr->db);
  rep = redis_cmd (kbr, "FLUSHDB");
  if (rep == NULL || rep->type != REDIS_REPLY_STATUS)
    {
      rc = -1;
      goto err_cleanup;
    }

  rc = 0;

err_cleanup:
  if (sigaction (SIGPIPE, &original_action, NULL))
    return -1;
  if (rep != NULL)
    freeReplyObject (rep);

  return rc;
}

/**
 * @brief Default KB operations.
 *        No selection mechanism is provided yet since there's only one
 *        implementation (redis-based).
 */
static const struct kb_operations KBRedisOperations = {
  .kb_new = redis_new,
  .kb_find = redis_find,
  .kb_delete = redis_delete,
  .kb_get_single = redis_get_single,
  .kb_get_str = redis_get_str,
  .kb_get_int = redis_get_int,
  .kb_get_nvt = redis_get_nvt,
  .kb_get_nvt_all = redis_get_nvt_all,
  .kb_get_nvt_oids = redis_get_oids,
  .kb_push_str = redis_push_str,
  .kb_pop_str = redis_pop_str,
  .kb_get_all = redis_get_all,
  .kb_get_pattern = redis_get_pattern,
  .kb_count = redis_count,
  .kb_add_str = redis_add_str,
  .kb_add_str_unique = redis_add_str_unique,
  .kb_set_str = redis_set_str,
  .kb_add_int = redis_add_int,
  .kb_add_int_unique = redis_add_int_unique,
  .kb_set_int = redis_set_int,
  .kb_add_nvt = redis_add_nvt,
  .kb_del_items = redis_del_items,
  .kb_lnk_reset = redis_lnk_reset,
  .kb_save = redis_save,
  .kb_flush = redis_flush_all,
  .kb_direct_conn = redis_direct_conn,
  .kb_get_kb_index = redis_get_kb_index,
};

const struct kb_operations *KBDefaultOperations = &KBRedisOperations;
