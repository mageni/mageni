/* Copyright (C) 2009-2018 Greenbone Networks GmbH
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
 * @file sql.c
 * @brief Generic SQL interface
 *
 * This is a small generic interface for SQL database access.
 *
 * To add support for a specific database, like Postgres, a few functions
 * (for example, sql_prepare_internal and sql_exec_internal) need to be
 * implemented for that database.
 */

#include "sql.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/* Headers of internal symbols defined in backend files. */

int
sql_prepare_internal (int, int, const char *, va_list, sql_stmt_t **);

int
sql_exec_internal (int, sql_stmt_t *);

int
sql_explain_internal (const char *, va_list);

/* Variables. */

/**
 * @brief Whether to log errors.
 *
 * Used to turn off logging when cancelling statements on exit.
 */
int log_errors = 1;

/* Helpers. */

/**
 * @brief Quotes a string of a known length to be passed to sql statements.
 *
 * @param[in]  string  String to quote.
 * @param[in]  length  Size of \p string.
 *
 * @return Freshly allocated, quoted string. Free with g_free.
 */
gchar *
sql_nquote (const char *string, size_t length)
{
  gchar *new, *new_start;
  const gchar *start, *end;
  int count = 0;

  assert (string);

  /* Count number of apostrophes. */

  start = string;
  while ((start = strchr (start, '\'')))
    start++, count++;

  /* Allocate new string. */

  new = new_start = g_malloc0 (length + count + 1);

  /* Copy string, replacing apostrophes with double apostrophes. */

  start = string;
  end = string + length;
  for (; start < end; start++, new ++)
    {
      char ch = *start;
      if (ch == '\'')
        {
          *new = '\'';
          new ++;
          *new = '\'';
        }
      else
        *new = ch;
    }

  return new_start;
}

/**
 * @brief Quotes a string to be passed to sql statements.
 *
 * @param[in]  string  String to quote, has to be \\0 terminated.
 *
 * @return Freshly allocated, quoted string. Free with g_free.
 */
gchar *
sql_quote (const char *string)
{
  assert (string);
  return sql_nquote (string, strlen (string));
}

/**
 * @brief Get the SQL insert expression for a string.
 *
 * @param[in]  string  The string, which may be NULL.
 *
 * @return Freshly allocated expression suitable for an INSERT statement,
 *         including SQL quotation marks.
 */
gchar *
sql_insert (const char *string)
{
  if (string)
    {
      gchar *quoted_value = sql_quote (string);
      gchar *insert = g_strdup_printf ("'%s'", quoted_value);
      g_free (quoted_value);
      return insert;
    }
  return g_strdup ("NULL");
}

/**
 * @brief Perform an SQL statement.
 *
 * @param[in]  retry  Whether to keep retrying while database is busy or locked.
 * @param[in]  sql    Format string for SQL statement.
 * @param[in]  args   Arguments for format string.
 *
 * @return 0 success, 1 gave up (even when retry given), -1 error.
 */
int
sqlv (int retry, char *sql, va_list args)
{
  while (1)
    {
      int ret;
      sql_stmt_t *stmt;
      va_list args_copy;

      /* Prepare statement.
       * Copy args for this because a va_list can only be used once.
       */
      va_copy (args_copy, args);
      ret = sql_prepare_internal (retry, 1, sql, args_copy, &stmt);
      va_end (args_copy);
      if (ret == -1)
        g_debug ("%s: sql_prepare_internal failed", __FUNCTION__);
      if (ret)
        return ret;

      /* Run statement. */

      while ((ret = sql_exec_internal (retry, stmt)) == 1)
        ;
      if ((ret == -1) && log_errors)
        g_debug ("%s: sql_exec_internal failed", __FUNCTION__);
      sql_finalize (stmt);
      if (ret == 2)
        continue;
      if (ret == -2)
        return 1;
      if (ret == -3)
        return -1;
      assert (ret == -1 || ret == 0);
      return ret;
    }
}

/**
 * @brief Perform an SQL statement, retrying if database is busy or locked.
 *
 * @param[in]  sql    Format string for SQL statement.
 * @param[in]  ...    Arguments for format string.
 */
void
sql (char *sql, ...)
{
  while (1)
    {
      va_list args;
      int ret;

      va_start (args, sql);
      ret = sqlv (1, sql, args);
      va_end (args);
      if (ret == -1)
        abort ();
      if (ret == 1)
        /* Gave up with statement reset. */
        continue;
      break;
    }
}

/**
 * @brief Perform an SQL statement, retrying if database is busy or locked.
 *
 * Return on error, instead of aborting.
 *
 * @param[in]  sql    Format string for SQL statement.
 * @param[in]  ...    Arguments for format string.
 *
 * @return 0 success, -1 error.
 */
int
sql_error (char *sql, ...)
{
  int ret;

  while (1)
    {
      va_list args;
      va_start (args, sql);
      ret = sqlv (1, sql, args);
      va_end (args);
      if (ret == 1)
        /* Gave up with statement reset. */
        continue;
      break;
    }

  return ret;
}

/**
 * @brief Perform an SQL statement, giving up if database is busy or locked.
 *
 * @param[in]  sql    Format string for SQL statement.
 * @param[in]  ...    Arguments for format string.
 *
 * @return 0 success, 1 gave up, -1 error.
 */
int
sql_giveup (char *sql, ...)
{
  int ret;
  va_list args;

  va_start (args, sql);
  ret = sqlv (0, sql, args);
  va_end (args);
  return ret;
}

/**
 * @brief Get a particular cell from a SQL query.
 *
 * @param[in]   log          Whether to do g_debug logging.
 * @param[in]   sql          Format string for SQL query.
 * @param[in]   args         Arguments for format string.
 * @param[out]  stmt_return  Return from statement.
 *
 * @return 0 success, 1 too few rows, -1 error.
 */
static int
sql_x_internal (int log, char *sql, va_list args, sql_stmt_t **stmt_return)
{
  int ret;

  assert (stmt_return);

  while (1)
    {
      /* Prepare statement.
       * Copy args for this because a va_list can only be used once.
       */
      va_list args_copy;
      va_copy (args_copy, args);
      ret = sql_prepare_internal (1, log, sql, args_copy, stmt_return);
      va_end (args_copy);

      if (ret)
        {
          g_debug ("%s: sql_prepare failed", __FUNCTION__);
          return -1;
        }

      /* Run statement. */

      ret = sql_exec_internal (1, *stmt_return);
      if (ret == -1)
        {
          if (log_errors)
              g_debug ("%s: sql_exec_internal failed", __FUNCTION__);
          return -1;
        }
      if (ret == 0)
        /* Too few rows. */
        return 1;
      if (ret == -3 || ret == -2 || ret == 2)
        {
          /* Busy or locked, with statement reset.  Or schema changed. */
          sql_finalize (*stmt_return);
          continue;
        }
      break;
    }
  assert (ret == 1);
  if (log)
    g_debug ("   sql_x end (%s)", sql);
  return 0;
}

/**
 * @brief Get a particular cell from a SQL query.
 *
 * Do logging as usual.
 *
 * @param[in]   sql          Format string for SQL query.
 * @param[in]   args         Arguments for format string.
 * @param[out]  stmt_return  Return from statement.
 *
 * @return 0 success, 1 too few rows, -1 error.
 */
int
sql_x (char *sql, va_list args, sql_stmt_t **stmt_return)
{
  return sql_x_internal (1, sql, args, stmt_return);
}

/**
 * @brief Get the first value from a SQL query, as a double.
 *
 * @warning Aborts on invalid queries.
 *
 * @warning Aborts when the query returns fewer rows than \p row.  The
 *          caller must ensure that the query will return sufficient rows.
 *
 * @param[in]  sql    Format string for SQL query.
 * @param[in]  ...    Arguments for format string.
 *
 * @return Result of the query as an integer.
 */
double
sql_double (char *sql, ...)
{
  sql_stmt_t *stmt;
  va_list args;
  double ret;

  int sql_x_ret;
  va_start (args, sql);
  sql_x_ret = sql_x (sql, args, &stmt);
  va_end (args);
  if (sql_x_ret)
    {
      sql_finalize (stmt);
      abort ();
    }
  ret = sql_column_double (stmt, 0);
  sql_finalize (stmt);
  return ret;
}

/**
 * @brief Get a particular cell from a SQL query, as an int.
 *
 * @warning Aborts on invalid queries.
 *
 * @warning Aborts when the query returns fewer rows than \p row.  The
 *          caller must ensure that the query will return sufficient rows.
 *
 * @param[in]  sql    Format string for SQL query.
 * @param[in]  ...    Arguments for format string.
 *
 * @return Result of the query as an integer.
 */
int
sql_int (char *sql, ...)
{
  sql_stmt_t *stmt;
  va_list args;
  int ret;

  int sql_x_ret;
  va_start (args, sql);
  sql_x_ret = sql_x (sql, args, &stmt);
  va_end (args);
  if (sql_x_ret)
    {
      sql_finalize (stmt);
      abort ();
    }
  ret = sql_column_int (stmt, 0);
  sql_finalize (stmt);
  return ret;
}

/**
 * @brief Get a particular cell from a SQL query, as an string.
 *
 * @param[in]  sql    Format string for SQL query.
 * @param[in]  ...    Arguments for format string.
 *
 * @return Freshly allocated string containing the result, NULL otherwise.
 *         NULL means that either the selected value was NULL or there were
 *         no rows in the result.
 */
char *
sql_string (char *sql, ...)
{
  sql_stmt_t *stmt;
  const char *ret2;
  char *ret;
  int sql_x_ret;

  va_list args;
  va_start (args, sql);
  sql_x_ret = sql_x (sql, args, &stmt);
  va_end (args);
  if (sql_x_ret)
    {
      sql_finalize (stmt);
      return NULL;
    }
  ret2 = sql_column_text (stmt, 0);
  ret = g_strdup (ret2);
  sql_finalize (stmt);
  return ret;
}

/**
 * @brief Get a particular cell from a SQL query, as an int64.
 *
 * @param[in]  ret    Return value.
 * @param[in]  sql    Format string for SQL query.
 * @param[in]  ...    Arguments for format string.
 *
 * @return 0 success, 1 too few rows, -1 error.
 */
int
sql_int64 (long long int *ret, char *sql, ...)
{
  sql_stmt_t *stmt;
  int sql_x_ret;
  va_list args;

  va_start (args, sql);
  sql_x_ret = sql_x (sql, args, &stmt);
  va_end (args);
  switch (sql_x_ret)
    {
    case 0:
      break;
    case 1:
      sql_finalize (stmt);
      return 1;
      break;
    default:
      assert (0);
      /* Fall through. */
    case -1:
      sql_finalize (stmt);
      return -1;
      break;
    }
  *ret = sql_column_int64 (stmt, 0);
  sql_finalize (stmt);
  return 0;
}

/**
 * @brief Get a first column of first row from a SQL query, as an int64.
 *
 * Return 0 on error.
 *
 * @param[in]  sql    Format string for SQL query.
 * @param[in]  ...    Arguments for format string.
 *
 * @return 0 success, 1 too few rows, -1 error.
 */
long long int
sql_int64_0 (char *sql, ...)
{
  sql_stmt_t *stmt;
  int sql_x_ret;
  long long int ret;
  va_list args;

  va_start (args, sql);
  sql_x_ret = sql_x (sql, args, &stmt);
  va_end (args);
  if (sql_x_ret)
    {
      sql_finalize (stmt);
      return 0;
    }
  ret = sql_column_int64 (stmt, 0);
  sql_finalize (stmt);
  return ret;
}

/**
 * @brief Write debug messages with the query plan for an SQL query to the log.
 *
 * @param[in] sql   Format string for the SQL query.
 * @param[in] ...   Format string arguments.
 *
 * @return 0 success, -1 error.
 */
int
sql_explain (const char *sql, ...)
{
  int ret;
  va_list args;
  va_start (args, sql);
  ret = sql_explain_internal (sql, args);
  va_end (args);

  return ret;
}

/* Iterators. */

/**
 * @brief Initialise an iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  stmt      Statement.
 */
void
init_prepared_iterator (iterator_t *iterator, sql_stmt_t *stmt)
{
  iterator->done = FALSE;
  iterator->stmt = stmt;
  iterator->prepared = 1;
  iterator->crypt_ctx = NULL;
  g_debug ("   sql: init prepared %p", stmt);
}

/**
 * @brief Initialise an iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  sql       Format string for SQL.
 */
void
init_iterator (iterator_t *iterator, const char *sql, ...)
{
  int ret;
  sql_stmt_t *stmt;
  va_list args;

  iterator->done = FALSE;
  iterator->prepared = 0;
  iterator->crypt_ctx = NULL;

  va_start (args, sql);
  ret = sql_prepare_internal (1, 1, sql, args, &stmt);
  va_end (args);
  if (ret)
    {
      g_warning ("%s: sql_prepare failed", __FUNCTION__);
      abort ();
    }
  iterator->stmt = stmt;
}

/**
 * @brief Get a double column from an iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  col       Column offset.
 *
 * @return Value of given column.
 */
double
iterator_double (iterator_t *iterator, int col)
{
  if (iterator->done)
    abort ();
  return sql_column_double (iterator->stmt, col);
}

/**
 * @brief Get a int column from an iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  col       Column offset.
 *
 * @return Value of given column.
 */
int
iterator_int (iterator_t *iterator, int col)
{
  if (iterator->done)
    abort ();
  return sql_column_int (iterator->stmt, col);
}

/**
 * @brief Get an integer column from an iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  col       Column offset.
 *
 * @return Value of given column.
 */
long long int
iterator_int64 (iterator_t *iterator, int col)
{
  if (iterator->done)
    abort ();
  return sql_column_int64 (iterator->stmt, col);
}

/**
 * @brief Get a string column from an iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  col       Column offset.
 *
 * @return Value of given column.
 */
const char *
iterator_string (iterator_t *iterator, int col)
{
  if (iterator->done)
    abort ();
  return sql_column_text (iterator->stmt, col);
}

/**
 * @brief Cleanup an iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
cleanup_iterator (iterator_t *iterator)
{
  if (iterator == NULL)
    {
      g_warning ("%s: null iterator pointer", __FUNCTION__);
      return;
    }

  if (iterator->prepared == 0)
    sql_finalize (iterator->stmt);
  if (iterator->crypt_ctx)
    {
      lsc_crypt_release (iterator->crypt_ctx);
      iterator->crypt_ctx = NULL;
    }
}

/**
 * @brief Increment an iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return TRUE if there was a next item, else FALSE.
 */
gboolean
next (iterator_t *iterator)
{
  int ret;

  if (iterator->done)
    return FALSE;

  if (iterator->crypt_ctx)
    lsc_crypt_flush (iterator->crypt_ctx);
  while (1)
    {
      ret = sql_exec_internal (1, iterator->stmt);
      if (ret == 0)
        {
          iterator->done = TRUE;
          return FALSE;
        }
      if (ret == -1)
        {
          if (log_errors)
            g_warning ("%s: sql_exec_internal failed", __FUNCTION__);
          abort ();
        }
      if (ret == -3 || ret == -2)
        {
          /* Busy or locked, with statement reset.  Just try step again like
           * we used to do in sql_exec_internal.  We're not supposed to do this
           * for SQLite, but it would mean quite a bit of reworking in the
           * callers to be able to handle this case. */
          g_warning ("%s: stepping after reset", __FUNCTION__);
          continue;
        }
      if (ret == 2)
        {
          /* Schema changed, for example an internal change due to a VACUUM.
           * Retrying will result in the same error, so abort.  We lock
           * exclusively around the VACUUM in --optimize, so hopefully when
           * using --optimize the schema error will happen earlier, in the
           * the init function for the iterator.
           *
           * This only applies to SQLite3. */
          g_warning ("%s: schema error.\n"
                     "  This is possibly due to running VACUUM while Manager\n"
                     "  is running.  Restart Manager.  In future use\n"
                     "  --optimize=vacuum instead of running VACUUM"
                     "  directly.",
                     __FUNCTION__);
          abort ();
        }
      break;
    }
  assert (ret == 1);
  return TRUE;
}

/* Prepared statements. */

/**
 * @brief Prepare a statement.
 *
 * @param[in]  sql  Format string for SQL.
 *
 * @return Statement on success, NULL on error.
 */
sql_stmt_t *
sql_prepare (const char *sql, ...)
{
  int ret;
  sql_stmt_t *stmt;
  va_list args;

  va_start (args, sql);
  ret = sql_prepare_internal (1, 1, sql, args, &stmt);
  va_end (args);
  if (ret)
    return NULL;
  return stmt;
}

/**
 * @brief Execute a prepared statement.
 *
 * @param[in]  stmt  Statement.
 *
 * @return 0 complete, 1 row available in results, 2 rerun prepare, -1 error,
 *         -2 gave up with statement reset.
 */
int
sql_exec (sql_stmt_t *stmt)
{
  return sql_exec_internal (1, stmt);
}
