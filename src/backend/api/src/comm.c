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
 * @file comm.c
 * @brief Generic communication utilities
 *
 * This file contains generic convenience utilities for handling a buffer that
 * is used to communicate with a server.
 */

#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/** @todo Consider moving to libs (so please leave "server" in the names). */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md   comm"

/** @cond STATIC */

/**
 * @brief The size of the \ref to_server data buffer.
 */
#define TO_SERVER_BUFFER_SIZE 26214400

/** @endcond */

/** @cond STATIC */

/**
 * @brief Buffer of output to the server.
 */
char to_server[TO_SERVER_BUFFER_SIZE];

/**
 * @brief The end of the data in the \ref to_server buffer.
 */
int to_server_end = 0;

/**
 * @brief The start of the data in the \ref to_server buffer.
 */
int to_server_start = 0;

/** @endcond */

/**
 * @brief Get the number of characters free in the server output buffer.
 *
 * @return Number of characters free in server output buffer.  0 when full.
 */
unsigned int
to_server_buffer_space ()
{
  if (to_server_end < to_server_start)
    abort ();
  return (unsigned int) (to_server_end - to_server_start);
}

/**
 * @brief Send a number of bytes to the server.
 *
 * @param[in]  msg  The message, a sequence of bytes.
 * @param[in]  n    The number of bytes from msg to send.
 *
 * @return 0 for success, any other value for failure.
 */
int
sendn_to_server (const void *msg, size_t n)
{
  if (TO_SERVER_BUFFER_SIZE - to_server_end < n)
    {
      g_debug ("   sendn_to_server: available space (%i) < n (%zu)",
               TO_SERVER_BUFFER_SIZE - to_server_end,
               n);
      return 1;
    }

  memmove (to_server + to_server_end, msg, n);
  g_debug ("s> server  (string) %.*s", (int) n, to_server + to_server_end);
  g_debug ("-> server  %zu bytes", n);
  to_server_end += n;

  return 0;
}

/**
 * @brief Send a message to the server.
 *
 * @param[in]  msg  The message, a string.
 *
 * @return 0 for success, any other value for failure.
 */
int
send_to_server (const char *msg)
{
  return sendn_to_server (msg, strlen (msg));
}

/**
 * @brief Format and send a message to the server.
 *
 * @param[in]  format  printf-style format string for message.
 *
 * @return 0 for success, any other value for failure.
 */
int
sendf_to_server (const char *format, ...)
{
  va_list args;
  gchar *msg;
  int ret;
  va_start (args, format);
  msg = g_strdup_vprintf (format, args);
  ret = send_to_server (msg);
  g_free (msg);
  va_end (args);
  return ret;
}
