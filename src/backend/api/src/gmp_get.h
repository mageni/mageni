// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Name: gmp_get.h
 * Brief: Common GET command headers.
 * 
 * Common GET headers code for the GVM GMP layer.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 * 
 * Copyright:
 * Copyright (C) 2018 Greenbone Networks GmbH
 * Copyright (C) 2022, Mageni Security LL
 * 
 */

#ifndef _GVMD_GMP_GET_H
#define _GVMD_GMP_GET_H

#include "manage.h"

void
get_data_parse_attributes (get_data_t *,
                           const gchar *,
                           const gchar **,
                           const gchar **);

int
init_get (gchar *, get_data_t *, const gchar *, int *);

/**
 * @brief Call init_get for a GET end handler.
 *
 * @param[in]  type     Resource type.
 * @param[in]  capital  Resource type, capitalised.
 */
#define INIT_GET(type, capital)                                   \
  count = 0;                                                      \
  ret = init_get ("get_" G_STRINGIFY (type) "s",                  \
                  &get_##type##s_data->get,                       \
                  G_STRINGIFY (capital) "s",                      \
                  &first);                                        \
  if (ret)                                                        \
    {                                                             \
      switch (ret)                                                \
        {                                                         \
        case 99:                                                  \
          SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX (              \
            "get_" G_STRINGIFY (type) "s", "Permission denied")); \
          break;                                                  \
        default:                                                  \
          internal_error_send_to_client (error);                  \
          return;                                                 \
        }                                                         \
      get_##type##s_data_reset (get_##type##s_data);              \
      set_client_state (CLIENT_AUTHENTIC);                        \
      return;                                                     \
    }

int
get_next (iterator_t *,
          get_data_t *,
          int *,
          int *,
          int (*) (iterator_t *, const get_data_t *));

int
send_get_start (const char *, int (*) (const char *, void *), void *);

/**
 * @brief Send start of GET response to client, returning on fail.
 *
 * @param[in]  type  Type of resource.
 * @param[in]  get   GET data.
 */
#define SEND_GET_START(type)                                                  \
  do                                                                          \
    {                                                                         \
      if (send_get_start (                                                    \
            type, gmp_parser->client_writer, gmp_parser->client_writer_data)) \
        {                                                                     \
          error_send_to_client (error);                                       \
          return;                                                             \
        }                                                                     \
    }                                                                         \
  while (0)

int
send_get_common (const char *,
                 get_data_t *,
                 iterator_t *,
                 int (*) (const char *, void *),
                 void *,
                 int,
                 int);

/**
 * @brief Send common part of GET response to client, returning on fail.
 *
 * @param[in]  type      Type of resource.
 * @param[in]  get       GET data.
 * @param[in]  iterator  Iterator.
 */
#define SEND_GET_COMMON(type, get, iterator)                               \
  do                                                                       \
    {                                                                      \
      if (send_get_common (                                                \
            G_STRINGIFY (type),                                            \
            get,                                                           \
            iterator,                                                      \
            gmp_parser->client_writer,                                     \
            gmp_parser->client_writer_data,                                \
            (get)->trash                                                   \
              ? trash_##type##_writable (get_iterator_resource (iterator)) \
              : type##_writable (get_iterator_resource (iterator)),        \
            (get)->trash                                                   \
              ? trash_##type##_in_use (get_iterator_resource (iterator))   \
              : type##_in_use (get_iterator_resource (iterator))))         \
        {                                                                  \
          error_send_to_client (error);                                    \
          return;                                                          \
        }                                                                  \
    }                                                                      \
  while (0)

int
buffer_get_filter_xml (GString *,
                       const char *,
                       const get_data_t *,
                       const char *,
                       const char *);

int
send_get_end (const char *,
              get_data_t *,
              int,
              int,
              int,
              int (*) (const char *, void *),
              void *);

int
send_get_end_no_counts (const char *,
                        get_data_t *,
                        int (*) (const char *, void *),
                        void *);

/**
 * @brief Send end of GET response to client, returning on fail.
 *
 * @param[in]  type  Type of resource.
 * @param[in]  get   GET data.
 */
#define SEND_GET_END(type, get, count, filtered)         \
  do                                                     \
    {                                                    \
      if (send_get_end (type,                            \
                        get,                             \
                        count,                           \
                        filtered,                        \
                        resource_count (type, get),      \
                        gmp_parser->client_writer,       \
                        gmp_parser->client_writer_data)) \
        {                                                \
          error_send_to_client (error);                  \
          return;                                        \
        }                                                \
    }                                                    \
  while (0)

#endif /* not _GVMD_GMP_GET_H */
