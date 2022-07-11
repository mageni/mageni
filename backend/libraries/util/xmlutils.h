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
 * @brief Headers for simple XML reader.
 */

#ifndef _GVM_XMLUTILS_H
#define _GVM_XMLUTILS_H

#include "serverutils.h"

#include <glib.h>
#include <gnutls/gnutls.h>
#include <stdio.h>

/**
 * @brief XML context.
 *
 * This structure is used to pass data between XML event handlers and the
 * caller of the XML parser.
 */
typedef struct
{
  GSList *first;   ///< The very first entity.
  GSList *current; ///< The element currently being parsed.
  gboolean done;   ///< Flag which is true when the first element is closed.
} context_data_t;

void
xml_handle_start_element (context_data_t *, const gchar *, const gchar **,
                          const gchar **);

void
xml_handle_end_element (context_data_t *, const gchar *);

void
xml_handle_text (context_data_t *, const gchar *, gsize);

/**
 * @brief Entities.
 */
typedef GSList *entities_t;

/**
 * @brief XML element.
 */
struct entity_s
{
  char *name;             ///< Name.
  char *text;             ///< Text.
  GHashTable *attributes; ///< Attributes.
  entities_t entities;    ///< Children.
};
typedef struct entity_s *entity_t;

/**
 * @brief Data for xml search functions.
 */
typedef struct
{
  int found;                   /**< Founded.*/
  int done;                    /**< Done. */
  gchar *find_element;         /**< Element to be find. */
  GHashTable *find_attributes; /**< Attributes to find. */
} xml_search_data_t;

entities_t next_entities (entities_t);

entity_t first_entity (entities_t);

entity_t
add_entity (entities_t *, const char *, const char *);

int compare_entities (entity_t, entity_t);

entity_t
entity_child (entity_t, const char *);

const char *
entity_attribute (entity_t, const char *);

char *
entity_name (entity_t entity);

char *
entity_text (entity_t entity);

void free_entity (entity_t);

void
print_entity (FILE *, entity_t);

void
print_entity_format (entity_t, gpointer indentation);

int
try_read_entity_and_string (gnutls_session_t *, int, entity_t *, GString **);

int
read_entity_and_string (gnutls_session_t *, entity_t *, GString **);

int
read_entity_and_string_c (gvm_connection_t *, entity_t *, GString **);

int
read_entity_and_text (gnutls_session_t *, entity_t *, char **);

int
read_entity_and_text_c (gvm_connection_t *, entity_t *, char **);

int
try_read_entity (gnutls_session_t *, int, entity_t *);

int
try_read_entity_c (gvm_connection_t *, int, entity_t *);

int
read_entity (gnutls_session_t *, entity_t *);

int
read_entity_s (int, entity_t *);

int
read_entity_c (gvm_connection_t *, entity_t *);

int
read_string (gnutls_session_t *, GString **);

int
read_string_c (gvm_connection_t *, GString **);

int
parse_entity (const char *, entity_t *);

void
print_entity_to_string (entity_t entity, GString *string);

int xml_count_entities (entities_t);

void
xml_string_append (GString *, const char *, ...);

/* XML file utilities */

int
find_element_in_xml_file (gchar *, gchar *, GHashTable *);

#endif /* not _GVM_XMLUTILS_H */
