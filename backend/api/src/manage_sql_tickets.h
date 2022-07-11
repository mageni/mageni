/* GVM
 * $Id$
 * Description: GVM management layer SQL: Ticket headers
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2019 Greenbone Networks GmbH
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

#ifndef _GVMD_MANAGE_SQL_TICKETS_H
#define _GVMD_MANAGE_SQL_TICKETS_H

#include "manage.h"

/**
 * @brief SQL to check if a result may have tickets.
 */
#define TICKET_SQL_RESULT_MAY_HAVE_TICKETS                         \
  "(SELECT EXISTS (SELECT * FROM tickets"                          \
  "                WHERE id IN (SELECT ticket FROM ticket_results" \
  "                             WHERE result = results.id"         \
  "                             AND result_location"               \
  "                                 = " G_STRINGIFY (LOCATION_TABLE) ")))"

user_t ticket_owner (ticket_t);

user_t ticket_assigned_to (ticket_t);

gchar *ticket_nvt_name (ticket_t);

int
delete_ticket (const char *, int);

int
restore_ticket (const char *);

void
empty_trashcan_tickets ();

void
check_tickets ();

void delete_tickets_user (user_t);

void inherit_tickets (user_t, user_t);

void tickets_remove_task (task_t);

void tickets_remove_tasks_user (user_t);

void tickets_trash_task (task_t);

void tickets_restore_task (task_t);

#endif /* not _GVMD_MANAGE_SQL_TICKETS_H */
