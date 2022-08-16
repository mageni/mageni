/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2019 Greenbone Networks GmbH
 * SPDX-FileComment: Ticket headers
 * SPDX-FileContributor: Matthew Mundell <matthew.mundell@greenbone.net>
 * SPDX-FileContributor: Mageni Security LLC
 * 
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
