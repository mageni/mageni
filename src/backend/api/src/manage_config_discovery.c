/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Copyright 2013-2018 Greenbone Networks GmbH
 * SPDX-FileComment: This file contains the creation of the predefined config Discovery.
 * SPDX-FileContributor: Mageni Security LLC
 * 
 */

#include "manage.h"
#include "sql.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md   main"

/**
 * @brief Insert a nvt selector.
 */
#define NVT_SELECTOR(selector, oid, family)                               \
  sql ("INSERT INTO nvt_selectors"                                        \
       " (name, exclude, type, family_or_nvt, family)"                    \
       " VALUES"                                                          \
       " ('%s', 0, " G_STRINGIFY (NVT_SELECTOR_TYPE_NVT) ", '%s','%s');", \
       selector,                                                          \
       oid,                                                               \
       family)

/**
 * @brief Make Discovery Scan Config.
 *
 * Caller must lock the db.
 *
 * @param[in]  selector_name  Name of NVT selector to use.
 */
void
make_config_discovery_service_detection (char *const selector_name)
{
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11929", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900534", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902019", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800991", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900539", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800995", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800997", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800999", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100106", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900381", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.901084", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900384", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902023", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900620", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.901089", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900387", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902028", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902106", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900547", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900705", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900628", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.901087", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900624", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900543", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900629", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801869", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11865", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.901174", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.12647", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900550", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.901178", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900632", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.80079", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900556", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900714", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801874", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900710", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100201", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100206", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100208", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900394", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900712", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11945", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.20377", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900562", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103652", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.901188", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902046", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900641", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103579", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902044", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900647", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.17583", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100215", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100217", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100219", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11963", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.80092", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900493", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900571", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.80095", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902134", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902058", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902137", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900578", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900576", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900659", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100221", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100301", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100302", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902053", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100226", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100224", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.18532", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.18533", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.18534", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801972", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100300", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902061", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902220", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900583", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900744", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900822", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900746", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900748", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900904", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902309", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.101013", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100154", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100313", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801988", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.101019", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.101018", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900827", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100311", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100233", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11986", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11987", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902311", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900596", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902078", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900598", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100082", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100160", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100240", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.101021", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900753", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100243", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900917", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.101025", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.18393", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900839", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100324", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100322", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100407", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100328", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100329", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902081", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902083", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902084", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900681", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902089", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900686", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900923", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100174", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900926", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100254", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100331", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100335", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100259", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100417", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100419", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900930", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900853", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900932", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900855", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100180", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100184", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100261", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100187", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100266", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100423", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100268", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100425", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100503", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.20834", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902187", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100192", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902503", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100194", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900867", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100196", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900945", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100432", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100437", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100517", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.19289", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800300", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100518", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801005", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801007", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.19608", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900950", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100280", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902513", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900956", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100285", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100288", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100367", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.102005", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.102006", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.102009", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.17975", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.102003", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800158", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801017", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800317", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.102001", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.66286", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902520", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900961", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902447", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900966", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100294", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.10159", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100374", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.102013", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100376", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100456", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.102011", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.102017", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801100", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800165", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801102", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103979", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801106", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100292", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800407", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900971", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902533", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900976", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100382", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100540", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100466", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100464", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100468", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800170", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800098", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801112", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.19559", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800413", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801038", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801115", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801117", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801119", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.10330", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.10175", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902545", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902701", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902547", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100392", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900983", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100460", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100552", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11032", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100395", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100477", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800180", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100479", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801040", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100558", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801121", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103997", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801124", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800268", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801126", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801209", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11120", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11121", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.10342", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11128", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902717", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.102048", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100801", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100489", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800272", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801053", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800274", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800276", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801213", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800355", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800279", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801138", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801217", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800432", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902480", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902561", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11134", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100486", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100571", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100573", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100651", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800280", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100819", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801069", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800523", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800603", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800525", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801067", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.14664", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800608", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801223", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800446", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100742", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800291", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801072", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801074", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100669", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100748", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801234", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800297", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100827", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.14674", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800617", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800610", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801152", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801232", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11153", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11154", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.10379", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801081", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100755", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100911", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100675", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801087", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100838", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801244", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800467", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801403", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800547", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800627", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.802109", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800707", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800464", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800709", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100836", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801247", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.10462", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800622", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.10622", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100681", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103021", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801091", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800391", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800470", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801251", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800394", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800630", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800553", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800631", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800477", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800712", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.14772", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800559", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800716", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800633", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.14773", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103106", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100846", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801415", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100770", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103111", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100850", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100854", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103118", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801340", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100937", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100859", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800643", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801421", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800568", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800802", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800564", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.17200", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800728", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800807", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.14788", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100845", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.9000001", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100780", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801242", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103123", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103124", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103048", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103125", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100867", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800571", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103206", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800573", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100783", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800575", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103204", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801278", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801350", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801438", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800816", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800818", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800579", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800496", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103207", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800735", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100870", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900200", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100795", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103059", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.100950", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801363", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801443", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.802145", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800900", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800901", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800821", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800825", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800905", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.15588", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103140", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.10666", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103141", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103143", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103223", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103147", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800590", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800592", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900218", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800594", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.802230", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800832", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800677", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800911", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800913", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800918", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.802158", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103070", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800598", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103073", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103230", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801612", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103156", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.901003", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103158", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801381", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800680", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800681", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.901008", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800683", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.802244", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103317", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800765", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800688", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800923", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800768", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.17244", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800925", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.15765", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.15766", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800928", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.10761", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103081", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103086", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.901013", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103245", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801390", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.901016", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800690", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801392", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800692", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800693", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.802178", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801394", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800933", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800779", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800936", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103326", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800939", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900242", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103098", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103255", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.901025", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.80003", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.80004", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.80005", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.80006", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.901107", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.901023", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800941", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800864", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800786", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800949", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103181", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.20301", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900251", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900253", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900256", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900334", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900259", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900338", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800792", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800790", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.901118", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800870", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800951", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.901036", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801575", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800877", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800878", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800955", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801812", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.18219", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103190", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801737", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.901121", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.901044", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.80100", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103514", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800884", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800964", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800969", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.20160", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.10884", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11822", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900194", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900352", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.901056", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11906", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11907", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900357", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800891", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.901135", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800893", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11908", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800895", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800898", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801916", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900360", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.103294", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11913", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.80044", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.80045", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.801681", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.902009", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800980", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800984", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.800988", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900371", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900374", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.900376", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.108198", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.108199", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.108203", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.108204", "Service detection");
}

/**
 * @brief Make Discovery Scan Config.
 *
 * Caller must lock the db.
 *
 * @param[in]  uuid           UUID for new scan config.
 * @param[in]  selector_name  Name of NVT selector to use.
 */
void
make_config_discovery (char *const uuid, char *const selector_name)
{
  /* First, create the Discovery config. */
  sql ("INSERT into configs (uuid, name, owner, nvt_selector, comment,"
       " family_count, nvt_count, nvts_growing, families_growing,"
       " type, creation_time, modification_time)"
       " VALUES ('%s', 'Discovery', NULL,"
       "         '%s', 'Network Discovery scan configuration.',"
       "         0, 0, 0, 0, 0, m_now (), m_now ());",
       uuid,
       selector_name);

  /* Setup the appropriate NVTs for the config. */
  make_config_discovery_service_detection (selector_name);
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.17586", "Brute force attacks");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.17584", "Brute force attacks");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.17368", "Brute force attacks");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.11762", "Firewalls");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.80059", "Firewalls");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100083", "Firewalls");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.14377", "Firewalls");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.14378", "Firewalls");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.80062", "FTP");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.80063", "FTP");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900518", "FTP");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800545", "FTP");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900608", "FTP");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.80064", "FTP");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100131", "FTP");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900815", "FTP");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.901005", "FTP");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10990", "FTP");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.901108", "FTP");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900510", "FTP");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.108477", "FTP");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801057", "FTP");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900506", "FTP");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10920", "Malware");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10758", "Malware");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10921", "Malware");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900514", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10762", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900440", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.11156", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900442", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10919", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800510", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800215", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800512", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800367", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800514", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800369", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800516", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900072", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800518", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100169", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900522", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800219", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900073", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800217", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900526", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100091", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900528", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900529", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900524", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.101007", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.80066", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100096", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100092", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900453", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900304", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900306", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.18373", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800221", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800225", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10107", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800227", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900234", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.103585", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800000", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10185", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900535", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900239", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800001", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100100", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.802501", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900462", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100105", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800904", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100108", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10263", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100109", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800236", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800532", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100033", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.103441", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100034", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.902816", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800538", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100036", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800239", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.90022", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10793", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800018", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800019", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900173", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.11033", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900470", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100114", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900472", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900474", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900324", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900326", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800241", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900479", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100119", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800540", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801754", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800542", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.103978", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.14221", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.11414", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800324", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.11040", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100121", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800326", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900330", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800329", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900482", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100127", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900189", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100129", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10281", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100125", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100123", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800029", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800257", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800108", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.13849", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900191", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900490", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100133", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100134", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800339", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900198", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100136", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100138", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800260", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.50282", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800262", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.103996", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10441", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900196", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.103999", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100061", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10742", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.14315", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100063", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10746", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.15604", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.15901", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.12643", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900124", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100069", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900123", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.13858", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800341", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900128", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100140", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800345", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100142", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800348", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.17585", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800120", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.14629", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900508", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100074", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.11140", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900430", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.17367", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.15615", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.15614", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800353", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.18356", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.800357", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900217", "General");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.51662", "General");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11431", "Peer-To-Peer File Sharing");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11427", "Peer-To-Peer File Sharing");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.11125", "Peer-To-Peer File Sharing");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.10946", "Peer-To-Peer File Sharing");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.19585", "Peer-To-Peer File Sharing");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.13751", "Peer-To-Peer File Sharing");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.14644", "Peer-To-Peer File Sharing");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10265", "SNMP");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.103416", "SNMP");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.18528", "SMTP problems");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.91984", "Remote file access");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900602", "RPC");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.11111", "RPC");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.11239", "Web Servers");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10661", "Web Servers");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.80024", "Web Servers");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.19689", "Web Servers");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10386", "Web Servers");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.108479", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.108102", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.108478", "Service detection");
  NVT_SELECTOR (
    selector_name, "1.3.6.1.4.1.25623.1.0.10942", "Service detection");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.12231", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.80039", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10394", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10006", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.90011", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900012", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100062", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10674", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900032", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.902798", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.900025", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.902425", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10144", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10401", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.103621", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10400", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.102016", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.11011", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10794", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.10150", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.802726", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.11882", "Windows");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803551", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801632", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.810010", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801634", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803520", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803523", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803524", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803525", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803563", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803564", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803529", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803566", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803567", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803568", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803569", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801253", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801604", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801291", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803528", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801298", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801299", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801649", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801685", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801800", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801801", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803533", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801803", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803570", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801805", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803537", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803574", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803575", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801610", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801261", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801611", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801650", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801651", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801619", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801691", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801693", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801695", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801696", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803540", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801698", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801811", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803543", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803508", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803507", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803547", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803549", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803544", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801621", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801237", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801666", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803510", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803512", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803550", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803516", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801821", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.801822", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.803519", "Nmap NSE");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104147", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104163", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104149", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104026", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104165", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104167", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104029", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104048", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104063", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104066", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104067", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104068", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104110", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104111", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104085", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104069", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104114", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104130", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104089", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104088", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104010", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104135", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104137", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104157", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104158", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104018", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104053", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104057", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104074", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104075", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104091", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104076", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104093", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104120", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104121", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104104", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104109", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104001", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104125", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104124", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104143", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104021", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.104098", "Nmap NSE net");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.100315", "Port scanners");
  NVT_SELECTOR (selector_name, "1.3.6.1.4.1.25623.1.0.14259", "Port scanners");

  /* Add the Product Detection family. */
  sql ("INSERT INTO nvt_selectors (name, exclude, type, family_or_nvt, family)"
       " VALUES ('%s', 0, " G_STRINGIFY (
         NVT_SELECTOR_TYPE_FAMILY) ","
                                   "         'Product detection', 'Product "
                                   "detection');",
       selector_name);

  /* Update number of families and nvts. */
  sql ("UPDATE configs"
       " SET family_count = %i, nvt_count = %i,"
       " modification_time = m_now ()"
       " WHERE uuid = '%s';",
       nvt_selector_family_count (selector_name, 0),
       nvt_selector_nvt_count (selector_name, NULL, 0),
       uuid);

  /* Add preferences for "ping host" nvt. */
  sql ("INSERT INTO config_preferences (config, type, name, value)"
       " VALUES ((SELECT id FROM configs WHERE uuid = '%s'),"
       "         'PLUGINS_PREFS',"
       "         'Ping Host[checkbox]:Mark unrechable Hosts as dead (not "
       "scanning)',"
       " 'yes');",
       uuid);
  sql ("INSERT INTO config_preferences (config, type, name, value)"
       " VALUES ((SELECT id FROM configs WHERE uuid = '%s'),"
       "         'PLUGINS_PREFS',"
       "         'Ping Host[checkbox]:Report about unrechable Hosts',"
       "         'no');",
       uuid);

  /* Add preferences for "Services" nvt in Discovery Scan Config. */
  sql ("INSERT INTO config_preferences (config, type, name, value)"
       " VALUES ((SELECT id FROM configs WHERE uuid = '%s'),"
       "         'PLUGINS_PREFS',"
       "         'Services[radio]:Test SSL based services',"
       "         'All;Known SSL ports;None');",
       uuid);
}

/**
 * @brief Ensure the Discovery config is up to date.
 *
 * @param[in]  uuid  UUID of config.
 *
 * @return 0 success, -1 error.
 */
int
check_config_discovery (const char *uuid)
{
  /* Check preferences. */

  sql ("UPDATE config_preferences SET value = 'no'"
       " WHERE config = (SELECT id FROM configs WHERE uuid = '%s')"
       " AND type = 'PLUGINS_PREFS'"
       " AND name = 'Ping Host[checkbox]:Report about unrechable Hosts'"
       " AND value = 'yes';",
       uuid);

  update_config_preference (uuid,
                            "PLUGINS_PREFS",
                            "Ping Host[checkbox]:Mark unrechable Hosts as dead"
                            " (not scanning)",
                            "yes",
                            TRUE);

  return 0;
}
