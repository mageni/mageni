###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_146.nasl 10611 2018-07-25 11:49:26Z cfischer $
#
# IT-Grundschutz, 14. EL, Maßnahme 4.146
#
# Authors:
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.94216");
  script_version("$Revision: 10611 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 13:49:26 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"general_note");
  script_name("IT-Grundschutz M4.146: Sicherer Betrieb von Windows Client-Betriebssystemen");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04146.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_dependencies("compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB-15");

  script_tag(name:"summary", value:"IT-Grundschutz M4.146: Sicherer Betrieb von Windows Client-Betriebssystemen.

Stand: 14. Ergänzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.146: Sicherer Betrieb von Windows Client-Betriebssystemen\n';
gshbm =  "IT-Grundschutz M4.146: ";

result = 'Prüfung dieser Maßnahme ist nicht implementierbar.';
desc = 'Prüfung dieser Maßnahme ist nicht implementierbar.';

set_kb_item(name:"GSHB/M4_146/result", value:result);
set_kb_item(name:"GSHB/M4_146/desc", value:desc);
set_kb_item(name:"GSHB/M4_146/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_146');

exit(0);
